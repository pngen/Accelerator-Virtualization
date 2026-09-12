// Accelerator Virtualization - CUDA adapter.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The narrow vendor seam. Everything in this file is REAL physical behaviour:
// device discovery, capability queries, device allocation, transfers and
// kernel execution. Nothing here creates a partition, a virtual function or a
// hardware isolation boundary, and nothing here claims one.
#include <cuda_runtime.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "av/cuda.hpp"

extern "C" int av_cuda_vector_add(const float* a, const float* b, float* out, int count);

namespace av {
namespace {

std::string cuda_error_text(cudaError_t status) {
  const char* name = cudaGetErrorName(status);
  const char* text = cudaGetErrorString(status);
  std::string out = name != nullptr ? std::string(name) : std::string("cudaError");
  out.append(": ");
  out.append(text != nullptr ? std::string(text) : std::string("unknown CUDA error"));
  return out;
}

CapabilityEntry make_capability(CapabilityKey key, CapabilityVerdict verdict, std::uint64_t value, std::string text,
                                std::string provenance) {
  CapabilityEntry entry;
  entry.key = key;
  entry.verdict = verdict;
  entry.value = value;
  entry.text = std::move(text);
  entry.provenance = std::move(provenance);
  return entry;
}

IsolationClaim make_claim(IsolationDimension dimension, IsolationState state, std::string rationale) {
  IsolationClaim claim;
  claim.dimension = dimension;
  claim.state = state;
  claim.mechanism = "cuda-runtime-shared-context";
  claim.rationale = std::move(rationale);
  return claim;
}

// The truthful isolation profile of a software-governed CUDA backing.
//
// Two virtual accelerators backed by the same physical device through this
// adapter share one CUDA context and one physical memory pool. That is
// software multiplexing with logical separation, not hardware isolation, and
// this profile says exactly that. UNKNOWN is used wherever the runtime cannot
// prove the property, and is never upgraded to ISOLATED.
std::vector<IsolationClaim> cuda_isolation() {
  return {
      make_claim(IsolationDimension::Memory, IsolationState::Shared,
                 "one physical device memory pool; per-virtual budgets are enforced by runtime accounting only"),
      make_claim(IsolationDimension::ExecutionContext, IsolationState::Shared,
                 "all virtual accelerators execute through one shared CUDA context"),
      make_claim(IsolationDimension::AddressSpace, IsolationState::Shared,
                 "the device address space is shared; there is no per-tenant device address-space boundary"),
      make_claim(IsolationDimension::Fault, IsolationState::Shared,
                 "an illegal access or device fault is not contained by this runtime"),
      make_claim(IsolationDimension::Reset, IsolationState::Shared,
                 "a device reset affects every virtual accelerator on the physical device"),
      make_claim(IsolationDimension::Performance, IsolationState::Shared,
                 "compute and bandwidth are shared and neighbours are not performance-isolated"),
      make_claim(IsolationDimension::Telemetry, IsolationState::Unknown,
                 "this runtime cannot attribute device telemetry to a single virtual accelerator"),
      make_claim(IsolationDimension::AdminControl, IsolationState::Partial,
                 "the governance plane is separate per virtual accelerator; the device administration plane is not"),
      make_claim(IsolationDimension::PeerVisibility, IsolationState::Shared,
                 "peer and device visibility is not partitioned"),
      make_claim(IsolationDimension::Dma, IsolationState::Unknown,
                 "DMA translation and IOMMU behaviour are outside this runtime and are not proven"),
      make_claim(IsolationDimension::TenantState, IsolationState::Isolated,
                 "tenant governance state, leases and authority are separate per virtual accelerator"),
  };
}

CapabilitySurface cuda_capabilities(const cudaDeviceProp& properties) {
  CapabilitySurface surface;
  surface.set(make_capability(CapabilityKey::MemoryTotalBytes, CapabilityVerdict::Supported,
                              properties.totalGlobalMem, {}, "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::SmCount, CapabilityVerdict::Supported,
                              static_cast<std::uint64_t>(properties.multiProcessorCount), {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::ComputeCapabilityMajor, CapabilityVerdict::Supported,
                              static_cast<std::uint64_t>(properties.major), {}, "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::ComputeCapabilityMinor, CapabilityVerdict::Supported,
                              static_cast<std::uint64_t>(properties.minor), {}, "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::ArchitectureFamily, CapabilityVerdict::Supported, 0,
                              std::string(properties.name), "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::MaxStreams, CapabilityVerdict::Unknown, 0,
                              "the CUDA runtime does not report a fixed stream ceiling", "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::MaxConcurrentKernels, CapabilityVerdict::Supported,
                              properties.concurrentKernels != 0 ? 1u : 0u, {}, "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::AsyncCopy, CapabilityVerdict::Supported,
                              static_cast<std::uint64_t>(properties.asyncEngineCount), {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::UnifiedMemory, CapabilityVerdict::Supported,
                              properties.unifiedAddressing != 0 ? 1u : 0u, {}, "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::PrecisionFp32, CapabilityVerdict::Supported, 0, {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::PrecisionFp16, CapabilityVerdict::Supported, 0, {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::PrecisionFp64, CapabilityVerdict::Supported, 0, {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::PrecisionBf16, CapabilityVerdict::Supported, 0, {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::PrecisionInt8, CapabilityVerdict::Supported, 0, {},
                              "cuda-device-properties"));
  // FP8 reaches the device through platform-specific feature sets that this
  // build does not query, so it stays UNKNOWN rather than guessed.
  surface.set(make_capability(CapabilityKey::PrecisionFp8, CapabilityVerdict::Unknown, 0, {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::PeerAccess, CapabilityVerdict::Unsupported, 0,
                              "peer access is not exposed by this runtime and is never implied",
                              "virtualization-policy"));
  surface.set(make_capability(CapabilityKey::ResetBehavior, CapabilityVerdict::Unknown, 0,
                              "reset behaviour is not proven by this runtime", "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::MemoryBandwidthBytesPerSecond, CapabilityVerdict::Unknown, 0, {},
                              "cuda-device-properties"));
  surface.set(make_capability(CapabilityKey::TransferCapability, CapabilityVerdict::Supported, 0,
                              "host to device and device to host transfers", "cuda-device-properties"));
  return surface;
}

struct CudaDevice {
  PhysicalDeviceDescriptor descriptor;
  int ordinal{0};
};

}  // namespace

class CudaBackendAdapter final : public BackendAdapter {
 public:
  CudaBackendAdapter() = default;

  std::string name() const override { return "cuda"; }
  Provenance provenance() const override { return Provenance::Real; }
  std::vector<BackingClass> supported_backing_classes() const override {
    return {BackingClass::DedicatedPhysical, BackingClass::CooperativeShared};
  }

  Result<std::vector<PhysicalDeviceDescriptor>> discover() override {
    int count = 0;
    const cudaError_t counted = cudaGetDeviceCount(&count);
    if (counted != cudaSuccess) {
      return Status(StatusCode::BackingUnavailable, "cudaGetDeviceCount failed: " + cuda_error_text(counted));
    }
    if (count <= 0) return std::vector<PhysicalDeviceDescriptor>{};
    if (count > 64) count = 64;  // defensive bound against a hostile driver

    std::vector<CudaDevice> devices;
    std::vector<PhysicalDeviceDescriptor> out;
    for (int index = 0; index < count; ++index) {
      auto device = describe(index);
      if (!device.ok()) continue;
      out.push_back(device.value().descriptor);
      devices.push_back(device.take());
    }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      devices_ = std::move(devices);
    }
    if (out.empty()) {
      return Status(StatusCode::BackingUnavailable, "no usable CUDA device could be described");
    }
    return out;
  }

  Result<PhysicalDeviceDescriptor> probe(std::string_view stable_key) override {
    auto devices = discover();
    if (!devices.ok()) return devices.status();
    for (const PhysicalDeviceDescriptor& descriptor : devices.value()) {
      if (descriptor.stable_key == stable_key) return descriptor;
    }
    return Status(StatusCode::NotFound, "CUDA device '" + std::string(stable_key) + "' is not present");
  }

  Result<ExecutionResult> execute(const ExecutionRequest& request) override {
    int ordinal = -1;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (const CudaDevice& device : devices_) {
        if (device.descriptor.stable_key == request.stable_key) {
          ordinal = device.ordinal;
          break;
        }
      }
    }
    if (ordinal < 0) {
      auto refreshed = discover();
      if (!refreshed.ok()) return refreshed.status();
      std::lock_guard<std::mutex> lock(mutex_);
      for (const CudaDevice& device : devices_) {
        if (device.descriptor.stable_key == request.stable_key) {
          ordinal = device.ordinal;
          break;
        }
      }
    }
    if (ordinal < 0) {
      return Status(StatusCode::StalePhysicalDevice,
                    "physical device '" + request.stable_key + "' is no longer present on this host");
    }

    ExecutionResult result;
    const cudaError_t selected = cudaSetDevice(ordinal);
    if (selected != cudaSuccess) {
      result.status = StatusCode::BackingUnavailable;
      result.detail = "cudaSetDevice failed: " + cuda_error_text(selected);
      return result;
    }

    switch (request.op) {
      case ExecutionOp::DeviceInfo:
        return device_info(result);
      case ExecutionOp::Allocate:
        return allocate(request, result);
      case ExecutionOp::Free:
        return release(request, result);
      case ExecutionOp::Upload:
        return upload(request, result);
      case ExecutionOp::Download:
        return download(request, result);
      case ExecutionOp::KernelVectorAdd:
        return vector_add(request, result);
      case ExecutionOp::Synchronize: {
        const cudaError_t status = cudaDeviceSynchronize();
        result.status = status == cudaSuccess ? StatusCode::Ok : StatusCode::Internal;
        result.detail = status == cudaSuccess ? std::string{} : cuda_error_text(status);
        return result;
      }
      case ExecutionOp::Unknown:
      default:
        result.status = StatusCode::Unsupported;
        result.detail = "unknown execution operation";
        return result;
    }
  }

 private:
  Result<CudaDevice> describe(int ordinal) {
    cudaDeviceProp properties{};
    const cudaError_t queried = cudaGetDeviceProperties(&properties, ordinal);
    if (queried != cudaSuccess) {
      return Status(StatusCode::BackingUnavailable,
                    "cudaGetDeviceProperties failed: " + cuda_error_text(queried));
    }
    CudaDevice device;
    device.ordinal = ordinal;

    // The stable identity is the PCI bus address of the device: a hardware
    // address rather than an enumeration ordinal. An ordinal or device index
    // can be reused by a different device and would resurrect stale virtual
    // authority.
    char bus_id[64] = {};
    const cudaError_t bus_status = cudaDeviceGetPCIBusId(bus_id, sizeof(bus_id), ordinal);
    if (bus_status != cudaSuccess || bus_id[0] == 0) {
      return Status(StatusCode::BackingUnavailable,
                    "the CUDA device does not expose a PCI bus identity: " + cuda_error_text(bus_status));
    }
    const std::string stable_key = "cuda:pci:" + std::string(bus_id);

    PhysicalDeviceDescriptor& descriptor = device.descriptor;
    descriptor.stable_key = stable_key;
    descriptor.vendor = "NVIDIA";
    descriptor.model = properties.name;
    int driver_version = 0;
    if (cudaDriverGetVersion(&driver_version) == cudaSuccess) {
      descriptor.driver_version =
          std::to_string(driver_version / 1000) + "." + std::to_string((driver_version % 1000) / 10);
    }
    descriptor.architecture = "sm_" + std::to_string(properties.major) + std::to_string(properties.minor);
    descriptor.provenance = Provenance::Real;
    descriptor.memory_total_bytes = properties.totalGlobalMem;
    descriptor.compute_units = static_cast<std::uint32_t>(properties.multiProcessorCount);
    descriptor.compute_capability_major = static_cast<std::uint32_t>(properties.major);
    descriptor.compute_capability_minor = static_cast<std::uint32_t>(properties.minor);
    descriptor.mechanism = "cuda-runtime";
    // This adapter does not implement, and therefore does not claim, hardware
    // partitioning, MIG or virtual functions.
    descriptor.hardware_partition_capable = false;
    descriptor.virtual_function_capable = false;
    descriptor.mig_capable = false;

    const std::vector<IsolationClaim> isolation = cuda_isolation();
    const CapabilitySurface capabilities = cuda_capabilities(properties);

    BackingDescriptor dedicated;
    dedicated.label = "cuda-dedicated";
    dedicated.klass = BackingClass::DedicatedPhysical;
    dedicated.multiplexing = MultiplexingMode::Dedicated;
    dedicated.isolation_class = IsolationClass::None;
    dedicated.capacity_bytes = properties.totalGlobalMem;
    dedicated.compute_units = static_cast<std::uint32_t>(properties.multiProcessorCount);
    dedicated.mechanism = "cuda-runtime-exclusive";
    dedicated.isolation = isolation;
    dedicated.capabilities = capabilities;
    dedicated.exclusive = true;
    descriptor.backings.push_back(dedicated);

    BackingDescriptor shared;
    shared.label = "cuda-shared-context";
    shared.klass = BackingClass::CooperativeShared;
    shared.multiplexing = MultiplexingMode::CooperativeShared;
    shared.isolation_class = IsolationClass::Logical;
    shared.capacity_bytes = properties.totalGlobalMem;
    shared.compute_units = static_cast<std::uint32_t>(properties.multiProcessorCount);
    shared.mechanism = "cuda-runtime-shared-context";
    shared.isolation = isolation;
    shared.capabilities = capabilities;
    shared.exclusive = false;
    descriptor.backings.push_back(shared);

    return device;
  }

  Result<ExecutionResult> device_info(ExecutionResult& result) {
    std::size_t free_bytes = 0;
    std::size_t total_bytes = 0;
    const cudaError_t status = cudaMemGetInfo(&free_bytes, &total_bytes);
    if (status != cudaSuccess) {
      result.status = StatusCode::Internal;
      result.detail = "cudaMemGetInfo failed: " + cuda_error_text(status);
      return result;
    }
    result.status = StatusCode::Ok;
    result.total_memory = total_bytes;
    result.free_memory = free_bytes;
    return result;
  }

  Result<ExecutionResult> allocate(const ExecutionRequest& request, ExecutionResult& result) {
    if (request.bytes == 0) {
      result.status = StatusCode::InvalidArgument;
      result.detail = "allocation size must be greater than zero";
      return result;
    }
    void* pointer = nullptr;
    const cudaError_t status = cudaMalloc(&pointer, static_cast<std::size_t>(request.bytes));
    if (status != cudaSuccess) {
      result.status = StatusCode::ResourceExhausted;
      result.detail = "cudaMalloc failed: " + cuda_error_text(status);
      return result;
    }
    const std::uint64_t handle = next_handle();
    {
      std::lock_guard<std::mutex> lock(mutex_);
      handles_[handle] = pointer;
    }
    result.status = StatusCode::Ok;
    result.handle = handle;
    result.bytes = request.bytes;
    return result;
  }

  Result<ExecutionResult> release(const ExecutionRequest& request, ExecutionResult& result) {
    void* pointer = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto it = handles_.find(request.handle);
      if (it == handles_.end()) {
        result.status = StatusCode::NotFound;
        result.detail = "unknown device allocation handle";
        return result;
      }
      pointer = it->second;
      handles_.erase(it);
    }
    const cudaError_t status = cudaFree(pointer);
    result.status = status == cudaSuccess ? StatusCode::Ok : StatusCode::Internal;
    result.detail = status == cudaSuccess ? std::string{} : cuda_error_text(status);
    return result;
  }

  Result<ExecutionResult> upload(const ExecutionRequest& request, ExecutionResult& result) {
    void* pointer = nullptr;
    if (!lookup(request.handle, pointer)) {
      result.status = StatusCode::NotFound;
      result.detail = "unknown device allocation handle";
      return result;
    }
    if (request.data.empty()) {
      result.status = StatusCode::InvalidArgument;
      result.detail = "no data was supplied for the transfer";
      return result;
    }
    const cudaError_t status = cudaMemcpy(static_cast<char*>(pointer) + request.bytes, request.data.data(),
                                          request.data.size(), cudaMemcpyHostToDevice);
    result.status = status == cudaSuccess ? StatusCode::Ok : StatusCode::Internal;
    result.detail = status == cudaSuccess ? std::string{} : cuda_error_text(status);
    return result;
  }

  Result<ExecutionResult> download(const ExecutionRequest& request, ExecutionResult& result) {
    void* pointer = nullptr;
    if (!lookup(request.handle, pointer)) {
      result.status = StatusCode::NotFound;
      result.detail = "unknown device allocation handle";
      return result;
    }
    if (request.data.empty()) {
      result.status = StatusCode::InvalidArgument;
      result.detail = "no transfer size was supplied";
      return result;
    }
    std::vector<std::uint8_t> host(request.data.size());
    const cudaError_t status = cudaMemcpy(host.data(), static_cast<char*>(pointer) + request.bytes, host.size(),
                                          cudaMemcpyDeviceToHost);
    if (status != cudaSuccess) {
      result.status = StatusCode::Internal;
      result.detail = cuda_error_text(status);
      return result;
    }
    result.status = StatusCode::Ok;
    result.data = std::move(host);
    return result;
  }

  Result<ExecutionResult> vector_add(const ExecutionRequest& request, ExecutionResult& result) {
    if (request.handles.size() != 3) {
      result.status = StatusCode::InvalidArgument;
      result.detail = "the vector add kernel requires exactly three device handles";
      return result;
    }
    void* a = nullptr;
    void* b = nullptr;
    void* out = nullptr;
    if (!lookup(request.handles[0], a) || !lookup(request.handles[1], b) || !lookup(request.handles[2], out)) {
      result.status = StatusCode::NotFound;
      result.detail = "one of the kernel operands is not a known device allocation";
      return result;
    }
    if (request.count == 0 || request.count > (1u << 26)) {
      result.status = StatusCode::InvalidArgument;
      result.detail = "kernel element count is outside the supported range";
      return result;
    }
    const int launched = av_cuda_vector_add(static_cast<const float*>(a), static_cast<const float*>(b),
                                            static_cast<float*>(out), static_cast<int>(request.count));
    if (launched != 0) {
      result.status = StatusCode::Internal;
      result.detail = "kernel launch or synchronisation failed with CUDA status " + std::to_string(launched);
      return result;
    }
    result.status = StatusCode::Ok;
    result.detail = "vector add executed and synchronised on the physical device";
    return result;
  }

  bool lookup(std::uint64_t handle, void*& pointer) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = handles_.find(handle);
    if (it == handles_.end()) return false;
    pointer = it->second;
    return true;
  }

  std::uint64_t next_handle() { return next_handle_.fetch_add(1) + 1; }

  std::mutex mutex_{};
  std::vector<CudaDevice> devices_{};
  std::map<std::uint64_t, void*> handles_{};
  std::atomic<std::uint64_t> next_handle_{0};
};

std::unique_ptr<BackendAdapter> make_cuda_backend() { return std::make_unique<CudaBackendAdapter>(); }

}  // namespace av
