// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Synthetic backends. These model mechanisms that the host does not provide.
// They are always reported as SYNTHETIC and are never evidence about real
// hardware.
#include "av/synthetic.hpp"

#include <array>
#include <string>
#include <utility>

namespace av {
namespace {

CapabilityEntry capability(CapabilityKey key, CapabilityVerdict verdict, std::uint64_t value, std::string text,
                           std::string provenance) {
  CapabilityEntry entry;
  entry.key = key;
  entry.verdict = verdict;
  entry.value = value;
  entry.text = std::move(text);
  entry.provenance = std::move(provenance);
  return entry;
}

IsolationClaim claim(IsolationDimension dimension, IsolationState state, std::string mechanism,
                     std::string rationale) {
  IsolationClaim value;
  value.dimension = dimension;
  value.state = state;
  value.mechanism = std::move(mechanism);
  value.rationale = std::move(rationale);
  return value;
}

// Parts that are genuinely separate in a hardware partition model, and parts
// that a partition model does not automatically provide.
std::vector<IsolationClaim> partition_isolation(std::string_view mechanism) {
  const std::string name(mechanism);
  return {
      claim(IsolationDimension::Memory, IsolationState::Isolated, name,
            "synthetic model: each partition owns a disjoint memory region"),
      claim(IsolationDimension::ExecutionContext, IsolationState::Isolated, name,
            "synthetic model: each partition owns a disjoint execution engine set"),
      claim(IsolationDimension::AddressSpace, IsolationState::Isolated, name,
            "synthetic model: partitions do not share an address space"),
      claim(IsolationDimension::Fault, IsolationState::Partial, name,
            "synthetic model: partition faults are modelled as contained, host-level faults are not"),
      claim(IsolationDimension::Reset, IsolationState::Partial, name,
            "synthetic model: partition reset is modelled as independent, device reset is not"),
      claim(IsolationDimension::Performance, IsolationState::Partial, name,
            "synthetic model: partitions contend for shared memory bandwidth"),
      claim(IsolationDimension::Telemetry, IsolationState::Unknown, name,
            "synthetic model does not model telemetry attribution"),
      claim(IsolationDimension::AdminControl, IsolationState::Partial, name,
            "synthetic model: administration is modelled per partition"),
      claim(IsolationDimension::PeerVisibility, IsolationState::Isolated, name,
            "synthetic model: partitions cannot see each other"),
      claim(IsolationDimension::Dma, IsolationState::Unknown, name,
            "synthetic model does not model DMA translation"),
      claim(IsolationDimension::TenantState, IsolationState::Isolated, name,
            "governance state is separate per virtual accelerator"),
  };
}

std::vector<IsolationClaim> virtual_function_isolation(std::string_view mechanism) {
  const std::string name(mechanism);
  return {
      claim(IsolationDimension::Memory, IsolationState::Isolated, name,
            "synthetic model: each virtual function owns its own memory aperture"),
      claim(IsolationDimension::ExecutionContext, IsolationState::Isolated, name,
            "synthetic model: each virtual function owns an execution context"),
      claim(IsolationDimension::AddressSpace, IsolationState::Isolated, name, "synthetic model"),
      claim(IsolationDimension::Fault, IsolationState::Unknown, name,
            "real virtual functions do not automatically contain faults; the synthetic model refuses to claim it"),
      claim(IsolationDimension::Reset, IsolationState::Unknown, name, "synthetic model refuses to claim reset isolation"),
      claim(IsolationDimension::Performance, IsolationState::Partial, name, "synthetic model"),
      claim(IsolationDimension::Telemetry, IsolationState::Unknown, name, "synthetic model"),
      claim(IsolationDimension::AdminControl, IsolationState::Partial, name, "synthetic model"),
      claim(IsolationDimension::PeerVisibility, IsolationState::Isolated, name, "synthetic model"),
      claim(IsolationDimension::Dma, IsolationState::Unknown, name,
            "real SR-IOV DMA isolation depends on the IOMMU configuration, which the synthetic model does not prove"),
      claim(IsolationDimension::TenantState, IsolationState::Isolated, name, "governance state is separate"),
  };
}

std::vector<IsolationClaim> remote_isolation(std::string_view mechanism) {
  const std::string name(mechanism);
  std::vector<IsolationClaim> claims;
  for (IsolationDimension dimension : all_isolation_dimensions()) {
    claims.push_back(claim(dimension, IsolationState::Unknown, name,
                           "synthetic remote backing models a network boundary whose properties are unknown"));
  }
  return claims;
}

std::vector<IsolationClaim> migratable_isolation(std::string_view mechanism) {
  const std::string name(mechanism);
  return {
      claim(IsolationDimension::Memory, IsolationState::Shared, name,
            "synthetic migratable backing deliberately models a shared memory pool so migration can be exercised"),
      claim(IsolationDimension::ExecutionContext, IsolationState::Shared, name, "synthetic model"),
      claim(IsolationDimension::AddressSpace, IsolationState::Shared, name, "synthetic model"),
      claim(IsolationDimension::Fault, IsolationState::Shared, name, "synthetic model"),
      claim(IsolationDimension::Reset, IsolationState::Shared, name, "synthetic model"),
      claim(IsolationDimension::Performance, IsolationState::Shared, name, "synthetic model"),
      claim(IsolationDimension::Telemetry, IsolationState::Unknown, name, "synthetic model"),
      claim(IsolationDimension::AdminControl, IsolationState::Partial, name, "synthetic model"),
      claim(IsolationDimension::PeerVisibility, IsolationState::Shared, name, "synthetic model"),
      claim(IsolationDimension::Dma, IsolationState::Unknown, name, "synthetic model"),
      claim(IsolationDimension::TenantState, IsolationState::Isolated, name, "governance state is separate"),
  };
}

CapabilitySurface base_capabilities(std::uint64_t memory_bytes, std::uint32_t compute_units,
                                    std::string_view provenance) {
  CapabilitySurface surface;
  const std::string tag(provenance);
  surface.set(capability(CapabilityKey::MemoryTotalBytes, CapabilityVerdict::Supported, memory_bytes, {}, tag));
  surface.set(capability(CapabilityKey::SmCount, CapabilityVerdict::Supported, compute_units, {}, tag));
  surface.set(capability(CapabilityKey::PrecisionFp32, CapabilityVerdict::Supported, 0, {}, tag));
  surface.set(capability(CapabilityKey::PrecisionFp16, CapabilityVerdict::Supported, 0, {}, tag));
  surface.set(capability(CapabilityKey::PrecisionFp64, CapabilityVerdict::Unsupported, 0, {}, tag));
  surface.set(capability(CapabilityKey::ResetBehavior, CapabilityVerdict::Unknown, 0, {}, tag));
  surface.set(capability(CapabilityKey::PeerAccess, CapabilityVerdict::Unsupported, 0, {}, tag));
  return surface;
}

BackingDescriptor make_backing(std::string label, BackingClass klass, MultiplexingMode mode,
                               IsolationClass isolation_class, std::uint64_t capacity, std::uint32_t units,
                               std::vector<IsolationClaim> isolation, std::string mechanism, bool exclusive) {
  BackingDescriptor backing;
  backing.label = std::move(label);
  backing.klass = klass;
  backing.multiplexing = mode;
  backing.isolation_class = isolation_class;
  backing.capacity_bytes = capacity;
  backing.compute_units = units;
  backing.mechanism = std::move(mechanism);
  backing.isolation = std::move(isolation);
  backing.capabilities = base_capabilities(capacity, units, "synthetic-evidence");
  backing.exclusive = exclusive;
  if (klass == BackingClass::SyntheticHardwarePartition) {
    backing.externally_lifecycle_managed = true;
    backing.external_partition_ref = "accelerator-partition-fabric/" + backing.label;
  }
  return backing;
}

class SyntheticAdapter final : public BackendAdapter {
 public:
  SyntheticAdapter(std::string name, PhysicalDeviceDescriptor descriptor, std::string description)
      : name_(std::move(name)), descriptor_(std::move(descriptor)), description_(std::move(description)) {}

  std::string name() const override { return name_; }
  Provenance provenance() const override { return Provenance::Synthetic; }
  std::vector<BackingClass> supported_backing_classes() const override {
    std::vector<BackingClass> out;
    for (const BackingDescriptor& backing : descriptor_.backings) out.push_back(backing.klass);
    return out;
  }
  Result<std::vector<PhysicalDeviceDescriptor>> discover() override {
    return std::vector<PhysicalDeviceDescriptor>{descriptor_};
  }
  Result<PhysicalDeviceDescriptor> probe(std::string_view stable_key) override {
    if (stable_key != descriptor_.stable_key) {
      return Status(StatusCode::NotFound, "synthetic device '" + std::string(stable_key) + "' is not offered by " + name_);
    }
    return descriptor_;
  }
  Result<ExecutionResult> execute(const ExecutionRequest& request) override {
    ExecutionResult result;
    result.status = StatusCode::Unsupported;
    result.detail = "synthetic backend " + name_ +
                    " does not execute work; it proves generic virtualization semantics only (" +
                    std::string(execution_op_name(request.op)) + ")";
    return result;
  }

 private:
  std::string name_;
  PhysicalDeviceDescriptor descriptor_;
  std::string description_;
};

PhysicalDeviceDescriptor make_device(std::string key, std::string model, std::uint64_t memory,
                                     std::uint32_t units, std::string mechanism,
                                     std::vector<BackingDescriptor> backings) {
  PhysicalDeviceDescriptor device;
  device.stable_key = std::move(key);
  device.vendor = "synthetic";
  device.model = std::move(model);
  device.driver_version = "synthetic-1.0";
  device.architecture = "synthetic";
  device.provenance = Provenance::Synthetic;
  device.memory_total_bytes = memory;
  device.compute_units = units;
  device.mechanism = std::move(mechanism);
  device.backings = std::move(backings);
  return device;
}

}  // namespace

std::vector<std::string_view> synthetic_adapter_names() {
  return {"synthetic-hardware-partition", "synthetic-vendor-virtual-function", "synthetic-remote",
          "synthetic-migratable", "synthetic-unproven-isolation", "synthetic-unsupported"};
}

std::vector<std::unique_ptr<BackendAdapter>> make_synthetic_backends() {
  return make_synthetic_backends(SyntheticBackendOptions{});
}

std::vector<std::unique_ptr<BackendAdapter>> make_synthetic_backends(const SyntheticBackendOptions& options) {
  if (options.partition_count == 0 || options.partition_count > 64) return {};
  if (options.memory_bytes == 0) return {};

  std::vector<std::unique_ptr<BackendAdapter>> adapters;
  const std::uint64_t memory = options.memory_bytes;
  const std::uint64_t partition_memory = memory / options.partition_count;
  const std::uint32_t units = 128;
  const std::uint32_t partition_units = units / options.partition_count;

  // 1. A device whose backings represent pre-existing hardware partitions. The
  //    partition lifecycle belongs to Accelerator Partition Fabric; this
  //    runtime only consumes the partitions it is given.
  {
    std::vector<BackingDescriptor> backings;
    for (std::uint32_t index = 0; index < options.partition_count; ++index) {
      const std::string label = "partition-" + std::to_string(index);
      backings.push_back(make_backing(label, BackingClass::SyntheticHardwarePartition,
                                      MultiplexingMode::HardwarePartitioned, IsolationClass::Synthetic,
                                      partition_memory, partition_units,
                                      partition_isolation("synthetic-hardware-partition"),
                                      "synthetic-partition-mechanism", true));
    }
    PhysicalDeviceDescriptor device = make_device("synthetic:pci:partition-device-0",
                                                  "Synthetic Partitioned Accelerator", memory, units,
                                                  "synthetic-partition-mechanism", std::move(backings));
    device.hardware_partition_capable = true;
    adapters.push_back(std::make_unique<SyntheticAdapter>("synthetic-hardware-partition", std::move(device),
                                                          "synthetic hardware partition model"));
  }

  // 2. A device offering virtual-function-like backings.
  {
    std::vector<BackingDescriptor> backings;
    for (std::uint32_t index = 0; index < 2; ++index) {
      const std::string label = "vf-" + std::to_string(index);
      backings.push_back(make_backing(label, BackingClass::SyntheticVendorVirtualFunction,
                                      MultiplexingMode::VirtualFunction, IsolationClass::Synthetic,
                                      memory / 2, units / 2, virtual_function_isolation("synthetic-vf"),
                                      "synthetic-vf-mechanism", true));
    }
    PhysicalDeviceDescriptor device =
        make_device("synthetic:pci:vf-device-0", "Synthetic Virtual Function Accelerator", memory, units,
                    "synthetic-vf-mechanism", std::move(backings));
    device.virtual_function_capable = true;
    adapters.push_back(std::make_unique<SyntheticAdapter>("synthetic-vendor-virtual-function", std::move(device),
                                                          "synthetic SR-IOV-like model"));
  }

  // 3. A remote accelerator whose isolation properties are entirely unknown.
  {
    std::vector<BackingDescriptor> backings;
    backings.push_back(make_backing("remote-0", BackingClass::SyntheticRemote, MultiplexingMode::Synthetic,
                                    IsolationClass::Unknown, memory, units,
                                    remote_isolation("synthetic-remote"), "synthetic-remote-mechanism", false));
    PhysicalDeviceDescriptor device = make_device("synthetic:remote:node-0", "Synthetic Remote Accelerator", memory,
                                                  units, "synthetic-remote-mechanism", std::move(backings));
    adapters.push_back(std::make_unique<SyntheticAdapter>("synthetic-remote", std::move(device),
                                                          "synthetic remote accelerator model"));
  }

  // 4. A pair of migratable devices so that cross-device migration semantics can
  //    be exercised. Both are SYNTHETIC.
  {
    std::vector<BackingDescriptor> backings;
    backings.push_back(make_backing("migratable", BackingClass::SyntheticMigratable, MultiplexingMode::Synthetic,
                                    IsolationClass::Synthetic, memory, units,
                                    migratable_isolation("synthetic-migratable"), "synthetic-migratable-mechanism",
                                    false));
    PhysicalDeviceDescriptor device = make_device("synthetic:fab:slot-0", "Synthetic Migratable Accelerator",
                                                  memory, units, "synthetic-migratable-mechanism",
                                                  std::move(backings));
    adapters.push_back(std::make_unique<SyntheticAdapter>("synthetic-migratable", std::move(device),
                                                          "synthetic migratable model (slot 0)"));
  }
  {
    std::vector<BackingDescriptor> backings;
    backings.push_back(make_backing("migratable", BackingClass::SyntheticMigratable, MultiplexingMode::Synthetic,
                                    IsolationClass::Synthetic, memory, units,
                                    migratable_isolation("synthetic-migratable"), "synthetic-migratable-mechanism",
                                    false));
    PhysicalDeviceDescriptor device = make_device("synthetic:fab:slot-1", "Synthetic Migratable Accelerator",
                                                  memory, units, "synthetic-migratable-mechanism",
                                                  std::move(backings));
    adapters.push_back(std::make_unique<SyntheticAdapter>("synthetic-migratable-2", std::move(device),
                                                          "synthetic migratable model (slot 1)"));
  }

  // 5. A device that reports UNKNOWN isolation. A contract or policy that
  //    requires a proven isolation dimension must be refused against it.
  {
    std::vector<BackingDescriptor> backings;
    std::vector<IsolationClaim> unknown;
    for (IsolationDimension dimension : all_isolation_dimensions()) {
      unknown.push_back(claim(dimension, IsolationState::Unknown, "synthetic-unproven",
                              "the mechanism reports UNKNOWN for every dimension and must never be upgraded"));
    }
    BackingDescriptor backing = make_backing("unproven", BackingClass::SyntheticMigratable,
                                             MultiplexingMode::CooperativeShared, IsolationClass::Unknown, memory,
                                             units, std::move(unknown), "synthetic-unproven-mechanism", false);
    backings.push_back(std::move(backing));
    PhysicalDeviceDescriptor device = make_device("synthetic:pci:unproven-device-0",
                                                  "Synthetic Unproven-Isolation Accelerator", memory, units,
                                                  "synthetic-unproven-mechanism", std::move(backings));
    adapters.push_back(std::make_unique<SyntheticAdapter>("synthetic-unproven-isolation", std::move(device),
                                                          "synthetic device whose isolation is UNKNOWN"));
  }

  // 6. A device whose mechanism is simply not available on this host. It is
  //    reported as UNSUPPORTED and can never back a virtual accelerator.
  {
    std::vector<BackingDescriptor> backings;
    BackingDescriptor backing = make_backing("mig-like", BackingClass::HardwarePartition,
                                             MultiplexingMode::HardwarePartitioned, IsolationClass::HardwarePartition,
                                             memory, units,
                                             partition_isolation("unavailable-hardware-partition"),
                                             "unavailable-hardware-partition", true);
    backings.push_back(std::move(backing));
    PhysicalDeviceDescriptor device = make_device("synthetic:pci:unsupported-device-0",
                                                  "Unavailable Hardware Partition Mechanism", memory, units,
                                                  "unavailable-hardware-partition", std::move(backings));
    device.provenance = Provenance::Unsupported;
    device.hardware_partition_capable = false;
    device.mig_capable = false;
    adapters.push_back(std::make_unique<SyntheticAdapter>("synthetic-unsupported", std::move(device),
                                                          "a mechanism that is not available on this host"));
  }

  return adapters;
}

}  // namespace av
