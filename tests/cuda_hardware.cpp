// Accelerator Virtualization - real hardware adapter test.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// This suite talks to the physical accelerator directly through the narrow
// adapter. It proves real discovery, real device memory, real transfers and
// real kernel execution, and it records the truthful isolation classification
// of the software multiplexing this runtime provides.
#include <algorithm>
#include <string>
#include <vector>

#include "av/cuda.hpp"
#include "support.hpp"

#ifdef AV_WITH_CUDA

namespace {

using av::StatusCode;

av::BackendAdapter& cuda() {
  static std::unique_ptr<av::BackendAdapter> adapter = av::make_cuda_backend();
  return *adapter;
}

av::PhysicalDeviceDescriptor first_device() {
  auto found = cuda().discover();
  if (!found.ok() || found->empty()) {
    AV_SKIP("no CUDA device is present on this host");
  }
  return found->front();
}

const av::BackingDescriptor& backing_named(const av::PhysicalDeviceDescriptor& device, const std::string& label) {
  for (const av::BackingDescriptor& backing : device.backings) {
    if (backing.label == label) return backing;
  }
  throw avtest::Failure("backing '" + label + "' is not offered by the adapter");
}

}  // namespace

AV_TEST(hardware, cuda_device_is_discovered_with_a_stable_identity) {
  AV_PHASE("REGISTER");
  const av::PhysicalDeviceDescriptor device = first_device();
  AV_EQUAL(device.provenance, av::Provenance::Real);
  AV_NOTE("device=" + device.model + " key=" + device.stable_key + " arch=" + device.architecture);
  AV_REQUIRE(device.stable_key.find("cuda:") == 0);
  AV_REQUIRE(device.stable_key.size() > 8);
  AV_REQUIRE(device.memory_total_bytes > 0);
  AV_REQUIRE(device.compute_units > 0);
  AV_REQUIRE(device.compute_capability_major >= 1);

  // Discovery must be deterministic: the same physical device yields the same
  // key every time, and the key is not an enumeration ordinal.
  auto again = cuda().discover();
  AV_RESULT(again);
  AV_EQUAL(again->front().stable_key, device.stable_key);

  AV_PHASE("VERIFY");
  // The adapter never claims a partition, MIG or virtual function it does not
  // implement.
  AV_REQUIRE(!device.hardware_partition_capable);
  AV_REQUIRE(!device.virtual_function_capable);
  AV_REQUIRE(!device.mig_capable);
}

AV_TEST(hardware, cuda_backing_reports_truthful_isolation) {
  AV_PHASE("VERIFY");
  const av::PhysicalDeviceDescriptor device = first_device();
  const av::BackingDescriptor& shared = backing_named(device, "cuda-shared-context");
  av::IsolationProfile profile;
  for (const av::IsolationClaim& claim : shared.isolation) profile.set(claim);
  AV_EQUAL(profile.state_of(av::IsolationDimension::Memory), av::IsolationState::Shared);
  AV_EQUAL(profile.state_of(av::IsolationDimension::Fault), av::IsolationState::Shared);
  AV_EQUAL(profile.state_of(av::IsolationDimension::Reset), av::IsolationState::Shared);
  AV_EQUAL(profile.state_of(av::IsolationDimension::Dma), av::IsolationState::Unknown);
  AV_EQUAL(profile.state_of(av::IsolationDimension::Telemetry), av::IsolationState::Unknown);
  AV_EQUAL(profile.state_of(av::IsolationDimension::TenantState), av::IsolationState::Isolated);
  AV_REQUIRE(profile.claims().size() == av::kIsolationDimensionCount);
  for (const av::IsolationClaim& claim : profile.claims()) {
    AV_REQUIRE(!claim.mechanism.empty());
    AV_REQUIRE(!claim.rationale.empty());
    // Hardware isolation is never claimed by a software-governed mechanism.
    if (claim.dimension == av::IsolationDimension::Memory || claim.dimension == av::IsolationDimension::Fault) {
      AV_REQUIRE(claim.state != av::IsolationState::Isolated);
    }
  }
}

AV_TEST(hardware, real_allocation_transfer_and_kernel_execution) {
  AV_PHASE("SETUP");
  const av::PhysicalDeviceDescriptor device = first_device();
  const av::BackingDescriptor& shared = backing_named(device, "cuda-shared-context");
  AV_REQUIRE(shared.capacity_bytes > 0);

  constexpr std::uint32_t kElements = 8192;
  const std::uint64_t buffer_bytes = static_cast<std::uint64_t>(kElements) * sizeof(float);

  av::ExecutionRequest request;
  request.stable_key = device.stable_key;
  request.count = kElements;

  AV_PHASE("EXECUTE");
  request.op = av::ExecutionOp::DeviceInfo;
  auto info = cuda().execute(request);
  AV_RESULT(info);
  AV_EQUAL(info->status, StatusCode::Ok);
  AV_REQUIRE(info->total_memory > 0);
  AV_NOTE("device_total_bytes=" + std::to_string(info->total_memory));

  auto allocate = [&request, buffer_bytes]() {
    request.op = av::ExecutionOp::Allocate;
    request.bytes = buffer_bytes;
    request.count = 0;
    auto result = cuda().execute(request);
    if (!result.ok()) throw avtest::Failure("allocate failed: " + result.status().to_string());
    if (result->status != StatusCode::Ok) throw avtest::Failure("allocate refused: " + result->detail);
    return result->handle;
  };
  const std::uint64_t handle_a = allocate();
  const std::uint64_t handle_b = allocate();
  const std::uint64_t handle_c = allocate();
  AV_REQUIRE(handle_a != 0 && handle_b != 0 && handle_c != 0);

  std::vector<std::uint8_t> host_a(buffer_bytes);
  std::vector<std::uint8_t> host_b(buffer_bytes);
  auto* floats_a = reinterpret_cast<float*>(host_a.data());
  auto* floats_b = reinterpret_cast<float*>(host_b.data());
  for (std::uint32_t index = 0; index < kElements; ++index) {
    floats_a[index] = static_cast<float>(index) * 0.5f;
    floats_b[index] = static_cast<float>(index) * 0.25f;
  }

  auto upload = [&request, buffer_bytes](std::uint64_t handle, const std::vector<std::uint8_t>& data) {
    request.op = av::ExecutionOp::Upload;
    request.handle = handle;
    request.bytes = 0;
    request.count = 0;
    request.data = data;
    auto result = cuda().execute(request);
    if (!result.ok()) throw avtest::Failure("upload failed: " + result.status().to_string());
    if (result->status != StatusCode::Ok) throw avtest::Failure("upload refused: " + result->detail);
  };
  upload(handle_a, host_a);
  upload(handle_b, host_b);

  request.op = av::ExecutionOp::KernelVectorAdd;
  request.handle = 0;
  request.bytes = 0;
  request.count = kElements;
  request.data.clear();
  request.handles = {handle_a, handle_b, handle_c};
  auto kernel = cuda().execute(request);
  AV_RESULT(kernel);
  AV_EQUAL(kernel->status, StatusCode::Ok);
  AV_NOTE("kernel_detail=" + kernel->detail);

  AV_PHASE("VERIFY");
  request.op = av::ExecutionOp::Download;
  request.handle = handle_c;
  request.count = 0;
  request.handles.clear();
  request.data.assign(buffer_bytes, 0);
  auto downloaded = cuda().execute(request);
  AV_RESULT(downloaded);
  AV_EQUAL(downloaded->status, StatusCode::Ok);
  AV_EQUAL(downloaded->data.size(), static_cast<std::size_t>(buffer_bytes));
  const auto* floats_c = reinterpret_cast<const float*>(downloaded->data.data());
  std::uint64_t mismatches = 0;
  for (std::uint32_t index = 0; index < kElements; ++index) {
    const float expected = floats_a[index] + floats_b[index];
    if (floats_c[index] != expected) ++mismatches;
  }
  AV_EQUAL(mismatches, 0ull);

  AV_PHASE("REVOKE");
  for (std::uint64_t handle : {handle_a, handle_b, handle_c}) {
    request.op = av::ExecutionOp::Free;
    request.handle = handle;
    request.bytes = 0;
    request.data.clear();
    auto released = cuda().execute(request);
    AV_RESULT(released);
    AV_EQUAL(released->status, StatusCode::Ok);
  }
  request.op = av::ExecutionOp::DeviceInfo;
  request.handle = 0;
  auto after = cuda().execute(request);
  AV_RESULT(after);
  AV_REQUIRE(after->free_memory >= info->free_memory - (4u << 20));
}

AV_TEST(hardware, adapter_refuses_unknown_handles_and_oversized_requests) {
  AV_PHASE("VERIFY");
  const av::PhysicalDeviceDescriptor device = first_device();
  av::ExecutionRequest request;
  request.stable_key = device.stable_key;
  request.op = av::ExecutionOp::Free;
  request.handle = 0xDEADBEEFu;
  auto unknown = cuda().execute(request);
  AV_RESULT(unknown);
  AV_EQUAL(unknown->status, StatusCode::NotFound);

  request.op = av::ExecutionOp::Allocate;
  request.handle = 0;
  request.bytes = 0;
  auto zero = cuda().execute(request);
  AV_RESULT(zero);
  AV_EQUAL(zero->status, StatusCode::InvalidArgument);

  request.op = av::ExecutionOp::KernelVectorAdd;
  request.count = 16;
  request.handles = {1, 2};
  auto wrong_arity = cuda().execute(request);
  AV_RESULT(wrong_arity);
  AV_EQUAL(wrong_arity->status, StatusCode::InvalidArgument);

  request.op = av::ExecutionOp::Allocate;
  request.handles.clear();
  request.bytes = 0xFFFFFFFFFFFFull;  // far beyond any device
  request.count = 0;
  auto absurd = cuda().execute(request);
  AV_RESULT(absurd);
  AV_REQUIRE(absurd->status != StatusCode::Ok);

  request.op = av::ExecutionOp::DeviceInfo;
  request.stable_key = "cuda:pci:this-device-does-not-exist";
  request.bytes = 0;
  auto missing = cuda().execute(request);
  AV_REQUIRE(!missing.ok());
}

AV_TEST(hardware, runtime_governs_two_virtual_accelerators_on_one_device) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  auto found = cuda().discover();
  if (!found.ok() || found->empty()) AV_SKIP("no CUDA device is present on this host");
  const av::PhysicalDeviceRecord physical = fixture.register_descriptor(found->front());
  AV_EQUAL(physical.provenance, av::Provenance::Real);

  const av::BackingRecord shared = fixture.backing_by_label(physical.id, "cuda-shared-context");
  const av::BackingRecord dedicated = fixture.backing_by_label(physical.id, "cuda-dedicated");
  const av::TenantRecord tenant = fixture.make_tenant("cuda-tenant");

  AV_PHASE("ASSIGN");
  av::VirtualAcceleratorRecord first = fixture.make_virtual_with_backing(
      "cuda-va-1", tenant.id, tenant.generation, avtest::permissive_contract(4u << 20), dedicated.id);
  av::VirtualAcceleratorRecord second = fixture.make_virtual_with_backing(
      "cuda-va-2", tenant.id, tenant.generation, avtest::permissive_contract(4u << 20), shared.id);
  AV_REQUIRE(first.id != second.id);
  AV_REQUIRE(first.backing != second.backing);

  AV_PHASE("VERIFY");
  const av::IsolationExplanation explanation = fixture.runtime().explain_isolation(second.id).take();
  AV_EQUAL(explanation.isolation_class, av::IsolationClass::Logical);
  AV_REQUIRE(explanation.satisfies_policy);
  AV_REQUIRE(explanation.shared.size() >= 4);

  AV_PHASE("VERIFY");
  // Independent identity, authority and accounting.
  auto one_view = fixture.runtime().query_virtual(fixture.epoch_only(), first.id);
  AV_RESULT(one_view);
  auto two_view = fixture.runtime().query_virtual(fixture.epoch_only(), second.id);
  AV_RESULT(two_view);
  AV_REQUIRE(one_view->id != two_view->id);
  AV_REQUIRE(one_view->backing_generation.valid());
  AV_EQUAL(one_view->backing_generation.value(), 1ull);
  AV_EQUAL(two_view->backing_generation.value(), 1ull);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

#else

AV_TEST(hardware, cuda_adapter_is_not_compiled) {
  AV_SKIP("this build has no CUDA adapter");
}

#endif
