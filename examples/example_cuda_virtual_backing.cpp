// Example: a real CUDA device behind a virtual accelerator identity.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "example_support.hpp"

#ifdef AV_WITH_CUDA
#include "av/cuda.hpp"
#endif

int main() {
  using namespace avexample;

#ifdef AV_WITH_CUDA
  say("== discover the real accelerator ==");
  auto runtime = make_runtime();
  auto adapter = av::make_cuda_backend();
  auto found = adapter->discover();
  if (!found.ok() || found->empty()) {
    say("no real accelerator is present on this host; this example is SKIPPED");
    return 0;
  }
  const av::PhysicalDeviceDescriptor& descriptor = found->front();
  say("device " + descriptor.model + " key " + descriptor.stable_key + " provenance " +
      std::string(av::provenance_name(descriptor.provenance)));
  say("reported capabilities: hardware partition " +
      std::string(descriptor.hardware_partition_capable ? "yes" : "no") + ", virtual function " +
      std::string(descriptor.virtual_function_capable ? "yes" : "no") + ", MIG " +
      std::string(descriptor.mig_capable ? "yes" : "no"));

  auto physical = runtime->instance->register_physical(runtime->instance->current_authority(), runtime->agent,
                                                       runtime->boot, descriptor);
  if (!physical.ok()) fail(physical.status().to_string());

  const av::TenantRecord tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "cuda-tenant", ""));
  auto backing = [&]() -> av::BackingRecord {
    for (const av::BackingRecord& candidate : backings_of(*runtime->instance, physical->id)) {
      if (candidate.label == "cuda-shared-context") return candidate;
    }
    fail("the CUDA adapter did not offer a shared backing");
    return {};
  }();

  av::VirtualAcceleratorRecord first = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "cuda-va-1", tenant.id, tenant.generation, contract(4u << 20)));
  av::VirtualAcceleratorRecord second = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "cuda-va-2", tenant.id, tenant.generation, contract(4u << 20)));

  auto assign = [&](av::VirtualAcceleratorRecord& record) {
    auto outcome = runtime->instance->assign_backing(
        authority_for(*runtime->instance, record, tenant.id, tenant.generation), backing.id, "example");
    require(outcome.ok() ? av::Status{} : outcome.status());
    record = take(runtime->instance->raw_virtual(record.id));
  };
  assign(first);
  assign(second);
  say("two virtual accelerators share one physical device under separate identities");

  const av::IsolationExplanation explanation = take(runtime->instance->explain_isolation(first.id));
  say("isolation class " + std::string(av::isolation_class_name(explanation.isolation_class)) + " mechanism " +
      explanation.mechanism);
  for (const av::IsolationClaim& claim : explanation.claims) {
    say("  " + std::string(av::isolation_dimension_name(claim.dimension)) + " " +
        std::string(av::isolation_state_name(claim.state)));
  }

  av::VirtualAcceleratorRecord attached = first;
  const av::LeaseRecord lease = take(runtime->instance->attach(
      authority_for(*runtime->instance, attached, tenant.id, tenant.generation)));
  attached = take(runtime->instance->raw_virtual(attached.id));
  auto lease_authority = authority_for(*runtime->instance, attached, tenant.id, tenant.generation);
  lease_authority.lease = lease.id;
  lease_authority.lease_generation = lease.generation;

  say("== the virtual memory contract is enforced before the device is asked ==");
  const av::Status within = status_of(runtime->instance->reserve_allocation(lease_authority, 1u << 20));
  say("1 MiB inside a 4 MiB ceiling: " + std::string(within.ok() ? "granted" : "refused"));
  require(runtime->instance->release_allocation(lease_authority, 1u << 20));
  const av::Status beyond = status_of(runtime->instance->reserve_allocation(lease_authority, 64u << 20));
  say("64 MiB against a 4 MiB ceiling: " + beyond.to_string());

  const av::AuditReport report = runtime->instance->audit();
  say("audit violations: " + std::to_string(report.violations.size()));
  return report.clean() ? 0 : 1;
#else
  say("this build has no CUDA adapter; the example is SKIPPED");
  return 0;
#endif
}