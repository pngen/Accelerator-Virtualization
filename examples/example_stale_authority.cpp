// Example: stale authority is refused, and the refusal says why.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "example_support.hpp"

int main() {
  using namespace avexample;

  say("== every generation-bound operation is checked ==");
  auto runtime = make_runtime();
  const av::PhysicalDeviceRecord device = register_device(*runtime, "synthetic-migratable");
  const av::BackingRecord backing = backings_of(*runtime->instance, device.id).front();
  const av::TenantRecord tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-a", ""));
  av::VirtualAcceleratorRecord record = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "va-a", tenant.id, tenant.generation, contract(1u << 20)));

  const av::Authority stale_epoch = [] {
    av::Authority authority;
    authority.epoch = av::CoordinatorEpoch::from_value(99);
    return authority;
  }();
  say("stale epoch          -> " + describe(runtime->instance->drain(stale_epoch, "stale")));

  auto authority = authority_for(*runtime->instance, record, tenant.id, tenant.generation);
  authority.tenant_generation = av::TenantGeneration::from_value(tenant.generation.value() + 7);
  say("stale tenant         -> " + describe(runtime->instance->drain(authority, "stale")));

  authority = authority_for(*runtime->instance, record, tenant.id, tenant.generation);
  authority.policy_generation = av::PolicyGeneration::from_value(1234);
  say("stale policy         -> " + describe(runtime->instance->drain(authority, "stale")));

  authority = authority_for(*runtime->instance, record, tenant.id, tenant.generation);
  authority.virtual_generation = av::VirtualAcceleratorGeneration::from_value(record.generation.value() + 5);
  say("stale virtual        -> " + describe(runtime->instance->drain(authority, "stale")));

  say("== assignment and attachment authority ==");
  auto assigned = runtime->instance->assign_backing(
      authority_for(*runtime->instance, record, tenant.id, tenant.generation), backing.id, "example");
  require(assigned);
  const av::Authority pre_assignment = authority_for(*runtime->instance, record, tenant.id, tenant.generation);
  record = take(runtime->instance->raw_virtual(record.id));
  say("assignment with the pre-assignment authority -> " +
      runtime->instance->attach(pre_assignment).status().to_string());

  const av::LeaseRecord lease = take(runtime->instance->attach(
      authority_for(*runtime->instance, record, tenant.id, tenant.generation)));
  record = take(runtime->instance->raw_virtual(record.id));

  say("== a revoked lease stays revoked ==");
  auto lease_authority = authority_for(*runtime->instance, record, tenant.id, tenant.generation);
  lease_authority.lease = lease.id;
  lease_authority.lease_generation = lease.generation;
  require(runtime->instance->revoke_lease(lease_authority, "example revocation"));
  record = take(runtime->instance->raw_virtual(record.id));
  auto repeated = authority_for(*runtime->instance, record, tenant.id, tenant.generation);
  repeated.lease = lease.id;
  repeated.lease_generation = lease.generation;
  say("repeated revoke      -> " + describe(runtime->instance->revoke_lease(repeated, "again")));

  say("== a replayed request identity is refused ==");
  auto replay = runtime->instance->current_authority();
  replay.request = av::RequestId::from_value(4321);
  replay.session = 7;
  require(runtime->instance->create_tenant(replay, "first", ""));
  say("replayed request     -> " + describe(runtime->instance->create_tenant(replay, "second", "")));

  const av::AuditReport report = runtime->instance->audit();
  say("audit violations: " + std::to_string(report.violations.size()));
  return report.clean() ? 0 : 1;
}