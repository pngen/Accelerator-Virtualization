// Accelerator Virtualization - runtime semantics unit tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <string>
#include <vector>

#include "support.hpp"

namespace {

using av::StatusCode;

}  // namespace

AV_TEST(runtime, virtual_identity_survives_backing_replacement) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const std::vector<av::BackingRecord> backings = fixture.backings_of(device.id);
  AV_REQUIRE(backings.size() >= 1);

  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va-alpha", tenant.id, tenant.generation, avtest::permissive_contract(), backings.front().id);
  const av::VirtualAcceleratorId identity = record.id;
  // The first assignment creates binding generation 1.
  AV_EQUAL(record.backing_generation.value(), 1ull);

  AV_PHASE("ASSIGN");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const std::vector<av::BackingRecord> second_backings = fixture.backings_of(second.id);
  AV_REQUIRE(!second_backings.empty());
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  auto replaced = fixture.runtime().replace_backing(authority, second_backings.front().id, "move");
  AV_RESULT(replaced);

  AV_PHASE("VERIFY");
  auto after = fixture.runtime().raw_virtual(identity);
  AV_RESULT(after);
  AV_EQUAL(after->id.value(), identity.value());
  AV_REQUIRE(after->generation > record.generation);
  AV_EQUAL(after->backing_generation.value(), 2ull);
  AV_REQUIRE(after->backing == second_backings.front().id);
  AV_REQUIRE(after->backing != backings.front().id);
  AV_EQUAL(after->backing_history.size(), static_cast<std::size_t>(2));
  AV_REQUIRE(!after->backing_history.front().current);
  AV_REQUIRE(after->backing_history.back().current);
  const av::AuditReport report = fixture.runtime().audit();
  AV_REQUIRE_MSG(report.clean(), report.canonical());
}

AV_TEST(runtime, attach_requires_backing_and_owner) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord owner = fixture.make_tenant("owner");
  const av::TenantRecord stranger = fixture.make_tenant("stranger");

  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", owner.id, owner.generation, avtest::permissive_contract());

  AV_PHASE("ATTACH");
  auto authority = fixture.for_virtual(record, owner.id, owner.generation);
  AV_CODE(fixture.runtime().attach(authority), StatusCode::BackingUnavailable);

  auto stranger_authority = fixture.for_virtual(record, stranger.id, stranger.generation);
  AV_CODE(fixture.runtime().attach(stranger_authority), StatusCode::NotAuthorized);

  AV_PHASE("ASSIGN");
  auto assigned = fixture.runtime().assign_backing(authority, backing.id, "assign");
  AV_RESULT(assigned);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  auto lease = fixture.runtime().attach(fixture.for_virtual(record, owner.id, owner.generation));
  AV_RESULT(lease);
  AV_EQUAL(lease->generation.value(), 1ull);
  AV_EQUAL(lease->tenant.value(), owner.id.value());
}

AV_TEST(runtime, stale_virtual_generation_is_rejected) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());

  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  auto assigned = fixture.runtime().assign_backing(authority, backing.id, "assign");
  AV_RESULT(assigned);

  AV_PHASE("VERIFY");
  // The stale authority still names the pre-assignment generation.
  AV_CODE(fixture.runtime().attach(authority), StatusCode::StaleVirtualGeneration);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  auto lease = fixture.runtime().attach(fixture.for_virtual(refreshed.value(), tenant.id, tenant.generation));
  AV_RESULT(lease);
}

AV_TEST(runtime, stale_epoch_tenant_and_policy_are_rejected) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());
  av::Authority authority = fixture.for_virtual(record, tenant.id, tenant.generation);

  AV_PHASE("VERIFY");
  av::Authority stale_epoch = authority;
  stale_epoch.epoch = av::CoordinatorEpoch::from_value(authority.epoch->value() + 5);
  AV_CODE(fixture.runtime().drain(stale_epoch, "x"), StatusCode::StaleEpoch);

  av::Authority stale_tenant = authority;
  stale_tenant.tenant_generation = av::TenantGeneration::from_value(tenant.generation.value() + 1);
  AV_CODE(fixture.runtime().drain(stale_tenant, "x"), StatusCode::StaleTenant);

  av::Authority unknown_tenant = authority;
  unknown_tenant.tenant = av::TenantId::from_value(9999);
  AV_CODE(fixture.runtime().drain(unknown_tenant, "x"), StatusCode::NotFound);

  av::Authority stale_policy = authority;
  stale_policy.policy_generation = av::PolicyGeneration::from_value(42);
  AV_CODE(fixture.runtime().drain(stale_policy, "x"), StatusCode::StalePolicy);
}

AV_TEST(runtime, lifecycle_rejects_impossible_operations) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());

  AV_PHASE("VERIFY");
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().activate(authority), StatusCode::NotAttached);
  AV_CODE(fixture.runtime().suspend(authority, "x"), StatusCode::InvalidTransition);

  auto assigned = fixture.runtime().assign_backing(authority, backing.id, "assign");
  AV_RESULT(assigned);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  auto lease = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(lease);
  refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  auto activated = fixture.runtime().activate(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(activated);
  record = activated.take();
  AV_EQUAL(record.state, av::VirtualLifecycleState::Active);

  AV_CODE(fixture.runtime().activate(fixture.for_virtual(record, tenant.id, tenant.generation)),
          StatusCode::InvalidTransition);

  auto retired = fixture.runtime().retire_virtual(fixture.for_virtual(record, tenant.id, tenant.generation), "done");
  AV_RESULT(retired);
  AV_EQUAL(retired->state, av::VirtualLifecycleState::Retired);
  AV_CODE(fixture.runtime().activate(fixture.for_virtual(retired.value(), tenant.id, tenant.generation)),
          StatusCode::VirtualRetired);
  auto report = fixture.runtime().audit();
  AV_REQUIRE(report.clean());
}

AV_TEST(runtime, fenced_virtual_accepts_no_mutation) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());

  AV_PHASE("VERIFY");
  auto fenced = fixture.runtime().fence_virtual(fixture.for_virtual(record, tenant.id, tenant.generation), "seal");
  AV_RESULT(fenced);
  AV_EQUAL(fenced->state, av::VirtualLifecycleState::Fenced);
  auto authority = fixture.for_virtual(fenced.value(), tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().assign_backing(authority, backing.id, "x"), StatusCode::VirtualFenced);
  AV_CODE(fixture.runtime().attach(authority), StatusCode::VirtualFenced);
  // Retirement is the one administrative step that may still follow fencing:
  // a sealed virtual accelerator must remain reclaimable.
  auto retired = fixture.runtime().retire_virtual(authority, "sealed and reclaimed");
  AV_RESULT(retired);
  AV_EQUAL(retired->state, av::VirtualLifecycleState::Retired);
}

AV_TEST(runtime, isolation_unknown_mandatory_is_refused) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-unproven-isolation");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());

  AV_PHASE("VERIFY");
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().assign_backing(authority, backing.id, "assign"),
          StatusCode::IsolationUnknownMandatory);
}

AV_TEST(runtime, unsupported_backing_can_never_be_assigned) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-unsupported");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  AV_EQUAL(backing.provenance, av::Provenance::Unsupported);
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());

  AV_PHASE("VERIFY");
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().assign_backing(authority, backing.id, "assign"), StatusCode::BackingUnavailable);
}

AV_TEST(runtime, exclusive_contract_refuses_a_shared_backing) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  AV_REQUIRE(!backing.exclusive);
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::ResourceContract contract = avtest::permissive_contract();
  contract.exclusivity_required = true;
  av::VirtualAcceleratorRecord record = fixture.make_virtual("va", tenant.id, tenant.generation, contract);

  AV_PHASE("VERIFY");
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().assign_backing(authority, backing.id, "assign"), StatusCode::ContractViolation);
}

AV_TEST(runtime, memory_budget_is_enforced_before_the_device_is_asked) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::ResourceContract contract = avtest::permissive_contract(1u << 20);
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing("va", tenant.id, tenant.generation,
                                                                        contract, backing.id);
  auto lease = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(lease);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();
  auto activated = fixture.runtime().activate(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(activated);
  record = activated.take();

  AV_PHASE("EXECUTE");
  auto authority = fixture.for_lease(record, lease.value(), tenant.id, tenant.generation);
  auto reserved = fixture.runtime().reserve_allocation(authority, 1u << 19);
  AV_RESULT(reserved);
  AV_EQUAL(reserved.value(), 1ull << 19);
  AV_CODE(fixture.runtime().reserve_allocation(authority, (1u << 19) + 1u), StatusCode::ContractViolation);
  AV_OK(fixture.runtime().release_allocation(authority, 1u << 19));
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_EQUAL(after->allocated_bytes, 0ull);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(runtime, lease_is_fenced_by_backing_replacement) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(first.id).front().id);
  auto lease = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(lease);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  AV_PHASE("MIGRATE");
  auto replaced = fixture.runtime().replace_backing(fixture.for_virtual(record, tenant.id, tenant.generation),
                                                    fixture.backings_of(second.id).front().id, "move");
  AV_RESULT(replaced);

  AV_PHASE("VERIFY");
  auto stale = fixture.runtime().renew_lease(fixture.for_lease(record, lease.value(), tenant.id, tenant.generation));
  AV_REQUIRE(!stale.ok());
  AV_REQUIRE(stale.status().code() == StatusCode::StaleVirtualGeneration ||
             stale.status().code() == StatusCode::StaleLease ||
             stale.status().code() == StatusCode::LeaseRevoked);
  auto stored = fixture.runtime().get_lease(lease->id);
  AV_RESULT(stored);
  AV_REQUIRE(!av::lease_state_is_live(stored->state));
}

AV_TEST(runtime, revoke_and_detach_are_explicit_and_idempotent) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);
  auto lease = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(lease);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();
  const av::LeaseGeneration stored_generation = lease->generation;

  AV_PHASE("REVOKE");
  auto authority = fixture.for_lease(record, lease.value(), tenant.id, tenant.generation);
  AV_OK(fixture.runtime().revoke_lease(authority, "revoked"));
  // The first revocation releases the last attachment, which advances the
  // virtual generation; the repeat uses the refreshed generation so it is
  // refused for the right reason rather than for staleness.
  auto current = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(current);
  record = current.take();
  auto repeated = fixture.for_lease(record, lease.value(), tenant.id, tenant.generation);
  repeated.lease_generation = stored_generation;
  AV_CODE(fixture.runtime().revoke_lease(repeated, "revoked again"), StatusCode::LeaseRevoked);
  AV_CODE(fixture.runtime().detach(repeated), StatusCode::LeaseRevoked);
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_EQUAL(after->active_attachments, 0u);
  AV_EQUAL(after->state, av::VirtualLifecycleState::Provisioned);
}

AV_TEST(runtime, duplicate_request_identity_is_refused) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");

  AV_PHASE("VERIFY");
  av::Authority authority = fixture.epoch_only();
  authority.request = av::RequestId::from_value(7);
  authority.session = 1;
  auto created = fixture.runtime().create_virtual(authority, "va", tenant.id, tenant.generation,
                                                  avtest::permissive_contract());
  AV_RESULT(created);
  AV_CODE(fixture.runtime().create_virtual(authority, "va-2", tenant.id, tenant.generation,
                                           avtest::permissive_contract()),
          StatusCode::DuplicateRequest);

  av::Authority other_session = authority;
  other_session.session = 2;
  auto second = fixture.runtime().create_virtual(other_session, "va-2", tenant.id, tenant.generation,
                                                 avtest::permissive_contract());
  AV_RESULT(second);
}

AV_TEST(runtime, capability_projection_is_bounded_by_contract_and_policy) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::ResourceContract contract = avtest::permissive_contract(3ull * 1024ull * 1024ull);
  contract.max_streams = 3;
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, contract, fixture.backings_of(device.id).front().id);

  AV_PHASE("VERIFY");
  const av::CapabilityProjection& projection = record.projection;
  AV_EQUAL(projection.surface.value_or(av::CapabilityKey::MemoryBudgetBytes, 0), 3ull * 1024ull * 1024ull);
  AV_EQUAL(projection.surface.value_or(av::CapabilityKey::MaxStreams, 0), 3ull);
  const av::CapabilityEntry* budget = projection.surface.find(av::CapabilityKey::MemoryBudgetBytes);
  AV_REQUIRE(budget != nullptr);
  AV_EQUAL(budget->verdict, av::CapabilityVerdict::Constrained);
  AV_EQUAL(projection.contract_generation, record.contract.generation);
  AV_EQUAL(projection.backing_generation, record.backing_generation);
  AV_REQUIRE(projection.generation.valid());
}

AV_TEST(runtime, policy_change_invalidates_leases_and_revalidates_bindings) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);
  auto lease = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(lease);

  AV_PHASE("VERIFY");
  av::VirtualizationPolicy policy = fixture.runtime().policy();
  policy.synthetic_backing_allowed = false;
  auto updated = fixture.runtime().set_policy(fixture.epoch_only(), policy);
  AV_RESULT(updated);
  AV_REQUIRE(updated->generation > av::PolicyGeneration::from_value(1));
  auto stored = fixture.runtime().get_lease(lease->id);
  AV_RESULT(stored);
  AV_REQUIRE(!av::lease_state_is_live(stored->state));
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_EQUAL(after->state, av::VirtualLifecycleState::RecoveryRequired);
  const av::AuditReport report = fixture.runtime().audit();
  AV_REQUIRE_MSG(report.clean(), report.canonical());
}

AV_TEST(runtime, migration_plan_staleness_is_detected) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(first.id).front().id);

  AV_PHASE("MIGRATE");
  auto planned = fixture.runtime().plan_migration(
      fixture.for_virtual(record, tenant.id, tenant.generation), fixture.backings_of(second.id).front().id,
      av::MigrationClass::RebindOnly);
  AV_RESULT(planned);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();
  // Planning alone does not move the lifecycle: the binding change starts when
  // the migration is prepared.
  AV_EQUAL(record.state, av::VirtualLifecycleState::Provisioned);
  AV_REQUIRE(record.migration.valid());

  // A contract update after planning invalidates the plan.
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_OK(fixture.runtime().update_contract(authority, avtest::permissive_contract(2ull << 20)));
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  record = after.take();

  av::Authority migration_authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  migration_authority.migration = planned->plan.id;
  migration_authority.migration_generation = planned->plan.generation;
  AV_CODE(fixture.runtime().commit_migration(migration_authority), StatusCode::StaleMigration);
}

AV_TEST(runtime, migration_cutover_leaves_one_authoritative_backing) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::BackingRecord source = fixture.backings_of(first.id).front();
  const av::BackingRecord destination = fixture.backings_of(second.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), source.id);

  AV_PHASE("MIGRATE");
  auto planned = fixture.runtime().plan_migration(fixture.for_virtual(record, tenant.id, tenant.generation),
                                                  destination.id, av::MigrationClass::RebindOnly);
  AV_RESULT(planned);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  av::Authority authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  authority.migration = planned->plan.id;
  authority.migration_generation = planned->plan.generation;
  auto prepared = fixture.runtime().prepare_migration(authority);
  AV_RESULT(prepared);
  AV_EQUAL(prepared->state, av::MigrationState::CommitReady);
  AV_REQUIRE(prepared->source_authoritative);
  AV_REQUIRE(!prepared->destination_authoritative);

  auto during = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(during);
  AV_EQUAL(during->state, av::VirtualLifecycleState::Migrating);
  authority.virtual_generation = during->generation;
  authority.migration_generation = prepared->plan.generation;
  auto committed = fixture.runtime().commit_migration(authority);
  AV_RESULT(committed);
  AV_EQUAL(committed->state, av::MigrationState::Committed);
  AV_REQUIRE(!committed->source_authoritative);
  AV_REQUIRE(committed->destination_authoritative);

  const std::vector<av::BackingAssignment> assignments = fixture.runtime().list_assignments();
  std::size_t authoritative = 0;
  for (const av::BackingAssignment& assignment : assignments) {
    if (assignment.virtual_id == record.id && assignment.authoritative) ++authoritative;
  }
  AV_EQUAL(authoritative, static_cast<std::size_t>(1));

  AV_PHASE("VERIFY");
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_EQUAL(after->id.value(), record.id.value());
  AV_REQUIRE(after->backing == destination.id);
  AV_EQUAL(after->backing_generation.value(), 2ull);

  authority.virtual_generation = after->generation;
  authority.migration_generation = committed->plan.generation;
  auto completed = fixture.runtime().complete_migration(authority);
  AV_RESULT(completed);
  AV_EQUAL(completed->state, av::MigrationState::Completed);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(runtime, unimplemented_migration_classes_are_refused) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(first.id).front().id);

  AV_PHASE("VERIFY");
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().plan_migration(authority, fixture.backings_of(second.id).front().id,
                                           av::MigrationClass::LiveStateTransfer),
          StatusCode::MigrationUnsupported);
  AV_CODE(fixture.runtime().plan_migration(authority, fixture.backings_of(second.id).front().id,
                                           av::MigrationClass::CheckpointRestore),
          StatusCode::MigrationUnsupported);
  auto explanation = fixture.runtime().explain_migration(record.id);
  AV_RESULT(explanation);
  AV_REQUIRE(explanation->supported);
  AV_REQUIRE(!explanation->live_state_movement);
  AV_REQUIRE(!explanation->state_transfer_required);
  AV_REQUIRE(explanation->reason.find("without execution-state") != std::string::npos);
}

AV_TEST(runtime, retirement_releases_everything) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing("va", tenant.id, tenant.generation,
                                                                        avtest::permissive_contract(), backing.id);
  auto lease = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(lease);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  AV_PHASE("REVOKE");
  auto retired = fixture.runtime().retire_virtual(fixture.for_virtual(record, tenant.id, tenant.generation), "eol");
  AV_RESULT(retired);
  AV_EQUAL(retired->state, av::VirtualLifecycleState::Retired);
  AV_EQUAL(retired->active_attachments, 0u);
  AV_REQUIRE(!retired->backing.valid());
  AV_REQUIRE(!retired->assignment.valid());

  auto stored_backing = fixture.runtime().get_backing(backing.id);
  AV_RESULT(stored_backing);
  AV_REQUIRE(!stored_backing->assigned_to.valid());
  const av::AuditReport report = fixture.runtime().audit();
  AV_REQUIRE_MSG(report.clean(), report.canonical());
}

AV_TEST(runtime, tenant_fencing_stops_all_authority) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);
  auto lease = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
  AV_RESULT(lease);

  AV_PHASE("REVOKE");
  AV_OK(fixture.runtime().fence_tenant(fixture.epoch_only(), tenant.id, tenant.generation, "compromised"));
  auto stored_lease = fixture.runtime().get_lease(lease->id);
  AV_RESULT(stored_lease);
  AV_REQUIRE(!av::lease_state_is_live(stored_lease->state));
  auto stored_tenant = fixture.runtime().get_tenant(tenant.id);
  AV_RESULT(stored_tenant);
  AV_REQUIRE(stored_tenant->fenced);
  AV_EQUAL(stored_tenant->active_attachments, 0u);
  // Unrelated work still succeeds: fencing is scoped to one tenant.
  AV_RESULT(fixture.runtime().create_tenant(fixture.epoch_only(), "gamma", ""));
  const av::AuditReport report = fixture.runtime().audit();
  AV_REQUIRE_MSG(report.clean(), report.canonical());
}

AV_TEST(runtime, ownership_transfer_is_explicit_and_generation_bound) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord owner = fixture.make_tenant("owner");
  const av::TenantRecord successor = fixture.make_tenant("successor");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", owner.id, owner.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);
  auto lease = fixture.runtime().attach(fixture.for_virtual(record, owner.id, owner.generation));
  AV_RESULT(lease);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  AV_PHASE("VERIFY");
  auto transferred = fixture.runtime().transfer_ownership(
      fixture.for_virtual(record, owner.id, owner.generation), successor.id, successor.generation);
  AV_RESULT(transferred);
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_EQUAL(after->owner.value(), successor.id.value());
  AV_EQUAL(after->owner_generation.value(), successor.generation.value());
  AV_EQUAL(after->active_attachments, 0u);
  auto stored_lease = fixture.runtime().get_lease(lease->id);
  AV_RESULT(stored_lease);
  AV_REQUIRE(!av::lease_state_is_live(stored_lease->state));

  // The previous owner keeps no authority at all.
  auto stale = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(stale);
  AV_CODE(fixture.runtime().drain(fixture.for_virtual(stale.value(), owner.id, owner.generation), "x"),
          StatusCode::NotAuthorized);
  const av::AuditReport report = fixture.runtime().audit();
  AV_REQUIRE_MSG(report.clean(), report.canonical());
}

AV_TEST(runtime, snapshot_text_is_deterministic_and_fingerprint_stable) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  const av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);

  AV_PHASE("VERIFY");
  const std::string first = fixture.runtime().snapshot_text();
  const std::string second = fixture.runtime().snapshot_text();
  AV_EQUAL(first, second);
  const std::uint64_t fingerprint = fixture.runtime().state_fingerprint();
  AV_EQUAL(fixture.runtime().state_fingerprint(), fingerprint);
  AV_REQUIRE(first.find(record.id.str()) != std::string::npos);
  AV_REQUIRE(first.find("virtual_accelerators=1") != std::string::npos);
}

AV_TEST(runtime, restart_advances_epoch_and_keeps_identity_but_not_leases) {
  AV_PHASE("SETUP");
  avtest::ScratchDirectory scratch("restart");
  av::RuntimeOptions options;
  options.name = "restart-test";
  av::StoreOptions store_options;
  store_options.directory = scratch.path();
  store_options.enabled = true;
  auto clock = std::make_shared<av::ManualClock>();

  av::VirtualAcceleratorId identity{};
  av::TenantId tenant_id{};
  {
    auto created = av::make_runtime(options, store_options, clock);
    AV_RESULT(created);
    std::unique_ptr<av::VirtualizationRuntime> runtime = created.take();
    auto session = runtime->register_agent("agent", "local", 1, av::AgentId{});
    AV_RESULT(session);
    auto adapters = av::make_synthetic_backends();
    AV_REQUIRE(!adapters.empty());
    auto found = adapters.front()->discover();
    AV_RESULT(found);
    auto physical = runtime->register_physical(runtime->current_authority(), session->id, session->boot,
                                               found->front());
    AV_RESULT(physical);
    auto tenant = runtime->create_tenant(runtime->current_authority(), "alpha", "");
    AV_RESULT(tenant);
    tenant_id = tenant->id;
    auto record = runtime->create_virtual(runtime->current_authority(), "va", tenant->id, tenant->generation,
                                          avtest::permissive_contract());
    AV_RESULT(record);
    identity = record->id;
    // Assign a backing so the durable relationship exists across the restart.
    for (const av::BackingRecord& backing : runtime->list_backings()) {
      if (backing.physical != physical->id) continue;
      av::Authority assign_authority = runtime->virtual_authority(record->id, record->generation);
      assign_authority.tenant = tenant->id;
      assign_authority.tenant_generation = tenant->generation;
      auto assigned = runtime->assign_backing(assign_authority, backing.id, "assign");
      AV_RESULT(assigned);
      break;
    }
    auto refreshed = runtime->raw_virtual(identity);
    AV_RESULT(refreshed);
    av::Authority attach_authority = runtime->virtual_authority(identity, refreshed->generation);
    attach_authority.tenant = tenant->id;
    attach_authority.tenant_generation = tenant->generation;
    auto lease = runtime->attach(attach_authority);
    AV_RESULT(lease);
    AV_OK(runtime->shutdown());
  }

  AV_PHASE("RECOVER");
  auto reopened = av::make_runtime(options, store_options, clock);
  AV_RESULT(reopened);
  std::unique_ptr<av::VirtualizationRuntime> runtime = reopened.take();
  AV_EQUAL(runtime->epoch().value(), 2ull);
  auto record = runtime->raw_virtual(identity);
  AV_RESULT(record);
  AV_EQUAL(record->id.value(), identity.value());
  AV_EQUAL(record->state, av::VirtualLifecycleState::Provisioned);
  AV_EQUAL(record->active_attachments, 0u);
  for (const av::LeaseRecord& lease : runtime->list_leases()) {
    AV_REQUIRE(!av::lease_state_is_live(lease.state));
  }
  for (const av::BackingRecord& backing : runtime->list_backings()) {
    AV_REQUIRE(!backing.evidence_fresh);
  }
  const av::AuditReport recovered = runtime->audit();
  AV_REQUIRE_MSG(recovered.clean(), recovered.canonical());

  AV_PHASE("ATTACH");
  // Process-local authority is refused, and the backing must be revalidated.
  av::Authority stale_attach = runtime->virtual_authority(identity, record->generation);
  stale_attach.tenant = tenant_id;
  stale_attach.tenant_generation = av::TenantGeneration::from_value(1);
  auto stale = runtime->attach(stale_attach);
  AV_REQUIRE(!stale.ok());
  AV_EQUAL(stale.status().code(), StatusCode::BackingUnavailable);
  (void)tenant_id;
}