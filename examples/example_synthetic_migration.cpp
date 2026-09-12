// Example: migration semantics over synthetic backings.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "example_support.hpp"

int main() {
  using namespace avexample;

  say("== migrate a virtual accelerator between two devices ==");
  auto runtime = make_runtime();
  const av::PhysicalDeviceRecord source_device = register_device(*runtime, "synthetic-migratable");
  const av::PhysicalDeviceRecord destination_device = register_device(*runtime, "synthetic-migratable-2");
  const av::BackingRecord source = backings_of(*runtime->instance, source_device.id).front();
  const av::BackingRecord destination = backings_of(*runtime->instance, destination_device.id).front();
  const av::TenantRecord tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-a", ""));

  av::VirtualAcceleratorRecord record = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "va-a", tenant.id, tenant.generation, contract(1u << 20)));
  auto assigned = runtime->instance->assign_backing(
      authority_for(*runtime->instance, record, tenant.id, tenant.generation), source.id, "initial");
  require(assigned);
  record = take(runtime->instance->raw_virtual(record.id));
  const av::VirtualAcceleratorId identity = record.id;

  const av::MigrationExplanation explanation = take(runtime->instance->explain_migration(identity));
  say("migration supported: " + std::string(explanation.supported ? "yes" : "no"));
  say("migration class: " + std::string(av::migration_class_name(explanation.klass)));
  say("state transfer required: " + std::string(explanation.state_transfer_required ? "yes" : "no"));
  say("live state movement: " + std::string(explanation.live_state_movement ? "yes" : "no"));
  say("reason: " + explanation.reason);

  av::MigrationRecord migration = take(runtime->instance->plan_migration(
      authority_for(*runtime->instance, record, tenant.id, tenant.generation), destination.id,
      av::MigrationClass::RebindOnly));
  say("planned: " + std::string(av::migration_state_name(migration.state)));

  auto phase_authority = authority_for(*runtime->instance, record, tenant.id, tenant.generation);
  phase_authority.migration = migration.plan.id;
  phase_authority.migration_generation = migration.plan.generation;
  migration = take(runtime->instance->prepare_migration(phase_authority));
  say("prepared: " + std::string(av::migration_state_name(migration.state)) + " source authoritative " +
      std::string(migration.source_authoritative ? "yes" : "no") + " destination authoritative " +
      std::string(migration.destination_authoritative ? "yes" : "no"));

  record = take(runtime->instance->raw_virtual(identity));
  phase_authority.virtual_generation = record.generation;
  phase_authority.migration_generation = migration.plan.generation;
  migration = take(runtime->instance->commit_migration(phase_authority));
  say("committed: " + std::string(av::migration_state_name(migration.state)) + " source authoritative " +
      std::string(migration.source_authoritative ? "yes" : "no") + " destination authoritative " +
      std::string(migration.destination_authoritative ? "yes" : "no"));

  record = take(runtime->instance->raw_virtual(identity));
  phase_authority.virtual_generation = record.generation;
  phase_authority.migration_generation = migration.plan.generation;
  migration = take(runtime->instance->complete_migration(phase_authority));
  say("completed: " + std::string(av::migration_state_name(migration.state)));

  record = take(runtime->instance->raw_virtual(identity));
  say("identity after migration: " + record.id.str() + " (unchanged: " +
      std::string(record.id == identity ? "yes" : "no") + ")");
  say("backing binding generation: " + record.backing_generation.str());

  std::size_t authoritative = 0;
  for (const av::BackingAssignment& assignment : runtime->instance->list_assignments()) {
    if (assignment.virtual_id == identity && assignment.authoritative) ++authoritative;
  }
  say("authoritative assignments after the cutover: " + std::to_string(authoritative));
  const av::AuditReport report = runtime->instance->audit();
  say("audit violations: " + std::to_string(report.violations.size()));
  return report.clean() && authoritative == 1 ? 0 : 1;
}
