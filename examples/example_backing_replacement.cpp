// Example: virtual identity survives a backing replacement.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "example_support.hpp"

int main() {
  using namespace avexample;

  say("== replace the backing behind a stable virtual identity ==");
  auto runtime = make_runtime();
  const av::PhysicalDeviceRecord source_device = register_device(*runtime, "synthetic-migratable");
  const av::PhysicalDeviceRecord destination_device = register_device(*runtime, "synthetic-migratable-2");
  const av::BackingRecord source = backings_of(*runtime->instance, source_device.id).front();
  const av::BackingRecord destination = backings_of(*runtime->instance, destination_device.id).front();

  const av::TenantRecord tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-a", ""));
  av::VirtualAcceleratorRecord record = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "va-a", tenant.id, tenant.generation, contract(1u << 20)));

  const av::VirtualAcceleratorId identity = record.id;
  auto assigned = runtime->instance->assign_backing(
      authority_for(*runtime->instance, record, tenant.id, tenant.generation), source.id, "initial");
  require(assigned);
  record = take(runtime->instance->raw_virtual(identity));
  say("before: identity " + record.id.str() + " backing " + record.backing.str() + " binding generation " +
      record.backing_generation.str());

  auto replaced = runtime->instance->replace_backing(
      authority_for(*runtime->instance, record, tenant.id, tenant.generation), destination.id, "rebalance");
  require(replaced.ok() ? av::Status{} : replaced.status());
  record = take(runtime->instance->raw_virtual(identity));
  say("after:  identity " + record.id.str() + " backing " + record.backing.str() + " binding generation " +
      record.backing_generation.str());
  say(std::string("identity preserved: ") + (record.id == identity ? "yes" : "no"));

  say("== binding history ==");
  for (const av::BackingHistoryEntry& entry : record.backing_history) {
    say(std::string("assignment ") + entry.assignment.str() + " backing " + entry.backing.str() +
        " binding generation " + entry.backing_generation.str() +
        (entry.current ? " (current)" : " (superseded)"));
  }
  const av::AuditReport report = runtime->instance->audit();
  say("audit violations: " + std::to_string(report.violations.size()));
  return report.clean() ? 0 : 1;
}
