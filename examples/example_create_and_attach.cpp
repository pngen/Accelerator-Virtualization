// Example: create a virtual accelerator, attach a tenant, activate it and query it.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "example_support.hpp"

int main() {
  using namespace avexample;

  say("== create a virtual accelerator ==");
  auto runtime = make_runtime();
  const av::PhysicalDeviceRecord device = register_device(*runtime, "synthetic-migratable");
  const av::BackingRecord backing = backings_of(*runtime->instance, device.id).front();

  const av::TenantRecord tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-a", ""));
  say("tenant " + tenant.id.str() + " generation " + tenant.generation.str());

  av::VirtualAcceleratorRecord record =
      take(runtime->instance->create_virtual(runtime->instance->current_authority(), "va-a", tenant.id,
                                             tenant.generation, contract(4u << 20)));
  say("virtual " + record.id.str() + " generation " + record.generation.str() + " state " +
      std::string(av::lifecycle_name(record.state)));

  say("== assign a backing ==");
  auto assigned = runtime->instance->assign_backing(authority_for(*runtime->instance, record, tenant.id,
                                                                 tenant.generation),
                                                   backing.id, "example");
  require(assigned);
  record = take(runtime->instance->raw_virtual(record.id));
  say("backing " + record.backing.str() + " binding generation " + record.backing_generation.str());

  say("== attach the tenant ==");
  const av::LeaseRecord lease =
      take(runtime->instance->attach(authority_for(*runtime->instance, record, tenant.id, tenant.generation)));
  record = take(runtime->instance->raw_virtual(record.id));
  say("lease " + lease.id.str() + " generation " + lease.generation.str() + " state " +
      std::string(av::lease_state_name(lease.state)));

  say("== activate ==");
  record = take(runtime->instance->activate(authority_for(*runtime->instance, record, tenant.id, tenant.generation)));
  say("state " + std::string(av::lifecycle_name(record.state)));

  say("== query ==");
  const av::VirtualView view = take(runtime->instance->query_virtual(runtime->instance->current_authority(),
                                                                    record.id));
  say(view.canonical());

  const av::AuditReport report = runtime->instance->audit();
  say("audit violations: " + std::to_string(report.violations.size()));
  return report.clean() ? 0 : 1;
}
