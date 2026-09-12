// Example: two virtual accelerators, one physical device, separate authority.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "example_support.hpp"

int main() {
  using namespace avexample;

  say("== two virtual accelerators over one shared physical backing ==");
  auto runtime = make_runtime();
  const av::PhysicalDeviceRecord device = register_device(*runtime, "synthetic-migratable");
  const av::BackingRecord shared = backings_of(*runtime->instance, device.id).front();
  say("physical " + device.id.str() + " key " + device.stable_key);

  const av::TenantRecord first_tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-a", ""));
  const av::TenantRecord second_tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-b", ""));

  av::VirtualAcceleratorRecord first = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "va-a", first_tenant.id, first_tenant.generation,
      contract(1u << 20)));
  av::VirtualAcceleratorRecord second = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "va-b", second_tenant.id, second_tenant.generation,
      contract(1u << 20)));

  auto assign = [&](av::VirtualAcceleratorRecord& record, const av::TenantRecord& tenant) {
    auto outcome = runtime->instance->assign_backing(
        authority_for(*runtime->instance, record, tenant.id, tenant.generation), shared.id, "example");
    require(outcome.ok() ? av::Status{} : outcome.status());
    record = take(runtime->instance->raw_virtual(record.id));
  };
  assign(first, first_tenant);
  assign(second, second_tenant);

  say("virtual A " + first.id.str() + " backing generation " + first.backing_generation.str());
  say("virtual B " + second.id.str() + " backing generation " + second.backing_generation.str());
  say(std::string("distinct virtual identities: ") + (first.id == second.id ? "no" : "yes"));
  say(std::string("distinct backing assignments: ") + (first.assignment == second.assignment ? "no" : "yes"));

  say("== tenant B cannot touch tenant A's virtual accelerator ==");
  const av::Status intrusion = status_of(runtime->instance->attach(
      authority_for(*runtime->instance, first, second_tenant.id, second_tenant.generation)));
  say("outcome: " + intrusion.to_string());

  say("== one virtual accelerator cannot change the other's lifecycle ==");
  const av::Status cross = status_of(runtime->instance->retire_virtual(
      authority_for(*runtime->instance, first, second_tenant.id, second_tenant.generation), "cross-tenant"));
  say("outcome: " + cross.to_string());

  say("== isolation is reported per dimension, not as one boolean ==");
  const av::IsolationExplanation explanation = take(runtime->instance->explain_isolation(first.id));
  say("isolation class " + std::string(av::isolation_class_name(explanation.isolation_class)));
  say("shared dimensions " + std::to_string(explanation.shared.size()) + ", unknown dimensions " +
      std::to_string(explanation.unknown.size()) + ", isolated dimensions " +
      std::to_string(explanation.isolated.size()));
  say("policy requirements satisfied: " + std::string(explanation.satisfies_policy ? "yes" : "no"));

  const av::AuditReport report = runtime->instance->audit();
  say("audit violations: " + std::to_string(report.violations.size()));
  return report.clean() ? 0 : 1;
}