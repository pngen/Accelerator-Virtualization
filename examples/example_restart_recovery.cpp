// Example: coordinator restart, durable identity and revoked process authority.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <chrono>
#include <filesystem>

#include "example_support.hpp"

int main() {
  using namespace avexample;

  std::error_code ec;
  const std::string directory =
      (std::filesystem::temp_directory_path(ec) /
       ("av-example-restart-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())))
          .string();

  av::VirtualAcceleratorId identity{};
  av::TenantId tenant_id{};
  av::LeaseId lease_id{};
  std::uint64_t first_epoch = 0;

  say("== first coordinator process ==");
  {
    auto runtime = make_runtime(directory);
    const av::PhysicalDeviceRecord device = register_device(*runtime, "synthetic-migratable");
    const av::BackingRecord backing = backings_of(*runtime->instance, device.id).front();
    const av::TenantRecord tenant =
        take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-a", ""));
    tenant_id = tenant.id;
    av::VirtualAcceleratorRecord record = take(runtime->instance->create_virtual(
        runtime->instance->current_authority(), "va-a", tenant.id, tenant.generation, contract(1u << 20)));
    identity = record.id;
    auto assigned = runtime->instance->assign_backing(
        authority_for(*runtime->instance, record, tenant.id, tenant.generation), backing.id, "initial");
    require(assigned);
    record = take(runtime->instance->raw_virtual(identity));
    const av::LeaseRecord lease = take(runtime->instance->attach(
        authority_for(*runtime->instance, record, tenant.id, tenant.generation)));
    lease_id = lease.id;
    first_epoch = runtime->instance->epoch().value();
    say("epoch " + std::to_string(first_epoch) + " virtual " + identity.str() + " lease " + lease_id.str());
    require(runtime->instance->shutdown());
  }

  say("== second coordinator process over the same durable state ==");
  {
    auto runtime = make_runtime(directory);
    const std::uint64_t epoch = runtime->instance->epoch().value();
    say("epoch " + std::to_string(epoch) + " (advanced: " + std::string(epoch > first_epoch ? "yes" : "no") + ")");
    const av::VirtualAcceleratorRecord record = take(runtime->instance->raw_virtual(identity));
    say("virtual " + record.id.str() + " generation " + record.generation.str() + " state " +
        std::string(av::lifecycle_name(record.state)));
    say("durable virtual identity restored: " + std::string(record.id == identity ? "yes" : "no"));
    const av::LeaseRecord lease = take(runtime->instance->get_lease(lease_id));
    say("previous lease state " + std::string(av::lease_state_name(lease.state)) + " (live: " +
        std::string(av::lease_state_is_live(lease.state) ? "yes" : "no") + ")");

    bool all_stale = true;
    for (const av::BackingRecord& backing : runtime->instance->list_backings()) {
      if (backing.evidence_fresh) all_stale = false;
    }
    say("dynamic backing evidence invalidated: " + std::string(all_stale ? "yes" : "no"));

    const av::Status attach = status_of(runtime->instance->attach([&] {
      av::Authority authority = runtime->instance->current_authority();
      authority.tenant = tenant_id;
      authority.tenant_generation = av::TenantGeneration::from_value(1);
      authority.virtual_id = identity;
      authority.virtual_generation = record.generation;
      return authority;
    }()));
    say("attach before revalidation -> " + attach.to_string());

    const av::AuditReport report = runtime->instance->audit();
    say("audit violations: " + std::to_string(report.violations.size()));
    require(runtime->instance->shutdown());
    if (!report.clean()) return 1;
  }

  std::filesystem::remove_all(directory, ec);
  return 0;
}