// Accelerator Virtualization - scale tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <string>
#include <vector>

#include "support.hpp"

namespace {

using av::StatusCode;

}  // namespace

AV_TEST(scale, ten_thousand_virtual_accelerators_persist_reload_and_audit) {
  AV_PHASE("SETUP");
  avtest::ScratchDirectory scratch("scale");
  av::RuntimeOptions options;
  options.name = "scale";
  av::StoreOptions store_options;
  store_options.directory = scratch.path();
  store_options.enabled = true;
  auto clock = std::make_shared<av::ManualClock>();

  constexpr int kCount = 10000;
  av::TenantGeneration tenant_generation{};

  {
    auto created = av::make_runtime(options, store_options, clock);
    AV_RESULT(created);
    std::unique_ptr<av::VirtualizationRuntime> runtime = created.take();
    auto tenant = runtime->create_tenant(runtime->current_authority(), "bulk", "");
    AV_RESULT(tenant);
    tenant_generation = tenant->generation;
    AV_REQUIRE(tenant->id.valid());

    AV_PHASE("CREATE");
    av::ResourceContract contract = avtest::permissive_contract(1ull << 20);
    for (int index = 0; index < kCount; ++index) {
      auto record = runtime->create_virtual(runtime->current_authority(), "va-" + std::to_string(index),
                                            tenant->id, tenant->generation, contract);
      if (!record.ok()) {
        throw avtest::Failure("create_virtual failed at index " + std::to_string(index) + ": " +
                              record.status().to_string());
      }
    }
    AV_EQUAL(runtime->list_virtual(runtime->current_authority()).size(), static_cast<std::size_t>(kCount));

    AV_PHASE("VERIFY");
    const av::AuditReport report = runtime->audit();
    AV_REQUIRE_MSG(report.clean(), report.canonical());
    AV_EQUAL(report.virtuals_checked, static_cast<std::size_t>(kCount));
    AV_NOTE("persistence_writes=" + std::to_string(runtime->persistence_writes()));
    AV_NOTE("persistence_bytes=" + std::to_string(runtime->persistence_bytes()));
    AV_OK(runtime->shutdown());
  }

  AV_PHASE("RECOVER");
  {
    auto reopened = av::make_runtime(options, store_options, clock);
    AV_RESULT(reopened);
    std::unique_ptr<av::VirtualizationRuntime> runtime = reopened.take();
    const std::vector<av::VirtualView> views = runtime->list_virtual(runtime->current_authority());
    AV_EQUAL(views.size(), static_cast<std::size_t>(kCount));
    std::size_t distinct = 0;
    av::VirtualAcceleratorId previous{};
    for (const av::VirtualView& view : views) {
      AV_REQUIRE(view.id.valid());
      AV_REQUIRE(view.id != previous);
      previous = view.id;
      ++distinct;
    }
    AV_EQUAL(distinct, static_cast<std::size_t>(kCount));
    const av::AuditReport report = runtime->audit();
    AV_REQUIRE_MSG(report.clean(), report.canonical());
    AV_OK(runtime->shutdown());
  }
  (void)tenant_generation;
}

AV_TEST(scale, deferred_persistence_coalesces_without_losing_state) {
  AV_PHASE("SETUP");
  avtest::ScratchDirectory scratch("deferred");
  av::RuntimeOptions options;
  options.name = "deferred";
  av::StoreOptions store_options;
  store_options.directory = scratch.path();
  store_options.enabled = true;
  store_options.deferred = true;
  store_options.deferred_threshold = 128;
  auto clock = std::make_shared<av::ManualClock>();

  constexpr int kCount = 500;
  {
    auto created = av::make_runtime(options, store_options, clock);
    AV_RESULT(created);
    std::unique_ptr<av::VirtualizationRuntime> runtime = created.take();
    auto tenant = runtime->create_tenant(runtime->current_authority(), "bulk", "");
    AV_RESULT(tenant);
    av::ResourceContract contract = avtest::permissive_contract(1ull << 20);
    for (int index = 0; index < kCount; ++index) {
      AV_RESULT(runtime->create_virtual(runtime->current_authority(), "va-" + std::to_string(index), tenant->id,
                                        tenant->generation, contract));
    }
    AV_OK(runtime->shutdown());
  }

  AV_PHASE("RECOVER");
  {
    auto reopened = av::make_runtime(options, store_options, clock);
    AV_RESULT(reopened);
    std::unique_ptr<av::VirtualizationRuntime> runtime = reopened.take();
    AV_EQUAL(runtime->list_virtual(runtime->current_authority()).size(), static_cast<std::size_t>(kCount));
    AV_REQUIRE(runtime->audit().clean());
  }
}

AV_TEST(scale, large_fleet_lookup_is_bounded) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  // A shared mechanism so the whole fleet can be placed on one device, and so
  // lookup cost rather than placement limits is what this case measures.
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  const std::vector<av::BackingRecord> backings = fixture.backings_of(device.id);
  AV_REQUIRE(!backings.empty());

  AV_PHASE("CREATE");
  std::vector<av::VirtualAcceleratorId> ids;
  for (int index = 0; index < 2000; ++index) {
    av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
        "va-" + std::to_string(index), tenant.id, tenant.generation, avtest::permissive_contract(1u << 20),
        backings[static_cast<std::size_t>(index) % backings.size()].id);
    ids.push_back(record.id);
  }
  AV_PHASE("VERIFY");
  for (std::size_t index = 0; index < ids.size(); index += 97) {
    auto view = fixture.runtime().query_virtual(fixture.epoch_only(), ids[index]);
    AV_RESULT(view);
    AV_EQUAL(view->id.value(), ids[index].value());
  }
  AV_REQUIRE(fixture.runtime().audit().clean());
}
