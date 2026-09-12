// Accelerator Virtualization - concurrency tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every case is a real concurrent exercise of the runtime's thread-safety
// claims, not a timing-based smoke test: the assertions are about the state
// that must hold when the threads have finished.
#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "support.hpp"

namespace {

using av::StatusCode;

}  // namespace

AV_TEST(concurrency, many_concurrent_queries_and_lists) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-hardware-partition");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  std::vector<av::VirtualAcceleratorId> ids;
  for (int index = 0; index < 16; ++index) {
    av::VirtualAcceleratorRecord record =
        fixture.make_virtual("va-" + std::to_string(index), tenant.id, tenant.generation,
                             avtest::permissive_contract());
    ids.push_back(record.id);
  }
  (void)device;

  AV_PHASE("VERIFY");
  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  for (int worker = 0; worker < 8; ++worker) {
    workers.emplace_back([&fixture, &ids, &failures, worker]() {
      for (int iteration = 0; iteration < 200; ++iteration) {
        const av::VirtualAcceleratorId id = ids[static_cast<std::size_t>(iteration) % ids.size()];
        auto view = fixture.runtime().query_virtual(fixture.epoch_only(), id);
        if (!view.ok()) {
          failures.fetch_add(1);
          continue;
        }
        if (view->id.value() != id.value()) failures.fetch_add(1);
        if ((iteration + worker) % 17 == 0) {
          const std::vector<av::VirtualView> listed = fixture.runtime().list_virtual(fixture.epoch_only());
          if (listed.size() != ids.size()) failures.fetch_add(1);
        }
      }
    });
  }
  for (std::thread& worker : workers) worker.join();
  AV_EQUAL(failures.load(), 0);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(concurrency, simultaneous_attach_respects_the_policy_limit) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);

  av::VirtualizationPolicy policy = fixture.runtime().policy();
  policy.max_attachments_per_virtual = 4;
  auto updated = fixture.runtime().set_policy(fixture.epoch_only(), policy);
  AV_RESULT(updated);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();

  AV_PHASE("ATTACH");
  std::atomic<int> granted{0};
  std::atomic<int> refused{0};
  std::vector<std::thread> workers;
  for (int worker = 0; worker < 8; ++worker) {
    workers.emplace_back([&fixture, &record, &tenant, &granted, &refused]() {
      auto outcome = fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
      if (outcome.ok()) {
        granted.fetch_add(1);
      } else if (outcome.status().code() == StatusCode::StaleVirtualGeneration ||
                 outcome.status().code() == StatusCode::AttachLimitReached) {
        refused.fetch_add(1);
      }
    });
  }
  for (std::thread& worker : workers) worker.join();

  AV_PHASE("VERIFY");
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_REQUIRE(after->active_attachments <= 4u);
  AV_REQUIRE(granted.load() >= 1);
  AV_EQUAL(static_cast<std::uint32_t>(granted.load()), after->active_attachments);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(concurrency, revoke_during_use_is_serialised) {
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

  AV_PHASE("REVOKE");
  std::atomic<int> successes{0};
  std::atomic<int> contract_refusals{0};
  std::thread user([&fixture, &record, &lease, &tenant, &successes, &contract_refusals]() {
    for (int iteration = 0; iteration < 200; ++iteration) {
      auto authority = fixture.for_lease(record, lease.value(), tenant.id, tenant.generation);
      auto outcome = fixture.runtime().reserve_allocation(authority, 4096);
      if (outcome.ok()) {
        successes.fetch_add(1);
        fixture.runtime().release_allocation(authority, 4096);
      } else if (outcome.status().code() == StatusCode::ContractViolation) {
        contract_refusals.fetch_add(1);
      }
    }
  });
  std::thread revoker([&fixture, &record, &lease, &tenant]() {
    auto authority = fixture.for_lease(record, lease.value(), tenant.id, tenant.generation);
    fixture.runtime().revoke_lease(authority, "revoked concurrently");
  });
  user.join();
  revoker.join();

  AV_PHASE("VERIFY");
  auto stored = fixture.runtime().get_lease(lease->id);
  AV_RESULT(stored);
  AV_REQUIRE(!av::lease_state_is_live(stored->state));
  auto final_record = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(final_record);
  AV_EQUAL(final_record->allocated_bytes, 0ull);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(concurrency, backing_replacement_under_concurrent_reads) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(first.id).front().id);

  AV_PHASE("MIGRATE");
  std::atomic<bool> stop{false};
  std::atomic<int> read_failures{0};
  std::vector<std::thread> readers;
  for (int worker = 0; worker < 4; ++worker) {
    readers.emplace_back([&fixture, &record, &stop, &read_failures]() {
      while (!stop.load()) {
        auto view = fixture.runtime().query_virtual(fixture.epoch_only(), record.id);
        if (!view.ok()) {
          read_failures.fetch_add(1);
          break;
        }
        if (view->id.value() != record.id.value()) read_failures.fetch_add(1);
      }
    });
  }
  std::vector<av::BackingId> candidates = {fixture.backings_of(first.id).front().id,
                                           fixture.backings_of(second.id).front().id};
  for (int step = 0; step < 6; ++step) {
    auto current = fixture.runtime().raw_virtual(record.id);
    AV_RESULT(current);
    const av::BackingId target = current->backing == candidates[0] ? candidates[1] : candidates[0];
    auto authority = fixture.for_virtual(current.value(), tenant.id, tenant.generation);
    const av::Result<av::BackingAssignment> outcome =
        current->backing.valid() ? fixture.runtime().replace_backing(authority, target, "move")
                                 : fixture.runtime().assign_backing(authority, target, "assign");
    AV_RESULT(outcome);
  }
  stop.store(true);
  for (std::thread& reader : readers) reader.join();

  AV_PHASE("VERIFY");
  AV_EQUAL(read_failures.load(), 0);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(concurrency, snapshot_during_mutation_is_consistent) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  // A shared mechanism, so every virtual accelerator in this case has a legal
  // backing while the observer reads the state.
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");

  AV_PHASE("CREATE");
  std::atomic<bool> creator_done{false};
  std::atomic<int> snapshots{0};
  std::atomic<int> inconsistent{0};
  // The observer takes a bounded number of snapshots while the creator mutates
  // the state. Every snapshot it observes must be internally consistent.
  // The observer takes a fixed, bounded number of snapshots so the case is
  // deterministic: it cannot exit before it has observed the state at least
  // once, however fast the creator happens to be.
  std::thread observer([&fixture, &creator_done, &snapshots, &inconsistent]() {
    (void)creator_done;
    for (int attempt = 0; attempt < 200; ++attempt) {
      auto state = fixture.runtime().snapshot_state();
      if (!state.ok()) {
        inconsistent.fetch_add(1);
        break;
      }
      const av::AuditReport report = av::run_invariant_audit(state.value());
      if (!report.clean()) {
        inconsistent.fetch_add(1);
        break;
      }
      snapshots.fetch_add(1);
    }
  });
  const std::vector<av::BackingRecord> backings = fixture.backings_of(device.id);
  AV_REQUIRE(!backings.empty());
  // The creator stops the observer and joins before it can propagate a failure:
  // a joinable thread destroyed during unwinding would terminate the process
  // instead of reporting a test failure.
  std::string creation_error;
  for (int index = 0; index < 32 && creation_error.empty(); ++index) {
    try {
      fixture.make_virtual_with_backing("va-" + std::to_string(index), tenant.id, tenant.generation,
                                        avtest::permissive_contract(),
                                        backings[static_cast<std::size_t>(index) % backings.size()].id);
    } catch (const std::exception& error) {
      creation_error = error.what();
    }
  }
  creator_done.store(true);
  observer.join();
  AV_REQUIRE_MSG(creation_error.empty(), creation_error);

  AV_PHASE("VERIFY");
  AV_EQUAL(inconsistent.load(), 0);
  AV_REQUIRE(snapshots.load() > 0);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(concurrency, repeated_shutdown_is_idempotent) {
  AV_PHASE("SHUTDOWN");
  avtest::Fixture fixture(true);
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  fixture.make_virtual_with_backing("va", tenant.id, tenant.generation, avtest::permissive_contract(),
                                    fixture.backings_of(device.id).front().id);
  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  for (int worker = 0; worker < 4; ++worker) {
    workers.emplace_back([&fixture, &failures]() {
      for (int attempt = 0; attempt < 3; ++attempt) {
        const av::Status status = fixture.runtime().shutdown();
        if (!status.ok()) failures.fetch_add(1);
      }
    });
  }
  for (std::thread& worker : workers) worker.join();
  AV_EQUAL(failures.load(), 0);
  AV_REQUIRE(!fixture.runtime().running());
}

AV_TEST(concurrency, retirement_contends_with_attach) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);

  AV_PHASE("REVOKE");
  std::atomic<bool> stopped{false};
  std::thread attacher([&fixture, &record, &tenant, &stopped]() {
    while (!stopped.load()) {
      auto current = fixture.runtime().raw_virtual(record.id);
      if (!current.ok()) break;
      fixture.runtime().attach(fixture.for_virtual(current.value(), tenant.id, tenant.generation));
    }
  });
  auto retired = fixture.runtime().retire_virtual(fixture.for_virtual(record, tenant.id, tenant.generation), "eol");
  AV_RESULT(retired);
  stopped.store(true);
  attacher.join();

  AV_PHASE("VERIFY");
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_EQUAL(after->state, av::VirtualLifecycleState::Retired);
  AV_EQUAL(after->active_attachments, 0u);
  AV_REQUIRE(fixture.runtime().audit().clean());
}
