// Accelerator Virtualization - randomised property tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every randomised case records its seed so a failure is reproducible.
#include <algorithm>
#include <string>
#include <vector>

#include "support.hpp"

namespace {

using av::StatusCode;

constexpr std::uint64_t kSeed = 0x5EED1234u;

// Drives a random sequence of legal operations and asserts that the durable
// invariants hold after every step.
void exercise(std::uint64_t seed, int steps) {
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::PhysicalDeviceRecord third = fixture.register_synthetic("synthetic-hardware-partition");
  const av::TenantRecord tenant = fixture.make_tenant("random");

  std::vector<av::BackingId> backings;
  for (const av::BackingRecord& backing : fixture.backings_of(first.id)) backings.push_back(backing.id);
  for (const av::BackingRecord& backing : fixture.backings_of(second.id)) backings.push_back(backing.id);
  for (const av::BackingRecord& backing : fixture.backings_of(third.id)) backings.push_back(backing.id);
  AV_REQUIRE(!backings.empty());

  avtest::Random random(seed);
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());

  for (int step = 0; step < steps; ++step) {
    auto refreshed = fixture.runtime().raw_virtual(record.id);
    AV_RESULT(refreshed);
    record = refreshed.take();
    av::Authority authority = fixture.for_virtual(record, tenant.id, tenant.generation);

    const std::uint32_t choice = random.below(7);
    if (choice == 0 && !record.backing.valid()) {
      fixture.runtime().assign_backing(authority, backings[random.below(static_cast<std::uint32_t>(backings.size()))],
                                       "random assign");
    } else if (choice == 1 && record.backing.valid()) {
      const av::BackingId target = backings[random.below(static_cast<std::uint32_t>(backings.size()))];
      if (target != record.backing) fixture.runtime().replace_backing(authority, target, "random replace");
    } else if (choice == 2) {
      fixture.runtime().attach(authority);
    } else if (choice == 3) {
      fixture.runtime().activate(authority);
    } else if (choice == 4) {
      fixture.runtime().drain(authority, "random drain");
    } else if (choice == 5) {
      // Detach one live lease if there is one.
      for (const av::LeaseRecord& lease : fixture.runtime().list_leases()) {
        if (lease.virtual_id != record.id || !av::lease_state_is_live(lease.state)) continue;
        auto stored = fixture.runtime().raw_virtual(record.id);
        if (!stored.ok()) break;
        fixture.runtime().detach(fixture.for_lease(stored.value(), lease, tenant.id, tenant.generation));
        break;
      }
    } else {
      fixture.runtime().suspend(authority, "random suspend");
      auto suspended = fixture.runtime().raw_virtual(record.id);
      if (suspended.ok() && suspended->state == av::VirtualLifecycleState::Suspended) {
        fixture.runtime().resume(fixture.for_virtual(suspended.value(), tenant.id, tenant.generation), "resume");
      }
    }

    const av::AuditReport report = fixture.runtime().audit();
    if (!report.clean()) {
      throw avtest::Failure("seed " + std::to_string(seed) + " step " + std::to_string(step) +
                            " broke an invariant: " + report.canonical());
    }
    const auto after = fixture.runtime().raw_virtual(record.id);
    AV_RESULT(after);
    if (after->generation < record.generation) {
      throw avtest::Failure("seed " + std::to_string(seed) + " step " + std::to_string(step) +
                            " moved the identity generation backwards");
    }
  }
  AV_REQUIRE(fixture.runtime().audit().clean());
}

}  // namespace

AV_TEST(property, randomised_lifecycle_sequences_hold_invariants) {
  AV_PHASE("SETUP");
  for (std::uint64_t seed = kSeed; seed < kSeed + 8; ++seed) {
    AV_NOTE("seed=" + std::to_string(seed));
    exercise(seed, 40);
  }
}

AV_TEST(property, backing_generation_is_strictly_monotonic) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());

  avtest::Random random(kSeed + 99);
  std::uint64_t previous = record.backing_generation.value();
  std::vector<av::BackingId> candidates = {fixture.backings_of(first.id).front().id,
                                           fixture.backings_of(second.id).front().id};
  bool assigned = false;
  for (int step = 0; step < 12; ++step) {
    auto refreshed = fixture.runtime().raw_virtual(record.id);
    AV_RESULT(refreshed);
    record = refreshed.take();
    const av::BackingId target = candidates[random.below(2)];
    if (target == record.backing) continue;
    auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
    const av::Result<av::BackingAssignment> outcome =
        assigned ? fixture.runtime().replace_backing(authority, target, "move")
                 : fixture.runtime().assign_backing(authority, target, "assign");
    AV_RESULT(outcome);
    assigned = true;
    auto after = fixture.runtime().raw_virtual(record.id);
    AV_RESULT(after);
    record = after.take();
    AV_REQUIRE(record.backing_generation.value() > previous);
    previous = record.backing_generation.value();
  }
}

AV_TEST(property, serialization_round_trip_preserves_fingerprint) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-hardware-partition");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  for (const av::BackingRecord& backing : fixture.backings_of(device.id)) {
    fixture.make_virtual_with_backing("va-" + backing.label, tenant.id, tenant.generation,
                                      avtest::permissive_contract(), backing.id);
  }

  AV_PHASE("VERIFY");
  auto snapshot = fixture.runtime().snapshot_state();
  AV_RESULT(snapshot);
  const std::vector<av::Byte> encoded = av::encode_snapshot(snapshot.value());
  auto decoded = av::decode_snapshot(av::ByteSpan{encoded.data(), encoded.size()});
  AV_RESULT(decoded);
  AV_EQUAL(av::state_fingerprint(decoded.value()), av::state_fingerprint(snapshot.value()));
  AV_EQUAL(av::render_snapshot(decoded.value()), av::render_snapshot(snapshot.value()));
  AV_OK(av::validate_state(decoded.value()));
}

AV_TEST(property, deterministic_replay_produces_identical_state) {
  AV_PHASE("SETUP");
  std::vector<std::uint64_t> fingerprints;
  for (int run = 0; run < 2; ++run) {
    avtest::Fixture fixture;
    fixture.attach_agent();
    const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
    const av::TenantRecord tenant = fixture.make_tenant("alpha");
    avtest::Random random(kSeed + 7);
    const std::vector<av::BackingRecord> backings = fixture.backings_of(device.id);
    AV_REQUIRE(!backings.empty());
    for (int index = 0; index < 8; ++index) {
      // The order is pseudo-random, the choice is deterministic given the seed:
      // two runs of the same sequence must produce identical durable state.
      const av::BackingRecord backing =
          backings[random.below(static_cast<std::uint32_t>(backings.size()))];
      fixture.make_virtual_with_backing("va-" + std::to_string(index), tenant.id, tenant.generation,
                                        avtest::permissive_contract(), backing.id);
    }
    fingerprints.push_back(fixture.runtime().state_fingerprint());
  }
  // Two identical operation sequences must produce byte-identical durable
  // state: nothing may depend on time, addresses or container iteration.
  AV_EQUAL(fingerprints[0], fingerprints[1]);
}

AV_TEST(property, randomised_attach_and_revoke_keeps_accounting_closed) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);

  avtest::Random random(kSeed + 31);
  for (int step = 0; step < 24; ++step) {
    auto refreshed = fixture.runtime().raw_virtual(record.id);
    AV_RESULT(refreshed);
    record = refreshed.take();
    if (random.chance(50)) {
      fixture.runtime().attach(fixture.for_virtual(record, tenant.id, tenant.generation));
    } else {
      auto leases = fixture.runtime().list_leases();
      for (const av::LeaseRecord& lease : leases) {
        if (lease.virtual_id != record.id || !av::lease_state_is_live(lease.state)) continue;
        fixture.runtime().detach(fixture.for_lease(record, lease, tenant.id, tenant.generation));
        break;
      }
    }
    AV_REQUIRE(fixture.runtime().audit().clean());
  }
  AV_PHASE("VERIFY");
  auto final_record = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(final_record);
  const av::AccountingCounters counters = fixture.runtime().accounting();
  AV_EQUAL(counters.attachments_active, static_cast<std::uint64_t>(final_record->active_attachments));
}
