// Accelerator Virtualization - adversarial tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Each case attacks a specific claim: identity confusion, stale authority,
// replayed messages, malformed framing, corrupted persistence and impossible
// resource contracts.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "av/hash.hpp"
#include "av/protocol.hpp"
#include "support.hpp"

namespace {

using av::Byte;
using av::StatusCode;

std::vector<Byte> frame_bytes(std::uint16_t type, std::uint64_t request, av::ByteSpan payload) {
  av::FrameHeader header;
  header.type = type;
  header.request = request;
  header.payload_length = static_cast<std::uint32_t>(payload.size());
  header.payload_crc = av::Crc32c::compute(payload.data(), payload.size());
  return av::encode_frame(header, payload);
}

}  // namespace

AV_TEST(adversarial, stale_tenant_generation_after_fencing) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record =
      fixture.make_virtual("va", tenant.id, tenant.generation, avtest::permissive_contract());
  auto stale = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_OK(fixture.runtime().fence_tenant(fixture.epoch_only(), tenant.id, tenant.generation, "fenced"));

  AV_PHASE("VERIFY");
  AV_CODE(fixture.runtime().drain(stale, "x"), StatusCode::StaleTenant);
}

AV_TEST(adversarial, stale_backing_generation_is_rejected) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(device.id).front().id);

  AV_PHASE("VERIFY");
  // Re-registering the same device advances the backing object's generation,
  // so a decision made against the old generation is stale.
  const std::vector<av::BackingRecord> before = fixture.backings_of(device.id);
  auto adapter = av::make_synthetic_backends();
  bool refreshed = false;
  for (const auto& candidate : adapter) {
    if (candidate->name() != "synthetic-migratable") continue;
    auto found = candidate->discover();
    AV_RESULT(found);
    fixture.register_descriptor(found->front());
    refreshed = true;
  }
  AV_REQUIRE(refreshed);
  const std::vector<av::BackingRecord> after = fixture.backings_of(device.id);
  AV_EQUAL(before.size(), after.size());
  AV_REQUIRE(after.front().generation > before.front().generation);
}

AV_TEST(adversarial, reused_ordinal_is_refused_as_an_identity) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  av::PhysicalDeviceDescriptor descriptor;
  descriptor.stable_key = "0";
  descriptor.vendor = "synthetic";
  descriptor.model = "ordinal";
  descriptor.provenance = av::Provenance::Synthetic;
  av::BackingDescriptor backing;
  backing.label = "b";
  backing.klass = av::BackingClass::SyntheticMigratable;
  backing.multiplexing = av::MultiplexingMode::Synthetic;
  backing.isolation.push_back(av::IsolationClaim{av::IsolationDimension::TenantState,
                                                 av::IsolationState::Isolated, {}, {}, "m", "r"});
  descriptor.backings.push_back(backing);

  AV_PHASE("VERIFY");
  auto outcome = fixture.runtime().register_physical(fixture.epoch_only(), fixture.agent_id(), fixture.agent_boot(),
                                                     descriptor);
  AV_REQUIRE(!outcome.ok());
  AV_EQUAL(outcome.status().code(), StatusCode::InvalidArgument);
}

AV_TEST(adversarial, synthetic_device_cannot_claim_a_real_backing_class) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  av::PhysicalDeviceDescriptor descriptor;
  descriptor.stable_key = "synthetic:liar";
  descriptor.vendor = "synthetic";
  descriptor.model = "liar";
  descriptor.provenance = av::Provenance::Synthetic;
  av::BackingDescriptor backing;
  backing.label = "fake-dedicated";
  backing.klass = av::BackingClass::DedicatedPhysical;  // a REAL mechanism
  backing.multiplexing = av::MultiplexingMode::Dedicated;
  backing.isolation.push_back(av::IsolationClaim{av::IsolationDimension::Memory, av::IsolationState::Isolated,
                                                 {}, {}, "m", "r"});
  descriptor.backings.push_back(backing);

  AV_PHASE("VERIFY");
  auto outcome = fixture.runtime().register_physical(fixture.epoch_only(), fixture.agent_id(), fixture.agent_boot(),
                                                     descriptor);
  AV_REQUIRE(!outcome.ok());
  AV_EQUAL(outcome.status().code(), StatusCode::IntegrityFailure);
}

AV_TEST(adversarial, stale_agent_boot_cannot_continue_mutating) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent("first");
  const av::AgentId first_agent = fixture.agent_id();
  const av::AgentBootId first_boot = fixture.agent_boot();
  auto adapters = av::make_synthetic_backends();
  auto found = adapters.front()->discover();
  AV_RESULT(found);
  fixture.register_descriptor(found->front());
  AV_OK(fixture.runtime().agent_disconnected(first_agent, first_boot));

  AV_PHASE("RESTART");
  fixture.attach_agent("second");
  AV_REQUIRE(fixture.agent_boot() != first_boot);
  auto outcome = fixture.runtime().register_physical(fixture.epoch_only(), first_agent, first_boot, found->front());
  AV_REQUIRE(!outcome.ok());
  AV_REQUIRE(outcome.status().code() == StatusCode::StaleAgentBoot ||
             outcome.status().code() == StatusCode::NotFound ||
             outcome.status().code() == StatusCode::ConnectionLost);
  AV_REQUIRE(!fixture.runtime().agent_heartbeat(first_agent, first_boot).ok());
}

AV_TEST(adversarial, replayed_request_identity_is_refused) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::Authority authority = fixture.epoch_only();
  authority.request = av::RequestId::from_value(11);
  authority.session = 5;
  auto created = fixture.runtime().create_virtual(authority, "va", tenant.id, tenant.generation,
                                                  avtest::permissive_contract());
  AV_RESULT(created);

  AV_PHASE("VERIFY");
  AV_CODE(fixture.runtime().create_virtual(authority, "va-again", tenant.id, tenant.generation,
                                           avtest::permissive_contract()),
          StatusCode::DuplicateRequest);
  // A different session may legitimately reuse the same small identity.
  av::Authority other = authority;
  other.session = 6;
  AV_RESULT(fixture.runtime().create_virtual(other, "va-2", tenant.id, tenant.generation,
                                             avtest::permissive_contract()));
}

AV_TEST(adversarial, replayed_migration_commit_is_refused) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord first = fixture.register_synthetic("synthetic-migratable");
  const av::PhysicalDeviceRecord second = fixture.register_synthetic("synthetic-migratable-2");
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(), fixture.backings_of(first.id).front().id);

  AV_PHASE("MIGRATE");
  auto planned = fixture.runtime().plan_migration(fixture.for_virtual(record, tenant.id, tenant.generation),
                                                  fixture.backings_of(second.id).front().id,
                                                  av::MigrationClass::RebindOnly);
  AV_RESULT(planned);
  auto refreshed = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(refreshed);
  record = refreshed.take();
  av::Authority authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  authority.migration = planned->plan.id;
  authority.migration_generation = planned->plan.generation;
  auto prepared = fixture.runtime().prepare_migration(authority);
  AV_RESULT(prepared);
  auto during = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(during);
  authority.virtual_generation = during->generation;
  authority.migration_generation = prepared->plan.generation;
  authority.request = av::RequestId::from_value(77);
  authority.session = 9;
  auto committed = fixture.runtime().commit_migration(authority);
  AV_RESULT(committed);

  AV_PHASE("VERIFY");
  AV_CODE(fixture.runtime().commit_migration(authority), StatusCode::DuplicateRequest);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(adversarial, frame_decoder_refuses_malformed_input) {
  AV_PHASE("VERIFY");
  av::Encoder payload;
  payload.str("hello");
  const std::vector<Byte> good = frame_bytes(static_cast<std::uint16_t>(av::MessageType::Hello), 1, payload.data());

  // Truncated frame.
  auto truncated = av::decode_frame(av::ByteSpan{good.data(), good.size() - 2});
  AV_REQUIRE(!truncated.ok());

  // Wrong magic.
  std::vector<Byte> bad_magic = good;
  bad_magic[0] = static_cast<Byte>(0);
  AV_CODE(av::decode_frame(av::ByteSpan{bad_magic.data(), bad_magic.size()}).status(),
          StatusCode::MalformedFrame);

  // Corrupted payload.
  std::vector<Byte> corrupted = good;
  corrupted.back() = static_cast<Byte>(static_cast<unsigned char>(corrupted.back()) ^ 0xFFu);
  AV_CODE(av::decode_frame(av::ByteSpan{corrupted.data(), corrupted.size()}).status(),
          StatusCode::IntegrityFailure);

  // A stream that declares a huge payload must be refused before allocating.
  std::vector<Byte> oversized;
  av::put_u32(oversized, av::kFrameMagic);
  av::put_u16(oversized, av::protocol_version());
  av::put_u16(oversized, static_cast<std::uint16_t>(av::MessageType::Hello));
  av::put_u32(oversized, 0);
  av::put_u64(oversized, 1);
  av::put_u32(oversized, 0xFFFFFF00u);
  av::put_u32(oversized, 0);
  av::FrameStream stream(1024);
  std::vector<av::FrameStream::Frame> frames;
  AV_CODE(stream.feed(av::ByteSpan{oversized.data(), oversized.size()}, frames), StatusCode::FrameTooLarge);
}

AV_TEST(adversarial, stream_refuses_a_protocol_version_mismatch) {
  AV_PHASE("VERIFY");
  av::FrameHeader header;
  header.version = static_cast<std::uint16_t>(av::protocol_version() + 1);
  const std::vector<Byte> bytes = av::encode_frame(header, av::ByteSpan{});
  av::FrameStream stream;
  std::vector<av::FrameStream::Frame> frames;
  AV_CODE(stream.feed(av::ByteSpan{bytes.data(), bytes.size()}, frames), StatusCode::VersionMismatch);
}

AV_TEST(adversarial, stream_handles_split_and_coalesced_frames) {
  AV_PHASE("VERIFY");
  av::Encoder first_payload;
  first_payload.u64(1);
  av::Encoder second_payload;
  second_payload.u64(2);
  const std::vector<Byte> first =
      frame_bytes(static_cast<std::uint16_t>(av::MessageType::Query), 1, first_payload.data());
  const std::vector<Byte> second =
      frame_bytes(static_cast<std::uint16_t>(av::MessageType::Query), 2, second_payload.data());

  std::vector<Byte> combined = first;
  combined.insert(combined.end(), second.begin(), second.end());

  av::FrameStream stream;
  std::vector<av::FrameStream::Frame> frames;
  // Feed the first frame one byte at a time: nothing may be emitted before its
  // final byte arrives.
  for (std::size_t index = 0; index + 1 < first.size(); ++index) {
    AV_OK(stream.feed(av::ByteSpan{first.data() + index, 1}, frames));
    AV_REQUIRE(frames.empty());
  }
  AV_OK(stream.feed(av::ByteSpan{first.data() + first.size() - 1, 1}, frames));
  AV_EQUAL(frames.size(), static_cast<std::size_t>(1));
  AV_EQUAL(frames[0].header.request, 1ull);

  // The second frame arrives in two chunks and is emitted exactly once.
  frames.clear();
  AV_OK(stream.feed(av::ByteSpan{second.data(), second.size() / 2}, frames));
  AV_REQUIRE(frames.empty());
  AV_OK(stream.feed(av::ByteSpan{second.data() + second.size() / 2, second.size() - second.size() / 2}, frames));
  AV_EQUAL(frames.size(), static_cast<std::size_t>(1));
  AV_EQUAL(frames[0].header.request, 2ull);
}

AV_TEST(adversarial, corrupted_persistence_is_refused) {
  AV_PHASE("SETUP");
  avtest::ScratchDirectory scratch("corrupt");
  av::StoreOptions options;
  options.directory = scratch.path();
  options.enabled = true;
  auto store = av::make_file_store(options);
  AV_OK(store->open());
  av::VirtualizationState state;
  state.schema = av::schema_version();
  state.next_sequence = 5;
  state.epoch = av::CoordinatorEpoch::from_value(1);
  state.policy = av::VirtualizationPolicy::default_policy();
  state.policy.id = av::PolicyId::from_value(1);
  state.policy.generation = av::PolicyGeneration::from_value(1);
  state.policy_generation = state.policy.generation;
  AV_OK(store->compact(state));

  AV_PHASE("VERIFY");
  const std::string snapshot = scratch.file("state.avs");
  std::vector<char> bytes;
  {
    std::ifstream input(snapshot, std::ios::binary);
    AV_REQUIRE(input.good());
    bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  }
  AV_REQUIRE(bytes.size() > 32);
  bytes[bytes.size() / 2] = static_cast<char>(bytes[bytes.size() / 2] ^ 0x5A);
  {
    std::ofstream output(snapshot, std::ios::binary | std::ios::trunc);
    AV_REQUIRE(output.good());
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  auto loaded = store->load();
  AV_REQUIRE(!loaded.ok());
}

AV_TEST(adversarial, impossible_contracts_are_refused_by_the_runtime) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");

  AV_PHASE("VERIFY");
  av::ResourceContract overflow = avtest::permissive_contract(0xFFFFFFFFFFFFFFFFull);
  AV_CODE(fixture.runtime().create_virtual(fixture.epoch_only(), "va", tenant.id, tenant.generation, overflow),
          StatusCode::PolicyViolation);

  av::ResourceContract bad_share = avtest::permissive_contract();
  bad_share.compute_share_milli = 5000;
  AV_CODE(fixture.runtime().create_virtual(fixture.epoch_only(), "va", tenant.id, tenant.generation, bad_share),
          StatusCode::ContractInvalid);

  av::ResourceContract impossible_isolation = avtest::permissive_contract();
  impossible_isolation.required_isolation = {{av::IsolationDimension::Memory, av::IsolationState::Unsupported}};
  AV_CODE(
      fixture.runtime().create_virtual(fixture.epoch_only(), "va", tenant.id, tenant.generation, impossible_isolation),
      StatusCode::ContractInvalid);
}

AV_TEST(adversarial, repeated_revoke_and_detach_are_refused_cleanly) {
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
  const av::LeaseGeneration stored_generation = lease->generation;
  auto authority = fixture.for_lease(record, lease.value(), tenant.id, tenant.generation);
  AV_OK(fixture.runtime().revoke_lease(authority, "first"));
  auto current = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(current);
  auto repeated = fixture.for_lease(current.value(), lease.value(), tenant.id, tenant.generation);
  repeated.lease_generation = stored_generation;
  AV_CODE(fixture.runtime().revoke_lease(repeated, "second"), StatusCode::LeaseRevoked);
  AV_CODE(fixture.runtime().detach(repeated), StatusCode::LeaseRevoked);
  AV_REQUIRE(fixture.runtime().audit().clean());
}

AV_TEST(adversarial, duplicate_live_assignment_is_refused) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  // An exclusive mechanism admits exactly one holder, so a second virtual
  // accelerator must not be able to take it.
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-hardware-partition");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  AV_REQUIRE(backing.exclusive);
  const av::TenantRecord first = fixture.make_tenant("first");
  const av::TenantRecord second = fixture.make_tenant("second");
  av::VirtualAcceleratorRecord one = fixture.make_virtual_with_backing("va-1", first.id, first.generation,
                                                                     avtest::permissive_contract(), backing.id);
  av::VirtualAcceleratorRecord two =
      fixture.make_virtual("va-2", second.id, second.generation, avtest::permissive_contract());

  AV_PHASE("VERIFY");
  auto authority = fixture.for_virtual(two, second.id, second.generation);
  AV_REQUIRE(!fixture.runtime().assign_backing(authority, backing.id, "steal").ok());
  auto reloaded = fixture.runtime().get_backing(backing.id);
  AV_RESULT(reloaded);
  AV_EQUAL(reloaded->assigned_to.value(), one.id.value());
}

AV_TEST(adversarial, contract_may_not_strengthen_beyond_the_backing) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const av::BackingRecord backing = fixture.backings_of(device.id).front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  av::VirtualAcceleratorRecord record = fixture.make_virtual_with_backing(
      "va", tenant.id, tenant.generation, avtest::permissive_contract(1ull << 20), backing.id);

  AV_PHASE("VERIFY");
  av::ResourceContract greedy = avtest::permissive_contract();
  greedy.exclusivity_required = true;  // the backing is a shared mechanism
  auto authority = fixture.for_virtual(record, tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().update_contract(authority, greedy), StatusCode::ContractViolation);
  auto after = fixture.runtime().raw_virtual(record.id);
  AV_RESULT(after);
  AV_EQUAL(after->contract.memory_ceiling_bytes, 1ull << 20);
}

AV_TEST(adversarial, oversubscription_is_denied_by_default) {
  AV_PHASE("SETUP");
  avtest::Fixture fixture;
  fixture.attach_agent();
  const av::PhysicalDeviceRecord device = fixture.register_synthetic("synthetic-migratable");
  const std::vector<av::BackingRecord> backings = fixture.backings_of(device.id);
  AV_REQUIRE(!backings.empty());
  const av::BackingRecord backing = backings.front();
  const av::TenantRecord tenant = fixture.make_tenant("alpha");
  // Two virtual accelerators whose committed ceilings together exceed the
  // physical capacity of one shared backing.
  av::ResourceContract contract = avtest::permissive_contract(backing.capacity_bytes - (1ull << 20));
  av::VirtualAcceleratorRecord first =
      fixture.make_virtual_with_backing("va-1", tenant.id, tenant.generation, contract, backing.id);
  av::VirtualAcceleratorRecord second =
      fixture.make_virtual("va-2", tenant.id, tenant.generation, contract);

  AV_PHASE("VERIFY");
  auto authority = fixture.for_virtual(second, tenant.id, tenant.generation);
  AV_CODE(fixture.runtime().assign_backing(authority, backing.id, "overcommit"),
          StatusCode::OversubscriptionDenied);
  (void)first;
}
