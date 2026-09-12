// Accelerator Virtualization - core unit tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "av/codec.hpp"
#include "av/hash.hpp"
#include "av/invariant.hpp"
#include "av/persistence.hpp"
#include "av/protocol.hpp"
#include "support.hpp"

namespace {

using av::Byte;
using av::StatusCode;
using av::Status;

std::vector<Byte> bytes_of(std::string_view text) {
  std::vector<Byte> out(text.size());
  for (std::size_t i = 0; i < text.size(); ++i) out[i] = static_cast<Byte>(text[i]);
  return out;
}

av::VirtualizationState sample_state() {
  av::VirtualizationState state;
  state.schema = av::schema_version();
  state.next_sequence = 42;
  state.epoch = av::CoordinatorEpoch::from_value(3);
  state.policy = av::VirtualizationPolicy::default_policy();
  state.policy.id = av::PolicyId::from_value(1);
  state.policy.generation = av::PolicyGeneration::from_value(1);
  state.policy_generation = state.policy.generation;

  av::TenantRecord tenant;
  tenant.id = av::TenantId::from_value(1);
  tenant.generation = av::TenantGeneration::from_value(1);
  tenant.name = "tenant";
  state.tenants[tenant.id] = tenant;

  av::PhysicalDeviceRecord physical;
  physical.id = av::PhysicalDeviceId::from_value(2);
  physical.generation = av::PhysicalDeviceGeneration::from_value(1);
  physical.stable_key = "pci:0000:01:00.0";
  physical.present = true;
  state.physical[physical.id] = physical;

  av::BackingRecord backing;
  backing.id = av::BackingId::from_value(3);
  backing.generation = av::BackingGeneration::from_value(1);
  backing.physical = physical.id;
  backing.physical_generation = physical.generation;
  backing.klass = av::BackingClass::SyntheticMigratable;
  backing.provenance = av::Provenance::Synthetic;
  backing.multiplexing = av::MultiplexingMode::Synthetic;
  backing.available = true;
  backing.evidence_fresh = true;
  backing.capacity_bytes = 1ull << 30;
  state.backings[backing.id] = backing;

  av::VirtualAcceleratorRecord record;
  record.id = av::VirtualAcceleratorId::from_value(4);
  record.generation = av::VirtualAcceleratorGeneration::from_value(2);
  record.name = "va";
  record.owner = tenant.id;
  record.owner_generation = tenant.generation;
  record.state = av::VirtualLifecycleState::Provisioned;
  record.state_generation = av::VirtualAcceleratorGeneration::from_value(1);
  record.contract = avtest::permissive_contract();
  record.contract.id = av::ResourceContractId::from_value(5);
  record.contract.generation = av::ResourceContractGeneration::from_value(1);
  record.projection.generation = av::CapabilityProjectionGeneration::from_value(1);
  record.projection.policy_generation = state.policy_generation;
  record.projection.contract_generation = record.contract.generation;
  record.policy_generation = state.policy_generation;
  record.epoch = state.epoch;
  state.virtuals[record.id] = record;
  state.accounting.virtual_active = 1;
  state.accounting.virtual_created = 1;
  return state;
}

}  // namespace

AV_TEST(identity, strong_types_are_distinct) {
  AV_PHASE("SETUP");
  const av::VirtualAcceleratorId virtual_id = av::VirtualAcceleratorId::from_value(7);
  const av::TenantId tenant_id = av::TenantId::from_value(7);
  // The two identities live in different namespaces and render differently even
  // though they carry the same numeric value.
  AV_REQUIRE(virtual_id.str() != tenant_id.str());
  AV_EQUAL(virtual_id.value(), tenant_id.value());
  AV_REQUIRE(virtual_id.valid());
  AV_REQUIRE(!av::VirtualAcceleratorId{}.valid());
}

AV_TEST(identity, render_and_parse_round_trip) {
  AV_PHASE("VERIFY");
  const av::VirtualAcceleratorId id = av::VirtualAcceleratorId::from_value(0x0123456789ABCDEFull);
  AV_EQUAL(id.str(), std::string("va-0123456789abcdef"));
  auto parsed = av::VirtualAcceleratorId::parse(id.str());
  AV_REQUIRE(parsed.has_value());
  AV_EQUAL(parsed->value(), id.value());
  AV_REQUIRE(!av::VirtualAcceleratorId::parse("tn-0123456789abcdef").has_value());
  AV_REQUIRE(!av::VirtualAcceleratorId::parse("va-zzzz").has_value());
  AV_REQUIRE(!av::VirtualAcceleratorId::parse("").has_value());
}

AV_TEST(identity, generation_monotonic) {
  AV_PHASE("VERIFY");
  av::VirtualAcceleratorGeneration generation = av::VirtualAcceleratorGeneration::initial();
  AV_EQUAL(generation.value(), 1ull);
  generation = generation.next();
  AV_EQUAL(generation.value(), 2ull);
  AV_REQUIRE(generation > av::VirtualAcceleratorGeneration::initial());
  AV_REQUIRE(!av::VirtualAcceleratorGeneration{}.valid());
}

AV_TEST(status, names_are_stable) {
  AV_PHASE("VERIFY");
  AV_EQUAL(std::string(av::code_name(StatusCode::StaleEpoch)), std::string("stale_epoch"));
  AV_EQUAL(std::string(av::code_name(StatusCode::IsolationUnknownMandatory)),
           std::string("isolation_unknown_mandatory"));
  AV_EQUAL(std::string(av::code_name(StatusCode::Ok)), std::string("ok"));
  AV_REQUIRE(av::is_stale_code(StatusCode::StaleLease));
  AV_REQUIRE(!av::is_stale_code(StatusCode::NotAuthorized));
  AV_REQUIRE(av::is_authority_code(StatusCode::NotAuthorized));
  AV_REQUIRE(av::is_integrity_code(StatusCode::CorruptState));
  AV_REQUIRE(av::is_integrity_code(StatusCode::MalformedFrame));
}

AV_TEST(codec, primitive_round_trip) {
  AV_PHASE("VERIFY");
  av::Encoder encoder;
  encoder.u8(0x12);
  encoder.u16(0x1234);
  encoder.u32(0x12345678u);
  encoder.u64(0x0123456789ABCDEFull);
  encoder.i64(-42);
  encoder.boolean(true);
  encoder.str("accelerator");
  av::Decoder decoder(encoder.data());
  AV_EQUAL(*decoder.u8(), static_cast<std::uint8_t>(0x12));
  AV_EQUAL(*decoder.u16(), static_cast<std::uint16_t>(0x1234));
  AV_EQUAL(*decoder.u32(), 0x12345678u);
  AV_EQUAL(*decoder.u64(), 0x0123456789ABCDEFull);
  AV_EQUAL(*decoder.i64(), static_cast<std::int64_t>(-42));
  AV_EQUAL(*decoder.boolean(), true);
  AV_EQUAL(*decoder.str(), std::string("accelerator"));
  AV_OK(decoder.require_end());
}

AV_TEST(codec, rejects_truncation_and_trailing_bytes) {
  AV_PHASE("VERIFY");
  av::Encoder encoder;
  encoder.u64(7);
  std::vector<Byte> data = encoder.take();
  data.resize(data.size() - 1);
  av::Decoder truncated(data);
  AV_CODE(truncated.u64(), StatusCode::TruncatedState);

  av::Encoder extended;
  extended.u64(7);
  std::vector<Byte> with_trailing = extended.take();
  with_trailing.push_back(static_cast<Byte>(0));
  av::Decoder reader(with_trailing);
  AV_OK(reader.u64());
  AV_CODE(reader.require_end(), StatusCode::ProtocolViolation);
}

AV_TEST(codec, rejects_oversized_lengths_without_allocating) {
  AV_PHASE("VERIFY");
  av::Encoder encoder;
  encoder.u32(0xFFFFFFF0u);  // a nine-digit length with no payload behind it
  av::Decoder decoder(encoder.data());
  AV_CODE(decoder.str(), StatusCode::LimitExceeded);

  av::Encoder list;
  list.u32(1u << 20);
  av::Decoder list_decoder(list.data());
  AV_CODE(list_decoder.list_header(1024), StatusCode::LimitExceeded);
}

AV_TEST(taxonomy, names_and_parsers_round_trip) {
  AV_PHASE("VERIFY");
  for (av::BackingClass klass : av::all_backing_classes()) {
    AV_EQUAL(av::parse_backing_class(av::backing_class_name(klass)).value(), klass);
  }
  for (av::MultiplexingMode mode : av::all_multiplexing_modes()) {
    AV_EQUAL(av::parse_multiplexing(av::multiplexing_name(mode)).value(), mode);
    AV_REQUIRE(!av::multiplexing_semantics(mode).isolation_guarantee.empty());
    AV_REQUIRE(!av::multiplexing_semantics(mode).failure_coupling.empty());
  }
  for (av::MigrationClass klass : av::all_migration_classes()) {
    AV_EQUAL(av::parse_migration_class(av::migration_class_name(klass)).value(), klass);
  }
  AV_REQUIRE(av::migration_moves_live_state(av::MigrationClass::LiveStateTransfer));
  AV_REQUIRE(!av::migration_moves_live_state(av::MigrationClass::RebindOnly));
  AV_REQUIRE(av::backing_class_rank(av::BackingClass::DedicatedPhysical) >
             av::backing_class_rank(av::BackingClass::TimeMultiplexedShare));
  AV_EQUAL(av::class_native_provenance(av::BackingClass::SyntheticRemote), av::Provenance::Synthetic);
  AV_EQUAL(av::class_native_provenance(av::BackingClass::DedicatedPhysical), av::Provenance::Real);
}

AV_TEST(lifecycle, legal_and_illegal_transitions) {
  AV_PHASE("VERIFY");
  AV_REQUIRE(av::is_legal_transition(av::VirtualLifecycleState::Created, av::VirtualLifecycleState::Provisioned));
  AV_REQUIRE(av::is_legal_transition(av::VirtualLifecycleState::Provisioned, av::VirtualLifecycleState::Attached));
  AV_REQUIRE(av::is_legal_transition(av::VirtualLifecycleState::Attached, av::VirtualLifecycleState::Active));
  AV_REQUIRE(!av::is_legal_transition(av::VirtualLifecycleState::Retired, av::VirtualLifecycleState::Active));
  AV_REQUIRE(!av::is_legal_transition(av::VirtualLifecycleState::Retired, av::VirtualLifecycleState::Provisioned));
  AV_REQUIRE(!av::is_legal_transition(av::VirtualLifecycleState::Fenced, av::VirtualLifecycleState::Active));
  AV_REQUIRE(!av::is_legal_transition(av::VirtualLifecycleState::Active, av::VirtualLifecycleState::Active));
  AV_CODE(av::check_transition(av::VirtualLifecycleState::Retired, av::VirtualLifecycleState::Active),
          StatusCode::InvalidTransition);
  AV_OK(av::check_transition(av::VirtualLifecycleState::Migrating, av::VirtualLifecycleState::Provisioned));
  AV_REQUIRE(av::lifecycle_is_terminal(av::VirtualLifecycleState::Retired));
  AV_REQUIRE(!av::lifecycle_accepts_mutation(av::VirtualLifecycleState::Fenced));
  AV_REQUIRE(!av::lifecycle_accepts_mutation(av::VirtualLifecycleState::Retired));
  AV_REQUIRE(av::lifecycle_requires_backing(av::VirtualLifecycleState::Active));
  AV_REQUIRE(!av::lifecycle_requires_backing(av::VirtualLifecycleState::Suspended));
  for (av::VirtualLifecycleState state : av::all_lifecycle_states()) {
    AV_EQUAL(av::parse_lifecycle(av::lifecycle_name(state)).value(), state);
  }
}

AV_TEST(isolation, unknown_never_satisfies_a_requirement) {
  AV_PHASE("VERIFY");
  av::IsolationProfile profile = av::IsolationProfile::uniform(av::IsolationState::Unknown, "probe", "unproven");
  std::vector<av::IsolationRequirement> requirements = {
      {av::IsolationDimension::Memory, av::IsolationState::Shared}};
  const av::IsolationEvaluation evaluation = av::evaluate_isolation(profile, requirements);
  AV_REQUIRE(!evaluation.satisfied);
  AV_EQUAL(evaluation.unmet.size(), static_cast<std::size_t>(1));

  profile.set(av::IsolationClaim{av::IsolationDimension::Memory, av::IsolationState::Isolated, {}, {}, "probe", "proven"});
  AV_REQUIRE(av::evaluate_isolation(profile, requirements).satisfied);
  AV_REQUIRE(!av::isolation_state_at_least(av::IsolationState::Unknown, av::IsolationState::Shared));
  AV_REQUIRE(!av::isolation_state_at_least(av::IsolationState::Shared, av::IsolationState::Partial));
  AV_REQUIRE(av::isolation_state_at_least(av::IsolationState::Isolated, av::IsolationState::Partial));
  AV_REQUIRE(std::string(av::isolation_state_meaning(av::IsolationState::Unknown)).find("fail closed") !=
             std::string::npos);
}

AV_TEST(isolation, profile_is_sorted_and_deterministic) {
  AV_PHASE("VERIFY");
  av::IsolationProfile first;
  first.set(av::IsolationClaim{av::IsolationDimension::Dma, av::IsolationState::Unknown, {}, {}, "m", "r"});
  first.set(av::IsolationClaim{av::IsolationDimension::Memory, av::IsolationState::Shared, {}, {}, "m", "r"});
  av::IsolationProfile second;
  second.set(av::IsolationClaim{av::IsolationDimension::Memory, av::IsolationState::Shared, {}, {}, "m", "r"});
  second.set(av::IsolationClaim{av::IsolationDimension::Dma, av::IsolationState::Unknown, {}, {}, "m", "r"});
  AV_EQUAL(first.canonical(), second.canonical());
  AV_EQUAL(first.fingerprint(), second.fingerprint());
  AV_EQUAL(first.state_of(av::IsolationDimension::Fault), av::IsolationState::Unknown);
}

AV_TEST(capability, surface_and_projection_are_deterministic) {
  AV_PHASE("VERIFY");
  av::CapabilitySurface surface;
  av::CapabilityEntry entry;
  entry.key = av::CapabilityKey::SmCount;
  entry.verdict = av::CapabilityVerdict::Supported;
  entry.value = 128;
  surface.set(entry);
  entry.key = av::CapabilityKey::PrecisionFp64;
  entry.verdict = av::CapabilityVerdict::Unsupported;
  surface.set(entry);
  AV_EQUAL(surface.entries().size(), static_cast<std::size_t>(2));
  // Entries are kept in ascending key order regardless of insertion order.
  AV_EQUAL(surface.entries()[0].key, av::CapabilityKey::SmCount);
  AV_EQUAL(surface.entries()[1].key, av::CapabilityKey::PrecisionFp64);
  AV_REQUIRE(surface.supported(av::CapabilityKey::SmCount));
  AV_REQUIRE(!surface.supported(av::CapabilityKey::PrecisionFp64));

  av::CapabilityProjection projection;
  projection.surface = surface;
  projection.mechanism = "test";
  projection.generation = av::CapabilityProjectionGeneration::from_value(1);
  projection.seal();
  const std::uint64_t first = projection.fingerprint;
  projection.seal();
  AV_EQUAL(projection.fingerprint, first);
}

AV_TEST(contract, validation_rejects_impossible_contracts) {
  AV_PHASE("VERIFY");
  av::ResourceContract contract;
  contract.compute_share_milli = 1001;
  AV_CODE(contract.validate(), StatusCode::ContractInvalid);
  contract.compute_share_milli = 0;
  contract.exclusivity_required = true;
  contract.oversubscription_allowed = true;
  AV_CODE(contract.validate(), StatusCode::ContractInvalid);
  contract.exclusivity_required = false;
  contract.oversubscription_allowed = false;
  contract.allowed_backing_classes = {av::BackingClass::Unknown};
  AV_CODE(contract.validate(), StatusCode::ContractInvalid);
  contract.allowed_backing_classes.clear();
  contract.required_isolation = {{av::IsolationDimension::Memory, av::IsolationState::Unsupported}};
  AV_CODE(contract.validate(), StatusCode::ContractInvalid);
}

AV_TEST(contract, permits_and_fingerprint) {
  AV_PHASE("VERIFY");
  av::ResourceContract contract = avtest::permissive_contract();
  AV_REQUIRE(contract.permits_backing_class(av::BackingClass::SyntheticMigratable));
  AV_REQUIRE(contract.permits_multiplexing(av::MultiplexingMode::CooperativeShared));
  AV_REQUIRE(contract.permits_migration_class(av::MigrationClass::RebindOnly));
  AV_REQUIRE(!contract.permits_migration_class(av::MigrationClass::LiveStateTransfer));
  const std::uint64_t fingerprint = contract.fingerprint();
  contract.normalize();
  AV_EQUAL(contract.fingerprint(), fingerprint);
}

AV_TEST(policy, default_policy_is_valid_and_deterministic) {
  AV_PHASE("VERIFY");
  const av::VirtualizationPolicy first = av::VirtualizationPolicy::default_policy();
  const av::VirtualizationPolicy second = av::VirtualizationPolicy::default_policy();
  AV_OK(first.validate());
  AV_EQUAL(first.canonical(), second.canonical());
  AV_EQUAL(first.fingerprint(), second.fingerprint());
  AV_REQUIRE(first.permits_backing_class(av::BackingClass::DedicatedPhysical));
  AV_REQUIRE(!first.permits_migration_class(av::MigrationClass::LiveStateTransfer));
  AV_REQUIRE(!first.permits_backing_class(av::BackingClass::Unknown));
}

AV_TEST(persistence, snapshot_round_trip_is_deterministic) {
  AV_PHASE("VERIFY");
  const av::VirtualizationState state = sample_state();
  const std::vector<Byte> first = av::encode_snapshot(state);
  const std::vector<Byte> second = av::encode_snapshot(state);
  AV_REQUIRE(first == second);
  auto decoded = av::decode_snapshot(av::ByteSpan{first.data(), first.size()});
  AV_RESULT(decoded);
  AV_EQUAL(av::encode_snapshot(decoded.value()), first);
  AV_EQUAL(av::state_fingerprint(decoded.value()), av::state_fingerprint(state));
  AV_OK(av::validate_state(decoded.value()));
}

AV_TEST(persistence, detects_a_flipped_byte) {
  AV_PHASE("VERIFY");
  av::VirtualizationState state = sample_state();
  std::vector<Byte> encoded = av::encode_snapshot(state);
  encoded[encoded.size() / 2] = static_cast<Byte>(static_cast<unsigned char>(encoded[encoded.size() / 2]) ^ 0x40u);
  auto decoded = av::decode_snapshot(av::ByteSpan{encoded.data(), encoded.size()});
  AV_REQUIRE(!decoded.ok());
}

AV_TEST(persistence, store_round_trip_and_corruption_detection) {
  AV_PHASE("SETUP");
  avtest::ScratchDirectory scratch("persistence");
  av::StoreOptions options;
  options.directory = scratch.path();
  options.enabled = true;
  auto store = av::make_file_store(options);
  AV_OK(store->open());

  av::VirtualizationState state = sample_state();
  av::ChangeSet changes;
  changes.header = true;
  changes.tenants.push_back(av::TenantId::from_value(1));
  changes.virtuals.push_back(av::VirtualAcceleratorId::from_value(4));
  AV_PHASE("ASSIGN");
  // A journal is a change log, so a fresh store is seeded with a full snapshot
  // and then receives incremental records.
  AV_OK(store->compact(state));
  AV_OK(store->apply(state, changes));
  auto loaded = store->load();
  AV_RESULT(loaded);
  AV_EQUAL(loaded->virtuals.size(), state.virtuals.size());
  AV_EQUAL(av::state_fingerprint(loaded.value()), av::state_fingerprint(state));

  AV_PHASE("VERIFY");
  AV_OK(store->compact(state));
  auto compacted = store->load();
  AV_RESULT(compacted);
  AV_EQUAL(av::state_fingerprint(compacted.value()), av::state_fingerprint(state));

  // Truncating the snapshot must be detected rather than silently accepted.
  const std::string snapshot = scratch.file("state.avs");
  const auto size = std::filesystem::file_size(snapshot);
  std::filesystem::resize_file(snapshot, size - 4);
  auto truncated = store->load();
  AV_REQUIRE(!truncated.ok());
}

AV_TEST(persistence, torn_journal_tail_is_rejected_or_discarded_explicitly) {
  AV_PHASE("SETUP");
  avtest::ScratchDirectory scratch("torn");
  av::StoreOptions options;
  options.directory = scratch.path();
  options.enabled = true;
  auto store = av::make_file_store(options);
  AV_OK(store->open());
  av::VirtualizationState state = sample_state();
  av::ChangeSet changes;
  changes.header = true;
  changes.virtuals.push_back(av::VirtualAcceleratorId::from_value(4));
  AV_OK(store->apply(state, changes));

  const std::string journal = scratch.file("state.avj");
  const auto size = std::filesystem::file_size(journal);
  std::filesystem::resize_file(journal, size - 3);

  AV_PHASE("VERIFY");
  auto rejected = store->load();
  AV_REQUIRE(!rejected.ok());
  AV_EQUAL(rejected.status().code(), StatusCode::TruncatedState);

  av::StoreOptions tolerant = options;
  tolerant.torn_tail = av::StoreOptions::TornTail::Discard;
  auto tolerant_store = av::make_file_store(tolerant);
  AV_OK(tolerant_store->open());
  auto discarded = tolerant_store->load();
  AV_RESULT(discarded);
  // The incomplete trailing record was never completed, so exactly that
  // record is absent and everything before it is intact.
  AV_EQUAL(discarded->virtuals.size(), static_cast<std::size_t>(0));
  AV_EQUAL(discarded->epoch.value(), state.epoch.value());
}

AV_TEST(invariant, clean_state_reports_no_violations) {
  AV_PHASE("VERIFY");
  const av::VirtualizationState state = sample_state();
  const av::AuditReport report = av::run_invariant_audit(state);
  AV_REQUIRE(report.clean());
  AV_EQUAL(report.violations.size(), static_cast<std::size_t>(0));
  AV_EQUAL(report.virtuals_checked, static_cast<std::size_t>(1));
  AV_REQUIRE(report.canonical().find("violation_count=0") != std::string::npos);
}

AV_TEST(invariant, detects_a_broken_tenant_reference) {
  AV_PHASE("VERIFY");
  av::VirtualizationState state = sample_state();
  state.virtuals.begin()->second.owner = av::TenantId::from_value(999);
  const av::AuditReport report = av::run_invariant_audit(state);
  AV_REQUIRE(!report.clean());
  AV_EQUAL(std::string(report.violations.front().code), std::string(av::invariant::kTenantReferenceValid));
}

AV_TEST(hash, crc32c_matches_known_vector) {
  AV_PHASE("VERIFY");
  // CRC-32C of the ASCII string "123456789".
  AV_EQUAL(av::Crc32c::compute(std::string_view{"123456789"}), 0xE3069283u);
}

AV_TEST(codec, field_map_is_order_independent_and_strict) {
  AV_PHASE("VERIFY");
  av::FieldWriter first;
  first.u64(av::kFieldEpoch, 3);
  first.str(av::kFieldReason, "because");
  av::FieldWriter second;
  second.str(av::kFieldReason, "because");
  second.u64(av::kFieldEpoch, 3);
  const std::vector<Byte> a = first.take();
  const std::vector<Byte> b = second.take();
  AV_REQUIRE(a == b);

  auto reader = av::FieldReader::create(av::ByteSpan{a.data(), a.size()});
  AV_RESULT(reader);
  AV_EQUAL(reader->require_u64(av::kFieldEpoch).value(), 3ull);
  AV_EQUAL(reader->require_str(av::kFieldReason).value(), std::string("because"));
  AV_CODE(reader->require_str(av::kFieldEpoch), StatusCode::ProtocolViolation);
  AV_CODE(reader->require_u64(av::kFieldVirtualId), StatusCode::ProtocolViolation);
}

AV_TEST(codec, field_map_rejects_duplicate_keys_and_trailing_bytes) {
  AV_PHASE("VERIFY");
  av::Encoder encoder;
  encoder.u32(2);
  encoder.u16(av::kFieldEpoch);
  encoder.u8(static_cast<std::uint8_t>(av::FieldType::U64));
  encoder.u32(8);
  encoder.u64(1);
  encoder.u16(av::kFieldEpoch);
  encoder.u8(static_cast<std::uint8_t>(av::FieldType::U64));
  encoder.u32(8);
  encoder.u64(2);
  const std::vector<Byte> duplicated = encoder.take();
  auto reader = av::FieldReader::create(av::ByteSpan{duplicated.data(), duplicated.size()});
  AV_CODE(reader.status(), StatusCode::ProtocolViolation);

  std::vector<Byte> trailing = duplicated;
  trailing.push_back(static_cast<Byte>(0));
  auto trailing_reader = av::FieldReader::create(av::ByteSpan{trailing.data(), trailing.size()});
  AV_REQUIRE(!trailing_reader.ok());
}
