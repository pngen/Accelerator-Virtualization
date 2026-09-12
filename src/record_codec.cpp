// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Deterministic record codecs. The same encoders serve the durable snapshot,
// the incremental journal and the control-plane wire blobs, so a replayed
// journal and a compacted snapshot always decode to identical state.
#include <cstdint>
#include <string>
#include <vector>

#include "av/codec.hpp"
#include "av/persistence.hpp"

namespace av {
namespace {

constexpr std::size_t kMaxListItems = 65536;

template <class T, class Fn>
void encode_list(Encoder& out, const std::vector<T>& items, Fn encode_item) {
  out.u32(static_cast<std::uint32_t>(items.size()));
  for (const T& item : items) encode_item(out, item);
}

template <class T, class Fn>
Result<std::vector<T>> decode_list(Decoder& in, std::size_t max_items, Fn decode_item) {
  auto count = in.list_header(max_items);
  if (!count.ok()) return count.status();
  std::vector<T> out;
  out.reserve(*count);
  for (std::size_t i = 0; i < *count; ++i) {
    auto item = decode_item(in);
    if (!item.ok()) return item.status();
    out.push_back(item.take());
  }
  in.depth_leave();
  return out;
}

template <class Enum>
void encode_enum(Encoder& out, Enum value) {
  out.u8(static_cast<std::uint8_t>(value));
}

template <class Enum, class Validator>
Result<Enum> decode_enum(Decoder& in, Enum max_value, Validator validate) {
  auto raw = in.u8();
  if (!raw.ok()) return raw.status();
  if (*raw > static_cast<std::uint8_t>(max_value)) {
    return Status(StatusCode::MalformedFrame, "enum value " + std::to_string(*raw) + " is outside its domain");
  }
  const Enum value = static_cast<Enum>(*raw);
  if (!validate(value)) {
    return Status(StatusCode::MalformedFrame, "enum value " + std::to_string(*raw) + " is not a modelled value");
  }
  return value;
}

void encode_id(Encoder& out, std::uint64_t value) { out.u64(value); }

template <class IdT>
void encode_strong_id(Encoder& out, const IdT& id) {
  encode_id(out, id.value());
}

Result<std::uint64_t> decode_raw_id(Decoder& in) { return in.u64(); }

bool valid_provenance(Provenance value) { return value <= Provenance::Unsupported; }
bool valid_multiplexing(MultiplexingMode value) { return value <= MultiplexingMode::Synthetic; }
bool valid_backing_class(BackingClass value) { return value <= BackingClass::SyntheticMigratable; }
bool valid_isolation_class(IsolationClass value) { return value <= IsolationClass::Synthetic; }
bool valid_migration_class(MigrationClass value) { return value <= MigrationClass::LiveStateTransfer; }
bool valid_lifecycle(VirtualLifecycleState value) { return value <= VirtualLifecycleState::Retired; }
bool valid_lease_state(LeaseState value) { return value <= LeaseState::Superseded; }
bool valid_assignment_state(AssignmentState value) { return value <= AssignmentState::Failed; }
bool valid_migration_state(MigrationState value) { return value <= MigrationState::Failed; }
bool valid_isolation_dimension(IsolationDimension value) { return value <= IsolationDimension::TenantState; }
bool valid_isolation_state(IsolationState value) { return value <= IsolationState::Isolated; }
bool valid_capability_key(CapabilityKey value) { return value <= CapabilityKey::VendorVisible; }
bool valid_capability_verdict(CapabilityVerdict value) { return value <= CapabilityVerdict::Constrained; }
bool valid_audit_kind(AuditKind value) { return value <= AuditKind::Persistence; }
bool valid_evidence_kind(EvidenceKind value) { return value <= EvidenceKind::RecoveryRevalidation; }
bool valid_transparency(BackingTransparency value) { return value <= BackingTransparency::Full; }
bool valid_sharing(TenantSharingPolicy value) { return value <= TenantSharingPolicy::Shared; }
bool valid_recovery(RecoveryBehavior value) { return value <= RecoveryBehavior::Optimistic; }

}  // namespace

std::string_view entity_kind_name(EntityKind kind) noexcept {
  switch (kind) {
    case EntityKind::Header: return "header";
    case EntityKind::Tenant: return "tenant";
    case EntityKind::Physical: return "physical";
    case EntityKind::Backing: return "backing";
    case EntityKind::Virtual: return "virtual";
    case EntityKind::Lease: return "lease";
    case EntityKind::Assignment: return "assignment";
    case EntityKind::Migration: return "migration";
    case EntityKind::Evidence: return "evidence";
    case EntityKind::Audit: return "audit";
    case EntityKind::Decision: return "decision";
    case EntityKind::Request: return "request";
  }
  return "unknown";
}

bool ChangeSet::empty() const noexcept { return count() == 0; }

std::size_t ChangeSet::count() const noexcept {
  return (header ? 1u : 0u) + tenants.size() + physical.size() + backings.size() + virtuals.size() + leases.size() +
         assignments.size() + migrations.size() + evidence.size() + audit.size() + decisions.size() + requests.size();
}

void ChangeSet::clear() noexcept {
  header = false;
  tenants.clear();
  physical.clear();
  backings.clear();
  virtuals.clear();
  leases.clear();
  assignments.clear();
  migrations.clear();
  evidence.clear();
  audit.clear();
  decisions.clear();
  requests.clear();
}

// ---- sub-record codecs ---------------------------------------------------

void encode_contract(Encoder& out, const ResourceContract& value) {
  encode_strong_id(out, value.id);
  encode_strong_id(out, value.generation);
  out.u64(value.memory_ceiling_bytes);
  out.u32(value.compute_share_milli);
  out.u32(value.max_streams);
  out.u32(value.max_concurrency);
  out.u64(value.bandwidth_allowance_bytes_per_second);
  out.boolean(value.exclusivity_required);
  out.u32(value.minimum_backing_rank);
  encode_list(out, value.allowed_backing_classes, [](Encoder& e, BackingClass item) { encode_enum(e, item); });
  encode_list(out, value.allowed_multiplexing_modes, [](Encoder& e, MultiplexingMode item) { encode_enum(e, item); });
  encode_list(out, value.required_isolation, [](Encoder& e, const IsolationRequirement& item) {
    encode_enum(e, item.dimension);
    encode_enum(e, item.minimum);
  });
  out.boolean(value.migration_allowed);
  encode_list(out, value.allowed_migration_classes, [](Encoder& e, MigrationClass item) { encode_enum(e, item); });
  out.boolean(value.oversubscription_allowed);
  out.boolean(value.burst_allowed);
}

Result<ResourceContract> decode_contract(Decoder& in) {
  ResourceContract value;
  auto id = decode_raw_id(in);
  if (!id.ok()) return id.status();
  value.id = ResourceContractId::from_value(*id);
  auto generation = decode_raw_id(in);
  if (!generation.ok()) return generation.status();
  value.generation = ResourceContractGeneration::from_value(*generation);
  auto memory = in.u64();
  if (!memory.ok()) return memory.status();
  value.memory_ceiling_bytes = *memory;
  auto share = in.u32();
  if (!share.ok()) return share.status();
  value.compute_share_milli = *share;
  auto streams = in.u32();
  if (!streams.ok()) return streams.status();
  value.max_streams = *streams;
  auto concurrency = in.u32();
  if (!concurrency.ok()) return concurrency.status();
  value.max_concurrency = *concurrency;
  auto bandwidth = in.u64();
  if (!bandwidth.ok()) return bandwidth.status();
  value.bandwidth_allowance_bytes_per_second = *bandwidth;
  auto exclusive = in.boolean();
  if (!exclusive.ok()) return exclusive.status();
  value.exclusivity_required = *exclusive;
  auto rank = in.u32();
  if (!rank.ok()) return rank.status();
  value.minimum_backing_rank = *rank;

  auto classes = decode_list<BackingClass>(in, 64, [](Decoder& d) {
    return decode_enum<BackingClass>(d, BackingClass::SyntheticMigratable, valid_backing_class);
  });
  if (!classes.ok()) return classes.status();
  value.allowed_backing_classes = classes.take();

  auto modes = decode_list<MultiplexingMode>(in, 64, [](Decoder& d) {
    return decode_enum<MultiplexingMode>(d, MultiplexingMode::Synthetic, valid_multiplexing);
  });
  if (!modes.ok()) return modes.status();
  value.allowed_multiplexing_modes = modes.take();

  auto isolation = decode_list<IsolationRequirement>(in, 64, [](Decoder& d) -> Result<IsolationRequirement> {
    IsolationRequirement requirement;
    auto dimension = decode_enum<IsolationDimension>(d, IsolationDimension::TenantState, valid_isolation_dimension);
    if (!dimension.ok()) return dimension.status();
    requirement.dimension = *dimension;
    auto minimum = decode_enum<IsolationState>(d, IsolationState::Isolated, valid_isolation_state);
    if (!minimum.ok()) return minimum.status();
    requirement.minimum = *minimum;
    return requirement;
  });
  if (!isolation.ok()) return isolation.status();
  value.required_isolation = isolation.take();

  auto migration = in.boolean();
  if (!migration.ok()) return migration.status();
  value.migration_allowed = *migration;

  auto migration_classes = decode_list<MigrationClass>(in, 64, [](Decoder& d) {
    return decode_enum<MigrationClass>(d, MigrationClass::LiveStateTransfer, valid_migration_class);
  });
  if (!migration_classes.ok()) return migration_classes.status();
  value.allowed_migration_classes = migration_classes.take();

  auto oversubscription = in.boolean();
  if (!oversubscription.ok()) return oversubscription.status();
  value.oversubscription_allowed = *oversubscription;
  auto burst = in.boolean();
  if (!burst.ok()) return burst.status();
  value.burst_allowed = *burst;

  return value;
}

void encode_capability_surface(Encoder& out, const CapabilitySurface& surface) {
  encode_list(out, surface.entries(), [](Encoder& e, const CapabilityEntry& entry) {
    e.u16(static_cast<std::uint16_t>(entry.key));
    encode_enum(e, entry.verdict);
    e.u64(entry.value);
    e.str(entry.text);
    e.str(entry.provenance);
  });
}

Result<CapabilitySurface> decode_capability_surface(Decoder& in) {
  auto entries = decode_list<CapabilityEntry>(in, 256, [](Decoder& d) -> Result<CapabilityEntry> {
    CapabilityEntry entry;
    auto key = d.u16();
    if (!key.ok()) return key.status();
    if (*key > static_cast<std::uint16_t>(CapabilityKey::VendorVisible)) {
      return Status(StatusCode::MalformedFrame, "capability key " + std::to_string(*key) + " is outside its domain");
    }
    entry.key = static_cast<CapabilityKey>(*key);
    auto verdict = decode_enum<CapabilityVerdict>(d, CapabilityVerdict::Constrained, valid_capability_verdict);
    if (!verdict.ok()) return verdict.status();
    entry.verdict = *verdict;
    auto value = d.u64();
    if (!value.ok()) return value.status();
    entry.value = *value;
    auto text = d.str();
    if (!text.ok()) return text.status();
    entry.text = text.take();
    auto provenance = d.str();
    if (!provenance.ok()) return provenance.status();
    entry.provenance = provenance.take();
    return entry;
  });
  if (!entries.ok()) return entries.status();
  CapabilitySurface surface;
  for (const CapabilityEntry& entry : entries.value()) surface.set(entry);
  return surface;
}

void encode_isolation_profile(Encoder& out, const IsolationProfile& profile) {
  encode_list(out, profile.claims(), [](Encoder& e, const IsolationClaim& claim) {
    encode_enum(e, claim.dimension);
    encode_enum(e, claim.state);
    encode_strong_id(e, claim.evidence);
    encode_strong_id(e, claim.evidence_gen);
    e.str(claim.mechanism);
    e.str(claim.rationale);
  });
}

Result<IsolationProfile> decode_isolation_profile(Decoder& in) {
  auto claims = decode_list<IsolationClaim>(in, kIsolationDimensionCount * 2, [](Decoder& d) -> Result<IsolationClaim> {
    IsolationClaim claim;
    auto dimension = decode_enum<IsolationDimension>(d, IsolationDimension::TenantState, valid_isolation_dimension);
    if (!dimension.ok()) return dimension.status();
    claim.dimension = *dimension;
    auto state = decode_enum<IsolationState>(d, IsolationState::Isolated, valid_isolation_state);
    if (!state.ok()) return state.status();
    claim.state = *state;
    auto evidence = decode_raw_id(d);
    if (!evidence.ok()) return evidence.status();
    claim.evidence = EvidenceId::from_value(*evidence);
    auto evidence_gen = decode_raw_id(d);
    if (!evidence_gen.ok()) return evidence_gen.status();
    claim.evidence_gen = EvidenceGeneration::from_value(*evidence_gen);
    auto mechanism = d.str();
    if (!mechanism.ok()) return mechanism.status();
    claim.mechanism = mechanism.take();
    auto rationale = d.str();
    if (!rationale.ok()) return rationale.status();
    claim.rationale = rationale.take();
    return claim;
  });
  if (!claims.ok()) return claims.status();
  IsolationProfile profile;
  for (const IsolationClaim& claim : claims.value()) profile.set(claim);
  return profile;
}

void encode_projection(Encoder& out, const CapabilityProjection& value) {
  encode_strong_id(out, value.id);
  encode_strong_id(out, value.generation);
  encode_capability_surface(out, value.surface);
  encode_list(out, value.hidden, [](Encoder& e, CapabilityKey key) { e.u16(static_cast<std::uint16_t>(key)); });
  encode_list(out, value.unknown, [](Encoder& e, CapabilityKey key) { e.u16(static_cast<std::uint16_t>(key)); });
  encode_strong_id(out, value.backing_generation);
  encode_strong_id(out, value.physical_generation);
  encode_strong_id(out, value.policy_generation);
  encode_strong_id(out, value.contract_generation);
  out.u64(value.fingerprint);
  out.str(value.mechanism);
}

Result<CapabilityProjection> decode_projection(Decoder& in) {
  CapabilityProjection value;
  auto id = decode_raw_id(in);
  if (!id.ok()) return id.status();
  value.id = CapabilityProjectionId::from_value(*id);
  auto generation = decode_raw_id(in);
  if (!generation.ok()) return generation.status();
  value.generation = CapabilityProjectionGeneration::from_value(*generation);
  auto surface = decode_capability_surface(in);
  if (!surface.ok()) return surface.status();
  value.surface = surface.take();
  auto hidden = decode_list<CapabilityKey>(in, 256, [](Decoder& d) -> Result<CapabilityKey> {
    auto raw = d.u16();
    if (!raw.ok()) return raw.status();
    if (*raw > static_cast<std::uint16_t>(CapabilityKey::VendorVisible)) {
      return Status(StatusCode::MalformedFrame, "hidden capability key is outside its domain");
    }
    return static_cast<CapabilityKey>(*raw);
  });
  if (!hidden.ok()) return hidden.status();
  value.hidden = hidden.take();
  auto unknown = decode_list<CapabilityKey>(in, 256, [](Decoder& d) -> Result<CapabilityKey> {
    auto raw = d.u16();
    if (!raw.ok()) return raw.status();
    if (*raw > static_cast<std::uint16_t>(CapabilityKey::VendorVisible)) {
      return Status(StatusCode::MalformedFrame, "unknown capability key is outside its domain");
    }
    return static_cast<CapabilityKey>(*raw);
  });
  if (!unknown.ok()) return unknown.status();
  value.unknown = unknown.take();
  auto backing = decode_raw_id(in);
  if (!backing.ok()) return backing.status();
  value.backing_generation = BackingGeneration::from_value(*backing);
  auto physical = decode_raw_id(in);
  if (!physical.ok()) return physical.status();
  value.physical_generation = PhysicalDeviceGeneration::from_value(*physical);
  auto policy = decode_raw_id(in);
  if (!policy.ok()) return policy.status();
  value.policy_generation = PolicyGeneration::from_value(*policy);
  auto contract = decode_raw_id(in);
  if (!contract.ok()) return contract.status();
  value.contract_generation = ResourceContractGeneration::from_value(*contract);
  auto fingerprint = in.u64();
  if (!fingerprint.ok()) return fingerprint.status();
  value.fingerprint = *fingerprint;
  auto mechanism = in.str();
  if (!mechanism.ok()) return mechanism.status();
  value.mechanism = mechanism.take();
  return value;
}

void encode_policy(Encoder& out, const VirtualizationPolicy& value) {
  encode_strong_id(out, value.id);
  encode_strong_id(out, value.generation);
  encode_list(out, value.allowed_backing_classes, [](Encoder& e, BackingClass item) { encode_enum(e, item); });
  encode_enum(out, value.tenant_sharing);
  encode_list(out, value.required_isolation, [](Encoder& e, const IsolationRequirement& item) {
    encode_enum(e, item.dimension);
    encode_enum(e, item.minimum);
  });
  out.boolean(value.oversubscription_allowed);
  encode_enum(out, value.transparency);
  out.boolean(value.migration_allowed);
  encode_list(out, value.allowed_migration_classes, [](Encoder& e, MigrationClass item) { encode_enum(e, item); });
  out.u32(value.max_attachments_per_virtual);
  out.u64(value.max_lease_duration_micros);
  encode_list(out, value.forbidden_capabilities, [](Encoder& e, CapabilityKey key) { e.u16(static_cast<std::uint16_t>(key)); });
  out.u64(value.max_memory_ceiling_bytes);
  out.u32(value.max_compute_share_milli);
  out.boolean(value.synthetic_backing_allowed);
  encode_enum(out, value.recovery);
  out.u64(value.evidence_max_age_micros);
  out.u32(value.max_virtual_accelerators);
  out.u32(value.max_tenants);
  out.u32(value.max_leases);
  out.u32(value.max_assignments);
  out.u32(value.max_migrations);
  out.u32(value.max_evidence_records);
}

Result<VirtualizationPolicy> decode_policy(Decoder& in) {
  VirtualizationPolicy value;
  auto id = decode_raw_id(in);
  if (!id.ok()) return id.status();
  value.id = PolicyId::from_value(*id);
  auto generation = decode_raw_id(in);
  if (!generation.ok()) return generation.status();
  value.generation = PolicyGeneration::from_value(*generation);

  auto classes = decode_list<BackingClass>(in, 64, [](Decoder& d) {
    return decode_enum<BackingClass>(d, BackingClass::SyntheticMigratable, valid_backing_class);
  });
  if (!classes.ok()) return classes.status();
  value.allowed_backing_classes = classes.take();

  auto sharing = decode_enum<TenantSharingPolicy>(in, TenantSharingPolicy::Shared, valid_sharing);
  if (!sharing.ok()) return sharing.status();
  value.tenant_sharing = *sharing;

  auto isolation = decode_list<IsolationRequirement>(in, 64, [](Decoder& d) -> Result<IsolationRequirement> {
    IsolationRequirement requirement;
    auto dimension = decode_enum<IsolationDimension>(d, IsolationDimension::TenantState, valid_isolation_dimension);
    if (!dimension.ok()) return dimension.status();
    requirement.dimension = *dimension;
    auto minimum = decode_enum<IsolationState>(d, IsolationState::Isolated, valid_isolation_state);
    if (!minimum.ok()) return minimum.status();
    requirement.minimum = *minimum;
    return requirement;
  });
  if (!isolation.ok()) return isolation.status();
  value.required_isolation = isolation.take();

  auto oversubscription = in.boolean();
  if (!oversubscription.ok()) return oversubscription.status();
  value.oversubscription_allowed = *oversubscription;

  auto transparency = decode_enum<BackingTransparency>(in, BackingTransparency::Full, valid_transparency);
  if (!transparency.ok()) return transparency.status();
  value.transparency = *transparency;

  auto migration = in.boolean();
  if (!migration.ok()) return migration.status();
  value.migration_allowed = *migration;

  auto migration_classes = decode_list<MigrationClass>(in, 64, [](Decoder& d) {
    return decode_enum<MigrationClass>(d, MigrationClass::LiveStateTransfer, valid_migration_class);
  });
  if (!migration_classes.ok()) return migration_classes.status();
  value.allowed_migration_classes = migration_classes.take();

  auto attachments = in.u32();
  if (!attachments.ok()) return attachments.status();
  value.max_attachments_per_virtual = *attachments;
  auto lease_duration = in.u64();
  if (!lease_duration.ok()) return lease_duration.status();
  value.max_lease_duration_micros = *lease_duration;

  auto forbidden = decode_list<CapabilityKey>(in, 256, [](Decoder& d) -> Result<CapabilityKey> {
    auto raw = d.u16();
    if (!raw.ok()) return raw.status();
    if (*raw > static_cast<std::uint16_t>(CapabilityKey::VendorVisible)) {
      return Status(StatusCode::MalformedFrame, "forbidden capability key is outside its domain");
    }
    return static_cast<CapabilityKey>(*raw);
  });
  if (!forbidden.ok()) return forbidden.status();
  value.forbidden_capabilities = forbidden.take();

  auto ceiling = in.u64();
  if (!ceiling.ok()) return ceiling.status();
  value.max_memory_ceiling_bytes = *ceiling;
  auto share = in.u32();
  if (!share.ok()) return share.status();
  value.max_compute_share_milli = *share;
  auto synthetic = in.boolean();
  if (!synthetic.ok()) return synthetic.status();
  value.synthetic_backing_allowed = *synthetic;

  auto recovery = decode_enum<RecoveryBehavior>(in, RecoveryBehavior::Optimistic, valid_recovery);
  if (!recovery.ok()) return recovery.status();
  value.recovery = *recovery;

  auto age = in.u64();
  if (!age.ok()) return age.status();
  value.evidence_max_age_micros = *age;
  auto max_virtual = in.u32();
  if (!max_virtual.ok()) return max_virtual.status();
  value.max_virtual_accelerators = *max_virtual;
  auto max_tenants = in.u32();
  if (!max_tenants.ok()) return max_tenants.status();
  value.max_tenants = *max_tenants;
  auto max_leases = in.u32();
  if (!max_leases.ok()) return max_leases.status();
  value.max_leases = *max_leases;
  auto max_assignments = in.u32();
  if (!max_assignments.ok()) return max_assignments.status();
  value.max_assignments = *max_assignments;
  auto max_migrations = in.u32();
  if (!max_migrations.ok()) return max_migrations.status();
  value.max_migrations = *max_migrations;
  auto max_evidence = in.u32();
  if (!max_evidence.ok()) return max_evidence.status();
  value.max_evidence_records = *max_evidence;
  return value;
}

void encode_migration_plan(Encoder& out, const MigrationPlan& plan) {
  encode_strong_id(out, plan.id);
  encode_strong_id(out, plan.generation);
  encode_strong_id(out, plan.virtual_id);
  encode_strong_id(out, plan.virtual_generation);
  encode_strong_id(out, plan.source_backing);
  encode_strong_id(out, plan.source_backing_generation);
  encode_strong_id(out, plan.destination_backing);
  encode_strong_id(out, plan.destination_backing_generation);
  encode_strong_id(out, plan.source_physical);
  encode_strong_id(out, plan.source_physical_generation);
  encode_strong_id(out, plan.destination_physical);
  encode_strong_id(out, plan.destination_physical_generation);
  encode_strong_id(out, plan.tenant);
  encode_strong_id(out, plan.tenant_generation);
  encode_strong_id(out, plan.contract_generation);
  encode_strong_id(out, plan.projection_generation);
  encode_strong_id(out, plan.policy_generation);
  encode_strong_id(out, plan.epoch);
  encode_enum(out, plan.klass);
  out.boolean(plan.state_transfer_required);
  out.boolean(plan.live_state_movement);
  out.str(plan.rationale);
}

Result<MigrationPlan> decode_migration_plan(Decoder& in) {
  MigrationPlan plan;
  auto id = decode_raw_id(in);
  if (!id.ok()) return id.status();
  plan.id = MigrationId::from_value(*id);
  auto generation = decode_raw_id(in);
  if (!generation.ok()) return generation.status();
  plan.generation = MigrationGeneration::from_value(*generation);

  auto read_id = [&in]() -> Result<std::uint64_t> { return decode_raw_id(in); };

  auto virtual_id = read_id();
  if (!virtual_id.ok()) return virtual_id.status();
  plan.virtual_id = VirtualAcceleratorId::from_value(*virtual_id);
  auto virtual_generation = read_id();
  if (!virtual_generation.ok()) return virtual_generation.status();
  plan.virtual_generation = VirtualAcceleratorGeneration::from_value(*virtual_generation);
  auto source_backing = read_id();
  if (!source_backing.ok()) return source_backing.status();
  plan.source_backing = BackingId::from_value(*source_backing);
  auto source_backing_generation = read_id();
  if (!source_backing_generation.ok()) return source_backing_generation.status();
  plan.source_backing_generation = BackingGeneration::from_value(*source_backing_generation);
  auto destination_backing = read_id();
  if (!destination_backing.ok()) return destination_backing.status();
  plan.destination_backing = BackingId::from_value(*destination_backing);
  auto destination_backing_generation = read_id();
  if (!destination_backing_generation.ok()) return destination_backing_generation.status();
  plan.destination_backing_generation = BackingGeneration::from_value(*destination_backing_generation);
  auto source_physical = read_id();
  if (!source_physical.ok()) return source_physical.status();
  plan.source_physical = PhysicalDeviceId::from_value(*source_physical);
  auto source_physical_generation = read_id();
  if (!source_physical_generation.ok()) return source_physical_generation.status();
  plan.source_physical_generation = PhysicalDeviceGeneration::from_value(*source_physical_generation);
  auto destination_physical = read_id();
  if (!destination_physical.ok()) return destination_physical.status();
  plan.destination_physical = PhysicalDeviceId::from_value(*destination_physical);
  auto destination_physical_generation = read_id();
  if (!destination_physical_generation.ok()) return destination_physical_generation.status();
  plan.destination_physical_generation = PhysicalDeviceGeneration::from_value(*destination_physical_generation);
  auto tenant = read_id();
  if (!tenant.ok()) return tenant.status();
  plan.tenant = TenantId::from_value(*tenant);
  auto tenant_generation = read_id();
  if (!tenant_generation.ok()) return tenant_generation.status();
  plan.tenant_generation = TenantGeneration::from_value(*tenant_generation);
  auto contract_generation = read_id();
  if (!contract_generation.ok()) return contract_generation.status();
  plan.contract_generation = ResourceContractGeneration::from_value(*contract_generation);
  auto projection_generation = read_id();
  if (!projection_generation.ok()) return projection_generation.status();
  plan.projection_generation = CapabilityProjectionGeneration::from_value(*projection_generation);
  auto policy_generation = read_id();
  if (!policy_generation.ok()) return policy_generation.status();
  plan.policy_generation = PolicyGeneration::from_value(*policy_generation);
  auto epoch = read_id();
  if (!epoch.ok()) return epoch.status();
  plan.epoch = CoordinatorEpoch::from_value(*epoch);

  auto klass = decode_enum<MigrationClass>(in, MigrationClass::LiveStateTransfer, valid_migration_class);
  if (!klass.ok()) return klass.status();
  plan.klass = *klass;
  auto transfer = in.boolean();
  if (!transfer.ok()) return transfer.status();
  plan.state_transfer_required = *transfer;
  auto live = in.boolean();
  if (!live.ok()) return live.status();
  plan.live_state_movement = *live;
  auto rationale = in.str();
  if (!rationale.ok()) return rationale.status();
  plan.rationale = rationale.take();
  return plan;
}

std::vector<Byte> encode_contract_blob(const ResourceContract& value) {
  Encoder out;
  encode_contract(out, value);
  return out.take();
}

Result<ResourceContract> decode_contract_blob(ByteSpan bytes) {
  Decoder in(bytes);
  auto value = decode_contract(in);
  if (!value.ok()) return value.status();
  Status end = in.require_end();
  if (!end.ok()) return end;
  return value.take();
}

}  // namespace av
