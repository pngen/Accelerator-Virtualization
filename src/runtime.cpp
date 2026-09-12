// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The authoritative virtualization runtime.
//
// Virtual identity is not physical identity. A virtual accelerator keeps its
// VirtualAcceleratorId across legal backing replacement while its backing
// binding generation advances. Every authoritative mutation validates the
// caller's authority, mutates durable state, persists it, and only then
// reports success.
#include <algorithm>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "av/hash.hpp"
#include "av/invariant.hpp"
#include "av/runtime.hpp"

namespace av {
namespace {

constexpr std::size_t kMaxListedVirtuals = 1u << 22;
constexpr std::size_t kMaxPhysicalDevices = 4096;

void append_kv(std::string& out, std::string_view key, std::string_view value) {
  out.append(key);
  out.push_back('=');
  out.append(value);
  out.push_back('\n');
}

void append_kv(std::string& out, std::string_view key, std::uint64_t value) {
  append_kv(out, key, std::to_string(value));
}

void append_kv(std::string& out, std::string_view key, bool value) {
  append_kv(out, key, value ? std::string_view{"true"} : std::string_view{"false"});
}

template <class T, class EncodeFn>
std::vector<Byte> blob_of(const T& value, EncodeFn encode) {
  Encoder out;
  encode(out, value);
  return out.take();
}

template <class T, class DecodeFn>
Result<T> value_of(ByteSpan bytes, DecodeFn decode) {
  Decoder in(bytes);
  auto value = decode(in);
  if (!value.ok()) return value.status();
  const Status end = in.require_end();
  if (!end.ok()) return end;
  return value.take();
}

}  // namespace

std::string Authority::canonical() const {
  std::string out;
  out.reserve(512);
  if (epoch.has_value()) append_kv(out, "epoch", epoch->str());
  if (tenant.has_value()) append_kv(out, "tenant", tenant->str());
  if (tenant_generation.has_value()) append_kv(out, "tenant_generation", tenant_generation->str());
  if (virtual_id.has_value()) append_kv(out, "virtual", virtual_id->str());
  if (virtual_generation.has_value()) append_kv(out, "virtual_generation", virtual_generation->str());
  if (backing.has_value()) append_kv(out, "backing", backing->str());
  if (backing_generation.has_value()) append_kv(out, "backing_generation", backing_generation->str());
  if (physical.has_value()) append_kv(out, "physical", physical->str());
  if (physical_generation.has_value()) append_kv(out, "physical_generation", physical_generation->str());
  if (lease.has_value()) append_kv(out, "lease", lease->str());
  if (lease_generation.has_value()) append_kv(out, "lease_generation", lease_generation->str());
  if (policy_generation.has_value()) append_kv(out, "policy_generation", policy_generation->str());
  if (migration.has_value()) append_kv(out, "migration", migration->str());
  if (migration_generation.has_value()) append_kv(out, "migration_generation", migration_generation->str());
  if (request.has_value()) append_kv(out, "request", request->str());
  if (session.has_value()) append_kv(out, "session", std::to_string(*session));
  return out;
}

std::string VirtualView::canonical() const {
  std::string out;
  out.reserve(1024);
  append_kv(out, "virtual", id.str());
  append_kv(out, "name", name);
  append_kv(out, "generation", generation.str());
  append_kv(out, "lifecycle", lifecycle_name(state));
  append_kv(out, "state_generation", state_generation.str());
  append_kv(out, "state_reason", state_reason);
  append_kv(out, "owner", owner.str());
  append_kv(out, "owner_generation", owner_generation.str());
  append_kv(out, "owner_is_caller", owner_is_caller);
  append_kv(out, "multiplexing", multiplexing_name(multiplexing));
  append_kv(out, "isolation_class", isolation_class_name(isolation_class));
  append_kv(out, "transparency", transparency_name(transparency));
  append_kv(out, "backing_disclosed", backing_disclosed);
  append_kv(out, "backing_class", backing_class_name(backing_class));
  append_kv(out, "backing_provenance", provenance_name(backing_provenance));
  append_kv(out, "backing_mechanism", backing_mechanism);
  append_kv(out, "backing_generation", backing_generation.str());
  append_kv(out, "physical_generation", physical_generation.str());
  append_kv(out, "physical_model", physical_model);
  append_kv(out, "active_attachments", static_cast<std::uint64_t>(active_attachments));
  append_kv(out, "attached_to_caller", attached_to_caller);
  append_kv(out, "caller_lease", caller_lease.str());
  append_kv(out, "caller_lease_generation", caller_lease_generation.str());
  append_kv(out, "migration_class", migration_class_name(migration_class));
  append_kv(out, "migration_supported", migration_supported);
  append_kv(out, "has_active_migration", has_active_migration);
  append_kv(out, "allocated_bytes", allocated_bytes);
  append_kv(out, "contract_generation", contract.generation.str());
  append_kv(out, "contract_memory_ceiling_bytes", contract.memory_ceiling_bytes);
  append_kv(out, "projection_generation", projection.generation.str());
  append_kv(out, "projection_fingerprint", projection.fingerprint);
  append_kv(out, "created_at", static_cast<std::uint64_t>(created_at));
  append_kv(out, "updated_at", static_cast<std::uint64_t>(updated_at));
  if (backing_disclosed && backing.valid()) append_kv(out, "backing", backing.str());
  if (backing_disclosed && physical.valid()) append_kv(out, "physical", physical.str());
  return out;
}

std::string IsolationExplanation::canonical() const {
  std::string out;
  out.reserve(1024);
  append_kv(out, "virtual", id.str());
  append_kv(out, "generation", generation.str());
  append_kv(out, "isolation_class", isolation_class_name(isolation_class));
  append_kv(out, "provenance", provenance_name(provenance));
  append_kv(out, "mechanism", mechanism);
  append_kv(out, "multiplexing", multiplexing_name(multiplexing));
  append_kv(out, "satisfies_policy", satisfies_policy);
  auto emit = [&out](std::string_view label, const std::vector<IsolationClaim>& claims) {
    for (const IsolationClaim& claim : claims) {
      out.append(label);
      out.push_back(' ');
      out.append(isolation_dimension_name(claim.dimension));
      out.push_back(' ');
      out.append(isolation_state_name(claim.state));
      out.push_back(' ');
      out.append(claim.mechanism);
      out.push_back(' ');
      out.append(claim.rationale);
      out.push_back('\n');
    }
  };
  emit("claim", claims);
  emit("isolated", isolated);
  emit("partial", partial);
  emit("shared", shared);
  emit("unknown", unknown);
  emit("unsupported", unsupported);
  for (const IsolationRequirement& requirement : unmet_requirements) {
    out.append("unmet ");
    out.append(isolation_dimension_name(requirement.dimension));
    out.push_back(' ');
    out.append(isolation_state_name(requirement.minimum));
    out.push_back('\n');
  }
  return out;
}

std::string MigrationExplanation::canonical() const {
  std::string out;
  out.reserve(256);
  append_kv(out, "virtual", id.str());
  append_kv(out, "supported", supported);
  append_kv(out, "class", migration_class_name(klass));
  append_kv(out, "state_transfer_required", state_transfer_required);
  append_kv(out, "live_state_movement", live_state_movement);
  append_kv(out, "has_active_migration", has_active_migration);
  append_kv(out, "migration_state", migration_state_name(state));
  append_kv(out, "reason", reason);
  return out;
}

// ---- inspection wire codecs ---------------------------------------------

std::vector<Byte> encode_view(const VirtualView& view) {
  Encoder out;
  out.u64(view.id.value());
  out.u64(view.generation.value());
  out.str(view.name);
  out.u8(static_cast<std::uint8_t>(view.state));
  out.u64(view.state_generation.value());
  out.str(view.state_reason);
  out.u64(view.owner.value());
  out.u64(view.owner_generation.value());
  out.boolean(view.owner_is_caller);
  encode_contract(out, view.contract);
  encode_projection(out, view.projection);
  out.u8(static_cast<std::uint8_t>(view.multiplexing));
  out.u8(static_cast<std::uint8_t>(view.isolation_class));
  out.u8(static_cast<std::uint8_t>(view.transparency));
  out.boolean(view.backing_disclosed);
  out.u8(static_cast<std::uint8_t>(view.backing_class));
  out.u8(static_cast<std::uint8_t>(view.backing_provenance));
  out.str(view.backing_mechanism);
  out.u64(view.backing.value());
  out.u64(view.backing_generation.value());
  out.u64(view.physical.value());
  out.u64(view.physical_generation.value());
  out.str(view.physical_stable_key);
  out.str(view.physical_model);
  out.u32(view.active_attachments);
  out.boolean(view.attached_to_caller);
  out.u64(view.caller_lease.value());
  out.u64(view.caller_lease_generation.value());
  out.u8(static_cast<std::uint8_t>(view.migration_class));
  out.boolean(view.migration_supported);
  out.boolean(view.has_active_migration);
  out.u64(view.allocated_bytes);
  out.i64(view.created_at);
  out.i64(view.updated_at);
  return out.take();
}

Result<VirtualView> decode_view(ByteSpan bytes) {
  Decoder in(bytes);
  VirtualView view;
  auto id = in.u64();
  if (!id.ok()) return id.status();
  view.id = VirtualAcceleratorId::from_value(*id);
  auto generation = in.u64();
  if (!generation.ok()) return generation.status();
  view.generation = VirtualAcceleratorGeneration::from_value(*generation);
  auto name = in.str();
  if (!name.ok()) return name.status();
  view.name = name.take();
  auto state = in.u8();
  if (!state.ok()) return state.status();
  if (*state > static_cast<std::uint8_t>(VirtualLifecycleState::Retired)) {
    return Status(StatusCode::ProtocolViolation, "lifecycle state is outside its domain");
  }
  view.state = static_cast<VirtualLifecycleState>(*state);
  auto state_generation = in.u64();
  if (!state_generation.ok()) return state_generation.status();
  view.state_generation = VirtualAcceleratorGeneration::from_value(*state_generation);
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  view.state_reason = reason.take();
  auto owner = in.u64();
  if (!owner.ok()) return owner.status();
  view.owner = TenantId::from_value(*owner);
  auto owner_generation = in.u64();
  if (!owner_generation.ok()) return owner_generation.status();
  view.owner_generation = TenantGeneration::from_value(*owner_generation);
  auto owner_is_caller = in.boolean();
  if (!owner_is_caller.ok()) return owner_is_caller.status();
  view.owner_is_caller = *owner_is_caller;
  auto contract = decode_contract(in);
  if (!contract.ok()) return contract.status();
  view.contract = contract.take();
  auto projection = decode_projection(in);
  if (!projection.ok()) return projection.status();
  view.projection = projection.take();
  auto multiplexing = in.u8();
  if (!multiplexing.ok()) return multiplexing.status();
  if (*multiplexing > static_cast<std::uint8_t>(MultiplexingMode::Synthetic)) {
    return Status(StatusCode::ProtocolViolation, "multiplexing mode is outside its domain");
  }
  view.multiplexing = static_cast<MultiplexingMode>(*multiplexing);
  auto isolation_class = in.u8();
  if (!isolation_class.ok()) return isolation_class.status();
  if (*isolation_class > static_cast<std::uint8_t>(IsolationClass::Synthetic)) {
    return Status(StatusCode::ProtocolViolation, "isolation class is outside its domain");
  }
  view.isolation_class = static_cast<IsolationClass>(*isolation_class);
  auto transparency = in.u8();
  if (!transparency.ok()) return transparency.status();
  if (*transparency > static_cast<std::uint8_t>(BackingTransparency::Full)) {
    return Status(StatusCode::ProtocolViolation, "transparency is outside its domain");
  }
  view.transparency = static_cast<BackingTransparency>(*transparency);
  auto disclosed = in.boolean();
  if (!disclosed.ok()) return disclosed.status();
  view.backing_disclosed = *disclosed;
  auto backing_class = in.u8();
  if (!backing_class.ok()) return backing_class.status();
  if (*backing_class > static_cast<std::uint8_t>(BackingClass::SyntheticMigratable)) {
    return Status(StatusCode::ProtocolViolation, "backing class is outside its domain");
  }
  view.backing_class = static_cast<BackingClass>(*backing_class);
  auto provenance = in.u8();
  if (!provenance.ok()) return provenance.status();
  if (*provenance > static_cast<std::uint8_t>(Provenance::Unsupported)) {
    return Status(StatusCode::ProtocolViolation, "provenance is outside its domain");
  }
  view.backing_provenance = static_cast<Provenance>(*provenance);
  auto mechanism = in.str();
  if (!mechanism.ok()) return mechanism.status();
  view.backing_mechanism = mechanism.take();
  auto backing = in.u64();
  if (!backing.ok()) return backing.status();
  view.backing = BackingId::from_value(*backing);
  auto backing_generation = in.u64();
  if (!backing_generation.ok()) return backing_generation.status();
  view.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto physical = in.u64();
  if (!physical.ok()) return physical.status();
  view.physical = PhysicalDeviceId::from_value(*physical);
  auto physical_generation = in.u64();
  if (!physical_generation.ok()) return physical_generation.status();
  view.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto stable_key = in.str();
  if (!stable_key.ok()) return stable_key.status();
  view.physical_stable_key = stable_key.take();
  auto model = in.str();
  if (!model.ok()) return model.status();
  view.physical_model = model.take();
  auto attachments = in.u32();
  if (!attachments.ok()) return attachments.status();
  view.active_attachments = *attachments;
  auto attached = in.boolean();
  if (!attached.ok()) return attached.status();
  view.attached_to_caller = *attached;
  auto lease = in.u64();
  if (!lease.ok()) return lease.status();
  view.caller_lease = LeaseId::from_value(*lease);
  auto lease_generation = in.u64();
  if (!lease_generation.ok()) return lease_generation.status();
  view.caller_lease_generation = LeaseGeneration::from_value(*lease_generation);
  auto migration_class = in.u8();
  if (!migration_class.ok()) return migration_class.status();
  if (*migration_class > static_cast<std::uint8_t>(MigrationClass::LiveStateTransfer)) {
    return Status(StatusCode::ProtocolViolation, "migration class is outside its domain");
  }
  view.migration_class = static_cast<MigrationClass>(*migration_class);
  auto migration_supported = in.boolean();
  if (!migration_supported.ok()) return migration_supported.status();
  view.migration_supported = *migration_supported;
  auto active_migration = in.boolean();
  if (!active_migration.ok()) return active_migration.status();
  view.has_active_migration = *active_migration;
  auto allocated = in.u64();
  if (!allocated.ok()) return allocated.status();
  view.allocated_bytes = *allocated;
  auto created = in.i64();
  if (!created.ok()) return created.status();
  view.created_at = *created;
  auto updated = in.i64();
  if (!updated.ok()) return updated.status();
  view.updated_at = *updated;
  const Status end = in.require_end();
  if (!end.ok()) return end;
  return view;
}

std::vector<Byte> encode_isolation_explanation(const IsolationExplanation& value) {
  Encoder out;
  out.u64(value.id.value());
  out.u64(value.generation.value());
  out.u8(static_cast<std::uint8_t>(value.isolation_class));
  out.u8(static_cast<std::uint8_t>(value.provenance));
  out.str(value.mechanism);
  out.u8(static_cast<std::uint8_t>(value.multiplexing));
  out.boolean(value.satisfies_policy);
  auto encode_claims = [&out](const std::vector<IsolationClaim>& claims) {
    out.u32(static_cast<std::uint32_t>(claims.size()));
    for (const IsolationClaim& claim : claims) {
      out.u8(static_cast<std::uint8_t>(claim.dimension));
      out.u8(static_cast<std::uint8_t>(claim.state));
      out.u64(claim.evidence.value());
      out.u64(claim.evidence_gen.value());
      out.str(claim.mechanism);
      out.str(claim.rationale);
    }
  };
  encode_claims(value.claims);
  encode_claims(value.isolated);
  encode_claims(value.partial);
  encode_claims(value.shared);
  encode_claims(value.unknown);
  encode_claims(value.unsupported);
  out.u32(static_cast<std::uint32_t>(value.unmet_requirements.size()));
  for (const IsolationRequirement& requirement : value.unmet_requirements) {
    out.u8(static_cast<std::uint8_t>(requirement.dimension));
    out.u8(static_cast<std::uint8_t>(requirement.minimum));
  }
  return out.take();
}

Result<IsolationExplanation> decode_isolation_explanation(ByteSpan bytes) {
  Decoder in(bytes);
  IsolationExplanation value;
  auto id = in.u64();
  if (!id.ok()) return id.status();
  value.id = VirtualAcceleratorId::from_value(*id);
  auto generation = in.u64();
  if (!generation.ok()) return generation.status();
  value.generation = VirtualAcceleratorGeneration::from_value(*generation);
  auto isolation_class = in.u8();
  if (!isolation_class.ok()) return isolation_class.status();
  if (*isolation_class > static_cast<std::uint8_t>(IsolationClass::Synthetic)) {
    return Status(StatusCode::ProtocolViolation, "isolation class is outside its domain");
  }
  value.isolation_class = static_cast<IsolationClass>(*isolation_class);
  auto provenance = in.u8();
  if (!provenance.ok()) return provenance.status();
  if (*provenance > static_cast<std::uint8_t>(Provenance::Unsupported)) {
    return Status(StatusCode::ProtocolViolation, "provenance is outside its domain");
  }
  value.provenance = static_cast<Provenance>(*provenance);
  auto mechanism = in.str();
  if (!mechanism.ok()) return mechanism.status();
  value.mechanism = mechanism.take();
  auto multiplexing = in.u8();
  if (!multiplexing.ok()) return multiplexing.status();
  if (*multiplexing > static_cast<std::uint8_t>(MultiplexingMode::Synthetic)) {
    return Status(StatusCode::ProtocolViolation, "multiplexing mode is outside its domain");
  }
  value.multiplexing = static_cast<MultiplexingMode>(*multiplexing);
  auto satisfies = in.boolean();
  if (!satisfies.ok()) return satisfies.status();
  value.satisfies_policy = *satisfies;

  auto decode_claims = [&in](std::vector<IsolationClaim>& target) -> Status {
    auto count = in.list_header(64);
    if (!count.ok()) return count.status();
    for (std::size_t i = 0; i < *count; ++i) {
      IsolationClaim claim;
      auto dimension = in.u8();
      if (!dimension.ok()) return dimension.status();
      if (*dimension > static_cast<std::uint8_t>(IsolationDimension::TenantState)) {
        return Status(StatusCode::ProtocolViolation, "isolation dimension is outside its domain");
      }
      claim.dimension = static_cast<IsolationDimension>(*dimension);
      auto state = in.u8();
      if (!state.ok()) return state.status();
      if (*state > static_cast<std::uint8_t>(IsolationState::Isolated)) {
        return Status(StatusCode::ProtocolViolation, "isolation state is outside its domain");
      }
      claim.state = static_cast<IsolationState>(*state);
      auto evidence = in.u64();
      if (!evidence.ok()) return evidence.status();
      claim.evidence = EvidenceId::from_value(*evidence);
      auto evidence_gen = in.u64();
      if (!evidence_gen.ok()) return evidence_gen.status();
      claim.evidence_gen = EvidenceGeneration::from_value(*evidence_gen);
      auto mechanism_text = in.str();
      if (!mechanism_text.ok()) return mechanism_text.status();
      claim.mechanism = mechanism_text.take();
      auto rationale = in.str();
      if (!rationale.ok()) return rationale.status();
      claim.rationale = rationale.take();
      target.push_back(std::move(claim));
    }
    in.depth_leave();
    return Status{};
  };
  Status status = decode_claims(value.claims);
  if (!status.ok()) return status;
  status = decode_claims(value.isolated);
  if (!status.ok()) return status;
  status = decode_claims(value.partial);
  if (!status.ok()) return status;
  status = decode_claims(value.shared);
  if (!status.ok()) return status;
  status = decode_claims(value.unknown);
  if (!status.ok()) return status;
  status = decode_claims(value.unsupported);
  if (!status.ok()) return status;

  auto unmet = in.list_header(64);
  if (!unmet.ok()) return unmet.status();
  for (std::size_t i = 0; i < *unmet; ++i) {
    IsolationRequirement requirement;
    auto dimension = in.u8();
    if (!dimension.ok()) return dimension.status();
    if (*dimension > static_cast<std::uint8_t>(IsolationDimension::TenantState)) {
      return Status(StatusCode::ProtocolViolation, "isolation dimension is outside its domain");
    }
    requirement.dimension = static_cast<IsolationDimension>(*dimension);
    auto minimum = in.u8();
    if (!minimum.ok()) return minimum.status();
    if (*minimum > static_cast<std::uint8_t>(IsolationState::Isolated)) {
      return Status(StatusCode::ProtocolViolation, "isolation state is outside its domain");
    }
    requirement.minimum = static_cast<IsolationState>(*minimum);
    value.unmet_requirements.push_back(requirement);
  }
  in.depth_leave();
  const Status end = in.require_end();
  if (!end.ok()) return end;
  return value;
}

std::vector<Byte> encode_migration_explanation(const MigrationExplanation& value) {
  Encoder out;
  out.u64(value.id.value());
  out.boolean(value.supported);
  out.u8(static_cast<std::uint8_t>(value.klass));
  out.str(value.reason);
  out.boolean(value.state_transfer_required);
  out.boolean(value.live_state_movement);
  out.boolean(value.has_active_migration);
  out.u8(static_cast<std::uint8_t>(value.state));
  return out.take();
}

Result<MigrationExplanation> decode_migration_explanation(ByteSpan bytes) {
  Decoder in(bytes);
  MigrationExplanation value;
  auto id = in.u64();
  if (!id.ok()) return id.status();
  value.id = VirtualAcceleratorId::from_value(*id);
  auto supported = in.boolean();
  if (!supported.ok()) return supported.status();
  value.supported = *supported;
  auto klass = in.u8();
  if (!klass.ok()) return klass.status();
  if (*klass > static_cast<std::uint8_t>(MigrationClass::LiveStateTransfer)) {
    return Status(StatusCode::ProtocolViolation, "migration class is outside its domain");
  }
  value.klass = static_cast<MigrationClass>(*klass);
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  value.reason = reason.take();
  auto transfer = in.boolean();
  if (!transfer.ok()) return transfer.status();
  value.state_transfer_required = *transfer;
  auto live = in.boolean();
  if (!live.ok()) return live.status();
  value.live_state_movement = *live;
  auto active = in.boolean();
  if (!active.ok()) return active.status();
  value.has_active_migration = *active;
  auto state = in.u8();
  if (!state.ok()) return state.status();
  if (*state > static_cast<std::uint8_t>(MigrationState::Failed)) {
    return Status(StatusCode::ProtocolViolation, "migration state is outside its domain");
  }
  value.state = static_cast<MigrationState>(*state);
  const Status end = in.require_end();
  if (!end.ok()) return end;
  return value;
}

std::vector<Byte> encode_audit_entry(const AuditEntry& entry) { return blob_of(entry, encode_audit); }
Result<AuditEntry> decode_audit_entry(ByteSpan bytes) { return value_of<AuditEntry>(bytes, decode_audit); }
std::vector<Byte> encode_decision_record(const Decision& decision) { return blob_of(decision, encode_decision); }
Result<Decision> decode_decision_record(ByteSpan bytes) { return value_of<Decision>(bytes, decode_decision); }

// One macro list keeps the accounting wire layout in a single place, so the
// encoder and the decoder cannot drift apart.
#define AV_ACCOUNTING_FIELDS(X)  \
  X(coordinator_boots)           \
  X(agent_boots)                 \
  X(physical_registered)         \
  X(physical_lost)               \
  X(virtual_created)             \
  X(virtual_retired)             \
  X(virtual_active)              \
  X(leases_issued)               \
  X(leases_renewed)              \
  X(leases_revoked)              \
  X(leases_fenced)               \
  X(attachments_active)          \
  X(peak_attachments_active)     \
  X(detaches)                    \
  X(backing_assignments)         \
  X(backing_replacements)        \
  X(backing_revocations)         \
  X(migrations_planned)          \
  X(migrations_prepared)         \
  X(migrations_committed)        \
  X(migrations_aborted)          \
  X(stale_authority_refusals)    \
  X(authority_refusals)          \
  X(lifecycle_refusals)          \
  X(contract_violation_refusals) \
  X(isolation_refusals)          \
  X(capability_refusals)         \
  X(oversubscription_denials)    \
  X(protocol_violations)         \
  X(duplicate_request_refusals)  \
  X(policy_updates)              \
  X(evidence_records)            \
  X(allocation_operations)       \
  X(kernel_operations)           \
  X(bytes_allocated_current)     \
  X(bytes_allocated_peak)        \
  X(persistence_writes)          \
  X(persistence_bytes)           \
  X(persistence_compactions)

std::vector<Byte> encode_accounting(const AccountingCounters& counters) {
  Encoder out;
#define AV_ENCODE_ACCOUNTING(name) out.u64(counters.name);
  AV_ACCOUNTING_FIELDS(AV_ENCODE_ACCOUNTING)
#undef AV_ENCODE_ACCOUNTING
  return out.take();
}

Result<AccountingCounters> decode_accounting(ByteSpan bytes) {
  Decoder in(bytes);
  AccountingCounters counters;
#define AV_DECODE_ACCOUNTING(name)          \
  {                                         \
    auto value = in.u64();                  \
    if (!value.ok()) return value.status(); \
    counters.name = *value;                 \
  }
  AV_ACCOUNTING_FIELDS(AV_DECODE_ACCOUNTING)
#undef AV_DECODE_ACCOUNTING
  const Status end = in.require_end();
  if (!end.ok()) return end;
  return counters;
}

#undef AV_ACCOUNTING_FIELDS

std::vector<Byte> encode_backing_record(const BackingRecord& record) { return blob_of(record, encode_backing); }
Result<BackingRecord> decode_backing_record(ByteSpan bytes) { return value_of<BackingRecord>(bytes, decode_backing); }
std::vector<Byte> encode_physical_record(const PhysicalDeviceRecord& record) {
  return blob_of(record, encode_physical);
}
Result<PhysicalDeviceRecord> decode_physical_record(ByteSpan bytes) {
  return value_of<PhysicalDeviceRecord>(bytes, decode_physical);
}
std::vector<Byte> encode_tenant_record(const TenantRecord& record) { return blob_of(record, encode_tenant); }
Result<TenantRecord> decode_tenant_record(ByteSpan bytes) { return value_of<TenantRecord>(bytes, decode_tenant); }
std::vector<Byte> encode_lease_record(const LeaseRecord& record) { return blob_of(record, encode_lease); }
Result<LeaseRecord> decode_lease_record(ByteSpan bytes) { return value_of<LeaseRecord>(bytes, decode_lease); }
std::vector<Byte> encode_migration_record(const MigrationRecord& record) { return blob_of(record, encode_migration); }
Result<MigrationRecord> decode_migration_record(ByteSpan bytes) {
  return value_of<MigrationRecord>(bytes, decode_migration);
}
std::vector<Byte> encode_virtual_record(const VirtualAcceleratorRecord& record) {
  return blob_of(record, encode_virtual);
}
Result<VirtualAcceleratorRecord> decode_virtual_record(ByteSpan bytes) {
  return value_of<VirtualAcceleratorRecord>(bytes, decode_virtual);
}
std::vector<Byte> encode_policy_blob(const VirtualizationPolicy& policy) { return blob_of(policy, encode_policy); }
Result<VirtualizationPolicy> decode_policy_blob(ByteSpan bytes) {
  return value_of<VirtualizationPolicy>(bytes, decode_policy);
}
std::vector<Byte> encode_plan_blob(const MigrationPlan& plan) { return blob_of(plan, encode_migration_plan); }
Result<MigrationPlan> decode_plan_blob(ByteSpan bytes) {
  return value_of<MigrationPlan>(bytes, decode_migration_plan);
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------
namespace {

// Everything an operation needs in order to produce one deterministic decision
// record naming the generations that produced it.
struct OpContext {
  std::string operation{};
  RequestId request{};
  std::uint64_t session{0};
  CoordinatorEpoch epoch{};
  VirtualAcceleratorId virtual_id{};
  VirtualAcceleratorGeneration virtual_generation{};
  TenantId tenant{};
  TenantGeneration tenant_generation{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  LeaseId lease{};
  LeaseGeneration lease_generation{};
  PolicyGeneration policy_generation{};
  MigrationId migration{};
  MigrationGeneration migration_generation{};

  void adopt(const VirtualAcceleratorRecord& record) {
    virtual_id = record.id;
    virtual_generation = record.generation;
    tenant = record.owner;
    tenant_generation = record.owner_generation;
    backing = record.backing;
    backing_generation = record.backing_generation;
    physical = record.physical;
    physical_generation = record.physical_generation;
    migration = record.migration;
    migration_generation = record.migration_generation;
    policy_generation = record.policy_generation;
  }

  void adopt(const TenantRecord& record) {
    tenant = record.id;
    tenant_generation = record.generation;
  }

  void adopt(const LeaseRecord& record) {
    lease = record.id;
    lease_generation = record.generation;
    virtual_id = record.virtual_id;
    virtual_generation = record.virtual_generation;
    tenant = record.tenant;
    tenant_generation = record.tenant_generation;
    backing_generation = record.backing_generation;
    physical_generation = record.physical_generation;
    policy_generation = record.policy_generation;
  }
};

// Undo information for one operation. Recording the previous value of every
// touched entity is what allows the runtime to refuse a mutation whose durable
// write failed instead of reporting authority that a restart could not
// recover.
struct UndoLog {
  bool header{false};
  std::uint64_t next_sequence{0};
  CoordinatorEpoch epoch{};
  VirtualizationPolicy policy{};
  PolicyGeneration policy_generation{};
  AccountingCounters accounting{};

  std::set<TenantId> tenants;
  std::map<TenantId, TenantRecord> tenant_records;
  std::set<PhysicalDeviceId> physical;
  std::map<PhysicalDeviceId, PhysicalDeviceRecord> physical_records;
  std::set<BackingId> backings;
  std::map<BackingId, BackingRecord> backing_records;
  std::set<VirtualAcceleratorId> virtuals;
  std::map<VirtualAcceleratorId, VirtualAcceleratorRecord> virtual_records;
  std::set<LeaseId> leases;
  std::map<LeaseId, LeaseRecord> lease_records;
  std::set<BackingAssignmentId> assignments;
  std::map<BackingAssignmentId, BackingAssignment> assignment_records;
  std::set<MigrationId> migrations;
  std::map<MigrationId, MigrationRecord> migration_records;
  std::set<EvidenceId> evidence;
  std::map<EvidenceId, EvidenceRecord> evidence_records;

  std::size_t audit_size{0};
  std::size_t decision_size{0};
  std::size_t request_size{0};
};

struct ChangeAccumulator {
  bool header{false};
  std::set<TenantId> tenants;
  std::set<PhysicalDeviceId> physical;
  std::set<BackingId> backings;
  std::set<VirtualAcceleratorId> virtuals;
  std::set<LeaseId> leases;
  std::set<BackingAssignmentId> assignments;
  std::set<MigrationId> migrations;
  std::set<EvidenceId> evidence;
  std::vector<AuditEntry> audit;
  std::vector<Decision> decisions;
  std::vector<RequestOutcomeRecord> requests;

  void clear() {
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

  ChangeSet to_change_set() const {
    ChangeSet out;
    out.header = header;
    out.tenants.assign(tenants.begin(), tenants.end());
    out.physical.assign(physical.begin(), physical.end());
    out.backings.assign(backings.begin(), backings.end());
    out.virtuals.assign(virtuals.begin(), virtuals.end());
    out.leases.assign(leases.begin(), leases.end());
    out.assignments.assign(assignments.begin(), assignments.end());
    out.migrations.assign(migrations.begin(), migrations.end());
    out.evidence.assign(evidence.begin(), evidence.end());
    out.audit = audit;
    out.decisions = decisions;
    out.requests = requests;
    return out;
  }
};

// Projection input: the runtime derives the advertised virtual capability
// surface from the contract, the policy and (when a backing exists) the
// evidence-backed backing capabilities. A capability the runtime cannot prove
// stays UNKNOWN and is never upgraded.
struct ProjectionInput {
  const ResourceContract* contract{nullptr};
  const BackingRecord* backing{nullptr};
  const PhysicalDeviceRecord* physical{nullptr};
  const VirtualizationPolicy* policy{nullptr};
  std::uint64_t identity{0};
  CapabilityProjectionGeneration generation{};
};

void set_capability(CapabilitySurface& surface, CapabilityKey key, CapabilityVerdict verdict, std::uint64_t value,
                    std::string text, std::string provenance) {
  CapabilityEntry entry;
  entry.key = key;
  entry.verdict = verdict;
  entry.value = value;
  entry.text = std::move(text);
  entry.provenance = std::move(provenance);
  surface.set(std::move(entry));
}

CapabilityProjection build_projection(const ProjectionInput& input) {
  const ResourceContract& contract = *input.contract;
  const VirtualizationPolicy& policy = *input.policy;

  CapabilityProjection projection;
  projection.id = CapabilityProjectionId::from_value(input.identity);
  projection.generation = input.generation;
  projection.policy_generation = policy.generation;
  projection.contract_generation = contract.generation;
  projection.backing_generation = input.backing != nullptr ? input.backing->generation : BackingGeneration{};
  projection.physical_generation = input.physical != nullptr ? input.physical->generation : PhysicalDeviceGeneration{};
  projection.mechanism = input.backing != nullptr ? input.backing->mechanism : std::string{"unassigned"};

  CapabilitySurface& surface = projection.surface;

  set_capability(surface, CapabilityKey::MemoryBudgetBytes,
                 contract.memory_ceiling_bytes > 0 ? CapabilityVerdict::Constrained : CapabilityVerdict::Unknown,
                 contract.memory_ceiling_bytes, {}, "resource-contract");
  set_capability(surface, CapabilityKey::ComputeShareMilli,
                 contract.compute_share_milli > 0 ? CapabilityVerdict::Constrained : CapabilityVerdict::Unknown,
                 contract.compute_share_milli, {}, "resource-contract");
  set_capability(surface, CapabilityKey::MaxStreams,
                 contract.max_streams > 0 ? CapabilityVerdict::Constrained : CapabilityVerdict::Unknown,
                 contract.max_streams, {}, "resource-contract");
  set_capability(surface, CapabilityKey::MaxConcurrentKernels,
                 contract.max_concurrency > 0 ? CapabilityVerdict::Constrained : CapabilityVerdict::Unknown,
                 contract.max_concurrency, {}, "resource-contract");

  const std::string multiplexing_text =
      input.backing != nullptr ? std::string(multiplexing_name(input.backing->multiplexing))
                               : std::string("unassigned");
  set_capability(surface, CapabilityKey::VirtualizationMechanism, CapabilityVerdict::Supported, 0, multiplexing_text,
                 "virtualization-policy");
  set_capability(surface, CapabilityKey::ConcurrencyMode, CapabilityVerdict::Supported, 0, multiplexing_text,
                 "virtualization-policy");

  const bool migration_ok = contract.migration_allowed && policy.migration_allowed;
  set_capability(surface, CapabilityKey::MigrationSupport,
                 migration_ok ? CapabilityVerdict::Supported : CapabilityVerdict::Unsupported, 0, {}, "policy");
  if (!migration_ok) projection.unknown.push_back(CapabilityKey::MigrationSupport);

  if (input.backing != nullptr) {
    set_capability(surface, CapabilityKey::MemoryTotalBytes, CapabilityVerdict::Supported,
                   input.backing->capacity_bytes, {}, "backing-evidence");
    if (input.backing->compute_units > 0) {
      set_capability(surface, CapabilityKey::SmCount, CapabilityVerdict::Supported, input.backing->compute_units, {},
                     "backing-evidence");
    } else {
      set_capability(surface, CapabilityKey::SmCount, CapabilityVerdict::Unknown, 0, {}, "backing-evidence");
      projection.unknown.push_back(CapabilityKey::SmCount);
    }
    if (input.physical != nullptr) {
      if (input.physical->compute_capability_major > 0) {
        set_capability(surface, CapabilityKey::ComputeCapabilityMajor, CapabilityVerdict::Supported,
                       input.physical->compute_capability_major, {}, "physical-evidence");
        set_capability(surface, CapabilityKey::ComputeCapabilityMinor, CapabilityVerdict::Supported,
                       input.physical->compute_capability_minor, {}, "physical-evidence");
      } else {
        projection.unknown.push_back(CapabilityKey::ComputeCapabilityMajor);
        projection.unknown.push_back(CapabilityKey::ComputeCapabilityMinor);
      }
      if (!input.physical->architecture.empty()) {
        set_capability(surface, CapabilityKey::ArchitectureFamily, CapabilityVerdict::Supported, 0,
                       input.physical->architecture, "physical-evidence");
      } else {
        projection.unknown.push_back(CapabilityKey::ArchitectureFamily);
      }
    }
    // Backing-reported capabilities. A capability the backing reports as
    // UNKNOWN stays UNKNOWN and is recorded as unproven rather than advertised.
    for (const CapabilityEntry& entry : input.backing->capabilities.entries()) {
      if (policy.forbids_capability(entry.key)) {
        projection.hidden.push_back(entry.key);
        continue;
      }
      if (entry.verdict == CapabilityVerdict::Unknown) {
        projection.unknown.push_back(entry.key);
        set_capability(surface, entry.key, CapabilityVerdict::Unknown, 0, entry.text, entry.provenance);
        continue;
      }
      set_capability(surface, entry.key, entry.verdict, entry.value, entry.text, entry.provenance);
    }
    for (CapabilityKey key : policy.forbidden_capabilities) {
      if (surface.find(key) != nullptr) {
        CapabilitySurface rebuilt;
        for (const CapabilityEntry& entry : surface.entries()) {
          if (entry.key != key) rebuilt.set(entry);
        }
        surface = rebuilt;
        projection.hidden.push_back(key);
      }
    }
  } else {
    set_capability(surface, CapabilityKey::MemoryTotalBytes, CapabilityVerdict::Unknown, 0, {}, "no-backing");
    projection.unknown.push_back(CapabilityKey::MemoryTotalBytes);
    projection.unknown.push_back(CapabilityKey::ArchitectureFamily);
    projection.unknown.push_back(CapabilityKey::SmCount);
    projection.unknown.push_back(CapabilityKey::ComputeCapabilityMajor);
    projection.unknown.push_back(CapabilityKey::ComputeCapabilityMinor);
  }

  set_capability(surface, CapabilityKey::VendorVisible,
                 policy.transparency == BackingTransparency::Opaque ? CapabilityVerdict::Unsupported
                                                                    : CapabilityVerdict::Supported,
                 0, std::string(transparency_name(policy.transparency)), "virtualization-policy");
  projection.seal();
  return projection;
}

// Validates a backing against the policy, the contract and the isolation
// requirements. Returns the truthful reason a candidate backing is refused.
Status validate_backing_for(const BackingRecord& backing, const PhysicalDeviceRecord* physical,
                            const VirtualAcceleratorRecord& record, const VirtualizationPolicy& policy,
                            const VirtualizationState& state) {
  if (!policy.permits_backing_class(backing.klass)) {
    return Status(StatusCode::BackingClassNotAllowed,
                  std::string("policy does not allow backing class ") + std::string(backing_class_name(backing.klass)));
  }
  if (!record.contract.permits_backing_class(backing.klass)) {
    return Status(StatusCode::BackingClassNotAllowed,
                  std::string("resource contract does not allow backing class ") +
                      std::string(backing_class_name(backing.klass)));
  }
  if (!record.contract.permits_multiplexing(backing.multiplexing)) {
    return Status(StatusCode::ContractViolation,
                  std::string("resource contract does not allow multiplexing mode ") +
                      std::string(multiplexing_name(backing.multiplexing)));
  }
  if (backing.provenance == Provenance::Synthetic && !policy.synthetic_backing_allowed) {
    return Status(StatusCode::PolicyViolation, "policy does not allow synthetic backing");
  }
  if (backing.provenance == Provenance::Unsupported) {
    return Status(StatusCode::BackingUnavailable,
                  "backing provenance is UNSUPPORTED: this mechanism is not available on this host");
  }
  if (backing.capability_rank < record.contract.minimum_backing_rank) {
    return Status(StatusCode::CapabilityProjectionMismatch,
                  "backing rank " + std::to_string(backing.capability_rank) +
                      " is below the contract minimum of " + std::to_string(record.contract.minimum_backing_rank));
  }
  if (record.contract.exclusivity_required && !backing.exclusive) {
    return Status(StatusCode::ContractViolation,
                  "resource contract requires exclusivity but the backing is a shared mechanism");
  }
  if (!backing.available) {
    return Status(StatusCode::BackingUnavailable, "backing " + backing.id.str() + " is not currently available");
  }
  if (backing.exclusive && backing.assigned_to.valid() && backing.assigned_to != record.id) {
    return Status(StatusCode::BackingBusy, "backing " + backing.id.str() +
                                               " is an exclusive mechanism already assigned to virtual accelerator " +
                                               backing.assigned_to.str());
  }
  if (policy.tenant_sharing == TenantSharingPolicy::Exclusive && !backing.exclusive) {
    return Status(StatusCode::PolicyViolation,
                  "policy requires exclusive tenancy but the backing is a shared mechanism");
  }
  if (physical != nullptr && !physical->present) {
    return Status(StatusCode::BackingUnavailable, "physical device " + physical->id.str() +
                                                       " is not present according to the latest evidence");
  }
  if (!backing.evidence_fresh) {
    return Status(StatusCode::BackingUnavailable,
                  "backing evidence for " + backing.id.str() +
                      " is stale; the backing must be revalidated before it can be assigned");
  }

  std::vector<IsolationRequirement> requirements = record.contract.required_isolation;
  requirements.insert(requirements.end(), policy.required_isolation.begin(), policy.required_isolation.end());
  std::sort(requirements.begin(), requirements.end(),
            [](const IsolationRequirement& a, const IsolationRequirement& b) {
              return static_cast<std::uint8_t>(a.dimension) < static_cast<std::uint8_t>(b.dimension);
            });
  requirements.erase(std::unique(requirements.begin(), requirements.end(),
                                 [](const IsolationRequirement& a, const IsolationRequirement& b) {
                                   return a.dimension == b.dimension;
                                 }),
                     requirements.end());

  for (const IsolationRequirement& requirement : requirements) {
    const IsolationState have = backing.isolation.state_of(requirement.dimension);
    if (have == IsolationState::Unknown && requirement.minimum != IsolationState::Unknown) {
      return Status(StatusCode::IsolationUnknownMandatory,
                    std::string("required isolation dimension ") +
                        std::string(isolation_dimension_name(requirement.dimension)) +
                        " is UNKNOWN for this backing; an unproven dimension can never satisfy a requirement");
    }
    if (!isolation_state_at_least(have, requirement.minimum)) {
      return Status(StatusCode::IsolationUnsatisfied,
                    std::string("backing provides ") + std::string(isolation_state_name(have)) + " for " +
                        std::string(isolation_dimension_name(requirement.dimension)) + " but " +
                        std::string(isolation_state_name(requirement.minimum)) + " is required");
    }
  }

  if (record.contract.memory_ceiling_bytes > 0 && !record.contract.oversubscription_allowed &&
      !policy.oversubscription_allowed) {
    std::uint64_t committed = 0;
    for (const auto& entry : state.assignments) {
      const BackingAssignment& assignment = entry.second;
      if (assignment.backing != backing.id || !assignment.authoritative) continue;
      if (assignment.virtual_id == record.id) continue;
      const auto other = state.virtuals.find(assignment.virtual_id);
      if (other == state.virtuals.end()) continue;
      committed += other->second.contract.memory_ceiling_bytes;
    }
    if (record.contract.memory_ceiling_bytes > backing.capacity_bytes ||
        committed + record.contract.memory_ceiling_bytes > backing.capacity_bytes) {
      return Status(StatusCode::OversubscriptionDenied,
                    "committed virtual memory ceilings would exceed the physical capacity of backing " +
                        backing.id.str() + " and oversubscription is not enabled by policy or contract");
    }
  }
  return Status{};
}

}  // namespace

// ---------------------------------------------------------------------------
// Runtime implementation
// ---------------------------------------------------------------------------
struct VirtualizationRuntime::Impl {
  RuntimeOptions options;
  std::unique_ptr<DurableStore> store;
  std::shared_ptr<Clock> clock;

  mutable std::mutex mutex;
  VirtualizationState state{};
  ChangeAccumulator changes{};
  UndoLog undo{};

  // Agent sessions are process-local by construction: they are never durable.
  std::map<AgentId, AgentSession> agents;

  bool running{false};
  bool store_failed{false};
  Status store_failure{};

  Impl(RuntimeOptions runtime_options, std::unique_ptr<DurableStore> durable_store, std::shared_ptr<Clock> time)
      : options(std::move(runtime_options)), store(std::move(durable_store)), clock(std::move(time)) {}

  // ---- identity allocation ---------------------------------------------
  std::uint64_t next_id() {
    const std::uint64_t value = state.next_sequence;
    state.next_sequence = value + 1;
    changes.header = true;
    return value;
  }

  AgentId next_agent_id() { return AgentId::from_value(next_id()); }

  // ---- change tracking --------------------------------------------------
  void touch_header() { changes.header = true; }

  void touch_tenant(const TenantId& id) {
    if (undo.tenants.insert(id).second) {
      const auto it = state.tenants.find(id);
      if (it != state.tenants.end()) undo.tenant_records.emplace(id, it->second);
    }
    changes.tenants.insert(id);
  }
  void touch_physical(const PhysicalDeviceId& id) {
    if (undo.physical.insert(id).second) {
      const auto it = state.physical.find(id);
      if (it != state.physical.end()) undo.physical_records.emplace(id, it->second);
    }
    changes.physical.insert(id);
  }
  void touch_backing(const BackingId& id) {
    if (undo.backings.insert(id).second) {
      const auto it = state.backings.find(id);
      if (it != state.backings.end()) undo.backing_records.emplace(id, it->second);
    }
    changes.backings.insert(id);
  }
  void touch_virtual(const VirtualAcceleratorId& id) {
    if (undo.virtuals.insert(id).second) {
      const auto it = state.virtuals.find(id);
      if (it != state.virtuals.end()) undo.virtual_records.emplace(id, it->second);
    }
    changes.virtuals.insert(id);
  }
  void touch_lease(const LeaseId& id) {
    if (undo.leases.insert(id).second) {
      const auto it = state.leases.find(id);
      if (it != state.leases.end()) undo.lease_records.emplace(id, it->second);
    }
    changes.leases.insert(id);
  }
  void touch_assignment(const BackingAssignmentId& id) {
    if (undo.assignments.insert(id).second) {
      const auto it = state.assignments.find(id);
      if (it != state.assignments.end()) undo.assignment_records.emplace(id, it->second);
    }
    changes.assignments.insert(id);
  }
  void touch_migration(const MigrationId& id) {
    if (undo.migrations.insert(id).second) {
      const auto it = state.migrations.find(id);
      if (it != state.migrations.end()) undo.migration_records.emplace(id, it->second);
    }
    changes.migrations.insert(id);
  }
  void touch_evidence(const EvidenceId& id) {
    if (undo.evidence.insert(id).second) {
      const auto it = state.evidence.find(id);
      if (it != state.evidence.end()) undo.evidence_records.emplace(id, it->second);
    }
    changes.evidence.insert(id);
  }

  void begin_op() {
    changes.clear();
    undo = UndoLog{};
    undo.header = true;
    undo.next_sequence = state.next_sequence;
    undo.epoch = state.epoch;
    undo.policy = state.policy;
    undo.policy_generation = state.policy_generation;
    undo.accounting = state.accounting;
    undo.audit_size = state.audit.size();
    undo.decision_size = state.decisions.size();
    undo.request_size = state.requests.size();
  }

  template <class MapT, class IdT, class RecordT>
  static void restore_map(MapT& map, const std::set<IdT>& touched, const std::map<IdT, RecordT>& previous) {
    for (const IdT& id : touched) {
      const auto it = previous.find(id);
      if (it == previous.end()) {
        map.erase(id);
      } else {
        map[id] = it->second;
      }
    }
  }

  void rollback() {
    if (undo.header) {
      state.next_sequence = undo.next_sequence;
      state.epoch = undo.epoch;
      state.policy = undo.policy;
      state.policy_generation = undo.policy_generation;
      state.accounting = undo.accounting;
    }
    restore_map(state.tenants, undo.tenants, undo.tenant_records);
    restore_map(state.physical, undo.physical, undo.physical_records);
    restore_map(state.backings, undo.backings, undo.backing_records);
    restore_map(state.virtuals, undo.virtuals, undo.virtual_records);
    restore_map(state.leases, undo.leases, undo.lease_records);
    restore_map(state.assignments, undo.assignments, undo.assignment_records);
    restore_map(state.migrations, undo.migrations, undo.migration_records);
    restore_map(state.evidence, undo.evidence, undo.evidence_records);
    if (state.audit.size() > undo.audit_size) state.audit.resize(undo.audit_size);
    if (state.decisions.size() > undo.decision_size) state.decisions.resize(undo.decision_size);
    if (state.requests.size() > undo.request_size) state.requests.resize(undo.request_size);
    undo = UndoLog{};
    changes.clear();
  }

  // Mutate -> persist -> externally visible success. A durable write failure
  // rolls the mutation back and puts the runtime into a fail-stop state rather
  // than reporting authority that a restart could not recover.
  Status commit() {
    for (const AuditEntry& entry : changes.audit) state.audit.push_back(entry);
    while (state.audit.size() > AuditLog::kCapacity) state.audit.erase(state.audit.begin());
    for (const Decision& decision : changes.decisions) state.decisions.push_back(decision);
    while (state.decisions.size() > kDecisionCapacity) state.decisions.erase(state.decisions.begin());
    for (const RequestOutcomeRecord& record : changes.requests) state.requests.push_back(record);
    while (state.requests.size() > kRequestWindowCapacity) state.requests.erase(state.requests.begin());

    Status status{};
    if (options.persist && store != nullptr) {
      const ChangeSet change_set = changes.to_change_set();
      if (!change_set.empty()) status = store->apply(state, change_set);
    }
    if (!status.ok()) {
      store_failed = true;
      store_failure = status;
      rollback();
      return Status(status.code(), std::string("durable persistence failed: ") + status.to_string());
    }
    changes.clear();
    undo = UndoLog{};
    return Status{};
  }

  void record(const OpContext& context, StatusCode outcome, const std::string& reason, AuditKind kind) {
    const UnixMicros now = clock->now_micros();
    Decision decision;
    decision.id = DecisionId::from_value(next_id());
    decision.at = now;
    decision.operation = context.operation;
    decision.outcome = outcome;
    decision.reason = reason;
    decision.epoch = context.epoch;
    decision.virtual_id = context.virtual_id;
    decision.virtual_generation = context.virtual_generation;
    decision.tenant = context.tenant;
    decision.tenant_generation = context.tenant_generation;
    decision.backing = context.backing;
    decision.backing_generation = context.backing_generation;
    decision.physical = context.physical;
    decision.physical_generation = context.physical_generation;
    decision.lease = context.lease;
    decision.lease_generation = context.lease_generation;
    decision.policy_generation = context.policy_generation;
    decision.migration = context.migration;
    decision.migration_generation = context.migration_generation;
    decision.request = context.request;
    changes.decisions.push_back(std::move(decision));

    AuditEntry entry;
    entry.id = DecisionId::from_value(next_id());
    entry.at = now;
    entry.kind = kind;
    entry.operation = context.operation;
    entry.outcome = outcome;
    entry.detail = reason;
    entry.epoch = context.epoch;
    entry.virtual_id = context.virtual_id;
    entry.virtual_generation = context.virtual_generation;
    entry.tenant = context.tenant;
    entry.tenant_generation = context.tenant_generation;
    entry.backing = context.backing;
    entry.backing_generation = context.backing_generation;
    entry.migration = context.migration;
    entry.migration_generation = context.migration_generation;
    changes.audit.push_back(std::move(entry));
    touch_header();
  }

  void account_refusal(StatusCode code) {
    if (is_stale_code(code)) {
      state.accounting.stale_authority_refusals += 1;
      touch_header();
    } else if (is_authority_code(code)) {
      state.accounting.authority_refusals += 1;
      touch_header();
    }
    switch (code) {
      case StatusCode::ContractViolation:
      case StatusCode::ContractInvalid:
        state.accounting.contract_violation_refusals += 1;
        touch_header();
        break;
      case StatusCode::IsolationUnsatisfied:
      case StatusCode::IsolationUnknownMandatory:
        state.accounting.isolation_refusals += 1;
        touch_header();
        break;
      case StatusCode::CapabilityProjectionMismatch:
      case StatusCode::CapabilityUnknown:
        state.accounting.capability_refusals += 1;
        touch_header();
        break;
      case StatusCode::OversubscriptionDenied:
        state.accounting.oversubscription_denials += 1;
        touch_header();
        break;
      case StatusCode::InvalidTransition:
        state.accounting.lifecycle_refusals += 1;
        touch_header();
        break;
      case StatusCode::DuplicateRequest:
        state.accounting.duplicate_request_refusals += 1;
        touch_header();
        break;
      case StatusCode::ProtocolViolation:
      case StatusCode::MalformedFrame:
      case StatusCode::FrameTooLarge:
        state.accounting.protocol_violations += 1;
        touch_header();
        break;
      default:
        break;
    }
  }

  // Records the decision and the audit entry, then persists. Returns the
  // persistence failure when the durable write failed, otherwise the original
  // outcome.
  Status finalize(const OpContext& context, Status status, AuditKind kind) {
    if (!status.ok()) account_refusal(status.code());
    record(context, status.code(), status.detail(), kind);
    if (context.request.valid()) {
      changes.requests.push_back(RequestOutcomeRecord{context.request, context.session, context.operation,
                                                      status.code(), clock->now_micros()});
    }
    const Status persisted = commit();
    if (!persisted.ok()) return persisted;
    return status;
  }

  Status guard_store() {
    if (store_failed) {
      return Status(StatusCode::IoFailure,
                    std::string("durable store is unavailable; the coordinator refuses further mutations: ") +
                        store_failure.to_string());
    }
    return Status{};
  }

  // ---- authority validation --------------------------------------------
  Status check_epoch(const Authority& auth) const {
    if (!auth.epoch.has_value()) {
      return Status(StatusCode::InvalidArgument, "authority must carry the coordinator epoch");
    }
    if (*auth.epoch != state.epoch) {
      return Status(StatusCode::StaleEpoch, "presented coordinator epoch " + auth.epoch->str() +
                                                " is not the current epoch " + state.epoch.str());
    }
    return Status{};
  }

  Status check_policy(const Authority& auth) const {
    if (!auth.policy_generation.has_value()) return Status{};
    if (*auth.policy_generation != state.policy_generation) {
      return Status(StatusCode::StalePolicy, "presented policy generation " + auth.policy_generation->str() +
                                                 " is not the current generation " +
                                                 state.policy_generation.str());
    }
    return Status{};
  }

  Status check_request(const Authority& auth, const std::string& operation) const {
    if (!auth.request.has_value()) return Status{};
    const std::uint64_t session = auth.session.value_or(0);
    for (const RequestOutcomeRecord& record : state.requests) {
      if (record.request == *auth.request && record.session == session) {
        return Status(StatusCode::DuplicateRequest,
                      "request " + auth.request->str() + " in session " + std::to_string(session) +
                          " was already processed as '" + record.operation + "' with outcome " +
                          std::string(code_name(record.outcome)));
      }
    }
    (void)operation;
    return Status{};
  }

  Result<TenantRecord*> resolve_tenant(const Authority& auth) {
    if (!auth.tenant.has_value()) {
      return Status(StatusCode::InvalidArgument, "authority must carry a tenant identity");
    }
    const auto it = state.tenants.find(*auth.tenant);
    if (it == state.tenants.end()) {
      return Status(StatusCode::NotFound, "tenant " + auth.tenant->str() + " is not known");
    }
    if (!auth.tenant_generation.has_value()) {
      return Status(StatusCode::InvalidArgument, "authority must carry the tenant generation");
    }
    if (*auth.tenant_generation != it->second.generation) {
      return Status(StatusCode::StaleTenant, "presented tenant generation " + auth.tenant_generation->str() +
                                                 " is not the current generation " +
                                                 it->second.generation.str() + " for tenant " + it->first.str());
    }
    return &it->second;
  }

  Result<VirtualAcceleratorRecord*> resolve_virtual(const Authority& auth) {
    if (!auth.virtual_id.has_value()) {
      return Status(StatusCode::InvalidArgument, "authority must carry a virtual accelerator identity");
    }
    const auto it = state.virtuals.find(*auth.virtual_id);
    if (it == state.virtuals.end()) {
      return Status(StatusCode::NotFound, "virtual accelerator " + auth.virtual_id->str() + " is not known");
    }
    if (!auth.virtual_generation.has_value()) {
      return Status(StatusCode::InvalidArgument,
                    "authority must carry the virtual accelerator generation for this operation");
    }
    if (*auth.virtual_generation != it->second.generation) {
      return Status(StatusCode::StaleVirtualGeneration,
                    "presented virtual generation " + auth.virtual_generation->str() +
                        " is not the current generation " + it->second.generation.str() + " for " + it->first.str());
    }
    return &it->second;
  }

  Status require_mutable(const VirtualAcceleratorRecord& record) const {
    if (record.state == VirtualLifecycleState::Retired) {
      return Status(StatusCode::VirtualRetired, "virtual accelerator " + record.id.str() + " is retired");
    }
    if (record.state == VirtualLifecycleState::Fenced) {
      return Status(StatusCode::VirtualFenced, "virtual accelerator " + record.id.str() + " is fenced");
    }
    return Status{};
  }

  Status require_owner(const VirtualAcceleratorRecord& record, const TenantRecord& tenant) const {
    if (record.owner != tenant.id) {
      return Status(StatusCode::NotAuthorized,
                    "tenant " + tenant.id.str() + " does not own virtual accelerator " + record.id.str());
    }
    if (record.owner_generation != tenant.generation) {
      return Status(StatusCode::StaleTenant, "virtual accelerator " + record.id.str() +
                                                 " is bound to tenant generation " + record.owner_generation.str() +
                                                 " but tenant " + tenant.id.str() + " is at generation " +
                                                 tenant.generation.str());
    }
    if (tenant.fenced) {
      return Status(StatusCode::TenantFenced, "tenant " + tenant.id.str() + " is fenced: " + tenant.fence_reason);
    }
    return Status{};
  }

  // Fences every live lease of a virtual accelerator and keeps the virtual,
  // tenant and global attachment accounting closed. Every path that drops
  // attachment authority goes through here.
  std::uint32_t fence_leases(VirtualAcceleratorRecord& record, const std::string& reason, UnixMicros now) {
    std::uint32_t live = 0;
    for (LeaseId lease_id : record.leases) {
      auto lease = state.leases.find(lease_id);
      if (lease == state.leases.end() || !lease_state_is_live(lease->second.state)) continue;
      touch_lease(lease_id);
      lease->second.state = LeaseState::Fenced;
      lease->second.revoked_at = now;
      lease->second.reason = reason;
      ++live;
    }
    if (live == 0) return 0;
    touch_virtual(record.id);
    record.active_attachments = 0;
    const auto tenant = state.tenants.find(record.owner);
    if (tenant != state.tenants.end()) {
      touch_tenant(tenant->first);
      tenant->second.active_attachments =
          tenant->second.active_attachments >= live ? tenant->second.active_attachments - live : 0;
      tenant->second.updated_at = now;
    }
    state.accounting.leases_fenced += live;
    state.accounting.attachments_active =
        state.accounting.attachments_active >= live ? state.accounting.attachments_active - live : 0;
    touch_header();
    return live;
  }

  // Always touch before mutating: the undo log must capture the pre-mutation
  // value, or a rolled-back operation would restore the mutated record.
  Status transition(VirtualAcceleratorRecord& record, VirtualLifecycleState target, std::string reason) {
    const Status legal = check_transition(record.state, target);
    if (!legal.ok()) {
      return Status(legal.code(), legal.detail() + " for virtual accelerator " + record.id.str());
    }
    const bool keeps_leases = lifecycle_allows_leases(record.state) && lifecycle_allows_leases(target);
    touch_virtual(record.id);
    record.state = target;
    record.state_generation = record.state_generation.next();
    record.state_reason = std::move(reason);
    record.generation = record.generation.next();
    record.updated_at = clock->now_micros();
    if (keeps_leases) {
      // Attached -> Active and Active -> Draining keep the backing and the
      // attachments; the live leases are carried forward to the new generation
      // instead of being invalidated by a step the tenant did not take.
      for (LeaseId lease_id : record.leases) {
        auto lease = state.leases.find(lease_id);
        if (lease == state.leases.end() || !lease_state_is_live(lease->second.state)) continue;
        touch_lease(lease_id);
        lease->second.virtual_generation = record.generation;
      }
    }
    return Status{};
  }

  void rebuild_projection(VirtualAcceleratorRecord& record) {
    ProjectionInput input;
    input.contract = &record.contract;
    input.policy = &state.policy;
    input.identity = next_id();
    input.generation = record.projection.generation.valid() ? record.projection.generation.next()
                                                            : CapabilityProjectionGeneration::initial();
    const auto backing_it = state.backings.find(record.backing);
    if (backing_it != state.backings.end()) {
      input.backing = &backing_it->second;
      const auto physical_it = state.physical.find(backing_it->second.physical);
      if (physical_it != state.physical.end()) input.physical = &physical_it->second;
    }
    record.projection = build_projection(input);
    // The projection is bound to the virtual accelerator's *binding*
    // generation, not to the backing object's own revision.
    record.projection.backing_generation = record.backing_generation;
    record.projection.physical_generation = record.physical_generation;
    record.projection.seal();
  }

  // Recomputes the counters that are derived from the records. Used wherever an
  // operation drops authority in bulk, so the accounting can never drift from
  // the state it describes.
  void recompute_derived_accounting() {
    std::uint64_t active = 0;
    std::uint64_t attachments = 0;
    std::uint64_t bytes = 0;
    for (const auto& entry : state.virtuals) {
      const VirtualAcceleratorRecord& record = entry.second;
      if (record.state != VirtualLifecycleState::Retired && record.state != VirtualLifecycleState::Suspended &&
          record.state != VirtualLifecycleState::Fenced) {
        ++active;
      }
      attachments += record.active_attachments;
      bytes += record.allocated_bytes;
    }
    state.accounting.virtual_active = active;
    state.accounting.attachments_active = attachments;
    state.accounting.bytes_allocated_current = bytes;
    touch_header();
  }

  // Shared by register_physical and refresh_physical. Callers hold the mutex.
  Result<PhysicalDeviceRecord> do_register_physical(const Authority& auth, AgentId agent, AgentBootId boot,
                                                    const PhysicalDeviceDescriptor& descriptor);
  // Shared by assign_backing and replace_backing. Callers hold the mutex.
  Result<BackingAssignment> do_assign_backing(const Authority& auth, OpContext& context, BackingId backing,
                                              bool replacing, std::string reason);
  // Recovery classification. The caller holds the mutex.
  Status do_classify_recovered_migrations();
};

// ---------------------------------------------------------------------------
// Free helpers used by the public surface
// ---------------------------------------------------------------------------
namespace {

struct MigrationCapability {
  bool supported{false};
  MigrationClass klass{MigrationClass::Unsupported};
  std::string reason{};
};

// The migration classes this runtime genuinely implements. Identity continuity
// is not state continuity: REBIND_ONLY keeps the virtual identity and moves no
// execution or memory state, and DRAIN_AND_RESTART additionally requires the
// caller to stop and restart. Anything that would need real state movement is
// reported as unsupported rather than implied.
MigrationCapability migration_capability(const VirtualizationPolicy& policy, const ResourceContract& contract) {
  MigrationCapability capability;
  if (!policy.migration_allowed) {
    capability.reason = "migration is disabled by the virtualization policy";
    return capability;
  }
  if (!contract.migration_allowed) {
    capability.reason = "migration is disabled by the resource contract";
    return capability;
  }
  const std::vector<MigrationClass> implemented = {MigrationClass::RebindOnly, MigrationClass::DrainAndRestart};
  bool any_allowed = false;
  for (MigrationClass klass : implemented) {
    if (policy.permits_migration_class(klass) && contract.permits_migration_class(klass)) {
      any_allowed = true;
      capability.klass = klass;
    }
  }
  if (!any_allowed) {
    capability.reason =
        "no implemented migration class is permitted; this runtime implements REBIND_ONLY and DRAIN_AND_RESTART only "
        "and never claims state transfer it does not perform";
    capability.klass = MigrationClass::Unsupported;
    return capability;
  }
  capability.supported = true;
  capability.reason = "identity continuity without execution-state or memory-state movement";
  return capability;
}

Status plan_staleness(const MigrationRecord& migration, const VirtualAcceleratorRecord& record,
                      const VirtualizationState& state) {
  const MigrationPlan& plan = migration.plan;
  if (plan.epoch != state.epoch) {
    return Status(StatusCode::StaleEpoch, "migration plan was built under coordinator epoch " + plan.epoch.str() +
                                              " but the current epoch is " + state.epoch.str());
  }
  if (plan.policy_generation != state.policy_generation) {
    return Status(StatusCode::StalePolicy, "migration plan was built under policy generation " +
                                               plan.policy_generation.str() + " but the current generation is " +
                                               state.policy_generation.str());
  }
  if (plan.virtual_generation != record.generation) {
    return Status(StatusCode::StaleMigration, "migration plan targets virtual generation " +
                                                  plan.virtual_generation.str() + " but " + record.id.str() +
                                                  " is at generation " + record.generation.str());
  }
  if (plan.contract_generation != record.contract.generation) {
    return Status(StatusCode::StaleMigration, "migration plan targets resource contract generation " +
                                                  plan.contract_generation.str() + " but the current generation is " +
                                                  record.contract.generation.str());
  }
  // Before the cutover the source must still be the virtual accelerator's
  // binding. After it the destination is, so the source comparison no longer
  // applies; the plan's own generation checks still guard the drift.
  if (!migration_state_after_cutover(migration.state) &&
      (plan.source_backing != record.backing || plan.source_backing_generation != record.backing_generation)) {
    return Status(StatusCode::StaleBacking, "migration plan source binding has changed");
  }
  const auto source = state.backings.find(plan.source_backing);
  if (source == state.backings.end()) {
    return Status(StatusCode::StaleBacking, "migration plan source backing no longer exists");
  }
  if (source->second.generation != plan.source_backing_generation) {
    return Status(StatusCode::StaleBacking, "migration plan source backing generation " +
                                                plan.source_backing_generation.str() +
                                                " is not the current generation " + source->second.generation.str());
  }
  const auto destination = state.backings.find(plan.destination_backing);
  if (destination == state.backings.end()) {
    return Status(StatusCode::StaleBacking, "migration plan destination backing no longer exists");
  }
  if (destination->second.generation != plan.destination_backing_generation) {
    return Status(StatusCode::StaleBacking, "migration plan destination backing generation " +
                                                plan.destination_backing_generation.str() +
                                                " is not the current generation " +
                                                destination->second.generation.str());
  }
  const auto tenant = state.tenants.find(plan.tenant);
  if (tenant == state.tenants.end()) {
    return Status(StatusCode::StaleTenant, "migration plan tenant no longer exists");
  }
  if (tenant->second.generation != plan.tenant_generation) {
    return Status(StatusCode::StaleTenant, "migration plan tenant generation " + plan.tenant_generation.str() +
                                               " is not the current generation " + tenant->second.generation.str());
  }
  return Status{};
}

VirtualView make_view(const VirtualizationState& state, const VirtualAcceleratorRecord& record,
                      const Authority& auth) {
  VirtualView view;
  view.id = record.id;
  view.generation = record.generation;
  view.name = record.name;
  view.state = record.state;
  view.state_generation = record.state_generation;
  view.state_reason = record.state_reason;
  view.owner = record.owner;
  view.owner_generation = record.owner_generation;
  view.owner_is_caller = auth.tenant.has_value() && *auth.tenant == record.owner;
  view.contract = record.contract;
  view.projection = record.projection;
  view.multiplexing = record.multiplexing;
  view.isolation_class = record.isolation_class;
  view.transparency = state.policy.transparency;
  view.active_attachments = record.active_attachments;
  view.allocated_bytes = record.allocated_bytes;
  view.created_at = record.created_at;
  view.updated_at = record.updated_at;
  view.backing_class = record.backing_class;
  view.backing_mechanism = record.projection.mechanism;

  const MigrationCapability capability = migration_capability(state.policy, record.contract);
  view.migration_supported = capability.supported;
  view.migration_class = capability.supported ? capability.klass : MigrationClass::Unsupported;
  const auto active_migration = state.migrations.find(record.migration);
  view.has_active_migration = record.migration.valid() && active_migration != state.migrations.end() &&
                              !migration_state_is_terminal(active_migration->second.state);

  switch (state.policy.transparency) {
    case BackingTransparency::Opaque:
      view.backing_disclosed = false;
      break;
    case BackingTransparency::Summary:
      view.backing_disclosed = true;
      view.backing_generation = record.backing_generation;
      view.physical_generation = record.physical_generation;
      break;
    case BackingTransparency::Full:
      view.backing_disclosed = true;
      view.backing = record.backing;
      view.backing_generation = record.backing_generation;
      view.physical = record.physical;
      view.physical_generation = record.physical_generation;
      break;
  }
  const auto backing = state.backings.find(record.backing);
  if (backing != state.backings.end()) {
    view.backing_provenance = backing->second.provenance;
    view.backing_mechanism = backing->second.mechanism;
    if (state.policy.transparency == BackingTransparency::Full) {
      const auto physical = state.physical.find(backing->second.physical);
      if (physical != state.physical.end()) {
        view.physical_stable_key = physical->second.stable_key;
        view.physical_model = physical->second.model;
      }
    }
  } else {
    view.backing_provenance = Provenance::Unknown;
  }
  if (auth.lease.has_value()) {
    const auto lease = state.leases.find(*auth.lease);
    if (lease != state.leases.end() && lease->second.virtual_id == record.id) {
      view.attached_to_caller = lease_state_is_live(lease->second.state);
      view.caller_lease = lease->second.id;
      view.caller_lease_generation = lease->second.generation;
    }
  }
  return view;
}

}  // namespace

// ---------------------------------------------------------------------------
// Runtime lifecycle
// ---------------------------------------------------------------------------
VirtualizationRuntime::VirtualizationRuntime(RuntimeOptions options, std::unique_ptr<DurableStore> store,
                                            std::shared_ptr<Clock> clock)
    : impl_(std::make_unique<Impl>(std::move(options), std::move(store),
                                   clock != nullptr ? clock : std::make_shared<SystemClock>())) {}

VirtualizationRuntime::~VirtualizationRuntime() {
  if (impl_ != nullptr && impl_->running) {
    const Status ignored = shutdown();
    (void)ignored;
  }
}

Status VirtualizationRuntime::start() {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (impl.running) return Status{};

  if (impl.store != nullptr) {
    const Status opened = impl.store->open();
    if (!opened.ok()) return opened;
  }

  impl.begin_op();
  OpContext context;
  context.operation = "coordinator_start";

  bool recovered = false;
  if (impl.store != nullptr) {
    recovered = impl.store->present();
    auto loaded = impl.store->load();
    if (!loaded.ok()) {
      impl.rollback();
      return Status(loaded.status().code(), std::string("recovery failed: ") + loaded.status().to_string());
    }
    impl.state = loaded.take();
  }

  if (!impl.state.epoch.valid()) {
    impl.state.epoch = CoordinatorEpoch::initial();
  } else if (recovered) {
    // A restart always advances the coordinator epoch. Process-local authority
    // from the previous epoch can never be reused.
    impl.state.epoch = impl.state.epoch.next();
  }
  impl.state.schema = schema_version();
  context.epoch = impl.state.epoch;

  if (!impl.state.policy_generation.valid()) {
    impl.state.policy = VirtualizationPolicy::default_policy();
    impl.state.policy.id = PolicyId::from_value(impl.next_id());
    impl.state.policy.generation = PolicyGeneration::initial();
    impl.state.policy_generation = impl.state.policy.generation;
  } else if (impl.state.policy.id.value() == 0) {
    impl.state.policy.id = PolicyId::from_value(impl.next_id());
    impl.state.policy.generation = impl.state.policy_generation;
  }
  impl.state.accounting.coordinator_boots += 1;
  impl.touch_header();

  if (recovered) {
    const UnixMicros now = impl.clock->now_micros();
    // Sessions and leases are process-local authority: they never survive.
    for (auto& entry : impl.state.leases) {
      LeaseRecord& lease = entry.second;
      if (!lease_state_is_live(lease.state)) continue;
      impl.touch_lease(lease.id);
      lease.state = LeaseState::Expired;
      lease.revoked_at = now;
      lease.reason = "coordinator restart advanced the epoch; process-local lease authority is not restored";
      impl.state.accounting.leases_fenced += 1;
      impl.touch_header();
    }
    for (auto& entry : impl.state.virtuals) {
      VirtualAcceleratorRecord& record = entry.second;
      if (record.active_attachments != 0) {
        impl.touch_virtual(record.id);
        record.active_attachments = 0;
      }
      if (record.state == VirtualLifecycleState::Attached || record.state == VirtualLifecycleState::Active ||
          record.state == VirtualLifecycleState::Draining) {
        impl.touch_virtual(record.id);
        record.state = VirtualLifecycleState::Provisioned;
        record.state_generation = record.state_generation.next();
        record.state_reason = "coordinator restart invalidated process-local attachment authority";
        record.generation = record.generation.next();
        record.updated_at = now;
      }
    }
    for (auto& entry : impl.state.tenants) {
      TenantRecord& tenant = entry.second;
      if (tenant.active_attachments != 0) {
        impl.touch_tenant(tenant.id);
        tenant.active_attachments = 0;
        tenant.updated_at = now;
      }
    }
    // Dynamic backing evidence is refreshed rather than trusted.
    for (auto& entry : impl.state.backings) {
      BackingRecord& backing = entry.second;
      impl.touch_backing(backing.id);
      backing.available = false;
      backing.evidence_fresh = false;
    }
    for (auto& entry : impl.state.physical) {
      PhysicalDeviceRecord& physical = entry.second;
      impl.touch_physical(physical.id);
      physical.present = false;
    }
    // The replay window belongs to the sessions of the previous process. Those
    // sessions are gone and the epoch fences everything they could present, so
    // the window is cleared rather than carried into a new session namespace
    // where every small request identity would look like a replay.
    if (!impl.state.requests.empty()) {
      impl.state.requests.clear();
      impl.touch_header();
    }
    impl.recompute_derived_accounting();
    impl.touch_header();
    impl.record(context, StatusCode::Ok, "coordinator restarted under epoch " + impl.state.epoch.str(),
                AuditKind::Recovery);
  } else {
    impl.record(context, StatusCode::Ok, "coordinator started with empty durable state", AuditKind::Recovery);
  }

  const Status persisted = impl.commit();
  if (!persisted.ok()) return persisted;

  if (recovered) {
    const Status classified = impl.do_classify_recovered_migrations();
    if (!classified.ok()) return classified;
    const Status valid = validate_state(impl.state);
    if (!valid.ok()) {
      return Status(valid.code(), std::string("recovered state is not trustworthy: ") + valid.to_string());
    }
  }

  if (impl.store != nullptr) {
    const Status compacted = impl.store->compact(impl.state);
    if (!compacted.ok()) return compacted;
  }
  impl.running = true;
  return Status{};
}

Status VirtualizationRuntime::shutdown() {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (!impl.running) return Status{};  // idempotent

  OpContext context;
  context.operation = "coordinator_shutdown";
  context.epoch = impl.state.epoch;
  impl.begin_op();

  const UnixMicros now = impl.clock->now_micros();
  for (auto& entry : impl.state.leases) {
    LeaseRecord& lease = entry.second;
    if (!lease_state_is_live(lease.state)) continue;
    impl.touch_lease(lease.id);
    lease.state = LeaseState::Fenced;
    lease.revoked_at = now;
    lease.reason = "coordinator shutdown revoked process-local authority";
    impl.state.accounting.leases_fenced += 1;
    impl.touch_header();
  }
  for (auto& entry : impl.state.virtuals) {
    VirtualAcceleratorRecord& record = entry.second;
    if (record.active_attachments != 0) {
      impl.touch_virtual(record.id);
      record.active_attachments = 0;
    }
    if (record.state == VirtualLifecycleState::Attached || record.state == VirtualLifecycleState::Active ||
        record.state == VirtualLifecycleState::Draining) {
      impl.touch_virtual(record.id);
      record.state = VirtualLifecycleState::Provisioned;
      record.state_generation = record.state_generation.next();
      record.state_reason = "coordinator shutdown released attachment authority";
      record.generation = record.generation.next();
      record.updated_at = now;
    }
  }
  for (auto& entry : impl.state.tenants) {
    if (entry.second.active_attachments != 0) {
      impl.touch_tenant(entry.second.id);
      entry.second.active_attachments = 0;
    }
  }
  impl.recompute_derived_accounting();
  impl.touch_header();
  impl.record(context, StatusCode::Ok, "coordinator shut down", AuditKind::Mutation);

  Status result = impl.commit();
  if (result.ok() && impl.store != nullptr) {
    result = impl.store->compact(impl.state);
    const Status closed = impl.store->close();
    if (result.ok()) result = closed;
  }
  impl.agents.clear();
  impl.running = false;
  return result;
}

bool VirtualizationRuntime::running() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->running;
}

CoordinatorEpoch VirtualizationRuntime::epoch() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->state.epoch;
}

PolicyGeneration VirtualizationRuntime::policy_generation() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->state.policy_generation;
}

const RuntimeOptions& VirtualizationRuntime::options() const { return impl_->options; }

std::shared_ptr<Clock> VirtualizationRuntime::clock() const { return impl_->clock; }

Authority VirtualizationRuntime::current_authority() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  Authority auth;
  auth.epoch = impl_->state.epoch;
  auth.policy_generation = impl_->state.policy_generation;
  return auth;
}

Authority VirtualizationRuntime::virtual_authority(VirtualAcceleratorId id,
                                                   VirtualAcceleratorGeneration generation) const {
  Authority auth = current_authority();
  auth.virtual_id = id;
  auth.virtual_generation = generation;
  return auth;
}

Result<std::unique_ptr<VirtualizationRuntime>> make_runtime(RuntimeOptions runtime_options,
                                                            StoreOptions store_options,
                                                            std::shared_ptr<Clock> clock) {
  std::unique_ptr<DurableStore> store;
  if (store_options.enabled && !store_options.directory.empty()) {
    store = make_file_store(std::move(store_options));
  } else {
    store = make_memory_store();
  }
  auto runtime =
      std::make_unique<VirtualizationRuntime>(std::move(runtime_options), std::move(store), std::move(clock));
  const Status started = runtime->start();
  if (!started.ok()) return started;
  return runtime;
}

// ---------------------------------------------------------------------------
// Agents and physical devices
// ---------------------------------------------------------------------------
Result<AgentSession> VirtualizationRuntime::register_agent(std::string name, std::string endpoint,
                                                           std::uint64_t connection_id, AgentId requested) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (name.empty()) return Status(StatusCode::InvalidArgument, "agent name must not be empty");
  if (name.size() > 128) return Status(StatusCode::InvalidArgument, "agent name is longer than 128 bytes");

  AgentId id = requested;
  if (!id.valid()) id = impl.next_agent_id();
  if (impl.agents.find(id) != impl.agents.end() && impl.agents[id].connected) {
    return Status(StatusCode::AlreadyExists, "agent " + id.str() + " already has a live session");
  }

  AgentSession session;
  session.id = id;
  // A fresh boot identity every time an agent process connects. The previous
  // boot identity can never be reused to continue mutations.
  session.boot = AgentBootId::from_value(impl.next_id());
  session.name = std::move(name);
  session.endpoint = std::move(endpoint);
  session.connected = true;
  session.connected_at = impl.clock->now_micros();
  session.last_seen = session.connected_at;
  session.connection_id = connection_id;
  impl.agents[id] = session;
  impl.state.accounting.agent_boots += 1;
  impl.begin_op();
  impl.touch_header();
  const Status persisted = impl.commit();
  if (!persisted.ok()) return persisted;
  return session;
}

Status VirtualizationRuntime::agent_heartbeat(AgentId id, AgentBootId boot) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  const auto it = impl.agents.find(id);
  if (it == impl.agents.end()) return Status(StatusCode::NotFound, "agent " + id.str() + " is not known");
  if (it->second.boot != boot) {
    return Status(StatusCode::StaleAgentBoot, "presented agent boot " + boot.str() +
                                                  " is not the current boot " + it->second.boot.str() +
                                                  " for agent " + id.str());
  }
  if (!it->second.connected) {
    return Status(StatusCode::NotAttached, "agent " + id.str() + " has no live session");
  }
  it->second.last_seen = impl.clock->now_micros();
  return Status{};
}

Status VirtualizationRuntime::agent_disconnected(AgentId id, AgentBootId boot) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  const auto it = impl.agents.find(id);
  if (it == impl.agents.end()) return Status(StatusCode::NotFound, "agent " + id.str() + " is not known");
  if (it->second.boot != boot) {
    return Status(StatusCode::StaleAgentBoot,
                  "presented agent boot does not match the live session for agent " + id.str());
  }
  it->second.connected = false;
  return Status{};
}

std::vector<AgentSession> VirtualizationRuntime::list_agents() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<AgentSession> out;
  out.reserve(impl_->agents.size());
  for (const auto& entry : impl_->agents) out.push_back(entry.second);
  return out;
}

Result<AgentSession> VirtualizationRuntime::find_agent(AgentId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->agents.find(id);
  if (it == impl_->agents.end()) return Status(StatusCode::NotFound, "agent " + id.str() + " is not known");
  return it->second;
}

namespace {

// A stable physical identity must never be an enumeration ordinal, a device
// index or a process id: those values are reused and would resurrect stale
// virtual authority.
Status validate_stable_key(std::string_view key) {
  if (key.empty()) return Status(StatusCode::InvalidArgument, "physical device stable key must not be empty");
  if (key.size() > 256) {
    return Status(StatusCode::InvalidArgument, "physical device stable key is longer than 256 bytes");
  }
  bool all_digits = true;
  for (char c : key) {
    if (c < '0' || c > '9') {
      all_digits = false;
      break;
    }
  }
  if (all_digits) {
    return Status(StatusCode::InvalidArgument,
                  "physical device stable key '" + std::string(key) +
                      "' is a bare ordinal; stable identity must not be an enumeration index");
  }
  return Status{};
}

bool same_physical_identity(const PhysicalDeviceRecord& record, const PhysicalDeviceDescriptor& descriptor) {
  return record.vendor == descriptor.vendor && record.model == descriptor.model &&
         record.memory_total_bytes == descriptor.memory_total_bytes &&
         record.architecture == descriptor.architecture;
}

}  // namespace

Result<PhysicalDeviceRecord> VirtualizationRuntime::register_physical(const Authority& auth, AgentId agent,
                                                                     AgentBootId boot,
                                                                     const PhysicalDeviceDescriptor& descriptor) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  return impl.do_register_physical(auth, agent, boot, descriptor);
}

Result<PhysicalDeviceRecord> VirtualizationRuntime::Impl::do_register_physical(
    const Authority& auth, AgentId agent, AgentBootId boot, const PhysicalDeviceDescriptor& descriptor) {
  auto& impl = *this;
  OpContext ctx;
  ctx.operation = "register_physical";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  if (status.ok()) status = validate_stable_key(descriptor.stable_key);
  const auto session = impl.agents.find(agent);
  if (status.ok() && session == impl.agents.end()) {
    status = Status(StatusCode::NotFound, "agent " + agent.str() + " is not registered");
  }
  if (status.ok() && session->second.boot != boot) {
    status = Status(StatusCode::StaleAgentBoot, "presented agent boot " + boot.str() +
                                                    " is not the live boot " + session->second.boot.str() +
                                                    " for agent " + agent.str());
  }
  if (status.ok() && !session->second.connected) {
    status = Status(StatusCode::ConnectionLost, "agent " + agent.str() + " has no live session");
  }
  if (status.ok() && descriptor.provenance == Provenance::Unknown) {
    status = Status(StatusCode::InvalidArgument, "physical device descriptor must declare its provenance");
  }
  if (status.ok()) {
    for (const BackingDescriptor& backing : descriptor.backings) {
      if (backing.klass == BackingClass::Unknown) {
        status = Status(StatusCode::InvalidArgument, "backing descriptor must declare its class");
        break;
      }
      const Provenance expected = class_native_provenance(backing.klass);
      // UNSUPPORTED may name a real mechanism: it means "this mechanism exists
      // in the world but is not available on this host". SYNTHETIC is never
      // allowed to name a real mechanism.
      const bool consistent = expected == descriptor.provenance ||
                              (descriptor.provenance == Provenance::Unsupported && expected == Provenance::Real) ||
                              (descriptor.provenance == Provenance::Synthetic && expected == Provenance::Synthetic);
      if (!consistent) {
        status = Status(StatusCode::IntegrityFailure,
                        std::string("backing class ") + std::string(backing_class_name(backing.klass)) + " is " +
                            std::string(provenance_name(expected)) + " but the device declares " +
                            std::string(provenance_name(descriptor.provenance)) +
                            "; SYNTHETIC mechanisms are never relabelled REAL");
        break;
      }
      if (backing.isolation.empty()) {
        status = Status(StatusCode::InvalidArgument,
                        "backing descriptor must carry an isolation claim for every dimension");
        break;
      }
    }
  }
  if (status.ok() && impl.state.physical.size() >= kMaxPhysicalDevices) {
    status = Status(StatusCode::LimitExceeded, "physical device registry is full");
  }

  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  PhysicalDeviceRecord* target = nullptr;
  bool generation_changed = false;
  for (auto& entry : impl.state.physical) {
    if (entry.second.stable_key == descriptor.stable_key) {
      target = &entry.second;
      break;
    }
  }
  if (target == nullptr) {
    PhysicalDeviceRecord record;
    record.id = PhysicalDeviceId::from_value(impl.next_id());
    record.generation = PhysicalDeviceGeneration::initial();
    record.stable_key = descriptor.stable_key;
    impl.touch_physical(record.id);
    auto inserted = impl.state.physical.emplace(record.id, record);
    target = &inserted.first->second;
  } else {
    generation_changed = !same_physical_identity(*target, descriptor);
    impl.touch_physical(target->id);
    if (generation_changed) target->generation = target->generation.next();
  }

  target->agent = agent;
  target->boot = boot;
  target->vendor = descriptor.vendor;
  target->model = descriptor.model;
  target->driver_version = descriptor.driver_version;
  target->architecture = descriptor.architecture;
  target->provenance = descriptor.provenance;
  target->memory_total_bytes = descriptor.memory_total_bytes;
  target->compute_units = descriptor.compute_units;
  target->compute_capability_major = descriptor.compute_capability_major;
  target->compute_capability_minor = descriptor.compute_capability_minor;
  target->mechanism = descriptor.mechanism;
  target->hardware_partition_capable = descriptor.hardware_partition_capable;
  target->virtual_function_capable = descriptor.virtual_function_capable;
  target->mig_capable = descriptor.mig_capable;
  if (target->registered_at == 0) target->registered_at = now;
  target->evidence_at = now;
  target->present = true;
  target->evidence = EvidenceId::from_value(impl.next_id());
  target->evidence_generation = EvidenceGeneration::initial();

  ctx.physical = target->id;
  ctx.physical_generation = target->generation;

  EvidenceRecord evidence;
  evidence.id = target->evidence;
  evidence.generation = target->evidence_generation;
  evidence.kind = generation_changed ? EvidenceKind::DeviceDiscovery : EvidenceKind::CapabilityQuery;
  evidence.provenance = descriptor.provenance;
  evidence.agent = agent;
  evidence.boot = boot;
  evidence.physical = target->id;
  evidence.physical_generation = target->generation;
  evidence.produced_at = now;
  evidence.mechanism = descriptor.mechanism;
  evidence.detail = descriptor.vendor + " " + descriptor.model;
  evidence.payload_fingerprint = Fnv1a64::compute(descriptor.vendor + "|" + descriptor.model + "|" +
                                                  std::to_string(descriptor.memory_total_bytes));
  impl.touch_evidence(evidence.id);
  impl.state.evidence[evidence.id] = evidence;
  impl.state.accounting.evidence_records += 1;

  // Materialise backings for this device. A backing that already exists is
  // refreshed, never duplicated.
  for (const BackingDescriptor& source : descriptor.backings) {
    BackingRecord* backing = nullptr;
    for (auto& entry : impl.state.backings) {
      if (entry.second.physical == target->id && entry.second.label == source.label) {
        backing = &entry.second;
        break;
      }
    }
    if (backing == nullptr) {
      BackingRecord record;
      record.id = BackingId::from_value(impl.next_id());
      record.generation = BackingGeneration::initial();
      record.physical = target->id;
      record.label = source.label;
      impl.touch_backing(record.id);
      auto inserted = impl.state.backings.emplace(record.id, record);
      backing = &inserted.first->second;
      target->backings.push_back(backing->id);
      std::sort(target->backings.begin(), target->backings.end());
    } else {
      impl.touch_backing(backing->id);
      backing->generation = backing->generation.next();
    }
    backing->physical_generation = target->generation;
    backing->klass = source.klass;
    backing->provenance = descriptor.provenance;
    backing->mechanism = source.mechanism;
    backing->multiplexing = source.multiplexing == MultiplexingMode::None ? default_multiplexing_for(source.klass)
                                                                        : source.multiplexing;
    backing->isolation_class = source.isolation_class;
    backing->isolation = IsolationProfile{};
    for (const IsolationClaim& claim : source.isolation) backing->isolation.set(claim);
    backing->capabilities = source.capabilities;
    backing->capacity_bytes = source.capacity_bytes;
    backing->compute_units = source.compute_units;
    backing->capability_rank = backing_class_rank(source.klass);
    backing->evidence = target->evidence;
    backing->evidence_generation = target->evidence_generation;
    backing->evidence_at = now;
    backing->evidence_fresh = true;
    backing->available = true;
    backing->exclusive = source.exclusive;
    backing->externally_lifecycle_managed = source.externally_lifecycle_managed;
    backing->external_partition_ref = source.external_partition_ref;
  }

  if (!generation_changed) {
    // Same device, fresh evidence: previously assigned backings become usable
    // again, but every virtual accelerator still has to re-attach because the
    // coordinator epoch advanced.
    for (BackingId id : target->backings) {
      const auto it = impl.state.backings.find(id);
      if (it == impl.state.backings.end()) continue;
      impl.touch_backing(id);
      it->second.available = true;
      it->second.evidence_fresh = true;
      it->second.evidence_at = now;
      it->second.evidence = target->evidence;
      it->second.evidence_generation = target->evidence_generation;
    }
  } else {
    // A different device now occupies the same identity slot. Every backing of
    // the previous device loses its evidence and any binding is invalidated.
    for (BackingId id : target->backings) {
      const auto it = impl.state.backings.find(id);
      if (it == impl.state.backings.end()) continue;
      const auto assignment = impl.state.assignments.find(it->second.active_assignment);
      if (assignment != impl.state.assignments.end() && assignment->second.authoritative) {
        impl.touch_assignment(assignment->first);
        assignment->second.authoritative = false;
        assignment->second.state = AssignmentState::Revoked;
        assignment->second.revoked_at = now;
        assignment->second.reason = "the physical device generation changed under this backing";
        impl.state.accounting.backing_revocations += 1;
        const auto holder = impl.state.virtuals.find(assignment->second.virtual_id);
        if (holder != impl.state.virtuals.end() &&
            holder->second.state != VirtualLifecycleState::Retired) {
          impl.touch_virtual(holder->first);
          holder->second.state = VirtualLifecycleState::RecoveryRequired;
          holder->second.state_generation = holder->second.state_generation.next();
          holder->second.state_reason =
              "the physical device generation changed; the binding must be re-established";
          holder->second.generation = holder->second.generation.next();
          holder->second.updated_at = now;
        }
      }
      impl.touch_backing(id);
      it->second.assigned_to = VirtualAcceleratorId{};
      it->second.active_assignment = BackingAssignmentId{};
    }
  }
  impl.state.accounting.physical_registered += 1;
  impl.touch_header();

  const PhysicalDeviceRecord result = *target;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return result;
}

Result<PhysicalDeviceRecord> VirtualizationRuntime::refresh_physical(const Authority& auth, PhysicalDeviceId id,
                                                                    PhysicalDeviceGeneration generation,
                                                                    const PhysicalDeviceDescriptor& descriptor) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  const auto it = impl.state.physical.find(id);
  if (it == impl.state.physical.end()) {
    return Status(StatusCode::NotFound, "physical device " + id.str() + " is not known");
  }
  if (it->second.generation != generation) {
    return Status(StatusCode::StalePhysicalDevice, "presented physical generation " + generation.str() +
                                                       " is not the current generation " +
                                                       it->second.generation.str() + " for " + id.str());
  }
  return impl.do_register_physical(auth, it->second.agent, it->second.boot, descriptor);
}

Result<PhysicalDeviceRecord> VirtualizationRuntime::get_physical(PhysicalDeviceId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.physical.find(id);
  if (it == impl_->state.physical.end()) {
    return Status(StatusCode::NotFound, "physical device " + id.str() + " is not known");
  }
  return it->second;
}

std::vector<PhysicalDeviceRecord> VirtualizationRuntime::list_physical() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<PhysicalDeviceRecord> out;
  out.reserve(impl_->state.physical.size());
  for (const auto& entry : impl_->state.physical) out.push_back(entry.second);
  return out;
}

Status VirtualizationRuntime::physical_lost(PhysicalDeviceId id, PhysicalDeviceGeneration generation,
                                            std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "physical_lost";
  ctx.epoch = impl.state.epoch;
  impl.begin_op();

  Status status = impl.guard_store();
  const auto it = impl.state.physical.find(id);
  if (status.ok() && it == impl.state.physical.end()) {
    status = Status(StatusCode::NotFound, "physical device " + id.str() + " is not known");
  }
  if (status.ok() && it->second.generation != generation) {
    status = Status(StatusCode::StalePhysicalDevice, "presented physical generation " + generation.str() +
                                                         " is not the current generation " +
                                                         it->second.generation.str());
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  ctx.physical = id;
  ctx.physical_generation = generation;
  impl.touch_physical(id);
  it->second.present = false;

  for (BackingId backing_id : it->second.backings) {
    auto backing = impl.state.backings.find(backing_id);
    if (backing == impl.state.backings.end()) continue;
    impl.touch_backing(backing_id);
    backing->second.available = false;
    backing->second.evidence_fresh = false;
    if (!backing->second.assigned_to.valid()) continue;

    const VirtualAcceleratorId holder = backing->second.assigned_to;
    auto virtual_it = impl.state.virtuals.find(holder);
    if (virtual_it == impl.state.virtuals.end()) continue;
    VirtualAcceleratorRecord& record = virtual_it->second;
    impl.touch_virtual(holder);
    if (record.state == VirtualLifecycleState::Attached || record.state == VirtualLifecycleState::Active ||
        record.state == VirtualLifecycleState::Draining) {
      record.state = VirtualLifecycleState::RecoveryRequired;
      record.state_generation = record.state_generation.next();
      record.state_reason = "backing device disappeared: " + reason;
      record.generation = record.generation.next();
      record.updated_at = now;
    }
    impl.fence_leases(record, "backing device disappeared: " + reason, now);
    if (record.assignment.valid()) {
      auto assignment = impl.state.assignments.find(record.assignment);
      if (assignment != impl.state.assignments.end() && assignment->second.authoritative) {
        impl.touch_assignment(assignment->first);
        assignment->second.authoritative = false;
        assignment->second.state = AssignmentState::Revoked;
        assignment->second.revoked_at = now;
        assignment->second.reason = "physical device disappeared";
        impl.state.accounting.backing_revocations += 1;
      }
    }
    backing->second.assigned_to = VirtualAcceleratorId{};
    backing->second.active_assignment = BackingAssignmentId{};
  }
  for (auto& entry : impl.state.tenants) {
    TenantRecord& tenant = entry.second;
    std::uint32_t live = 0;
    for (VirtualAcceleratorId owned : tenant.owned) {
      const auto record = impl.state.virtuals.find(owned);
      if (record == impl.state.virtuals.end()) continue;
      live += record->second.active_attachments;
    }
    if (live != tenant.active_attachments) {
      impl.touch_tenant(tenant.id);
      tenant.active_attachments = live;
      tenant.updated_at = now;
    }
  }
  impl.state.accounting.physical_lost += 1;
  impl.recompute_derived_accounting();
  impl.touch_header();
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  return persisted;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------
Result<VirtualizationPolicy> VirtualizationRuntime::set_policy(const Authority& auth, VirtualizationPolicy policy) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "set_policy";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  ctx.policy_generation = impl.state.policy_generation;
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  if (status.ok()) {
    policy.normalize();
    status = policy.validate();
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  impl.touch_header();
  VirtualizationPolicy updated = policy;
  updated.id = PolicyId::from_value(impl.next_id());
  updated.generation = impl.state.policy_generation.next();
  impl.state.policy = updated;
  impl.state.policy_generation = updated.generation;
  impl.state.accounting.policy_updates += 1;

  // Derived authority does not survive a policy change: leases were granted
  // under the previous generation and are fenced, and every virtual
  // accelerator is revalidated against the new policy.
  for (auto& entry : impl.state.leases) {
    LeaseRecord& lease = entry.second;
    if (!lease_state_is_live(lease.state)) continue;
    impl.touch_lease(lease.id);
    lease.state = LeaseState::Superseded;
    lease.revoked_at = now;
    lease.reason = "policy generation advanced to " + updated.generation.str();
    impl.state.accounting.leases_fenced += 1;
  }
  for (auto& entry : impl.state.virtuals) {
    VirtualAcceleratorRecord& record = entry.second;
    if (record.state == VirtualLifecycleState::Retired) continue;
    impl.touch_virtual(record.id);
    if (record.active_attachments != 0) record.active_attachments = 0;
    if (record.state == VirtualLifecycleState::Attached || record.state == VirtualLifecycleState::Active ||
        record.state == VirtualLifecycleState::Draining) {
      record.state = VirtualLifecycleState::Provisioned;
      record.state_generation = record.state_generation.next();
      record.state_reason = "policy generation advanced; authority must be re-established";
      record.generation = record.generation.next();
      record.updated_at = now;
    }
    record.policy_generation = updated.generation;

    bool backing_ok = true;
    const auto backing = impl.state.backings.find(record.backing);
    if (backing != impl.state.backings.end()) {
      const auto physical = impl.state.physical.find(backing->second.physical);
      backing_ok = validate_backing_for(backing->second,
                                        physical != impl.state.physical.end() ? &physical->second : nullptr,
                                        record, updated, impl.state)
                       .ok();
    }
    if (!backing_ok) {
      if (record.assignment.valid()) {
        auto assignment = impl.state.assignments.find(record.assignment);
        if (assignment != impl.state.assignments.end() && assignment->second.authoritative) {
          impl.touch_assignment(assignment->first);
          assignment->second.authoritative = false;
          assignment->second.state = AssignmentState::Revoked;
          assignment->second.revoked_at = now;
          assignment->second.reason = "policy generation advanced and the backing no longer satisfies the contract";
          impl.state.accounting.backing_revocations += 1;
        }
      }
      if (backing != impl.state.backings.end()) {
        impl.touch_backing(backing->first);
        backing->second.assigned_to = VirtualAcceleratorId{};
        backing->second.active_assignment = BackingAssignmentId{};
      }
      record.assignment = BackingAssignmentId{};
      record.state = VirtualLifecycleState::RecoveryRequired;
      record.state_generation = record.state_generation.next();
      record.state_reason = "policy generation advanced; the current backing no longer satisfies the new policy";
      record.generation = record.generation.next();
      record.updated_at = now;
    }
    // The capability projection is generation-bound to the policy, so it is
    // rebuilt on both branches.
    impl.rebuild_projection(record);
  }
  for (auto& entry : impl.state.tenants) {
    if (entry.second.active_attachments != 0) {
      impl.touch_tenant(entry.second.id);
      entry.second.active_attachments = 0;
      entry.second.updated_at = now;
    }
  }
  impl.recompute_derived_accounting();
  impl.touch_header();
  ctx.policy_generation = updated.generation;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return updated;
}

VirtualizationPolicy VirtualizationRuntime::policy() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->state.policy;
}

// ---------------------------------------------------------------------------
// Tenancy
// ---------------------------------------------------------------------------
Result<TenantRecord> VirtualizationRuntime::create_tenant(const Authority& auth, std::string name,
                                                         std::string external_subject) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "create_tenant";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  if (status.ok() && name.empty()) status = Status(StatusCode::InvalidArgument, "tenant name must not be empty");
  if (status.ok() && name.size() > 256) {
    status = Status(StatusCode::InvalidArgument, "tenant name is longer than 256 bytes");
  }
  if (status.ok() && external_subject.size() > 512) {
    status = Status(StatusCode::InvalidArgument, "external subject is longer than 512 bytes");
  }
  if (status.ok() && impl.state.tenants.size() >= impl.state.policy.max_tenants) {
    status = Status(StatusCode::LimitExceeded, "tenant count has reached the policy maximum of " +
                                                   std::to_string(impl.state.policy.max_tenants));
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  TenantRecord record;
  record.id = TenantId::from_value(impl.next_id());
  record.generation = TenantGeneration::initial();
  record.name = std::move(name);
  record.external_subject = std::move(external_subject);
  record.created_at = impl.clock->now_micros();
  record.updated_at = record.created_at;
  impl.touch_tenant(record.id);
  impl.state.tenants[record.id] = record;
  ctx.adopt(record);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return record;
}

Result<TenantRecord> VirtualizationRuntime::get_tenant(TenantId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.tenants.find(id);
  if (it == impl_->state.tenants.end()) return Status(StatusCode::NotFound, "tenant " + id.str() + " is not known");
  return it->second;
}

std::vector<TenantRecord> VirtualizationRuntime::list_tenants() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<TenantRecord> out;
  out.reserve(impl_->state.tenants.size());
  for (const auto& entry : impl_->state.tenants) out.push_back(entry.second);
  return out;
}

Status VirtualizationRuntime::fence_tenant(const Authority& auth, TenantId id, TenantGeneration generation,
                                           std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "fence_tenant";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  const auto it = impl.state.tenants.find(id);
  if (status.ok() && it == impl.state.tenants.end()) {
    status = Status(StatusCode::NotFound, "tenant " + id.str() + " is not known");
  }
  if (status.ok() && it->second.generation != generation) {
    status = Status(StatusCode::StaleTenant, "presented tenant generation " + generation.str() +
                                                 " is not the current generation " + it->second.generation.str());
  }
  if (status.ok() && it->second.fenced) {
    status = Status(StatusCode::TenantFenced, "tenant " + id.str() + " is already fenced");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  impl.touch_tenant(id);
  it->second.fenced = true;
  it->second.fence_reason = reason;
  it->second.generation = it->second.generation.next();
  it->second.updated_at = now;

  // A fenced tenant retains no live mutation authority anywhere.
  for (VirtualAcceleratorId owned : it->second.owned) {
    auto record = impl.state.virtuals.find(owned);
    if (record == impl.state.virtuals.end()) continue;
    impl.touch_virtual(owned);
    record->second.owner_generation = it->second.generation;
    impl.fence_leases(record->second, "tenant " + id.str() + " was fenced", now);
    if (record->second.state == VirtualLifecycleState::Attached ||
        record->second.state == VirtualLifecycleState::Active ||
        record->second.state == VirtualLifecycleState::Draining) {
      record->second.state = VirtualLifecycleState::Fenced;
      record->second.state_generation = record->second.state_generation.next();
      record->second.state_reason = "owning tenant " + id.str() + " was fenced";
      record->second.generation = record->second.generation.next();
      record->second.updated_at = now;
    }
  }
  it->second.active_attachments = 0;
  impl.recompute_derived_accounting();
  ctx.adopt(it->second);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  return persisted;
}

Result<TenantRecord> VirtualizationRuntime::transfer_ownership(const Authority& auth, TenantId new_owner,
                                                              TenantGeneration new_owner_generation) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "transfer_ownership";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  auto destination = impl.state.tenants.find(new_owner);
  if (status.ok() && destination == impl.state.tenants.end()) {
    status = Status(StatusCode::NotFound, "destination tenant " + new_owner.str() + " is not known");
  }
  if (status.ok() && destination->second.generation != new_owner_generation) {
    status = Status(StatusCode::StaleTenant, "presented destination tenant generation " +
                                                 new_owner_generation.str() + " is not the current generation " +
                                                 destination->second.generation.str());
  }
  if (status.ok() && destination->second.fenced) {
    status = Status(StatusCode::TenantFenced, "destination tenant " + new_owner.str() + " is fenced");
  }
  if (status.ok() && new_owner == record.value()->owner) {
    status = Status(StatusCode::Conflict, "virtual accelerator is already owned by that tenant");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& target = *record.value();
  TenantRecord& source = *tenant.value();
  TenantRecord& dest = destination->second;
  ctx.adopt(target);

  // Ownership transfer invalidates every lease granted to the previous owner.
  impl.fence_leases(target, "ownership transferred to tenant " + new_owner.str(), now);
  source.owned.erase(std::remove(source.owned.begin(), source.owned.end(), target.id), source.owned.end());
  source.active_attachments = 0;
  source.updated_at = now;
  impl.touch_tenant(source.id);

  dest.owned.push_back(target.id);
  std::sort(dest.owned.begin(), dest.owned.end());
  dest.updated_at = now;
  impl.touch_tenant(dest.id);

  impl.touch_virtual(target.id);
  target.owner = dest.id;
  target.owner_generation = dest.generation;
  target.active_attachments = 0;
  if (target.state == VirtualLifecycleState::Attached || target.state == VirtualLifecycleState::Active ||
      target.state == VirtualLifecycleState::Draining) {
    target.state = VirtualLifecycleState::Provisioned;
    target.state_generation = target.state_generation.next();
    target.state_reason = "ownership transferred; attachments were released";
  }
  target.generation = target.generation.next();
  target.updated_at = now;
  const TenantRecord updated_owner = dest;
  ctx.adopt(target);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return updated_owner;
}

// ---------------------------------------------------------------------------
// Virtual accelerator lifecycle
// ---------------------------------------------------------------------------
Result<VirtualAcceleratorRecord> VirtualizationRuntime::create_virtual(const Authority& auth, std::string name,
                                                                      TenantId owner,
                                                                      TenantGeneration owner_generation,
                                                                      ResourceContract contract) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "create_virtual";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  const auto tenant = impl.state.tenants.find(owner);
  if (status.ok() && tenant == impl.state.tenants.end()) {
    status = Status(StatusCode::NotFound, "tenant " + owner.str() + " is not known");
  }
  if (status.ok() && tenant->second.generation != owner_generation) {
    status = Status(StatusCode::StaleTenant, "presented owner generation " + owner_generation.str() +
                                                 " is not the current generation " +
                                                 tenant->second.generation.str() + " for tenant " + owner.str());
  }
  if (status.ok() && tenant->second.fenced) {
    status = Status(StatusCode::TenantFenced, "tenant " + owner.str() + " is fenced: " + tenant->second.fence_reason);
  }
  if (status.ok() && name.empty()) {
    status = Status(StatusCode::InvalidArgument, "virtual accelerator name must not be empty");
  }
  if (status.ok() && name.size() > 256) {
    status = Status(StatusCode::InvalidArgument, "virtual accelerator name is longer than 256 bytes");
  }
  contract.normalize();
  if (status.ok()) status = contract.validate();
  if (status.ok() && contract.memory_ceiling_bytes > impl.state.policy.max_memory_ceiling_bytes) {
    status = Status(StatusCode::PolicyViolation, "contract memory ceiling " +
                                                     std::to_string(contract.memory_ceiling_bytes) +
                                                     " exceeds the policy maximum of " +
                                                     std::to_string(impl.state.policy.max_memory_ceiling_bytes));
  }
  if (status.ok() && contract.compute_share_milli > impl.state.policy.max_compute_share_milli) {
    status = Status(StatusCode::PolicyViolation, "contract compute share exceeds the policy maximum");
  }
  if (status.ok() && impl.state.virtuals.size() >= impl.state.policy.max_virtual_accelerators) {
    status = Status(StatusCode::LimitExceeded, "virtual accelerator count has reached the policy maximum of " +
                                                   std::to_string(impl.state.policy.max_virtual_accelerators));
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord record;
  record.id = VirtualAcceleratorId::from_value(impl.next_id());
  record.generation = VirtualAcceleratorGeneration::initial();
  record.name = std::move(name);
  record.owner = owner;
  record.owner_generation = owner_generation;
  record.contract = contract;
  record.contract.id = ResourceContractId::from_value(impl.next_id());
  record.contract.generation = ResourceContractGeneration::initial();
  record.policy_generation = impl.state.policy_generation;
  record.epoch = impl.state.epoch;
  record.created_at = now;
  record.updated_at = now;
  record.state = VirtualLifecycleState::Provisioned;
  record.state_generation = VirtualAcceleratorGeneration::initial();
  record.state_reason = "provisioned with resource contract and capability projection";
  impl.touch_virtual(record.id);
  impl.rebuild_projection(record);
  impl.state.virtuals[record.id] = record;

  TenantRecord& tenant_record = tenant->second;
  impl.touch_tenant(tenant_record.id);
  tenant_record.owned.push_back(record.id);
  std::sort(tenant_record.owned.begin(), tenant_record.owned.end());
  tenant_record.updated_at = now;

  impl.state.accounting.virtual_created += 1;
  impl.state.accounting.virtual_active += 1;
  impl.touch_header();
  ctx.adopt(record);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return record;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::update_contract(const Authority& auth,
                                                                       ResourceContract contract) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "update_contract";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok()) status = impl.require_mutable(*record.value());
  contract.normalize();
  if (status.ok()) status = contract.validate();
  if (status.ok() && contract.memory_ceiling_bytes > impl.state.policy.max_memory_ceiling_bytes) {
    status = Status(StatusCode::PolicyViolation, "contract memory ceiling exceeds the policy maximum");
  }
  if (status.ok() && contract.compute_share_milli > impl.state.policy.max_compute_share_milli) {
    status = Status(StatusCode::PolicyViolation, "contract compute share exceeds the policy maximum");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  VirtualAcceleratorRecord& target = *record.value();
  ctx.adopt(target);
  // The replacement contract must remain satisfiable by the current backing: a
  // virtual accelerator may never advertise a stronger contract than its
  // backing mechanism can honour.
  const auto backing = impl.state.backings.find(target.backing);
  if (backing != impl.state.backings.end()) {
    const auto physical = impl.state.physical.find(backing->second.physical);
    VirtualAcceleratorRecord probe = target;
    probe.contract = contract;
    probe.contract.id = ResourceContractId::from_value(impl.next_id());
    probe.contract.generation = target.contract.generation.next();
    const Status compatible =
        validate_backing_for(backing->second,
                             physical != impl.state.physical.end() ? &physical->second : nullptr, probe,
                             impl.state.policy, impl.state);
    if (!compatible.ok()) {
      const Status persisted = impl.finalize(ctx, compatible, AuditKind::AuthorityRefusal);
      return persisted.ok() ? compatible : persisted;
    }
  }

  const UnixMicros now = impl.clock->now_micros();
  impl.touch_virtual(target.id);
  target.contract = contract;
  target.contract.id = ResourceContractId::from_value(impl.next_id());
  target.contract.generation = target.contract.generation.next();
  target.generation = target.generation.next();
  target.updated_at = now;
  impl.rebuild_projection(target);
  ctx.adopt(target);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return target;
}

namespace {

template <class ImplT>
Status simple_transition(ImplT& impl, const Authority& auth, OpContext& ctx, VirtualLifecycleState target,
                         const std::string& reason, AuditKind kind) {
  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok()) status = impl.require_mutable(*record.value());
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  const Status transitioned = impl.transition(value, target, reason);
  if (!transitioned.ok()) {
    const Status persisted = impl.finalize(ctx, transitioned, AuditKind::AuthorityRefusal);
    return persisted.ok() ? transitioned : persisted;
  }
  ctx.adopt(value);
  const Status persisted = impl.finalize(ctx, Status{}, kind);
  return persisted;
}

}  // namespace

Result<VirtualAcceleratorRecord> VirtualizationRuntime::activate(const Authority& auth) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "activate";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok()) status = impl.require_mutable(*record.value());
  if (status.ok()) {
    VirtualAcceleratorRecord& value = *record.value();
    if (value.state == VirtualLifecycleState::Active) {
      status = Status(StatusCode::InvalidTransition,
                      "virtual accelerator " + value.id.str() + " is already Active");
    } else if (value.state != VirtualLifecycleState::Attached) {
      status = Status(StatusCode::NotAttached,
                      "virtual accelerator " + value.id.str() + " is " + std::string(lifecycle_name(value.state)) +
                          "; activation requires an attachment");
    } else if (!value.backing.valid()) {
      status = Status(StatusCode::BackingUnavailable,
                      "virtual accelerator " + value.id.str() + " has no authoritative backing");
    } else {
      const auto assignment = impl.state.assignments.find(value.assignment);
      if (assignment == impl.state.assignments.end() || !assignment->second.authoritative) {
        status = Status(StatusCode::BackingUnavailable,
                        "virtual accelerator " + value.id.str() + " has no authoritative backing assignment");
      } else {
        const auto backing = impl.state.backings.find(value.backing);
        if (backing == impl.state.backings.end() || !backing->second.available) {
          status =
              Status(StatusCode::BackingUnavailable, "backing " + value.backing.str() + " is not currently available");
        }
      }
    }
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  status = impl.transition(value, VirtualLifecycleState::Active, "activated");
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  impl.recompute_derived_accounting();
  ctx.adopt(value);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::LifecycleChange);
  if (!persisted.ok()) return persisted;
  return value;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::drain(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "drain";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();
  const Status status =
      simple_transition(impl, auth, ctx, VirtualLifecycleState::Draining, reason, AuditKind::LifecycleChange);
  if (!status.ok()) return status;
  const auto record = impl.state.virtuals.find(ctx.virtual_id);
  if (record == impl.state.virtuals.end()) return Status(StatusCode::NotFound, "virtual accelerator disappeared");
  return record->second;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::resolve_recovery(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "resolve_recovery";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();
  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok() && record.value()->state != VirtualLifecycleState::RecoveryRequired) {
    status = Status(StatusCode::InvalidTransition, "virtual accelerator is " +
                                                       std::string(lifecycle_name(record.value()->state)) +
                                                       " and is not in RecoveryRequired");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  status = impl.transition(value, VirtualLifecycleState::Suspended, reason);
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  ctx.adopt(value);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::LifecycleChange);
  if (!persisted.ok()) return persisted;
  return value;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::suspend(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "suspend";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok()) status = impl.require_mutable(*record.value());
  if (status.ok()) {
    VirtualAcceleratorRecord& value = *record.value();
    if (value.active_attachments != 0) {
      status = Status(StatusCode::Draining, "virtual accelerator " + value.id.str() + " still holds " +
                                                std::to_string(value.active_attachments) +
                                                " active attachment(s); detach or revoke first");
    } else if (value.state != VirtualLifecycleState::Provisioned &&
               value.state != VirtualLifecycleState::Draining) {
      status = Status(StatusCode::InvalidTransition,
                      "virtual accelerator " + value.id.str() + " is " +
                          std::string(lifecycle_name(value.state)) + "; suspend requires Provisioned or Draining");
    } else if (!value.assignment.valid() && value.state != VirtualLifecycleState::Draining) {
      // Suspension means "deliberately without an authoritative backing", so
      // there must be a binding to release.
      status = Status(StatusCode::InvalidTransition,
                      "virtual accelerator " + value.id.str() +
                          " holds no authoritative backing assignment to release");
    }
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  // Suspend is deliberately the no-backing mode: it releases the authoritative
  // assignment instead of pretending to keep it.
  if (value.assignment.valid()) {
    auto assignment = impl.state.assignments.find(value.assignment);
    if (assignment != impl.state.assignments.end() && assignment->second.authoritative) {
      impl.touch_assignment(assignment->first);
      assignment->second.authoritative = false;
      assignment->second.state = AssignmentState::Revoked;
      assignment->second.revoked_at = now;
      assignment->second.reason = "virtual accelerator suspended: " + reason;
      impl.state.accounting.backing_revocations += 1;
    }
  }
  auto backing = impl.state.backings.find(value.backing);
  if (backing != impl.state.backings.end()) {
    impl.touch_backing(backing->first);
    backing->second.assigned_to = VirtualAcceleratorId{};
    backing->second.active_assignment = BackingAssignmentId{};
  }
  impl.touch_virtual(value.id);
  for (BackingHistoryEntry& entry : value.backing_history) entry.current = false;
  value.assignment = BackingAssignmentId{};
  value.backing = BackingId{};
  value.backing_class = BackingClass::Unknown;
  value.multiplexing = MultiplexingMode::None;
  value.isolation_class = IsolationClass::Unknown;
  value.isolation = IsolationProfile{};
  impl.rebuild_projection(value);
  status = impl.transition(value, VirtualLifecycleState::Suspended, reason);
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  impl.recompute_derived_accounting();
  ctx.adopt(value);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::LifecycleChange);
  if (!persisted.ok()) return persisted;
  return value;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::resume(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "resume";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();
  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok() && record.value()->state != VirtualLifecycleState::Suspended) {
    status = Status(StatusCode::InvalidTransition, "resume requires the Suspended state");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  status = impl.transition(value, VirtualLifecycleState::Provisioned, reason);
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  impl.recompute_derived_accounting();
  ctx.adopt(value);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::LifecycleChange);
  if (!persisted.ok()) return persisted;
  return value;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::fence_virtual(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "fence_virtual";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok() && record.value()->state == VirtualLifecycleState::Retired) {
    status = Status(StatusCode::VirtualRetired, "retired virtual accelerators cannot be fenced again");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  impl.fence_leases(value, "virtual accelerator fenced: " + reason, now);
  impl.touch_virtual(value.id);
  status = impl.transition(value, VirtualLifecycleState::Fenced, reason);
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  impl.recompute_derived_accounting();
  ctx.adopt(value);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::LifecycleChange);
  if (!persisted.ok()) return persisted;
  return value;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::retire_virtual(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "retire_virtual";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok() && record.value()->state == VirtualLifecycleState::Retired) {
    status = Status(StatusCode::VirtualRetired, "virtual accelerator is already retired");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  impl.fence_leases(value, "virtual accelerator retired", now);
  TenantRecord& owner = impl.state.tenants[value.owner];
  impl.touch_tenant(owner.id);
  owner.owned.erase(std::remove(owner.owned.begin(), owner.owned.end(), value.id), owner.owned.end());

  if (value.assignment.valid()) {
    auto assignment = impl.state.assignments.find(value.assignment);
    if (assignment != impl.state.assignments.end() && assignment->second.authoritative) {
      impl.touch_assignment(assignment->first);
      assignment->second.authoritative = false;
      assignment->second.state = AssignmentState::Revoked;
      assignment->second.revoked_at = now;
      assignment->second.reason = "virtual accelerator retired";
      impl.state.accounting.backing_revocations += 1;
    }
  }
  auto backing = impl.state.backings.find(value.backing);
  if (backing != impl.state.backings.end()) {
    impl.touch_backing(backing->first);
    backing->second.assigned_to = VirtualAcceleratorId{};
    backing->second.active_assignment = BackingAssignmentId{};
  }
  impl.touch_virtual(value.id);
  for (BackingHistoryEntry& entry : value.backing_history) {
    entry.current = false;
    if (entry.to == 0) entry.to = now;
  }
  value.active_attachments = 0;
  value.retired_at = now;
  value.retirement_reason = reason;
  value.assignment = BackingAssignmentId{};
  value.backing = BackingId{};
  value.backing_class = BackingClass::Unknown;
  value.multiplexing = MultiplexingMode::None;
  value.isolation_class = IsolationClass::Unknown;
  value.isolation = IsolationProfile{};
  impl.rebuild_projection(value);
  status = impl.transition(value, VirtualLifecycleState::Retired, reason);
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  impl.state.accounting.virtual_retired += 1;
  impl.recompute_derived_accounting();
  ctx.adopt(value);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::LifecycleChange);
  if (!persisted.ok()) return persisted;
  return value;
}

// ---------------------------------------------------------------------------
// Backing assignment
// ---------------------------------------------------------------------------
Result<BackingAssignment> VirtualizationRuntime::Impl::do_assign_backing(const Authority& auth, OpContext& context,
                                                                        BackingId backing_id, bool replacing,
                                                                        std::string reason) {
  auto& impl = *this;
  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, context.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok()) status = impl.require_mutable(*record.value());

  const auto backing = impl.state.backings.find(backing_id);
  if (status.ok() && backing == impl.state.backings.end()) {
    status = Status(StatusCode::NotFound, "backing " + backing_id.str() + " is not known");
  }
  if (status.ok()) {
    VirtualAcceleratorRecord& value = *record.value();
    const bool assignable = value.state == VirtualLifecycleState::Provisioned ||
                            value.state == VirtualLifecycleState::Suspended;
    const bool drainable = replacing && (value.state == VirtualLifecycleState::Attached ||
                                         value.state == VirtualLifecycleState::Active ||
                                         value.state == VirtualLifecycleState::Draining);
    if (!assignable && !drainable) {
      status = Status(StatusCode::InvalidTransition,
                      "virtual accelerator " + value.id.str() + " is " +
                          std::string(lifecycle_name(value.state)) +
                          (replacing ? "; a backing can be replaced in Provisioned, Suspended, Attached, Active or "
                                       "Draining"
                                     : "; a backing can be assigned in Provisioned or Suspended"));
    }
    if (status.ok() && replacing && !value.assignment.valid()) {
      status = Status(StatusCode::BackingUnavailable,
                      "backing replacement requires an existing authoritative assignment");
    }
    if (status.ok() && !replacing && value.assignment.valid()) {
      const auto existing = impl.state.assignments.find(value.assignment);
      if (existing != impl.state.assignments.end() && existing->second.authoritative) {
        status = Status(StatusCode::Conflict, "virtual accelerator " + value.id.str() +
                                                  " already holds an authoritative backing assignment; use "
                                                  "replace_backing");
      }
    }
    if (status.ok() && backing->second.id == value.backing) {
      status = Status(StatusCode::Conflict, "the requested backing is already assigned to this virtual accelerator");
    }
  }
  if (status.ok()) {
    VirtualAcceleratorRecord& value = *record.value();
    const auto physical = impl.state.physical.find(backing->second.physical);
    status = validate_backing_for(backing->second,
                                  physical != impl.state.physical.end() ? &physical->second : nullptr, value,
                                  impl.state.policy, impl.state);
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(context, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record.value();
  context.adopt(value);
  context.backing = backing_id;

  // Drain the previous binding first: the source stops being authoritative
  // before the replacement commits, and this operation explicitly accepts the
  // resulting downtime.
  if (replacing) {
    auto previous = impl.state.assignments.find(value.assignment);
    if (previous != impl.state.assignments.end()) {
      impl.touch_assignment(previous->first);
      previous->second.authoritative = false;
      previous->second.state = AssignmentState::Superseded;
      previous->second.revoked_at = now;
      previous->second.reason = "replaced by a new authoritative assignment";
      impl.state.accounting.backing_revocations += 1;
    }
    auto previous_backing = impl.state.backings.find(value.backing);
    if (previous_backing != impl.state.backings.end()) {
      impl.touch_backing(previous_backing->first);
      previous_backing->second.assigned_to = VirtualAcceleratorId{};
      previous_backing->second.active_assignment = BackingAssignmentId{};
    }
    impl.touch_virtual(value.id);
    for (BackingHistoryEntry& entry : value.backing_history) {
      entry.current = false;
      if (entry.to == 0) entry.to = now;
    }
    impl.fence_leases(value, "backing replaced; the lease was bound to the previous backing generation", now);
  }

  BackingAssignment assignment;
  assignment.id = BackingAssignmentId::from_value(impl.next_id());
  assignment.virtual_id = value.id;
  assignment.virtual_generation = value.generation;
  assignment.backing = backing->second.id;
  assignment.backing_generation = value.backing_generation.next();
  assignment.physical = backing->second.physical;
  assignment.physical_generation = backing->second.physical_generation;
  assignment.tenant = value.owner;
  assignment.tenant_generation = value.owner_generation;
  assignment.policy_generation = impl.state.policy_generation;
  assignment.contract_generation = value.contract.generation;
  assignment.projection_generation = value.projection.generation;
  assignment.epoch = impl.state.epoch;
  assignment.state = AssignmentState::Active;
  assignment.authoritative = true;
  assignment.proposed_at = now;
  assignment.committed_at = now;
  assignment.reason = reason;

  impl.touch_virtual(value.id);
  value.assignment = assignment.id;
  value.backing = backing->second.id;
  value.backing_generation = assignment.backing_generation;
  value.physical = backing->second.physical;
  value.physical_generation = backing->second.physical_generation;
  value.backing_class = backing->second.klass;
  value.multiplexing = backing->second.multiplexing;
  value.isolation_class = backing->second.isolation_class;
  value.isolation = backing->second.isolation;
  value.policy_generation = impl.state.policy_generation;
  value.state = VirtualLifecycleState::Provisioned;
  value.state_generation = value.state_generation.next();
  value.state_reason = replacing ? "backing replaced; the tenant must re-attach" : "backing assigned";
  value.generation = value.generation.next();
  value.updated_at = now;
  impl.rebuild_projection(value);
  assignment.projection_generation = value.projection.generation;
  assignment.virtual_generation = value.generation;

  BackingHistoryEntry history;
  history.assignment = assignment.id;
  history.backing = backing->second.id;
  history.backing_generation = assignment.backing_generation;
  history.physical = backing->second.physical;
  history.physical_generation = backing->second.physical_generation;
  history.klass = backing->second.klass;
  history.multiplexing = backing->second.multiplexing;
  history.from = now;
  history.current = true;
  history.reason = reason;
  value.backing_history.push_back(history);

  impl.touch_assignment(assignment.id);
  impl.state.assignments[assignment.id] = assignment;

  impl.touch_backing(backing->first);
  backing->second.assigned_to = value.id;
  backing->second.active_assignment = assignment.id;
  backing->second.assigned_generation = assignment.backing_generation;

  if (replacing) {
    impl.state.accounting.backing_replacements += 1;
  } else {
    impl.state.accounting.backing_assignments += 1;
  }
  impl.touch_header();
  context.backing = assignment.backing;
  context.backing_generation = assignment.backing_generation;
  context.virtual_generation = value.generation;
  context.physical = assignment.physical;
  context.physical_generation = assignment.physical_generation;

  const Status persisted = impl.finalize(context, Status{}, AuditKind::BackingChange);
  if (!persisted.ok()) return persisted;
  return assignment;
}

Result<BackingAssignment> VirtualizationRuntime::assign_backing(const Authority& auth, BackingId backing,
                                                               std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "assign_backing";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();
  return impl.do_assign_backing(auth, ctx, backing, false, std::move(reason));
}

Result<BackingAssignment> VirtualizationRuntime::replace_backing(const Authority& auth, BackingId destination,
                                                                std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "replace_backing";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();
  return impl.do_assign_backing(auth, ctx, destination, true, std::move(reason));
}

Result<BackingRecord> VirtualizationRuntime::get_backing(BackingId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.backings.find(id);
  if (it == impl_->state.backings.end()) return Status(StatusCode::NotFound, "backing " + id.str() + " is not known");
  return it->second;
}

std::vector<BackingRecord> VirtualizationRuntime::list_backings() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<BackingRecord> out;
  out.reserve(impl_->state.backings.size());
  for (const auto& entry : impl_->state.backings) out.push_back(entry.second);
  return out;
}

std::vector<BackingAssignment> VirtualizationRuntime::list_assignments() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<BackingAssignment> out;
  out.reserve(impl_->state.assignments.size());
  for (const auto& entry : impl_->state.assignments) out.push_back(entry.second);
  return out;
}

Result<BackingAssignment> VirtualizationRuntime::get_assignment(BackingAssignmentId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.assignments.find(id);
  if (it == impl_->state.assignments.end()) {
    return Status(StatusCode::NotFound, "backing assignment " + id.str() + " is not known");
  }
  return it->second;
}

// ---------------------------------------------------------------------------
// Attachments and leases
// ---------------------------------------------------------------------------
Result<LeaseRecord> VirtualizationRuntime::attach(const Authority& auth) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "attach";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok()) status = impl.require_mutable(*record.value());

  if (status.ok()) {
    VirtualAcceleratorRecord& value = *record.value();
    if (value.state != VirtualLifecycleState::Provisioned && value.state != VirtualLifecycleState::Suspended) {
      status = Status(StatusCode::InvalidTransition,
                      "virtual accelerator " + value.id.str() + " is " +
                          std::string(lifecycle_name(value.state)) +
                          "; an attachment requires Provisioned or Suspended");
    } else if (!value.backing.valid()) {
      status = Status(StatusCode::BackingUnavailable,
                      "virtual accelerator " + value.id.str() + " has no backing assignment");
    } else {
      const auto assignment = impl.state.assignments.find(value.assignment);
      if (assignment == impl.state.assignments.end() || !assignment->second.authoritative) {
        status = Status(StatusCode::BackingUnavailable,
                        "virtual accelerator " + value.id.str() + " has no authoritative backing assignment");
      } else {
        const auto backing = impl.state.backings.find(value.backing);
        if (backing == impl.state.backings.end()) {
          status = Status(StatusCode::StaleBacking, "the assigned backing no longer exists");
        } else if (backing->second.exclusive &&
                   (backing->second.assigned_to != value.id ||
                    backing->second.active_assignment != value.assignment)) {
          // Only an exclusive mechanism records exactly one authoritative
          // holder; a shared mechanism is held by several at once.
          status = Status(StatusCode::StaleAssignment,
                          "backing " + backing->first.str() +
                              " no longer records this virtual accelerator as its authoritative holder");
        } else if (!backing->second.available || !backing->second.evidence_fresh) {
          status = Status(StatusCode::BackingUnavailable,
                          "backing " + backing->first.str() +
                              " is not currently available; it must be revalidated before use");
        }
      }
    }
    if (status.ok()) {
      std::uint32_t live = 0;
      for (LeaseId lease_id : value.leases) {
        const auto lease = impl.state.leases.find(lease_id);
        if (lease != impl.state.leases.end() && lease_state_is_live(lease->second.state)) ++live;
      }
      if (live >= impl.state.policy.max_attachments_per_virtual) {
        status = Status(StatusCode::AttachLimitReached,
                        "virtual accelerator " + value.id.str() + " has reached the policy attachment limit of " +
                            std::to_string(impl.state.policy.max_attachments_per_virtual));
      }
      if (impl.state.leases.size() >= impl.state.policy.max_leases) {
        status = Status(StatusCode::LimitExceeded, "lease count has reached the policy maximum");
      }
    }
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record.value();
  TenantRecord& tenant_record = *tenant.value();
  ctx.adopt(value);

  LeaseRecord lease;
  lease.id = LeaseId::from_value(impl.next_id());
  lease.generation = LeaseGeneration::initial();
  lease.virtual_id = value.id;
  lease.virtual_generation = value.generation;
  lease.tenant = tenant_record.id;
  lease.tenant_generation = tenant_record.generation;
  lease.backing_generation = value.backing_generation;
  lease.physical_generation = value.physical_generation;
  lease.policy_generation = impl.state.policy_generation;
  lease.epoch = impl.state.epoch;
  lease.grant_request = ctx.request;
  lease.state = LeaseState::Active;
  lease.granted_at = now;
  lease.expires_at = impl.state.policy.max_lease_duration_micros > 0
                         ? now + static_cast<UnixMicros>(impl.state.policy.max_lease_duration_micros)
                         : 0;
  const LeaseId lease_id = lease.id;

  impl.touch_virtual(value.id);
  value.leases.push_back(lease_id);
  std::sort(value.leases.begin(), value.leases.end());
  value.active_attachments += 1;
  value.updated_at = now;
  impl.touch_tenant(tenant_record.id);
  tenant_record.active_attachments += 1;
  tenant_record.updated_at = now;
  const bool was_attached = value.state == VirtualLifecycleState::Attached ||
                            value.state == VirtualLifecycleState::Active ||
                            value.state == VirtualLifecycleState::Draining;
  if (!was_attached) {
    status = impl.transition(value, VirtualLifecycleState::Attached, "tenant attached under a generation-bound lease");
    if (!status.ok()) {
      const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
      return persisted.ok() ? status : persisted;
    }
  }
  // The lease is generation-bound, so it must record the generation the
  // virtual accelerator holds *after* the lifecycle transition that the
  // attachment itself performed.
  lease.virtual_generation = value.generation;
  impl.touch_lease(lease_id);
  impl.state.leases[lease_id] = lease;
  impl.state.accounting.leases_issued += 1;
  impl.state.accounting.attachments_active += 1;
  if (impl.state.accounting.attachments_active > impl.state.accounting.peak_attachments_active) {
    impl.state.accounting.peak_attachments_active = impl.state.accounting.attachments_active;
  }
  impl.touch_header();
  ctx.adopt(lease);
  ctx.virtual_generation = value.generation;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return lease;
}

Result<LeaseRecord> VirtualizationRuntime::renew_lease(const Authority& auth) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "renew_lease";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());

  if (status.ok() && !auth.lease.has_value()) {
    status = Status(StatusCode::InvalidArgument, "renewal requires the lease identity");
  }
  const auto lease = auth.lease.has_value() ? impl.state.leases.find(*auth.lease) : impl.state.leases.end();
  if (status.ok() && lease == impl.state.leases.end()) {
    status = Status(StatusCode::NotFound, "lease is not known");
  }
  if (status.ok()) {
    if (!auth.lease_generation.has_value()) {
      status = Status(StatusCode::InvalidArgument, "renewal requires the lease generation");
    } else if (lease->second.generation != *auth.lease_generation) {
      status = Status(StatusCode::StaleLease, "presented lease generation " + auth.lease_generation->str() +
                                                  " is not the current generation " +
                                                  lease->second.generation.str());
    } else if (lease->second.virtual_id != record.value()->id) {
      status = Status(StatusCode::NotAuthorized, "the lease does not belong to that virtual accelerator");
    } else if (!lease_state_is_live(lease->second.state)) {
      status = Status(StatusCode::LeaseRevoked,
                      "lease is " + std::string(lease_state_name(lease->second.state)) + " and cannot be renewed");
    } else if (lease->second.virtual_generation != record.value()->generation) {
      status = Status(StatusCode::StaleLease, "the lease was bound to a superseded virtual generation");
    } else if (lease->second.backing_generation != record.value()->backing_generation) {
      status = Status(StatusCode::StaleLease, "the lease was bound to a superseded backing generation");
    } else if (lease->second.policy_generation != impl.state.policy_generation) {
      status = Status(StatusCode::StalePolicy, "the lease was granted under a superseded policy generation");
    } else if (lease->second.epoch != impl.state.epoch) {
      status = Status(StatusCode::StaleEpoch, "the lease was granted under a superseded coordinator epoch");
    }
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  LeaseRecord& target = lease->second;
  ctx.adopt(target);
  impl.touch_lease(target.id);
  target.generation = target.generation.next();
  target.renewed_at = now;
  target.renewals += 1;
  target.expires_at = impl.state.policy.max_lease_duration_micros > 0
                          ? now + static_cast<UnixMicros>(impl.state.policy.max_lease_duration_micros)
                          : 0;
  impl.state.accounting.leases_renewed += 1;
  impl.touch_header();
  ctx.adopt(target);
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return target;
}

namespace {

// Shared validation for the two lease-releasing operations.
template <class ImplT>
Status resolve_lease_for(ImplT& impl, const Authority& auth, const std::string& operation,
                         VirtualAcceleratorRecord*& record, LeaseRecord*& lease, bool allow_dead) {
  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto virtual_record = impl.resolve_virtual(auth);
  if (status.ok() && !virtual_record.ok()) status = virtual_record.status();
  if (status.ok()) status = impl.require_owner(*virtual_record.value(), *tenant.value());
  if (status.ok() && !auth.lease.has_value()) {
    status = Status(StatusCode::InvalidArgument, "the lease identity is required");
  }
  if (status.ok()) {
    const auto it = impl.state.leases.find(*auth.lease);
    if (it == impl.state.leases.end()) {
      status = Status(StatusCode::NotFound, "lease is not known");
    } else if (!auth.lease_generation.has_value()) {
      status = Status(StatusCode::InvalidArgument, "the lease generation is required");
    } else if (it->second.generation != *auth.lease_generation) {
      status = Status(StatusCode::StaleLease, "presented lease generation " + auth.lease_generation->str() +
                                                  " is not the current generation " +
                                                  it->second.generation.str());
    } else if (it->second.virtual_id != virtual_record.value()->id) {
      status = Status(StatusCode::NotAuthorized, "the lease does not belong to that virtual accelerator");
    } else if (!allow_dead && !lease_state_is_live(it->second.state)) {
      status = Status(StatusCode::LeaseRevoked,
                      "lease is already " + std::string(lease_state_name(it->second.state)));
    } else {
      lease = &it->second;
      record = virtual_record.value();
    }
  }
  return status;
}

}  // namespace

Status VirtualizationRuntime::detach(const Authority& auth) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "detach";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  VirtualAcceleratorRecord* record = nullptr;
  LeaseRecord* lease = nullptr;
  Status status = resolve_lease_for(impl, auth, ctx.operation, record, lease, false);
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record;
  ctx.adopt(*lease);
  impl.touch_lease(lease->id);
  lease->state = LeaseState::Revoked;
  lease->revoked_at = now;
  lease->reason = "detached by the tenant";
  const TenantId tenant_id = lease->tenant;
  const auto tenant_it = impl.state.tenants.find(tenant_id);

  impl.touch_virtual(value.id);
  if (value.active_attachments > 0) value.active_attachments -= 1;
  value.updated_at = now;
  if (tenant_it != impl.state.tenants.end()) {
    impl.touch_tenant(tenant_id);
    if (tenant_it->second.active_attachments > 0) tenant_it->second.active_attachments -= 1;
    tenant_it->second.updated_at = now;
  }
  impl.state.accounting.detaches += 1;
  if (impl.state.accounting.attachments_active > 0) impl.state.accounting.attachments_active -= 1;
  impl.touch_header();

  if (value.active_attachments == 0) {
    const Status transitioned =
        impl.transition(value, VirtualLifecycleState::Provisioned, "the last attachment was released");
    if (!transitioned.ok()) {
      const Status persisted = impl.finalize(ctx, transitioned, AuditKind::AuthorityRefusal);
      return persisted.ok() ? transitioned : persisted;
    }
  }
  ctx.virtual_generation = value.generation;
  return impl.finalize(ctx, Status{}, AuditKind::Mutation);
}

Status VirtualizationRuntime::revoke_lease(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "revoke";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  VirtualAcceleratorRecord* record = nullptr;
  LeaseRecord* lease = nullptr;
  Status status = resolve_lease_for(impl, auth, ctx.operation, record, lease, false);
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record;
  ctx.adopt(*lease);
  const bool was_live = lease_state_is_live(lease->state);
  const TenantId tenant_id = lease->tenant;
  impl.touch_lease(lease->id);
  lease->state = LeaseState::Revoked;
  lease->revoked_at = now;
  lease->reason = reason.empty() ? std::string("revoked") : reason;
  if (was_live) {
    impl.touch_virtual(value.id);
    if (value.active_attachments > 0) value.active_attachments -= 1;
    value.updated_at = now;
    const auto tenant_it = impl.state.tenants.find(tenant_id);
    if (tenant_it != impl.state.tenants.end()) {
      impl.touch_tenant(tenant_id);
      if (tenant_it->second.active_attachments > 0) tenant_it->second.active_attachments -= 1;
      tenant_it->second.updated_at = now;
    }
    impl.state.accounting.leases_revoked += 1;
    if (impl.state.accounting.attachments_active > 0) impl.state.accounting.attachments_active -= 1;
  }
  impl.touch_header();
  if (was_live && value.active_attachments == 0) {
    const Status transitioned =
        impl.transition(value, VirtualLifecycleState::Provisioned, "the last attachment was revoked");
    if (!transitioned.ok()) {
      const Status persisted = impl.finalize(ctx, transitioned, AuditKind::AuthorityRefusal);
      return persisted.ok() ? transitioned : persisted;
    }
  }
  ctx.virtual_generation = value.generation;
  return impl.finalize(ctx, Status{}, AuditKind::Mutation);
}

Result<LeaseRecord> VirtualizationRuntime::get_lease(LeaseId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.leases.find(id);
  if (it == impl_->state.leases.end()) return Status(StatusCode::NotFound, "lease " + id.str() + " is not known");
  return it->second;
}

std::vector<LeaseRecord> VirtualizationRuntime::list_leases() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<LeaseRecord> out;
  out.reserve(impl_->state.leases.size());
  for (const auto& entry : impl_->state.leases) out.push_back(entry.second);
  return out;
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------
Result<MigrationRecord> VirtualizationRuntime::plan_migration(const Authority& auth, BackingId destination,
                                                             MigrationClass klass) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "migration_plan";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok()) status = impl.require_mutable(*record.value());

  if (status.ok()) {
    VirtualAcceleratorRecord& value = *record.value();
    if (!value.assignment.valid() || !value.backing.valid()) {
      status = Status(StatusCode::BackingUnavailable,
                      "migration requires an authoritative source backing assignment");
    } else if (value.migration.valid()) {
      const auto in_flight = impl.state.migrations.find(value.migration);
      if (in_flight != impl.state.migrations.end() && !migration_state_is_terminal(in_flight->second.state)) {
        status = Status(StatusCode::MigrationInProgress, "a migration is already in flight for " + value.id.str());
      }
    }
    if (status.ok() && value.state == VirtualLifecycleState::Migrating) {
      status = Status(StatusCode::MigrationInProgress, "a migration is already in flight for " + value.id.str());
    } else if (value.state != VirtualLifecycleState::Provisioned &&
               value.state != VirtualLifecycleState::Attached &&
               value.state != VirtualLifecycleState::Active &&
               value.state != VirtualLifecycleState::Draining &&
               value.state != VirtualLifecycleState::Suspended) {
      status = Status(StatusCode::InvalidTransition,
                      "virtual accelerator " + value.id.str() + " is " + std::string(lifecycle_name(value.state)) +
                          " and cannot start a migration");
    } else if (destination == value.backing) {
      status = Status(StatusCode::Conflict, "the destination backing is the current backing");
    }
  }
  if (status.ok()) {
    const MigrationCapability capability = migration_capability(impl.state.policy, record.value()->contract);
    if (!capability.supported) {
      status = Status(StatusCode::MigrationUnsupported, capability.reason);
    } else if (klass == MigrationClass::Unknown || klass == MigrationClass::Unsupported ||
               klass == MigrationClass::CheckpointRestore || klass == MigrationClass::LiveStateTransfer ||
               klass == MigrationClass::StateReconstruction) {
      status = Status(StatusCode::MigrationUnsupported,
                      std::string("migration class ") + std::string(migration_class_name(klass)) +
                          " requires state movement this runtime does not implement; implemented classes are "
                          "REBIND_ONLY and DRAIN_AND_RESTART");
    } else if (!impl.state.policy.permits_migration_class(klass)) {
      status = Status(StatusCode::MigrationClassNotAllowed,
                      std::string("the virtualization policy does not allow migration class ") +
                          std::string(migration_class_name(klass)));
    } else if (!record.value()->contract.permits_migration_class(klass)) {
      status = Status(StatusCode::MigrationClassNotAllowed,
                      std::string("the resource contract does not allow migration class ") +
                          std::string(migration_class_name(klass)));
    }
  }
  const auto destination_backing = impl.state.backings.find(destination);
  if (status.ok() && destination_backing == impl.state.backings.end()) {
    status = Status(StatusCode::NotFound, "destination backing " + destination.str() + " is not known");
  }
  if (status.ok()) {
    VirtualAcceleratorRecord probe = *record.value();
    const auto physical = impl.state.physical.find(destination_backing->second.physical);
    status = validate_backing_for(destination_backing->second,
                                  physical != impl.state.physical.end() ? &physical->second : nullptr, probe,
                                  impl.state.policy, impl.state);
  }
  if (status.ok() && impl.state.migrations.size() >= impl.state.policy.max_migrations) {
    status = Status(StatusCode::LimitExceeded, "migration count has reached the policy maximum");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(value);
  const auto source_backing = impl.state.backings.find(value.backing);
  const auto source_physical = impl.state.physical.find(source_backing->second.physical);

  MigrationRecord migration;
  migration.plan.id = MigrationId::from_value(impl.next_id());
  migration.plan.generation = MigrationGeneration::initial();
  migration.plan.virtual_id = value.id;
  migration.plan.virtual_generation = value.generation;
  migration.plan.source_backing = value.backing;
  migration.plan.source_backing_generation = source_backing->second.generation;
  migration.plan.destination_backing = destination;
  migration.plan.destination_backing_generation = destination_backing->second.generation;
  migration.plan.source_physical = source_backing->second.physical;
  migration.plan.source_physical_generation = source_physical != impl.state.physical.end()
                                                  ? source_physical->second.generation
                                                  : source_backing->second.physical_generation;
  migration.plan.destination_physical = destination_backing->second.physical;
  migration.plan.destination_physical_generation = destination_backing->second.physical_generation;
  migration.plan.tenant = value.owner;
  migration.plan.tenant_generation = value.owner_generation;
  migration.plan.contract_generation = value.contract.generation;
  migration.plan.projection_generation = value.projection.generation;
  migration.plan.policy_generation = impl.state.policy_generation;
  migration.plan.epoch = impl.state.epoch;
  migration.plan.klass = klass;
  migration.plan.state_transfer_required = false;
  migration.plan.live_state_movement = false;
  migration.plan.rationale =
      "identity continuity across backing replacement; no execution-state or memory-state movement is claimed";
  migration.state = MigrationState::Planned;
  migration.source_authoritative = true;
  migration.destination_authoritative = false;
  migration.source_assignment = value.assignment;
  migration.planned_at = now;
  migration.note =
      "plan bound to virtual, backing, physical, tenant, contract, projection, policy and epoch generations";

  impl.touch_virtual(value.id);
  value.migration = migration.plan.id;
  value.migration_generation = migration.plan.generation;
  impl.touch_migration(migration.plan.id);
  impl.state.migrations[migration.plan.id] = migration;
  impl.state.accounting.migrations_planned += 1;
  impl.touch_header();

  ctx.migration = migration.plan.id;
  ctx.migration_generation = migration.plan.generation;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::MigrationChange);
  if (!persisted.ok()) return persisted;
  return migration;
}

namespace {

// Shared prologue for the migration phases after planning.
template <class ImplT>
Status migration_prologue(ImplT& impl, const Authority& auth, OpContext& ctx, MigrationRecord*& migration,
                          VirtualAcceleratorRecord*& record) {
  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  if (status.ok()) status = impl.check_request(auth, ctx.operation);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto virtual_record = impl.resolve_virtual(auth);
  if (status.ok() && !virtual_record.ok()) status = virtual_record.status();
  if (status.ok()) status = impl.require_owner(*virtual_record.value(), *tenant.value());
  if (status.ok() && !auth.migration.has_value()) {
    status = Status(StatusCode::InvalidArgument, "migration phase requires the migration identity");
  }
  if (status.ok() && !auth.migration_generation.has_value()) {
    status = Status(StatusCode::InvalidArgument, "migration phase requires the migration generation");
  }
  if (status.ok()) {
    const auto it = impl.state.migrations.find(*auth.migration);
    if (it == impl.state.migrations.end()) {
      status = Status(StatusCode::NotFound, "migration " + auth.migration->str() + " is not known");
    } else if (it->second.plan.generation != *auth.migration_generation) {
      status = Status(StatusCode::StaleMigration, "presented migration generation " +
                                                      auth.migration_generation->str() +
                                                      " is not the current generation " +
                                                      it->second.plan.generation.str());
    } else if (it->second.plan.virtual_id != virtual_record.value()->id) {
      status = Status(StatusCode::NotAuthorized, "the migration does not belong to that virtual accelerator");
    } else {
      migration = &it->second;
      record = virtual_record.value();
      status = plan_staleness(it->second, *record, impl.state);
    }
  }
  return status;
}

}  // namespace

Result<MigrationRecord> VirtualizationRuntime::prepare_migration(const Authority& auth) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "migration_prepare";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  ctx.migration = auth.migration.value_or(MigrationId{});
  ctx.migration_generation = auth.migration_generation.value_or(MigrationGeneration{});
  impl.begin_op();

  MigrationRecord* migration = nullptr;
  VirtualAcceleratorRecord* record = nullptr;
  Status status = migration_prologue(impl, auth, ctx, migration, record);
  if (status.ok() && migration->state != MigrationState::Planned) {
    status = Status(StatusCode::InvalidTransition, "migration is " +
                                                       std::string(migration_state_name(migration->state)) +
                                                       "; preparation requires Planned");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  ctx.adopt(*record);
  ctx.migration = migration->plan.id;
  ctx.migration_generation = migration->plan.generation;

  // Prepared -> SourceDraining -> DestinationPrepared -> CommitReady. The
  // source stays authoritative throughout; nothing here moves authority.
  const Status drained = impl.transition(*record, VirtualLifecycleState::Migrating,
                                         "migration prepared; leases are drained before cutover");
  if (!drained.ok()) {
    const Status persisted = impl.finalize(ctx, drained, AuditKind::AuthorityRefusal);
    return persisted.ok() ? drained : persisted;
  }
  impl.fence_leases(*record, "migration drained the source backing; the lease is bound to the source generation",
                    now);

  const auto destination = impl.state.backings.find(migration->plan.destination_backing);
  BackingAssignment destination_assignment;
  destination_assignment.id = BackingAssignmentId::from_value(impl.next_id());
  destination_assignment.virtual_id = record->id;
  destination_assignment.virtual_generation = record->generation;
  destination_assignment.backing = destination->second.id;
  destination_assignment.backing_generation = record->backing_generation.next();
  destination_assignment.physical = destination->second.physical;
  destination_assignment.physical_generation = destination->second.physical_generation;
  destination_assignment.tenant = record->owner;
  destination_assignment.tenant_generation = record->owner_generation;
  destination_assignment.policy_generation = impl.state.policy_generation;
  destination_assignment.contract_generation = record->contract.generation;
  destination_assignment.projection_generation = record->projection.generation;
  destination_assignment.epoch = impl.state.epoch;
  destination_assignment.state = AssignmentState::Prepared;
  destination_assignment.authoritative = false;
  destination_assignment.proposed_at = now;
  destination_assignment.reason = "prepared destination for migration " + migration->plan.id.str();
  impl.touch_assignment(destination_assignment.id);
  impl.state.assignments[destination_assignment.id] = destination_assignment;

  impl.touch_migration(migration->plan.id);
  migration->state = MigrationState::CommitReady;
  migration->destination_assignment = destination_assignment.id;
  migration->prepared_at = now;
  migration->note = "prepared, source drained through SourceDraining and DestinationPrepared";
  migration->plan.generation = migration->plan.generation.next();
  // The plan targets the generation the migration itself just produced. Any
  // later change by anyone else advances the generation again and makes the
  // plan stale, which is exactly the drift the check must catch.
  migration->plan.virtual_generation = record->generation;
  migration->plan.contract_generation = record->contract.generation;
  migration->plan.projection_generation = record->projection.generation;
  migration->source_authoritative = true;
  migration->destination_authoritative = false;
  impl.state.accounting.migrations_prepared += 1;
  impl.touch_header();

  ctx.migration_generation = migration->plan.generation;
  ctx.backing_generation = destination_assignment.backing_generation;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::MigrationChange);
  if (!persisted.ok()) return persisted;
  return *migration;
}

Result<MigrationRecord> VirtualizationRuntime::commit_migration(const Authority& auth) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "migration_commit";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  ctx.migration = auth.migration.value_or(MigrationId{});
  ctx.migration_generation = auth.migration_generation.value_or(MigrationGeneration{});
  impl.begin_op();

  MigrationRecord* migration = nullptr;
  VirtualAcceleratorRecord* record = nullptr;
  Status status = migration_prologue(impl, auth, ctx, migration, record);
  if (status.ok() && migration->state != MigrationState::CommitReady) {
    status = Status(StatusCode::InvalidTransition, "migration is " +
                                                       std::string(migration_state_name(migration->state)) +
                                                       "; commit requires CommitReady");
  }
  if (status.ok()) {
    const auto source = impl.state.assignments.find(migration->source_assignment);
    if (source == impl.state.assignments.end() || !source->second.authoritative) {
      status = Status(StatusCode::StaleAssignment, "the source assignment is no longer authoritative");
    }
  }
  if (status.ok() && impl.state.assignments.find(migration->destination_assignment) == impl.state.assignments.end()) {
    status = Status(StatusCode::StaleAssignment, "the prepared destination assignment has disappeared");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  ctx.adopt(*record);
  ctx.migration = migration->plan.id;

  auto source_assignment = impl.state.assignments.find(migration->source_assignment);
  auto destination_assignment = impl.state.assignments.find(migration->destination_assignment);
  auto source_backing = impl.state.backings.find(migration->plan.source_backing);
  auto destination_backing = impl.state.backings.find(migration->plan.destination_backing);

  // ---- the cutover point ----
  // Before this block the source is authoritative. After it the destination is,
  // and the source is revoked inside the same durable record set, so no restart
  // can observe both as authoritative.
  impl.touch_virtual(record->id);
  record->backing = migration->plan.destination_backing;
  record->backing_generation = destination_assignment->second.backing_generation;
  record->physical = destination_backing->second.physical;
  record->physical_generation = destination_backing->second.physical_generation;
  record->backing_class = destination_backing->second.klass;
  record->multiplexing = destination_backing->second.multiplexing;
  record->isolation_class = destination_backing->second.isolation_class;
  record->isolation = destination_backing->second.isolation;
  record->assignment = destination_assignment->first;
  record->policy_generation = impl.state.policy_generation;
  record->state = VirtualLifecycleState::Provisioned;
  record->state_generation = record->state_generation.next();
  record->state_reason = "migration committed: the destination backing is authoritative";
  record->generation = record->generation.next();
  record->updated_at = now;
  for (BackingHistoryEntry& entry : record->backing_history) {
    entry.current = false;
    if (entry.to == 0) entry.to = now;
  }
  impl.rebuild_projection(*record);

  BackingHistoryEntry history;
  history.assignment = destination_assignment->first;
  history.backing = destination_backing->first;
  history.backing_generation = destination_assignment->second.backing_generation;
  history.physical = destination_backing->second.physical;
  history.physical_generation = destination_backing->second.physical_generation;
  history.klass = destination_backing->second.klass;
  history.multiplexing = destination_backing->second.multiplexing;
  history.from = now;
  history.current = true;
  history.reason = "migration " + migration->plan.id.str() + " committed";
  record->backing_history.push_back(history);

  impl.touch_assignment(source_assignment->first);
  source_assignment->second.authoritative = false;
  source_assignment->second.state = AssignmentState::Revoked;
  source_assignment->second.revoked_at = now;
  source_assignment->second.reason = "migration cutover revoked the source authority";
  impl.state.accounting.backing_revocations += 1;

  impl.touch_assignment(destination_assignment->first);
  destination_assignment->second.authoritative = true;
  destination_assignment->second.state = AssignmentState::Active;
  destination_assignment->second.committed_at = now;
  destination_assignment->second.virtual_generation = record->generation;
  destination_assignment->second.projection_generation = record->projection.generation;

  impl.touch_backing(source_backing->first);
  source_backing->second.assigned_to = VirtualAcceleratorId{};
  source_backing->second.active_assignment = BackingAssignmentId{};
  impl.touch_backing(destination_backing->first);
  destination_backing->second.assigned_to = record->id;
  destination_backing->second.active_assignment = destination_assignment->first;
  destination_backing->second.assigned_generation = destination_assignment->second.backing_generation;

  impl.touch_migration(migration->plan.id);
  migration->state = MigrationState::Committed;
  migration->plan.virtual_generation = record->generation;
  migration->plan.contract_generation = record->contract.generation;
  migration->plan.projection_generation = record->projection.generation;
  migration->source_authoritative = false;
  migration->destination_authoritative = true;
  migration->committed_at = now;
  migration->note = "cutover performed; the source authority was revoked in the same durable step";
  impl.state.accounting.migrations_committed += 1;
  impl.touch_header();

  ctx.adopt(*record);
  ctx.migration = migration->plan.id;
  ctx.migration_generation = migration->plan.generation;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::MigrationChange);
  if (!persisted.ok()) return persisted;
  return *migration;
}

Result<MigrationRecord> VirtualizationRuntime::complete_migration(const Authority& auth) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "migration_complete";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  MigrationRecord* migration = nullptr;
  VirtualAcceleratorRecord* record = nullptr;
  Status status = migration_prologue(impl, auth, ctx, migration, record);
  if (status.ok() && migration->state != MigrationState::Committed) {
    status = Status(StatusCode::InvalidTransition, "migration is " +
                                                       std::string(migration_state_name(migration->state)) +
                                                       "; completion requires Committed");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  ctx.adopt(*record);
  ctx.migration = migration->plan.id;
  ctx.migration_generation = migration->plan.generation;
  impl.touch_migration(migration->plan.id);
  migration->state = MigrationState::SourceRevoked;
  migration->state = MigrationState::Completed;
  migration->completed_at = now;
  migration->note = "identity continuity preserved; the tenant must re-establish attachment authority";
  impl.touch_virtual(record->id);
  record->migration_generation = migration->plan.generation;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::MigrationChange);
  if (!persisted.ok()) return persisted;
  return *migration;
}

Result<MigrationRecord> VirtualizationRuntime::abort_migration(const Authority& auth, std::string reason) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "migration_abort";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  MigrationRecord* migration = nullptr;
  VirtualAcceleratorRecord* record = nullptr;
  Status status = migration_prologue(impl, auth, ctx, migration, record);
  if (status.ok() && migration_state_after_cutover(migration->state)) {
    status = Status(StatusCode::InvalidTransition,
                    "migration already crossed the cutover point; the destination is authoritative and the "
                    "migration cannot be aborted");
  }
  if (status.ok() && migration_state_is_terminal(migration->state)) {
    status = Status(StatusCode::InvalidTransition,
                    "migration is already " + std::string(migration_state_name(migration->state)));
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  const UnixMicros now = impl.clock->now_micros();
  ctx.adopt(*record);
  ctx.migration = migration->plan.id;
  ctx.migration_generation = migration->plan.generation;
  auto destination_assignment = impl.state.assignments.find(migration->destination_assignment);
  if (destination_assignment != impl.state.assignments.end()) {
    impl.touch_assignment(destination_assignment->first);
    destination_assignment->second.state = AssignmentState::Failed;
    destination_assignment->second.authoritative = false;
    destination_assignment->second.revoked_at = now;
    destination_assignment->second.reason = "migration aborted before cutover: " + reason;
  }
  impl.touch_migration(migration->plan.id);
  migration->state = MigrationState::Aborted;
  migration->source_authoritative = true;
  migration->destination_authoritative = false;
  migration->completed_at = now;
  migration->note = reason;
  impl.state.accounting.migrations_aborted += 1;
  if (record->state == VirtualLifecycleState::Migrating) {
    const Status transitioned =
        impl.transition(*record, VirtualLifecycleState::Provisioned,
                        "migration aborted before cutover; the source backing remains authoritative");
    if (!transitioned.ok()) {
      const Status persisted = impl.finalize(ctx, transitioned, AuditKind::AuthorityRefusal);
      return persisted.ok() ? transitioned : persisted;
    }
  }
  impl.touch_header();
  ctx.virtual_generation = record->generation;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::MigrationChange);
  if (!persisted.ok()) return persisted;
  return *migration;
}

Result<MigrationRecord> VirtualizationRuntime::get_migration(MigrationId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.migrations.find(id);
  if (it == impl_->state.migrations.end()) {
    return Status(StatusCode::NotFound, "migration " + id.str() + " is not known");
  }
  return it->second;
}

std::vector<MigrationRecord> VirtualizationRuntime::list_migrations() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<MigrationRecord> out;
  out.reserve(impl_->state.migrations.size());
  for (const auto& entry : impl_->state.migrations) out.push_back(entry.second);
  return out;
}

Status VirtualizationRuntime::classify_recovered_migrations() {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  return impl.do_classify_recovered_migrations();
}

Status VirtualizationRuntime::Impl::do_classify_recovered_migrations() {
  auto& impl = *this;
  OpContext ctx;
  ctx.operation = "classify_recovered_migrations";
  ctx.epoch = impl.state.epoch;
  impl.begin_op();

  const UnixMicros now = impl.clock->now_micros();
  std::size_t classified = 0;
  for (auto& entry : impl.state.migrations) {
    MigrationRecord& migration = entry.second;
    const auto record = impl.state.virtuals.find(migration.plan.virtual_id);
    if (record == impl.state.virtuals.end()) continue;

    if (migration.state == MigrationState::Committed) {
      impl.touch_migration(migration.plan.id);
      migration.state = MigrationState::SourceRevoked;
      migration.state = MigrationState::Completed;
      migration.completed_at = now;
      migration.note = "cutover was durable before the restart; the migration is completed";
      ++classified;
      continue;
    }
    if (migration_state_is_terminal(migration.state)) continue;
    if (migration.state == MigrationState::RecoveryRequired) continue;

    // Pre-cutover states: because the cutover is persisted before it is
    // acknowledged, a pre-cutover record after a restart means the cutover
    // never happened. The source remains authoritative.
    impl.touch_migration(migration.plan.id);
    migration.state = MigrationState::Aborted;
    migration.source_authoritative = true;
    migration.destination_authoritative = false;
    migration.completed_at = now;
    migration.note =
        "coordinator restart found an in-flight migration before the cutover; the source remains authoritative";
    impl.state.accounting.migrations_aborted += 1;
    auto destination_assignment = impl.state.assignments.find(migration.destination_assignment);
    if (destination_assignment != impl.state.assignments.end() && !destination_assignment->second.authoritative) {
      impl.touch_assignment(destination_assignment->first);
      destination_assignment->second.state = AssignmentState::Failed;
      destination_assignment->second.revoked_at = now;
      destination_assignment->second.reason = migration.note;
    }
    VirtualAcceleratorRecord& value = record->second;
    impl.touch_virtual(value.id);
    if (value.state == VirtualLifecycleState::Migrating) {
      value.state = VirtualLifecycleState::Provisioned;
      value.state_generation = value.state_generation.next();
      value.state_reason = migration.note;
      value.generation = value.generation.next();
      value.updated_at = now;
    }
    ++classified;
  }
  if (classified == 0) {
    impl.changes.clear();
    impl.undo = UndoLog{};
    return Status{};
  }
  impl.touch_header();
  return impl.finalize(ctx, Status{}, AuditKind::Recovery);
}

// ---------------------------------------------------------------------------
// Execution accounting
// ---------------------------------------------------------------------------
Result<std::uint64_t> VirtualizationRuntime::reserve_allocation(const Authority& auth, std::uint64_t bytes) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "reserve_allocation";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  if (status.ok()) status = impl.check_policy(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());

  LeaseRecord* lease = nullptr;
  if (status.ok()) {
    if (!auth.lease.has_value() || !auth.lease_generation.has_value()) {
      status = Status(StatusCode::NotAttached, "allocation requires a live attachment lease");
    } else {
      const auto it = impl.state.leases.find(*auth.lease);
      if (it == impl.state.leases.end()) {
        status = Status(StatusCode::NotFound, "lease is not known");
      } else if (it->second.generation != *auth.lease_generation) {
        status = Status(StatusCode::StaleLease, "presented lease generation " + auth.lease_generation->str() +
                                                    " is not the current generation " +
                                                    it->second.generation.str());
      } else if (it->second.virtual_id != record.value()->id || it->second.tenant != tenant.value()->id ||
                 !lease_state_is_live(it->second.state)) {
        status = Status(StatusCode::NotAttached, "the presented lease does not authorise this virtual accelerator");
      } else if (it->second.virtual_generation != record.value()->generation) {
        status = Status(StatusCode::StaleLease, "the lease was bound to a superseded virtual generation");
      } else if (it->second.backing_generation != record.value()->backing_generation) {
        status = Status(StatusCode::StaleLease, "the lease was bound to a superseded backing generation");
      } else if (it->second.policy_generation != impl.state.policy_generation) {
        status = Status(StatusCode::StalePolicy, "the lease was granted under a superseded policy generation");
      } else if (it->second.epoch != impl.state.epoch) {
        status = Status(StatusCode::StaleEpoch, "the lease was granted under a superseded coordinator epoch");
      } else {
        lease = &it->second;
      }
    }
  }
  if (status.ok()) {
    VirtualAcceleratorRecord& value = *record.value();
    const std::uint64_t ceiling = value.contract.memory_ceiling_bytes;
    if (impl.options.enforce_memory_budget && ceiling > 0) {
      if (bytes > ceiling || value.allocated_bytes > ceiling - bytes) {
        status = Status(StatusCode::ContractViolation,
                        "allocation of " + std::to_string(bytes) + " byte(s) would exceed the virtual memory "
                        "ceiling of " + std::to_string(ceiling) + " byte(s) for " + value.id.str() + " (currently " +
                        std::to_string(value.allocated_bytes) + " byte(s) allocated)");
      }
    }
    if (status.ok() && value.state != VirtualLifecycleState::Active &&
        value.state != VirtualLifecycleState::Attached) {
      status = Status(StatusCode::InvalidTransition,
                      "virtual accelerator " + value.id.str() + " is " + std::string(lifecycle_name(value.state)) +
                          " and cannot execute");
    }
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }

  VirtualAcceleratorRecord& value = *record.value();
  ctx.adopt(*lease);
  impl.touch_virtual(value.id);
  value.allocated_bytes += bytes;
  if (value.allocated_bytes > value.peak_allocated_bytes) value.peak_allocated_bytes = value.allocated_bytes;
  value.allocation_operations += 1;
  impl.state.accounting.allocation_operations += 1;
  impl.state.accounting.bytes_allocated_current += bytes;
  if (impl.state.accounting.bytes_allocated_current > impl.state.accounting.bytes_allocated_peak) {
    impl.state.accounting.bytes_allocated_peak = impl.state.accounting.bytes_allocated_current;
  }
  impl.touch_header();
  const std::uint64_t allocated = value.allocated_bytes;
  const Status persisted = impl.finalize(ctx, Status{}, AuditKind::Mutation);
  if (!persisted.ok()) return persisted;
  return allocated;
}

Status VirtualizationRuntime::release_allocation(const Authority& auth, std::uint64_t bytes) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "release_allocation";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  // Releasing bytes that are already accounted for is a reconciliation, not a
  // new grant of authority: it can only reduce accounting that the caller's own
  // tenant owns. It therefore requires current tenant authority and ownership,
  // but not a current virtual generation, so an allocation that was in flight
  // when the lifecycle moved underneath it can always be settled.
  if (status.ok() && !auth.virtual_id.has_value()) {
    status = Status(StatusCode::InvalidArgument, "authority must carry a virtual accelerator identity");
  }
  auto record = auth.virtual_id.has_value() ? impl.state.virtuals.find(*auth.virtual_id)
                                            : impl.state.virtuals.end();
  if (status.ok() && record == impl.state.virtuals.end()) {
    status = Status(StatusCode::NotFound, "virtual accelerator " + auth.virtual_id->str() + " is not known");
  }
  if (status.ok()) status = impl.require_owner(record->second, *tenant.value());
  if (status.ok() && record->second.allocated_bytes < bytes) {
    status = Status(StatusCode::ContractViolation, "release of " + std::to_string(bytes) +
                                                       " byte(s) exceeds the currently allocated " +
                                                       std::to_string(record->second.allocated_bytes) + " byte(s)");
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  VirtualAcceleratorRecord& value = record->second;
  ctx.adopt(value);
  impl.touch_virtual(value.id);
  value.allocated_bytes -= bytes;
  impl.state.accounting.bytes_allocated_current = impl.state.accounting.bytes_allocated_current >= bytes
                                                      ? impl.state.accounting.bytes_allocated_current - bytes
                                                      : 0;
  impl.touch_header();
  return impl.finalize(ctx, Status{}, AuditKind::Mutation);
}

Status VirtualizationRuntime::account_kernel(const Authority& auth, std::uint32_t count) {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  OpContext ctx;
  ctx.operation = "account_kernel";
  if (auth.epoch.has_value()) ctx.epoch = *auth.epoch;
  ctx.request = auth.request.value_or(RequestId{});
  ctx.session = auth.session.value_or(0);
  impl.begin_op();

  Status status = impl.guard_store();
  if (status.ok()) status = impl.check_epoch(auth);
  auto tenant = impl.resolve_tenant(auth);
  if (status.ok() && !tenant.ok()) status = tenant.status();
  auto record = impl.resolve_virtual(auth);
  if (status.ok() && !record.ok()) status = record.status();
  if (status.ok()) status = impl.require_owner(*record.value(), *tenant.value());
  if (status.ok() && !auth.lease.has_value()) {
    status = Status(StatusCode::NotAttached, "execution accounting requires a live attachment lease");
  }
  if (status.ok()) {
    const auto lease = impl.state.leases.find(*auth.lease);
    if (lease == impl.state.leases.end() || !lease_state_is_live(lease->second.state)) {
      status = Status(StatusCode::NotAttached, "the presented lease is not live");
    } else if (auth.lease_generation.has_value() && lease->second.generation != *auth.lease_generation) {
      status = Status(StatusCode::StaleLease, "the presented lease generation is not current");
    } else {
      ctx.adopt(lease->second);
    }
  }
  if (!status.ok()) {
    const Status persisted = impl.finalize(ctx, status, AuditKind::AuthorityRefusal);
    return persisted.ok() ? status : persisted;
  }
  VirtualAcceleratorRecord& value = *record.value();
  impl.touch_virtual(value.id);
  value.kernel_operations += count;
  impl.state.accounting.kernel_operations += count;
  impl.touch_header();
  return impl.finalize(ctx, Status{}, AuditKind::Mutation);
}

// ---------------------------------------------------------------------------
// Queries and explainability
// ---------------------------------------------------------------------------
Result<VirtualView> VirtualizationRuntime::query_virtual(const Authority& auth, VirtualAcceleratorId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.virtuals.find(id);
  if (it == impl_->state.virtuals.end()) {
    return Status(StatusCode::NotFound, "virtual accelerator " + id.str() + " is not known");
  }
  return make_view(impl_->state, it->second, auth);
}

std::vector<VirtualView> VirtualizationRuntime::list_virtual(const Authority& auth) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<VirtualView> out;
  out.reserve(impl_->state.virtuals.size());
  for (const auto& entry : impl_->state.virtuals) {
    if (auth.tenant.has_value() && entry.second.owner != *auth.tenant) continue;
    out.push_back(make_view(impl_->state, entry.second, auth));
    if (out.size() >= kMaxListedVirtuals) break;
  }
  return out;
}

Result<VirtualAcceleratorRecord> VirtualizationRuntime::raw_virtual(VirtualAcceleratorId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.virtuals.find(id);
  if (it == impl_->state.virtuals.end()) {
    return Status(StatusCode::NotFound, "virtual accelerator " + id.str() + " is not known");
  }
  return it->second;
}

Result<CapabilityProjection> VirtualizationRuntime::get_projection(VirtualAcceleratorId id) const {
  auto record = raw_virtual(id);
  if (!record.ok()) return record.status();
  return record->projection;
}

Result<ResourceContract> VirtualizationRuntime::get_contract(VirtualAcceleratorId id) const {
  auto record = raw_virtual(id);
  if (!record.ok()) return record.status();
  return record->contract;
}

Result<IsolationExplanation> VirtualizationRuntime::explain_isolation(VirtualAcceleratorId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.virtuals.find(id);
  if (it == impl_->state.virtuals.end()) {
    return Status(StatusCode::NotFound, "virtual accelerator " + id.str() + " is not known");
  }
  const VirtualAcceleratorRecord& record = it->second;
  IsolationExplanation explanation;
  explanation.id = record.id;
  explanation.generation = record.generation;
  explanation.isolation_class = record.isolation_class;
  explanation.multiplexing = record.multiplexing;
  const auto backing = impl_->state.backings.find(record.backing);
  if (backing != impl_->state.backings.end()) {
    explanation.provenance = backing->second.provenance;
    explanation.mechanism = backing->second.mechanism;
  } else {
    explanation.provenance = Provenance::Unknown;
    explanation.mechanism = "no-backing";
  }

  for (IsolationDimension dimension : all_isolation_dimensions()) {
    IsolationClaim claim;
    const IsolationClaim* existing = record.isolation.find(dimension);
    if (existing != nullptr) {
      claim = *existing;
    } else {
      claim.dimension = dimension;
      claim.state = IsolationState::Unknown;
      claim.mechanism = explanation.mechanism;
      claim.rationale = "no evidence-backed claim is recorded for this dimension";
    }
    if (claim.mechanism.empty()) claim.mechanism = explanation.mechanism;
    if (claim.rationale.empty()) claim.rationale = std::string(isolation_state_meaning(claim.state));
    explanation.claims.push_back(claim);
    switch (claim.state) {
      case IsolationState::Isolated:
        explanation.isolated.push_back(claim);
        break;
      case IsolationState::Partial:
        explanation.partial.push_back(claim);
        break;
      case IsolationState::Shared:
        explanation.shared.push_back(claim);
        break;
      case IsolationState::Unknown:
        explanation.unknown.push_back(claim);
        break;
      case IsolationState::Unsupported:
      default:
        explanation.unsupported.push_back(claim);
        break;
    }
  }

  std::vector<IsolationRequirement> requirements = record.contract.required_isolation;
  requirements.insert(requirements.end(), impl_->state.policy.required_isolation.begin(),
                      impl_->state.policy.required_isolation.end());
  std::sort(requirements.begin(), requirements.end(),
            [](const IsolationRequirement& a, const IsolationRequirement& b) {
              return static_cast<std::uint8_t>(a.dimension) < static_cast<std::uint8_t>(b.dimension);
            });
  requirements.erase(std::unique(requirements.begin(), requirements.end(),
                                 [](const IsolationRequirement& a, const IsolationRequirement& b) {
                                   return a.dimension == b.dimension;
                                 }),
                     requirements.end());
  const IsolationEvaluation evaluation = evaluate_isolation(record.isolation, requirements);
  explanation.unmet_requirements = evaluation.unmet;
  explanation.satisfies_policy = evaluation.satisfied;
  return explanation;
}

Result<MigrationExplanation> VirtualizationRuntime::explain_migration(VirtualAcceleratorId id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->state.virtuals.find(id);
  if (it == impl_->state.virtuals.end()) {
    return Status(StatusCode::NotFound, "virtual accelerator " + id.str() + " is not known");
  }
  MigrationExplanation explanation;
  explanation.id = id;
  const MigrationCapability capability = migration_capability(impl_->state.policy, it->second.contract);
  explanation.supported = capability.supported;
  explanation.klass = capability.supported ? capability.klass : MigrationClass::Unsupported;
  explanation.reason = capability.reason;
  explanation.state_transfer_required = false;
  explanation.live_state_movement = false;
  const auto migration = impl_->state.migrations.find(it->second.migration);
  explanation.has_active_migration = migration != impl_->state.migrations.end() &&
                                     !migration_state_is_terminal(migration->second.state);
  if (migration != impl_->state.migrations.end()) explanation.state = migration->second.state;
  if (!it->second.backing.valid()) {
    explanation.supported = false;
    explanation.klass = MigrationClass::Unsupported;
    explanation.reason = "migration requires an authoritative source backing assignment";
  }
  return explanation;
}

std::vector<Decision> VirtualizationRuntime::explain_decisions(VirtualAcceleratorId id, std::size_t limit) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<Decision> out;
  for (auto it = impl_->state.decisions.rbegin(); it != impl_->state.decisions.rend(); ++it) {
    if (it->virtual_id != id) continue;
    out.push_back(*it);
    if (out.size() >= limit) break;
  }
  return out;
}

std::vector<AuditEntry> VirtualizationRuntime::audit_tail(std::size_t limit) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<AuditEntry> out;
  const std::size_t take = std::min(limit, impl_->state.audit.size());
  for (std::size_t i = impl_->state.audit.size() - take; i < impl_->state.audit.size(); ++i) {
    out.push_back(impl_->state.audit[i]);
  }
  return out;
}

AccountingCounters VirtualizationRuntime::accounting() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->state.accounting;
}

AuditReport VirtualizationRuntime::audit() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  AuditReport report = run_invariant_audit(impl_->state);
  report.state_fingerprint = av::state_fingerprint(impl_->state);
  report.epoch = impl_->state.epoch.value();
  return report;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------
Status VirtualizationRuntime::flush() {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (impl.store == nullptr) return Status{};
  return impl.store->flush();
}

Status VirtualizationRuntime::compact() {
  auto& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (impl.store == nullptr) return Status{};
  return impl.store->compact(impl.state);
}

Result<VirtualizationState> VirtualizationRuntime::snapshot_state() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->state;
}

std::string VirtualizationRuntime::snapshot_text() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return render_snapshot(impl_->state);
}

std::uint64_t VirtualizationRuntime::state_fingerprint() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return av::state_fingerprint(impl_->state);
}

bool VirtualizationRuntime::store_present() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->store != nullptr && impl_->store->present();
}

std::string VirtualizationRuntime::store_description() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->store == nullptr ? std::string{"no-store"} : impl_->store->describe();
}

std::uint64_t VirtualizationRuntime::persistence_bytes() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->store == nullptr ? 0 : impl_->store->bytes_written();
}

std::uint64_t VirtualizationRuntime::persistence_writes() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->store == nullptr ? 0 : impl_->store->write_count();
}

std::size_t VirtualizationRuntime::pending_persistence_changes() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->store == nullptr ? 0 : impl_->store->pending_changes();
}

}  // namespace av
