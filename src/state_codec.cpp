// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Aggregate and per-record codecs for the durable virtualization state.
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "av/codec.hpp"
#include "av/hash.hpp"
#include "av/model.hpp"
#include "av/persistence.hpp"

namespace av {
namespace {

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

Result<std::uint64_t> read_id(Decoder& in) { return in.u64(); }

}  // namespace

// ---- header --------------------------------------------------------------

void encode_header(Encoder& out, const VirtualizationState& state) {
  out.u32(state.schema);
  out.u64(state.next_sequence);
  out.u64(state.epoch.value());
  out.u64(state.policy_generation.value());
  encode_policy(out, state.policy);
  out.u64(state.accounting.coordinator_boots);
  out.u64(state.accounting.agent_boots);
  out.u64(state.accounting.physical_registered);
  out.u64(state.accounting.physical_lost);
  out.u64(state.accounting.virtual_created);
  out.u64(state.accounting.virtual_retired);
  out.u64(state.accounting.virtual_active);
  out.u64(state.accounting.leases_issued);
  out.u64(state.accounting.leases_renewed);
  out.u64(state.accounting.leases_revoked);
  out.u64(state.accounting.leases_fenced);
  out.u64(state.accounting.attachments_active);
  out.u64(state.accounting.peak_attachments_active);
  out.u64(state.accounting.detaches);
  out.u64(state.accounting.backing_assignments);
  out.u64(state.accounting.backing_replacements);
  out.u64(state.accounting.backing_revocations);
  out.u64(state.accounting.migrations_planned);
  out.u64(state.accounting.migrations_prepared);
  out.u64(state.accounting.migrations_committed);
  out.u64(state.accounting.migrations_aborted);
  out.u64(state.accounting.stale_authority_refusals);
  out.u64(state.accounting.authority_refusals);
  out.u64(state.accounting.lifecycle_refusals);
  out.u64(state.accounting.contract_violation_refusals);
  out.u64(state.accounting.isolation_refusals);
  out.u64(state.accounting.capability_refusals);
  out.u64(state.accounting.oversubscription_denials);
  out.u64(state.accounting.protocol_violations);
  out.u64(state.accounting.duplicate_request_refusals);
  out.u64(state.accounting.policy_updates);
  out.u64(state.accounting.evidence_records);
  out.u64(state.accounting.allocation_operations);
  out.u64(state.accounting.kernel_operations);
  out.u64(state.accounting.bytes_allocated_current);
  out.u64(state.accounting.bytes_allocated_peak);
  out.u64(state.accounting.persistence_writes);
  out.u64(state.accounting.persistence_bytes);
  out.u64(state.accounting.persistence_compactions);
}

Result<VirtualizationState> decode_header(Decoder& in) {
  VirtualizationState state;
  auto schema = in.u32();
  if (!schema.ok()) return schema.status();
  state.schema = *schema;
  auto sequence = in.u64();
  if (!sequence.ok()) return sequence.status();
  state.next_sequence = *sequence;
  auto epoch = in.u64();
  if (!epoch.ok()) return epoch.status();
  state.epoch = CoordinatorEpoch::from_value(*epoch);
  auto policy_generation = in.u64();
  if (!policy_generation.ok()) return policy_generation.status();
  state.policy_generation = PolicyGeneration::from_value(*policy_generation);
  auto policy = decode_policy(in);
  if (!policy.ok()) return policy.status();
  state.policy = policy.take();

  std::uint64_t* counters[] = {
      &state.accounting.coordinator_boots,
      &state.accounting.agent_boots,
      &state.accounting.physical_registered,
      &state.accounting.physical_lost,
      &state.accounting.virtual_created,
      &state.accounting.virtual_retired,
      &state.accounting.virtual_active,
      &state.accounting.leases_issued,
      &state.accounting.leases_renewed,
      &state.accounting.leases_revoked,
      &state.accounting.leases_fenced,
      &state.accounting.attachments_active,
      &state.accounting.peak_attachments_active,
      &state.accounting.detaches,
      &state.accounting.backing_assignments,
      &state.accounting.backing_replacements,
      &state.accounting.backing_revocations,
      &state.accounting.migrations_planned,
      &state.accounting.migrations_prepared,
      &state.accounting.migrations_committed,
      &state.accounting.migrations_aborted,
      &state.accounting.stale_authority_refusals,
      &state.accounting.authority_refusals,
      &state.accounting.lifecycle_refusals,
      &state.accounting.contract_violation_refusals,
      &state.accounting.isolation_refusals,
      &state.accounting.capability_refusals,
      &state.accounting.oversubscription_denials,
      &state.accounting.protocol_violations,
      &state.accounting.duplicate_request_refusals,
      &state.accounting.policy_updates,
      &state.accounting.evidence_records,
      &state.accounting.allocation_operations,
      &state.accounting.kernel_operations,
      &state.accounting.bytes_allocated_current,
      &state.accounting.bytes_allocated_peak,
      &state.accounting.persistence_writes,
      &state.accounting.persistence_bytes,
      &state.accounting.persistence_compactions,
  };
  for (std::uint64_t* counter : counters) {
    auto value = in.u64();
    if (!value.ok()) return value.status();
    *counter = *value;
  }
  return state;
}

// ---- tenant --------------------------------------------------------------

void encode_tenant(Encoder& out, const TenantRecord& record) {
  out.u64(record.id.value());
  out.u64(record.generation.value());
  out.str(record.name);
  out.str(record.external_subject);
  out.i64(record.created_at);
  out.i64(record.updated_at);
  out.boolean(record.fenced);
  out.str(record.fence_reason);
  out.u32(record.active_attachments);
  encode_list(out, record.owned, [](Encoder& e, const VirtualAcceleratorId& id) { e.u64(id.value()); });
}

Result<TenantRecord> decode_tenant(Decoder& in) {
  TenantRecord record;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  record.id = TenantId::from_value(*id);
  auto generation = read_id(in);
  if (!generation.ok()) return generation.status();
  record.generation = TenantGeneration::from_value(*generation);
  auto name = in.str();
  if (!name.ok()) return name.status();
  record.name = name.take();
  auto subject = in.str();
  if (!subject.ok()) return subject.status();
  record.external_subject = subject.take();
  auto created = in.i64();
  if (!created.ok()) return created.status();
  record.created_at = *created;
  auto updated = in.i64();
  if (!updated.ok()) return updated.status();
  record.updated_at = *updated;
  auto fenced = in.boolean();
  if (!fenced.ok()) return fenced.status();
  record.fenced = *fenced;
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  record.fence_reason = reason.take();
  auto attachments = in.u32();
  if (!attachments.ok()) return attachments.status();
  record.active_attachments = *attachments;
  auto owned = decode_list<VirtualAcceleratorId>(in, 1u << 22, [](Decoder& d) -> Result<VirtualAcceleratorId> {
    auto raw = read_id(d);
    if (!raw.ok()) return raw.status();
    return VirtualAcceleratorId::from_value(*raw);
  });
  if (!owned.ok()) return owned.status();
  record.owned = owned.take();
  std::sort(record.owned.begin(), record.owned.end());
  return record;
}

// ---- physical ------------------------------------------------------------

void encode_physical(Encoder& out, const PhysicalDeviceRecord& record) {
  out.u64(record.id.value());
  out.u64(record.generation.value());
  out.u64(record.agent.value());
  out.u64(record.boot.value());
  out.str(record.stable_key);
  out.str(record.vendor);
  out.str(record.model);
  out.str(record.driver_version);
  out.str(record.architecture);
  out.u8(static_cast<std::uint8_t>(record.provenance));
  out.u64(record.memory_total_bytes);
  out.u32(record.compute_units);
  out.u32(record.compute_capability_major);
  out.u32(record.compute_capability_minor);
  out.str(record.mechanism);
  out.boolean(record.hardware_partition_capable);
  out.boolean(record.virtual_function_capable);
  out.boolean(record.mig_capable);
  out.i64(record.registered_at);
  out.i64(record.evidence_at);
  out.u64(record.evidence.value());
  out.u64(record.evidence_generation.value());
  out.boolean(record.present);
  encode_list(out, record.backings, [](Encoder& e, const BackingId& id) { e.u64(id.value()); });
}

Result<PhysicalDeviceRecord> decode_physical(Decoder& in) {
  PhysicalDeviceRecord record;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  record.id = PhysicalDeviceId::from_value(*id);
  auto generation = read_id(in);
  if (!generation.ok()) return generation.status();
  record.generation = PhysicalDeviceGeneration::from_value(*generation);
  auto agent = read_id(in);
  if (!agent.ok()) return agent.status();
  record.agent = AgentId::from_value(*agent);
  auto boot = read_id(in);
  if (!boot.ok()) return boot.status();
  record.boot = AgentBootId::from_value(*boot);
  auto stable_key = in.str();
  if (!stable_key.ok()) return stable_key.status();
  record.stable_key = stable_key.take();
  auto vendor = in.str();
  if (!vendor.ok()) return vendor.status();
  record.vendor = vendor.take();
  auto model = in.str();
  if (!model.ok()) return model.status();
  record.model = model.take();
  auto driver = in.str();
  if (!driver.ok()) return driver.status();
  record.driver_version = driver.take();
  auto architecture = in.str();
  if (!architecture.ok()) return architecture.status();
  record.architecture = architecture.take();
  auto provenance = in.u8();
  if (!provenance.ok()) return provenance.status();
  if (*provenance > static_cast<std::uint8_t>(Provenance::Unsupported)) {
    return Status(StatusCode::CorruptState, "stored provenance value is outside its domain");
  }
  record.provenance = static_cast<Provenance>(*provenance);
  auto memory = in.u64();
  if (!memory.ok()) return memory.status();
  record.memory_total_bytes = *memory;
  auto units = in.u32();
  if (!units.ok()) return units.status();
  record.compute_units = *units;
  auto major = in.u32();
  if (!major.ok()) return major.status();
  record.compute_capability_major = *major;
  auto minor = in.u32();
  if (!minor.ok()) return minor.status();
  record.compute_capability_minor = *minor;
  auto mechanism = in.str();
  if (!mechanism.ok()) return mechanism.status();
  record.mechanism = mechanism.take();
  auto hw = in.boolean();
  if (!hw.ok()) return hw.status();
  record.hardware_partition_capable = *hw;
  auto vf = in.boolean();
  if (!vf.ok()) return vf.status();
  record.virtual_function_capable = *vf;
  auto mig = in.boolean();
  if (!mig.ok()) return mig.status();
  record.mig_capable = *mig;
  auto registered = in.i64();
  if (!registered.ok()) return registered.status();
  record.registered_at = *registered;
  auto evidence_at = in.i64();
  if (!evidence_at.ok()) return evidence_at.status();
  record.evidence_at = *evidence_at;
  auto evidence = read_id(in);
  if (!evidence.ok()) return evidence.status();
  record.evidence = EvidenceId::from_value(*evidence);
  auto evidence_generation = read_id(in);
  if (!evidence_generation.ok()) return evidence_generation.status();
  record.evidence_generation = EvidenceGeneration::from_value(*evidence_generation);
  auto present = in.boolean();
  if (!present.ok()) return present.status();
  record.present = *present;
  auto backings = decode_list<BackingId>(in, 1u << 22, [](Decoder& d) -> Result<BackingId> {
    auto raw = read_id(d);
    if (!raw.ok()) return raw.status();
    return BackingId::from_value(*raw);
  });
  if (!backings.ok()) return backings.status();
  record.backings = backings.take();
  std::sort(record.backings.begin(), record.backings.end());
  return record;
}

// ---- backing -------------------------------------------------------------

void encode_backing(Encoder& out, const BackingRecord& record) {
  out.u64(record.id.value());
  out.u64(record.generation.value());
  out.u64(record.physical.value());
  out.u64(record.physical_generation.value());
  out.u8(static_cast<std::uint8_t>(record.klass));
  out.u8(static_cast<std::uint8_t>(record.provenance));
  out.str(record.label);
  out.str(record.mechanism);
  out.u8(static_cast<std::uint8_t>(record.multiplexing));
  out.u8(static_cast<std::uint8_t>(record.isolation_class));
  encode_isolation_profile(out, record.isolation);
  encode_capability_surface(out, record.capabilities);
  out.u64(record.capacity_bytes);
  out.u32(record.compute_units);
  out.u32(record.capability_rank);
  out.u64(record.evidence.value());
  out.u64(record.evidence_generation.value());
  out.i64(record.evidence_at);
  out.boolean(record.evidence_fresh);
  out.boolean(record.available);
  out.boolean(record.exclusive);
  out.boolean(record.externally_lifecycle_managed);
  out.str(record.external_partition_ref);
  out.u64(record.assigned_to.value());
  out.u64(record.active_assignment.value());
  out.u64(record.assigned_generation.value());
}

Result<BackingRecord> decode_backing(Decoder& in) {
  BackingRecord record;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  record.id = BackingId::from_value(*id);
  auto generation = read_id(in);
  if (!generation.ok()) return generation.status();
  record.generation = BackingGeneration::from_value(*generation);
  auto physical = read_id(in);
  if (!physical.ok()) return physical.status();
  record.physical = PhysicalDeviceId::from_value(*physical);
  auto physical_generation = read_id(in);
  if (!physical_generation.ok()) return physical_generation.status();
  record.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto klass = in.u8();
  if (!klass.ok()) return klass.status();
  if (*klass > static_cast<std::uint8_t>(BackingClass::SyntheticMigratable)) {
    return Status(StatusCode::CorruptState, "stored backing class is outside its domain");
  }
  record.klass = static_cast<BackingClass>(*klass);
  auto provenance = in.u8();
  if (!provenance.ok()) return provenance.status();
  if (*provenance > static_cast<std::uint8_t>(Provenance::Unsupported)) {
    return Status(StatusCode::CorruptState, "stored provenance is outside its domain");
  }
  record.provenance = static_cast<Provenance>(*provenance);
  auto label = in.str();
  if (!label.ok()) return label.status();
  record.label = label.take();
  auto mechanism = in.str();
  if (!mechanism.ok()) return mechanism.status();
  record.mechanism = mechanism.take();
  auto multiplexing = in.u8();
  if (!multiplexing.ok()) return multiplexing.status();
  if (*multiplexing > static_cast<std::uint8_t>(MultiplexingMode::Synthetic)) {
    return Status(StatusCode::CorruptState, "stored multiplexing mode is outside its domain");
  }
  record.multiplexing = static_cast<MultiplexingMode>(*multiplexing);
  auto isolation_class = in.u8();
  if (!isolation_class.ok()) return isolation_class.status();
  if (*isolation_class > static_cast<std::uint8_t>(IsolationClass::Synthetic)) {
    return Status(StatusCode::CorruptState, "stored isolation class is outside its domain");
  }
  record.isolation_class = static_cast<IsolationClass>(*isolation_class);
  auto isolation = decode_isolation_profile(in);
  if (!isolation.ok()) return isolation.status();
  record.isolation = isolation.take();
  auto capabilities = decode_capability_surface(in);
  if (!capabilities.ok()) return capabilities.status();
  record.capabilities = capabilities.take();
  auto capacity = in.u64();
  if (!capacity.ok()) return capacity.status();
  record.capacity_bytes = *capacity;
  auto units = in.u32();
  if (!units.ok()) return units.status();
  record.compute_units = *units;
  auto rank = in.u32();
  if (!rank.ok()) return rank.status();
  record.capability_rank = *rank;
  auto evidence = read_id(in);
  if (!evidence.ok()) return evidence.status();
  record.evidence = EvidenceId::from_value(*evidence);
  auto evidence_generation = read_id(in);
  if (!evidence_generation.ok()) return evidence_generation.status();
  record.evidence_generation = EvidenceGeneration::from_value(*evidence_generation);
  auto evidence_at = in.i64();
  if (!evidence_at.ok()) return evidence_at.status();
  record.evidence_at = *evidence_at;
  auto evidence_fresh = in.boolean();
  if (!evidence_fresh.ok()) return evidence_fresh.status();
  record.evidence_fresh = *evidence_fresh;
  auto available = in.boolean();
  if (!available.ok()) return available.status();
  record.available = *available;
  auto exclusive = in.boolean();
  if (!exclusive.ok()) return exclusive.status();
  record.exclusive = *exclusive;
  auto managed = in.boolean();
  if (!managed.ok()) return managed.status();
  record.externally_lifecycle_managed = *managed;
  auto reference = in.str();
  if (!reference.ok()) return reference.status();
  record.external_partition_ref = reference.take();
  auto assigned_to = read_id(in);
  if (!assigned_to.ok()) return assigned_to.status();
  record.assigned_to = VirtualAcceleratorId::from_value(*assigned_to);
  auto active_assignment = read_id(in);
  if (!active_assignment.ok()) return active_assignment.status();
  record.active_assignment = BackingAssignmentId::from_value(*active_assignment);
  auto assigned_generation = read_id(in);
  if (!assigned_generation.ok()) return assigned_generation.status();
  record.assigned_generation = BackingGeneration::from_value(*assigned_generation);
  return record;
}

// ---- virtual -------------------------------------------------------------

void encode_backing_history(Encoder& out, const BackingHistoryEntry& entry) {
  out.u64(entry.assignment.value());
  out.u64(entry.backing.value());
  out.u64(entry.backing_generation.value());
  out.u64(entry.physical.value());
  out.u64(entry.physical_generation.value());
  out.u8(static_cast<std::uint8_t>(entry.klass));
  out.u8(static_cast<std::uint8_t>(entry.multiplexing));
  out.i64(entry.from);
  out.i64(entry.to);
  out.boolean(entry.current);
  out.str(entry.reason);
}

Result<BackingHistoryEntry> decode_backing_history(Decoder& in) {
  BackingHistoryEntry entry;
  auto assignment = read_id(in);
  if (!assignment.ok()) return assignment.status();
  entry.assignment = BackingAssignmentId::from_value(*assignment);
  auto backing = read_id(in);
  if (!backing.ok()) return backing.status();
  entry.backing = BackingId::from_value(*backing);
  auto backing_generation = read_id(in);
  if (!backing_generation.ok()) return backing_generation.status();
  entry.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto physical = read_id(in);
  if (!physical.ok()) return physical.status();
  entry.physical = PhysicalDeviceId::from_value(*physical);
  auto physical_generation = read_id(in);
  if (!physical_generation.ok()) return physical_generation.status();
  entry.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto klass = in.u8();
  if (!klass.ok()) return klass.status();
  if (*klass > static_cast<std::uint8_t>(BackingClass::SyntheticMigratable)) {
    return Status(StatusCode::CorruptState, "stored backing history class is outside its domain");
  }
  entry.klass = static_cast<BackingClass>(*klass);
  auto multiplexing = in.u8();
  if (!multiplexing.ok()) return multiplexing.status();
  if (*multiplexing > static_cast<std::uint8_t>(MultiplexingMode::Synthetic)) {
    return Status(StatusCode::CorruptState, "stored backing history multiplexing is outside its domain");
  }
  entry.multiplexing = static_cast<MultiplexingMode>(*multiplexing);
  auto from = in.i64();
  if (!from.ok()) return from.status();
  entry.from = *from;
  auto to = in.i64();
  if (!to.ok()) return to.status();
  entry.to = *to;
  auto current = in.boolean();
  if (!current.ok()) return current.status();
  entry.current = *current;
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  entry.reason = reason.take();
  return entry;
}

void encode_virtual(Encoder& out, const VirtualAcceleratorRecord& record) {
  out.u64(record.id.value());
  out.u64(record.generation.value());
  out.str(record.name);
  out.u64(record.owner.value());
  out.u64(record.owner_generation.value());
  out.u8(static_cast<std::uint8_t>(record.state));
  out.u64(record.state_generation.value());
  out.str(record.state_reason);
  encode_contract(out, record.contract);
  encode_projection(out, record.projection);
  out.u64(record.assignment.value());
  out.u64(record.backing.value());
  out.u64(record.backing_generation.value());
  out.u64(record.physical.value());
  out.u64(record.physical_generation.value());
  out.u8(static_cast<std::uint8_t>(record.backing_class));
  out.u8(static_cast<std::uint8_t>(record.multiplexing));
  out.u8(static_cast<std::uint8_t>(record.isolation_class));
  encode_isolation_profile(out, record.isolation);
  out.u64(record.policy_generation.value());
  out.u64(record.epoch.value());
  out.u64(record.migration.value());
  out.u64(record.migration_generation.value());
  out.i64(record.created_at);
  out.i64(record.updated_at);
  out.i64(record.retired_at);
  out.str(record.retirement_reason);
  out.u64(record.allocated_bytes);
  out.u64(record.peak_allocated_bytes);
  out.u64(record.allocation_operations);
  out.u64(record.kernel_operations);
  out.u32(record.active_attachments);
  encode_list(out, record.leases, [](Encoder& e, const LeaseId& id) { e.u64(id.value()); });
  encode_list(out, record.backing_history, encode_backing_history);
}

Result<VirtualAcceleratorRecord> decode_virtual(Decoder& in) {
  VirtualAcceleratorRecord record;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  record.id = VirtualAcceleratorId::from_value(*id);
  auto generation = read_id(in);
  if (!generation.ok()) return generation.status();
  record.generation = VirtualAcceleratorGeneration::from_value(*generation);
  auto name = in.str();
  if (!name.ok()) return name.status();
  record.name = name.take();
  auto owner = read_id(in);
  if (!owner.ok()) return owner.status();
  record.owner = TenantId::from_value(*owner);
  auto owner_generation = read_id(in);
  if (!owner_generation.ok()) return owner_generation.status();
  record.owner_generation = TenantGeneration::from_value(*owner_generation);
  auto state = in.u8();
  if (!state.ok()) return state.status();
  if (*state > static_cast<std::uint8_t>(VirtualLifecycleState::Retired)) {
    return Status(StatusCode::CorruptState, "stored lifecycle state is outside its domain");
  }
  record.state = static_cast<VirtualLifecycleState>(*state);
  auto state_generation = read_id(in);
  if (!state_generation.ok()) return state_generation.status();
  record.state_generation = VirtualAcceleratorGeneration::from_value(*state_generation);
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  record.state_reason = reason.take();
  auto contract = decode_contract(in);
  if (!contract.ok()) return contract.status();
  record.contract = contract.take();
  auto projection = decode_projection(in);
  if (!projection.ok()) return projection.status();
  record.projection = projection.take();
  auto assignment = read_id(in);
  if (!assignment.ok()) return assignment.status();
  record.assignment = BackingAssignmentId::from_value(*assignment);
  auto backing = read_id(in);
  if (!backing.ok()) return backing.status();
  record.backing = BackingId::from_value(*backing);
  auto backing_generation = read_id(in);
  if (!backing_generation.ok()) return backing_generation.status();
  record.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto physical = read_id(in);
  if (!physical.ok()) return physical.status();
  record.physical = PhysicalDeviceId::from_value(*physical);
  auto physical_generation = read_id(in);
  if (!physical_generation.ok()) return physical_generation.status();
  record.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto backing_class = in.u8();
  if (!backing_class.ok()) return backing_class.status();
  if (*backing_class > static_cast<std::uint8_t>(BackingClass::SyntheticMigratable)) {
    return Status(StatusCode::CorruptState, "stored backing class is outside its domain");
  }
  record.backing_class = static_cast<BackingClass>(*backing_class);
  auto multiplexing = in.u8();
  if (!multiplexing.ok()) return multiplexing.status();
  if (*multiplexing > static_cast<std::uint8_t>(MultiplexingMode::Synthetic)) {
    return Status(StatusCode::CorruptState, "stored multiplexing mode is outside its domain");
  }
  record.multiplexing = static_cast<MultiplexingMode>(*multiplexing);
  auto isolation_class = in.u8();
  if (!isolation_class.ok()) return isolation_class.status();
  if (*isolation_class > static_cast<std::uint8_t>(IsolationClass::Synthetic)) {
    return Status(StatusCode::CorruptState, "stored isolation class is outside its domain");
  }
  record.isolation_class = static_cast<IsolationClass>(*isolation_class);
  auto isolation = decode_isolation_profile(in);
  if (!isolation.ok()) return isolation.status();
  record.isolation = isolation.take();
  auto policy_generation = read_id(in);
  if (!policy_generation.ok()) return policy_generation.status();
  record.policy_generation = PolicyGeneration::from_value(*policy_generation);
  auto epoch = read_id(in);
  if (!epoch.ok()) return epoch.status();
  record.epoch = CoordinatorEpoch::from_value(*epoch);
  auto migration = read_id(in);
  if (!migration.ok()) return migration.status();
  record.migration = MigrationId::from_value(*migration);
  auto migration_generation = read_id(in);
  if (!migration_generation.ok()) return migration_generation.status();
  record.migration_generation = MigrationGeneration::from_value(*migration_generation);
  auto created = in.i64();
  if (!created.ok()) return created.status();
  record.created_at = *created;
  auto updated = in.i64();
  if (!updated.ok()) return updated.status();
  record.updated_at = *updated;
  auto retired = in.i64();
  if (!retired.ok()) return retired.status();
  record.retired_at = *retired;
  auto retirement_reason = in.str();
  if (!retirement_reason.ok()) return retirement_reason.status();
  record.retirement_reason = retirement_reason.take();
  auto allocated = in.u64();
  if (!allocated.ok()) return allocated.status();
  record.allocated_bytes = *allocated;
  auto peak = in.u64();
  if (!peak.ok()) return peak.status();
  record.peak_allocated_bytes = *peak;
  auto allocation_ops = in.u64();
  if (!allocation_ops.ok()) return allocation_ops.status();
  record.allocation_operations = *allocation_ops;
  auto kernel_ops = in.u64();
  if (!kernel_ops.ok()) return kernel_ops.status();
  record.kernel_operations = *kernel_ops;
  auto attachments = in.u32();
  if (!attachments.ok()) return attachments.status();
  record.active_attachments = *attachments;
  auto leases = decode_list<LeaseId>(in, 1u << 22, [](Decoder& d) -> Result<LeaseId> {
    auto raw = read_id(d);
    if (!raw.ok()) return raw.status();
    return LeaseId::from_value(*raw);
  });
  if (!leases.ok()) return leases.status();
  record.leases = leases.take();
  std::sort(record.leases.begin(), record.leases.end());
  auto history = decode_list<BackingHistoryEntry>(in, 1u << 22, decode_backing_history);
  if (!history.ok()) return history.status();
  record.backing_history = history.take();
  return record;
}

// ---- lease ---------------------------------------------------------------

void encode_lease(Encoder& out, const LeaseRecord& record) {
  out.u64(record.id.value());
  out.u64(record.generation.value());
  out.u64(record.virtual_id.value());
  out.u64(record.virtual_generation.value());
  out.u64(record.tenant.value());
  out.u64(record.tenant_generation.value());
  out.u64(record.backing_generation.value());
  out.u64(record.physical_generation.value());
  out.u64(record.policy_generation.value());
  out.u64(record.epoch.value());
  out.u64(record.grant_request.value());
  out.u8(static_cast<std::uint8_t>(record.state));
  out.i64(record.granted_at);
  out.i64(record.renewed_at);
  out.i64(record.expires_at);
  out.i64(record.revoked_at);
  out.u32(record.renewals);
  out.str(record.reason);
}

Result<LeaseRecord> decode_lease(Decoder& in) {
  LeaseRecord record;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  record.id = LeaseId::from_value(*id);
  auto generation = read_id(in);
  if (!generation.ok()) return generation.status();
  record.generation = LeaseGeneration::from_value(*generation);
  auto virtual_id = read_id(in);
  if (!virtual_id.ok()) return virtual_id.status();
  record.virtual_id = VirtualAcceleratorId::from_value(*virtual_id);
  auto virtual_generation = read_id(in);
  if (!virtual_generation.ok()) return virtual_generation.status();
  record.virtual_generation = VirtualAcceleratorGeneration::from_value(*virtual_generation);
  auto tenant = read_id(in);
  if (!tenant.ok()) return tenant.status();
  record.tenant = TenantId::from_value(*tenant);
  auto tenant_generation = read_id(in);
  if (!tenant_generation.ok()) return tenant_generation.status();
  record.tenant_generation = TenantGeneration::from_value(*tenant_generation);
  auto backing_generation = read_id(in);
  if (!backing_generation.ok()) return backing_generation.status();
  record.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto physical_generation = read_id(in);
  if (!physical_generation.ok()) return physical_generation.status();
  record.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto policy_generation = read_id(in);
  if (!policy_generation.ok()) return policy_generation.status();
  record.policy_generation = PolicyGeneration::from_value(*policy_generation);
  auto epoch = read_id(in);
  if (!epoch.ok()) return epoch.status();
  record.epoch = CoordinatorEpoch::from_value(*epoch);
  auto request = read_id(in);
  if (!request.ok()) return request.status();
  record.grant_request = RequestId::from_value(*request);
  auto state = in.u8();
  if (!state.ok()) return state.status();
  if (*state > static_cast<std::uint8_t>(LeaseState::Superseded)) {
    return Status(StatusCode::CorruptState, "stored lease state is outside its domain");
  }
  record.state = static_cast<LeaseState>(*state);
  auto granted = in.i64();
  if (!granted.ok()) return granted.status();
  record.granted_at = *granted;
  auto renewed = in.i64();
  if (!renewed.ok()) return renewed.status();
  record.renewed_at = *renewed;
  auto expires = in.i64();
  if (!expires.ok()) return expires.status();
  record.expires_at = *expires;
  auto revoked = in.i64();
  if (!revoked.ok()) return revoked.status();
  record.revoked_at = *revoked;
  auto renewals = in.u32();
  if (!renewals.ok()) return renewals.status();
  record.renewals = *renewals;
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  record.reason = reason.take();
  return record;
}

// ---- assignment ----------------------------------------------------------

void encode_assignment(Encoder& out, const BackingAssignment& record) {
  out.u64(record.id.value());
  out.u64(record.virtual_id.value());
  out.u64(record.virtual_generation.value());
  out.u64(record.backing.value());
  out.u64(record.backing_generation.value());
  out.u64(record.physical.value());
  out.u64(record.physical_generation.value());
  out.u64(record.tenant.value());
  out.u64(record.tenant_generation.value());
  out.u64(record.policy_generation.value());
  out.u64(record.contract_generation.value());
  out.u64(record.projection_generation.value());
  out.u64(record.epoch.value());
  out.u8(static_cast<std::uint8_t>(record.state));
  out.boolean(record.authoritative);
  out.i64(record.proposed_at);
  out.i64(record.committed_at);
  out.i64(record.revoked_at);
  out.str(record.reason);
}

Result<BackingAssignment> decode_assignment(Decoder& in) {
  BackingAssignment record;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  record.id = BackingAssignmentId::from_value(*id);
  auto virtual_id = read_id(in);
  if (!virtual_id.ok()) return virtual_id.status();
  record.virtual_id = VirtualAcceleratorId::from_value(*virtual_id);
  auto virtual_generation = read_id(in);
  if (!virtual_generation.ok()) return virtual_generation.status();
  record.virtual_generation = VirtualAcceleratorGeneration::from_value(*virtual_generation);
  auto backing = read_id(in);
  if (!backing.ok()) return backing.status();
  record.backing = BackingId::from_value(*backing);
  auto backing_generation = read_id(in);
  if (!backing_generation.ok()) return backing_generation.status();
  record.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto physical = read_id(in);
  if (!physical.ok()) return physical.status();
  record.physical = PhysicalDeviceId::from_value(*physical);
  auto physical_generation = read_id(in);
  if (!physical_generation.ok()) return physical_generation.status();
  record.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto tenant = read_id(in);
  if (!tenant.ok()) return tenant.status();
  record.tenant = TenantId::from_value(*tenant);
  auto tenant_generation = read_id(in);
  if (!tenant_generation.ok()) return tenant_generation.status();
  record.tenant_generation = TenantGeneration::from_value(*tenant_generation);
  auto policy_generation = read_id(in);
  if (!policy_generation.ok()) return policy_generation.status();
  record.policy_generation = PolicyGeneration::from_value(*policy_generation);
  auto contract_generation = read_id(in);
  if (!contract_generation.ok()) return contract_generation.status();
  record.contract_generation = ResourceContractGeneration::from_value(*contract_generation);
  auto projection_generation = read_id(in);
  if (!projection_generation.ok()) return projection_generation.status();
  record.projection_generation = CapabilityProjectionGeneration::from_value(*projection_generation);
  auto epoch = read_id(in);
  if (!epoch.ok()) return epoch.status();
  record.epoch = CoordinatorEpoch::from_value(*epoch);
  auto state = in.u8();
  if (!state.ok()) return state.status();
  if (*state > static_cast<std::uint8_t>(AssignmentState::Failed)) {
    return Status(StatusCode::CorruptState, "stored assignment state is outside its domain");
  }
  record.state = static_cast<AssignmentState>(*state);
  auto authoritative = in.boolean();
  if (!authoritative.ok()) return authoritative.status();
  record.authoritative = *authoritative;
  auto proposed = in.i64();
  if (!proposed.ok()) return proposed.status();
  record.proposed_at = *proposed;
  auto committed = in.i64();
  if (!committed.ok()) return committed.status();
  record.committed_at = *committed;
  auto revoked = in.i64();
  if (!revoked.ok()) return revoked.status();
  record.revoked_at = *revoked;
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  record.reason = reason.take();
  return record;
}

// ---- migration -----------------------------------------------------------

void encode_migration(Encoder& out, const MigrationRecord& record) {
  encode_migration_plan(out, record.plan);
  out.u8(static_cast<std::uint8_t>(record.state));
  out.boolean(record.source_authoritative);
  out.boolean(record.destination_authoritative);
  out.boolean(record.state_transfer_performed);
  out.u64(record.source_assignment.value());
  out.u64(record.destination_assignment.value());
  out.u64(record.destination_projection_generation.value());
  out.i64(record.planned_at);
  out.i64(record.prepared_at);
  out.i64(record.committed_at);
  out.i64(record.completed_at);
  out.str(record.note);
}

Result<MigrationRecord> decode_migration(Decoder& in) {
  MigrationRecord record;
  auto plan = decode_migration_plan(in);
  if (!plan.ok()) return plan.status();
  record.plan = plan.take();
  auto state = in.u8();
  if (!state.ok()) return state.status();
  if (*state > static_cast<std::uint8_t>(MigrationState::Failed)) {
    return Status(StatusCode::CorruptState, "stored migration state is outside its domain");
  }
  record.state = static_cast<MigrationState>(*state);
  auto source = in.boolean();
  if (!source.ok()) return source.status();
  record.source_authoritative = *source;
  auto destination = in.boolean();
  if (!destination.ok()) return destination.status();
  record.destination_authoritative = *destination;
  auto transfer = in.boolean();
  if (!transfer.ok()) return transfer.status();
  record.state_transfer_performed = *transfer;
  auto source_assignment = read_id(in);
  if (!source_assignment.ok()) return source_assignment.status();
  record.source_assignment = BackingAssignmentId::from_value(*source_assignment);
  auto destination_assignment = read_id(in);
  if (!destination_assignment.ok()) return destination_assignment.status();
  record.destination_assignment = BackingAssignmentId::from_value(*destination_assignment);
  auto projection = read_id(in);
  if (!projection.ok()) return projection.status();
  record.destination_projection_generation = CapabilityProjectionGeneration::from_value(*projection);
  auto planned = in.i64();
  if (!planned.ok()) return planned.status();
  record.planned_at = *planned;
  auto prepared = in.i64();
  if (!prepared.ok()) return prepared.status();
  record.prepared_at = *prepared;
  auto committed = in.i64();
  if (!committed.ok()) return committed.status();
  record.committed_at = *committed;
  auto completed = in.i64();
  if (!completed.ok()) return completed.status();
  record.completed_at = *completed;
  auto note = in.str();
  if (!note.ok()) return note.status();
  record.note = note.take();
  return record;
}

// ---- evidence / audit / decision / request -------------------------------

void encode_evidence(Encoder& out, const EvidenceRecord& record) {
  out.u64(record.id.value());
  out.u64(record.generation.value());
  out.u8(static_cast<std::uint8_t>(record.kind));
  out.u8(static_cast<std::uint8_t>(record.provenance));
  out.u64(record.agent.value());
  out.u64(record.boot.value());
  out.u64(record.physical.value());
  out.u64(record.physical_generation.value());
  out.u64(record.backing.value());
  out.u64(record.backing_generation.value());
  out.i64(record.produced_at);
  out.u64(record.payload_fingerprint);
  out.str(record.mechanism);
  out.str(record.detail);
}

Result<EvidenceRecord> decode_evidence(Decoder& in) {
  EvidenceRecord record;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  record.id = EvidenceId::from_value(*id);
  auto generation = read_id(in);
  if (!generation.ok()) return generation.status();
  record.generation = EvidenceGeneration::from_value(*generation);
  auto kind = in.u8();
  if (!kind.ok()) return kind.status();
  if (*kind > static_cast<std::uint8_t>(EvidenceKind::RecoveryRevalidation)) {
    return Status(StatusCode::CorruptState, "stored evidence kind is outside its domain");
  }
  record.kind = static_cast<EvidenceKind>(*kind);
  auto provenance = in.u8();
  if (!provenance.ok()) return provenance.status();
  if (*provenance > static_cast<std::uint8_t>(Provenance::Unsupported)) {
    return Status(StatusCode::CorruptState, "stored evidence provenance is outside its domain");
  }
  record.provenance = static_cast<Provenance>(*provenance);
  auto agent = read_id(in);
  if (!agent.ok()) return agent.status();
  record.agent = AgentId::from_value(*agent);
  auto boot = read_id(in);
  if (!boot.ok()) return boot.status();
  record.boot = AgentBootId::from_value(*boot);
  auto physical = read_id(in);
  if (!physical.ok()) return physical.status();
  record.physical = PhysicalDeviceId::from_value(*physical);
  auto physical_generation = read_id(in);
  if (!physical_generation.ok()) return physical_generation.status();
  record.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto backing = read_id(in);
  if (!backing.ok()) return backing.status();
  record.backing = BackingId::from_value(*backing);
  auto backing_generation = read_id(in);
  if (!backing_generation.ok()) return backing_generation.status();
  record.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto produced = in.i64();
  if (!produced.ok()) return produced.status();
  record.produced_at = *produced;
  auto fingerprint = in.u64();
  if (!fingerprint.ok()) return fingerprint.status();
  record.payload_fingerprint = *fingerprint;
  auto mechanism = in.str();
  if (!mechanism.ok()) return mechanism.status();
  record.mechanism = mechanism.take();
  auto detail = in.str();
  if (!detail.ok()) return detail.status();
  record.detail = detail.take();
  return record;
}

void encode_audit(Encoder& out, const AuditEntry& entry) {
  out.u64(entry.id.value());
  out.i64(entry.at);
  out.u8(static_cast<std::uint8_t>(entry.kind));
  out.str(entry.operation);
  out.u32(static_cast<std::uint32_t>(entry.outcome));
  out.str(entry.detail);
  out.u64(entry.epoch.value());
  out.u64(entry.virtual_id.value());
  out.u64(entry.virtual_generation.value());
  out.u64(entry.tenant.value());
  out.u64(entry.tenant_generation.value());
  out.u64(entry.backing.value());
  out.u64(entry.backing_generation.value());
  out.u64(entry.migration.value());
  out.u64(entry.migration_generation.value());
}

Result<AuditEntry> decode_audit(Decoder& in) {
  AuditEntry entry;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  entry.id = DecisionId::from_value(*id);
  auto at = in.i64();
  if (!at.ok()) return at.status();
  entry.at = *at;
  auto kind = in.u8();
  if (!kind.ok()) return kind.status();
  if (*kind > static_cast<std::uint8_t>(AuditKind::Persistence)) {
    return Status(StatusCode::CorruptState, "stored audit kind is outside its domain");
  }
  entry.kind = static_cast<AuditKind>(*kind);
  auto operation = in.str();
  if (!operation.ok()) return operation.status();
  entry.operation = operation.take();
  auto outcome = in.u32();
  if (!outcome.ok()) return outcome.status();
  entry.outcome = static_cast<StatusCode>(*outcome);
  auto detail = in.str();
  if (!detail.ok()) return detail.status();
  entry.detail = detail.take();
  auto epoch = read_id(in);
  if (!epoch.ok()) return epoch.status();
  entry.epoch = CoordinatorEpoch::from_value(*epoch);
  auto virtual_id = read_id(in);
  if (!virtual_id.ok()) return virtual_id.status();
  entry.virtual_id = VirtualAcceleratorId::from_value(*virtual_id);
  auto virtual_generation = read_id(in);
  if (!virtual_generation.ok()) return virtual_generation.status();
  entry.virtual_generation = VirtualAcceleratorGeneration::from_value(*virtual_generation);
  auto tenant = read_id(in);
  if (!tenant.ok()) return tenant.status();
  entry.tenant = TenantId::from_value(*tenant);
  auto tenant_generation = read_id(in);
  if (!tenant_generation.ok()) return tenant_generation.status();
  entry.tenant_generation = TenantGeneration::from_value(*tenant_generation);
  auto backing = read_id(in);
  if (!backing.ok()) return backing.status();
  entry.backing = BackingId::from_value(*backing);
  auto backing_generation = read_id(in);
  if (!backing_generation.ok()) return backing_generation.status();
  entry.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto migration = read_id(in);
  if (!migration.ok()) return migration.status();
  entry.migration = MigrationId::from_value(*migration);
  auto migration_generation = read_id(in);
  if (!migration_generation.ok()) return migration_generation.status();
  entry.migration_generation = MigrationGeneration::from_value(*migration_generation);
  return entry;
}

void encode_decision(Encoder& out, const Decision& decision) {
  out.u64(decision.id.value());
  out.i64(decision.at);
  out.str(decision.operation);
  out.u32(static_cast<std::uint32_t>(decision.outcome));
  out.str(decision.reason);
  out.u64(decision.epoch.value());
  out.u64(decision.virtual_id.value());
  out.u64(decision.virtual_generation.value());
  out.u64(decision.tenant.value());
  out.u64(decision.tenant_generation.value());
  out.u64(decision.backing.value());
  out.u64(decision.backing_generation.value());
  out.u64(decision.physical.value());
  out.u64(decision.physical_generation.value());
  out.u64(decision.lease.value());
  out.u64(decision.lease_generation.value());
  out.u64(decision.policy_generation.value());
  out.u64(decision.migration.value());
  out.u64(decision.migration_generation.value());
  out.u64(decision.request.value());
}

Result<Decision> decode_decision(Decoder& in) {
  Decision decision;
  auto id = read_id(in);
  if (!id.ok()) return id.status();
  decision.id = DecisionId::from_value(*id);
  auto at = in.i64();
  if (!at.ok()) return at.status();
  decision.at = *at;
  auto operation = in.str();
  if (!operation.ok()) return operation.status();
  decision.operation = operation.take();
  auto outcome = in.u32();
  if (!outcome.ok()) return outcome.status();
  decision.outcome = static_cast<StatusCode>(*outcome);
  auto reason = in.str();
  if (!reason.ok()) return reason.status();
  decision.reason = reason.take();
  auto epoch = read_id(in);
  if (!epoch.ok()) return epoch.status();
  decision.epoch = CoordinatorEpoch::from_value(*epoch);
  auto virtual_id = read_id(in);
  if (!virtual_id.ok()) return virtual_id.status();
  decision.virtual_id = VirtualAcceleratorId::from_value(*virtual_id);
  auto virtual_generation = read_id(in);
  if (!virtual_generation.ok()) return virtual_generation.status();
  decision.virtual_generation = VirtualAcceleratorGeneration::from_value(*virtual_generation);
  auto tenant = read_id(in);
  if (!tenant.ok()) return tenant.status();
  decision.tenant = TenantId::from_value(*tenant);
  auto tenant_generation = read_id(in);
  if (!tenant_generation.ok()) return tenant_generation.status();
  decision.tenant_generation = TenantGeneration::from_value(*tenant_generation);
  auto backing = read_id(in);
  if (!backing.ok()) return backing.status();
  decision.backing = BackingId::from_value(*backing);
  auto backing_generation = read_id(in);
  if (!backing_generation.ok()) return backing_generation.status();
  decision.backing_generation = BackingGeneration::from_value(*backing_generation);
  auto physical = read_id(in);
  if (!physical.ok()) return physical.status();
  decision.physical = PhysicalDeviceId::from_value(*physical);
  auto physical_generation = read_id(in);
  if (!physical_generation.ok()) return physical_generation.status();
  decision.physical_generation = PhysicalDeviceGeneration::from_value(*physical_generation);
  auto lease = read_id(in);
  if (!lease.ok()) return lease.status();
  decision.lease = LeaseId::from_value(*lease);
  auto lease_generation = read_id(in);
  if (!lease_generation.ok()) return lease_generation.status();
  decision.lease_generation = LeaseGeneration::from_value(*lease_generation);
  auto policy_generation = read_id(in);
  if (!policy_generation.ok()) return policy_generation.status();
  decision.policy_generation = PolicyGeneration::from_value(*policy_generation);
  auto migration = read_id(in);
  if (!migration.ok()) return migration.status();
  decision.migration = MigrationId::from_value(*migration);
  auto migration_generation = read_id(in);
  if (!migration_generation.ok()) return migration_generation.status();
  decision.migration_generation = MigrationGeneration::from_value(*migration_generation);
  auto request = read_id(in);
  if (!request.ok()) return request.status();
  decision.request = RequestId::from_value(*request);
  return decision;
}

void encode_request_outcome(Encoder& out, const RequestOutcomeRecord& record) {
  out.u64(record.request.value());
  out.u64(record.session);
  out.str(record.operation);
  out.u32(static_cast<std::uint32_t>(record.outcome));
  out.i64(record.at);
}

Result<RequestOutcomeRecord> decode_request_outcome(Decoder& in) {
  RequestOutcomeRecord record;
  auto request = read_id(in);
  if (!request.ok()) return request.status();
  record.request = RequestId::from_value(*request);
  auto session = in.u64();
  if (!session.ok()) return session.status();
  record.session = *session;
  auto operation = in.str();
  if (!operation.ok()) return operation.status();
  record.operation = operation.take();
  auto outcome = in.u32();
  if (!outcome.ok()) return outcome.status();
  record.outcome = static_cast<StatusCode>(*outcome);
  auto at = in.i64();
  if (!at.ok()) return at.status();
  record.at = *at;
  return record;
}

// ---- aggregate -----------------------------------------------------------

std::vector<Byte> encode_snapshot(const VirtualizationState& state) {
  Encoder out;
  encode_header(out, state);

  out.u32(static_cast<std::uint32_t>(state.tenants.size()));
  for (const auto& entry : state.tenants) encode_tenant(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.physical.size()));
  for (const auto& entry : state.physical) encode_physical(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.backings.size()));
  for (const auto& entry : state.backings) encode_backing(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.virtuals.size()));
  for (const auto& entry : state.virtuals) encode_virtual(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.leases.size()));
  for (const auto& entry : state.leases) encode_lease(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.assignments.size()));
  for (const auto& entry : state.assignments) encode_assignment(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.migrations.size()));
  for (const auto& entry : state.migrations) encode_migration(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.evidence.size()));
  for (const auto& entry : state.evidence) encode_evidence(out, entry.second);
  out.u32(static_cast<std::uint32_t>(state.audit.size()));
  for (const AuditEntry& entry : state.audit) encode_audit(out, entry);
  out.u32(static_cast<std::uint32_t>(state.decisions.size()));
  for (const Decision& decision : state.decisions) encode_decision(out, decision);
  out.u32(static_cast<std::uint32_t>(state.requests.size()));
  for (const RequestOutcomeRecord& record : state.requests) encode_request_outcome(out, record);
  return out.take();
}

Result<VirtualizationState> decode_snapshot(ByteSpan bytes) {
  Decoder in(bytes, DecodeLimits{64u * 1024u, 1024u * 1024u, 1u << 22, 32});
  auto header = decode_header(in);
  if (!header.ok()) return header.status();
  VirtualizationState state = header.take();

  auto tenants = decode_list<TenantRecord>(in, 1u << 22, decode_tenant);
  if (!tenants.ok()) return tenants.status();
  for (TenantRecord& record : tenants.value()) state.tenants.emplace(record.id, std::move(record));

  auto physical = decode_list<PhysicalDeviceRecord>(in, 1u << 22, decode_physical);
  if (!physical.ok()) return physical.status();
  for (PhysicalDeviceRecord& record : physical.value()) state.physical.emplace(record.id, std::move(record));

  auto backings = decode_list<BackingRecord>(in, 1u << 22, decode_backing);
  if (!backings.ok()) return backings.status();
  for (BackingRecord& record : backings.value()) state.backings.emplace(record.id, std::move(record));

  auto virtuals = decode_list<VirtualAcceleratorRecord>(in, 1u << 22, decode_virtual);
  if (!virtuals.ok()) return virtuals.status();
  for (VirtualAcceleratorRecord& record : virtuals.value()) state.virtuals.emplace(record.id, std::move(record));

  auto leases = decode_list<LeaseRecord>(in, 1u << 22, decode_lease);
  if (!leases.ok()) return leases.status();
  for (LeaseRecord& record : leases.value()) state.leases.emplace(record.id, std::move(record));

  auto assignments = decode_list<BackingAssignment>(in, 1u << 22, decode_assignment);
  if (!assignments.ok()) return assignments.status();
  for (BackingAssignment& record : assignments.value()) state.assignments.emplace(record.id, std::move(record));

  auto migrations = decode_list<MigrationRecord>(in, 1u << 22, decode_migration);
  if (!migrations.ok()) return migrations.status();
  for (MigrationRecord& record : migrations.value()) state.migrations.emplace(record.plan.id, std::move(record));

  auto evidence = decode_list<EvidenceRecord>(in, 1u << 22, decode_evidence);
  if (!evidence.ok()) return evidence.status();
  for (EvidenceRecord& record : evidence.value()) state.evidence.emplace(record.id, std::move(record));

  auto audit = decode_list<AuditEntry>(in, 1u << 22, decode_audit);
  if (!audit.ok()) return audit.status();
  state.audit = audit.take();

  auto decisions = decode_list<Decision>(in, 1u << 22, decode_decision);
  if (!decisions.ok()) return decisions.status();
  state.decisions = decisions.take();

  auto requests = decode_list<RequestOutcomeRecord>(in, 1u << 22, decode_request_outcome);
  if (!requests.ok()) return requests.status();
  state.requests = requests.take();

  Status end = in.require_end();
  if (!end.ok()) return end;
  return state;
}

std::uint64_t state_fingerprint(const VirtualizationState& state) {
  const std::vector<Byte> bytes = encode_snapshot(state);
  return Fnv1a64::compute(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

Status validate_state(const VirtualizationState& state) {
  if (state.schema != schema_version()) {
    return Status(StatusCode::CorruptState,
                  "state schema " + std::to_string(state.schema) + " is not the supported schema " +
                      std::to_string(schema_version()));
  }
  if (!state.epoch.valid()) {
    return Status(StatusCode::CorruptState, "coordinator epoch is unset");
  }
  if (state.next_sequence == 0) {
    return Status(StatusCode::CorruptState, "entity sequence is unset");
  }
  if (!state.policy_generation.valid()) {
    return Status(StatusCode::CorruptState, "policy generation is unset");
  }
  Status policy_status = state.policy.validate();
  if (!policy_status.ok()) {
    return Status(StatusCode::CorruptState, std::string("stored policy is invalid: ") + policy_status.to_string());
  }

  for (const auto& entry : state.tenants) {
    const TenantRecord& record = entry.second;
    if (!record.generation.valid()) {
      return Status(StatusCode::CorruptState, "tenant " + record.id.str() + " has no generation");
    }
    if (record.owned.size() > state.virtuals.size()) {
      return Status(StatusCode::CorruptState,
                    "tenant " + record.id.str() + " references more virtual accelerators than exist");
    }
  }

  for (const auto& entry : state.physical) {
    const PhysicalDeviceRecord& record = entry.second;
    if (!record.generation.valid()) {
      return Status(StatusCode::CorruptState, "physical device " + record.id.str() + " has no generation");
    }
  }

  for (const auto& entry : state.backings) {
    const BackingRecord& record = entry.second;
    if (!record.generation.valid()) {
      return Status(StatusCode::CorruptState, "backing " + record.id.str() + " has no generation");
    }
    if (state.physical.find(record.physical) == state.physical.end()) {
      return Status(StatusCode::CorruptState,
                    "backing " + record.id.str() + " references unknown physical device " + record.physical.str());
    }
  }

  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    if (!record.generation.valid()) {
      return Status(StatusCode::CorruptState, "virtual accelerator " + record.id.str() + " has no generation");
    }
    const auto owner = state.tenants.find(record.owner);
    if (owner == state.tenants.end()) {
      return Status(StatusCode::CorruptState,
                    "virtual accelerator " + record.id.str() + " references unknown tenant " + record.owner.str());
    }
    if (record.contract.id.valid()) {
      Status contract_status = record.contract.validate();
      if (!contract_status.ok()) {
        return Status(StatusCode::CorruptState, std::string("virtual accelerator ") + record.id.str() +
                                                    " holds an invalid resource contract: " +
                                                    contract_status.to_string());
      }
    }
    if (lifecycle_requires_backing(record.state)) {
      if (!record.backing.valid()) {
        return Status(StatusCode::CorruptState, "virtual accelerator " + record.id.str() + " is " +
                                                    std::string(lifecycle_name(record.state)) +
                                                    " without a backing assignment");
      }
      if (state.backings.find(record.backing) == state.backings.end()) {
        return Status(StatusCode::CorruptState,
                      "virtual accelerator " + record.id.str() + " references unknown backing " + record.backing.str());
      }
      const auto assignment = state.assignments.find(record.assignment);
      if (assignment == state.assignments.end() || !assignment->second.authoritative) {
        return Status(StatusCode::CorruptState, "virtual accelerator " + record.id.str() + " is " +
                                                    std::string(lifecycle_name(record.state)) +
                                                    " without an authoritative backing assignment");
      }
    }
    if (record.active_attachments > record.leases.size()) {
      return Status(StatusCode::CorruptState,
                    "virtual accelerator " + record.id.str() + " reports more active attachments than leases");
    }
  }

  for (const auto& entry : state.leases) {
    const LeaseRecord& record = entry.second;
    if (!record.generation.valid()) {
      return Status(StatusCode::CorruptState, "lease " + record.id.str() + " has no generation");
    }
    if (state.virtuals.find(record.virtual_id) == state.virtuals.end()) {
      return Status(StatusCode::CorruptState, "lease " + record.id.str() + " references unknown virtual accelerator");
    }
    if (state.tenants.find(record.tenant) == state.tenants.end()) {
      return Status(StatusCode::CorruptState, "lease " + record.id.str() + " references unknown tenant");
    }
  }

  for (const auto& entry : state.assignments) {
    const BackingAssignment& record = entry.second;
    if (state.virtuals.find(record.virtual_id) == state.virtuals.end()) {
      return Status(StatusCode::CorruptState,
                    "assignment " + record.id.str() + " references unknown virtual accelerator");
    }
    if (state.backings.find(record.backing) == state.backings.end()) {
      return Status(StatusCode::CorruptState, "assignment " + record.id.str() + " references unknown backing");
    }
  }

  for (const auto& entry : state.migrations) {
    const MigrationRecord& record = entry.second;
    if (state.virtuals.find(record.plan.virtual_id) == state.virtuals.end()) {
      return Status(StatusCode::CorruptState,
                    "migration " + record.plan.id.str() + " references unknown virtual accelerator");
    }
    if (state.backings.find(record.plan.source_backing) == state.backings.end()) {
      return Status(StatusCode::CorruptState, "migration " + record.plan.id.str() + " references unknown source backing");
    }
    if (state.backings.find(record.plan.destination_backing) == state.backings.end()) {
      return Status(StatusCode::CorruptState,
                    "migration " + record.plan.id.str() + " references unknown destination backing");
    }
  }

  if (state.virtuals.size() > state.policy.max_virtual_accelerators) {
    return Status(StatusCode::CorruptState, "stored virtual accelerator count exceeds the policy maximum");
  }
  if (state.tenants.size() > state.policy.max_tenants) {
    return Status(StatusCode::CorruptState, "stored tenant count exceeds the policy maximum");
  }
  return Status{};
}

}  // namespace av
