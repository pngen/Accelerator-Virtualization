// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "av/codec.hpp"
#include "av/model.hpp"
#include "av/status.hpp"

namespace av {

enum class EntityKind : std::uint8_t {
  Header = 0,
  Tenant = 1,
  Physical = 2,
  Backing = 3,
  Virtual = 4,
  Lease = 5,
  Assignment = 6,
  Migration = 7,
  Evidence = 8,
  Audit = 9,
  Decision = 10,
  Request = 11,
};

std::string_view entity_kind_name(EntityKind kind) noexcept;

// Records that changed since the last durable apply. The journal is purely
// additive: entities are superseded by newer records, never deleted, so the
// durable history can always be replayed forward.
struct ChangeSet {
  bool header{false};
  std::vector<TenantId> tenants{};
  std::vector<PhysicalDeviceId> physical{};
  std::vector<BackingId> backings{};
  std::vector<VirtualAcceleratorId> virtuals{};
  std::vector<LeaseId> leases{};
  std::vector<BackingAssignmentId> assignments{};
  std::vector<MigrationId> migrations{};
  std::vector<EvidenceId> evidence{};
  std::vector<AuditEntry> audit{};
  std::vector<Decision> decisions{};
  std::vector<RequestOutcomeRecord> requests{};

  bool empty() const noexcept;
  void clear() noexcept;
  std::size_t count() const noexcept;
};

// ---- record codecs -------------------------------------------------------
// The same encoders serve the full snapshot and the incremental journal, so a
// replayed journal and a compacted snapshot decode to identical state.

void encode_header(Encoder& out, const VirtualizationState& state);
// Decodes only the header record. The returned state carries the header
// scalars, the policy and the accounting counters, never the entity maps.
Result<VirtualizationState> decode_header(Decoder& in);
void encode_tenant(Encoder& out, const TenantRecord& record);
void encode_physical(Encoder& out, const PhysicalDeviceRecord& record);
void encode_backing(Encoder& out, const BackingRecord& record);
void encode_virtual(Encoder& out, const VirtualAcceleratorRecord& record);
void encode_lease(Encoder& out, const LeaseRecord& record);
void encode_assignment(Encoder& out, const BackingAssignment& record);
void encode_migration(Encoder& out, const MigrationRecord& record);
void encode_evidence(Encoder& out, const EvidenceRecord& record);
void encode_audit(Encoder& out, const AuditEntry& record);
void encode_decision(Encoder& out, const Decision& record);
void encode_request_outcome(Encoder& out, const RequestOutcomeRecord& record);

void encode_contract(Encoder& out, const ResourceContract& value);
void encode_policy(Encoder& out, const VirtualizationPolicy& value);
void encode_projection(Encoder& out, const CapabilityProjection& value);
void encode_isolation_profile(Encoder& out, const IsolationProfile& value);
void encode_capability_surface(Encoder& out, const CapabilitySurface& value);
void encode_migration_plan(Encoder& out, const MigrationPlan& value);

Result<ResourceContract> decode_contract(Decoder& in);
Result<VirtualizationPolicy> decode_policy(Decoder& in);
Result<CapabilityProjection> decode_projection(Decoder& in);
Result<IsolationProfile> decode_isolation_profile(Decoder& in);
Result<CapabilitySurface> decode_capability_surface(Decoder& in);
Result<MigrationPlan> decode_migration_plan(Decoder& in);

// Blob helpers: one canonical byte string per value, used identically by the
// durable store and by the control-plane wire format.
template <class T, class EncodeFn>
std::vector<Byte> encode_blob(const T& value, EncodeFn encode) {
  Encoder out;
  encode(out, value);
  return out.take();
}
std::vector<Byte> encode_contract_blob(const ResourceContract& value);
Result<ResourceContract> decode_contract_blob(ByteSpan bytes);

Result<TenantRecord> decode_tenant(Decoder& in);
Result<PhysicalDeviceRecord> decode_physical(Decoder& in);
Result<BackingRecord> decode_backing(Decoder& in);
Result<VirtualAcceleratorRecord> decode_virtual(Decoder& in);
Result<LeaseRecord> decode_lease(Decoder& in);
Result<BackingAssignment> decode_assignment(Decoder& in);
Result<MigrationRecord> decode_migration(Decoder& in);
Result<EvidenceRecord> decode_evidence(Decoder& in);
Result<AuditEntry> decode_audit(Decoder& in);
Result<Decision> decode_decision(Decoder& in);
Result<RequestOutcomeRecord> decode_request_outcome(Decoder& in);

// Full-state codec used for snapshots and for corruption testing.
std::vector<Byte> encode_snapshot(const VirtualizationState& state);
Result<VirtualizationState> decode_snapshot(ByteSpan bytes);
// Structural validation applied after decoding, before the state is trusted.
Status validate_state(const VirtualizationState& state);

struct StoreOptions {
  enum class TornTail : std::uint8_t {
    Reject = 0,   // a torn journal tail is a hard integrity failure
    Discard = 1,  // discard an incomplete trailing record, then continue
  };

  std::string directory{};
  bool enabled{true};
  // Deferred mode coalesces journal appends. It trades a bounded crash window
  // for throughput and is never the default.
  bool deferred{false};
  std::size_t deferred_threshold{256};
  std::size_t compaction_journal_bytes{4u * 1024u * 1024u};
  TornTail torn_tail{TornTail::Reject};
  bool durable_sync{true};
};

// Durable metadata store: versioned schema, deterministic serialization,
// integrity validation, atomic replace, corruption and truncation detection.
class DurableStore {
 public:
  virtual ~DurableStore() = default;

  virtual Status open() = 0;
  virtual Status apply(const VirtualizationState& state, const ChangeSet& changes) = 0;
  virtual Status compact(const VirtualizationState& state) = 0;
  virtual Result<VirtualizationState> load() = 0;
  virtual Status flush() = 0;
  virtual Status close() = 0;

  virtual std::string describe() const = 0;
  virtual bool present() const = 0;
  virtual std::uint64_t bytes_written() const = 0;
  virtual std::uint64_t write_count() const = 0;
  virtual std::uint64_t compactions() const = 0;
  virtual std::size_t pending_changes() const = 0;
};

std::unique_ptr<DurableStore> make_file_store(StoreOptions options);
std::unique_ptr<DurableStore> make_memory_store();

}  // namespace av
