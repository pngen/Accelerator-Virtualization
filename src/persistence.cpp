// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Durable virtualization metadata store.
//
// Layout inside the state directory:
//   state.avs   atomic full snapshot (magic, schema, length, CRC-32C, payload)
//   state.avj   append-only journal of per-record upserts
//
// A mutation appends one bounded record per changed entity, so a single
// mutation costs O(changed records) rather than O(total state). Recovery
// replays the journal over the last snapshot. Compaction rewrites the snapshot
// atomically and truncates the journal.
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "av/codec.hpp"
#include "av/hash.hpp"
#include "av/persistence.hpp"

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace av {
namespace {

constexpr std::uint32_t kSnapshotMagic = 0x31535641u;  // "AVS1"
constexpr std::uint32_t kJournalMagic = 0x314A5641u;   // "AVJ1"
constexpr std::size_t kSnapshotHeaderSize = 16;
constexpr std::size_t kJournalHeaderSize = 8;
constexpr std::size_t kJournalRecordHeaderSize = 8;
constexpr std::size_t kJournalRecordPrefixSize = 9;  // kind byte + u64 identity
// Bounds a single journal record. This is a persistence bound, deliberately
// independent of the network frame bound.
constexpr std::uint32_t kMaxJournalRecord = 16u * 1024u * 1024u;

std::string describe_errno(int code) { return "errno " + std::to_string(code); }

Status ensure_directory(const std::string& path) {
  if (path.empty()) return Status{};
  std::error_code ec;
  std::filesystem::create_directories(std::filesystem::path(path), ec);
  if (ec) {
    return Status(StatusCode::IoFailure, "cannot create state directory '" + path + "': " + ec.message());
  }
  return Status{};
}

Result<std::vector<Byte>> read_file_bytes(const std::string& path, bool* exists) {
  if (exists != nullptr) *exists = false;
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) return std::vector<Byte>{};
  if (exists != nullptr) *exists = true;

  std::vector<Byte> out;
  std::array<unsigned char, 64u * 1024u> buffer{};
  for (;;) {
    const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
    if (read > 0) {
      const auto* begin = reinterpret_cast<const Byte*>(buffer.data());
      out.insert(out.end(), begin, begin + read);
    }
    if (read < buffer.size()) {
      if (std::ferror(file) != 0) {
        std::fclose(file);
        return Status(StatusCode::IoFailure, "read failure on '" + path + "'");
      }
      break;
    }
  }
  std::fclose(file);
  return out;
}

Status sync_file(std::FILE* file, bool durable) {
  if (std::fflush(file) != 0) return Status(StatusCode::IoFailure, "flush failed");
  if (!durable) return Status{};
#ifdef _WIN32
  if (_commit(_fileno(file)) != 0) return Status(StatusCode::IoFailure, "commit to disk failed");
#else
  if (fsync(fileno(file)) != 0) return Status(StatusCode::IoFailure, "commit to disk failed");
#endif
  return Status{};
}

Status write_file_atomic(const std::string& path, ByteSpan data, bool durable) {
  const std::string temporary = path + ".tmp";
  std::FILE* file = std::fopen(temporary.c_str(), "wb");
  if (file == nullptr) {
    return Status(StatusCode::IoFailure, "cannot open '" + temporary + "' for writing: " + describe_errno(errno));
  }
  if (!data.empty()) {
    const std::size_t written = std::fwrite(data.data(), 1, data.size(), file);
    if (written != data.size()) {
      std::fclose(file);
      return Status(StatusCode::IoFailure, "short write to '" + temporary + "'");
    }
  }
  const Status sync = sync_file(file, durable);
  std::fclose(file);
  if (!sync.ok()) return sync;

#ifdef _WIN32
  if (::MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return Status(StatusCode::IoFailure, "atomic replace of '" + path + "' failed");
  }
#else
  std::error_code ec;
  std::filesystem::rename(temporary, path, ec);
  if (ec) return Status(StatusCode::IoFailure, "atomic replace of '" + path + "' failed: " + ec.message());
#endif
  return Status{};
}

Status append_file_bytes(const std::string& path, ByteSpan data, bool durable) {
  if (data.empty()) return Status{};
  std::FILE* file = std::fopen(path.c_str(), "ab");
  if (file == nullptr) {
    return Status(StatusCode::IoFailure, "cannot open '" + path + "' for append: " + describe_errno(errno));
  }
  const std::size_t written = std::fwrite(data.data(), 1, data.size(), file);
  if (written != data.size()) {
    std::fclose(file);
    return Status(StatusCode::IoFailure, "short append to '" + path + "'");
  }
  const Status sync = sync_file(file, durable);
  std::fclose(file);
  return sync;
}

std::vector<Byte> journal_header_bytes() {
  std::vector<Byte> out;
  put_u32(out, kJournalMagic);
  put_u32(out, schema_version());
  return out;
}

Status apply_record(VirtualizationState& state, EntityKind kind, Decoder& body) {
  switch (kind) {
    case EntityKind::Header: {
      auto header = decode_header(body);
      if (!header.ok()) return header.status();
      const VirtualizationState& source = header.value();
      state.schema = source.schema;
      state.next_sequence = source.next_sequence;
      state.epoch = source.epoch;
      state.policy = source.policy;
      state.policy_generation = source.policy_generation;
      state.accounting = source.accounting;
      return Status{};
    }
    case EntityKind::Tenant: {
      auto record = decode_tenant(body);
      if (!record.ok()) return record.status();
      state.tenants[record->id] = record.take();
      return Status{};
    }
    case EntityKind::Physical: {
      auto record = decode_physical(body);
      if (!record.ok()) return record.status();
      state.physical[record->id] = record.take();
      return Status{};
    }
    case EntityKind::Backing: {
      auto record = decode_backing(body);
      if (!record.ok()) return record.status();
      state.backings[record->id] = record.take();
      return Status{};
    }
    case EntityKind::Virtual: {
      auto record = decode_virtual(body);
      if (!record.ok()) return record.status();
      state.virtuals[record->id] = record.take();
      return Status{};
    }
    case EntityKind::Lease: {
      auto record = decode_lease(body);
      if (!record.ok()) return record.status();
      state.leases[record->id] = record.take();
      return Status{};
    }
    case EntityKind::Assignment: {
      auto record = decode_assignment(body);
      if (!record.ok()) return record.status();
      state.assignments[record->id] = record.take();
      return Status{};
    }
    case EntityKind::Migration: {
      auto record = decode_migration(body);
      if (!record.ok()) return record.status();
      state.migrations[record->plan.id] = record.take();
      return Status{};
    }
    case EntityKind::Evidence: {
      auto record = decode_evidence(body);
      if (!record.ok()) return record.status();
      state.evidence[record->id] = record.take();
      return Status{};
    }
    case EntityKind::Audit: {
      auto record = decode_audit(body);
      if (!record.ok()) return record.status();
      state.audit.push_back(record.take());
      while (state.audit.size() > AuditLog::kCapacity) state.audit.erase(state.audit.begin());
      return Status{};
    }
    case EntityKind::Decision: {
      auto record = decode_decision(body);
      if (!record.ok()) return record.status();
      state.decisions.push_back(record.take());
      while (state.decisions.size() > kDecisionCapacity) state.decisions.erase(state.decisions.begin());
      return Status{};
    }
    case EntityKind::Request: {
      auto record = decode_request_outcome(body);
      if (!record.ok()) return record.status();
      state.requests.push_back(record.take());
      while (state.requests.size() > kRequestWindowCapacity) state.requests.erase(state.requests.begin());
      return Status{};
    }
  }
  return Status(StatusCode::CorruptState, "journal record carries an unknown entity kind");
}

// One encoded change, ready to be framed into the journal or applied directly
// to an in-memory state.
struct EncodedChange {
  EntityKind kind;
  std::uint64_t id;
  std::vector<Byte> body;
};

std::vector<EncodedChange> encode_changes(const VirtualizationState& state, const ChangeSet& changes) {
  std::vector<EncodedChange> out;
  Encoder encoder;
  auto push = [&out, &encoder](EntityKind kind, std::uint64_t id, bool present) {
    if (!present) return;
    out.push_back(EncodedChange{kind, id, encoder.buffer()});
  };

  if (changes.header) {
    encoder.clear();
    encode_header(encoder, state);
    push(EntityKind::Header, 0, true);
  }
  for (const TenantId& id : changes.tenants) {
    const auto it = state.tenants.find(id);
    if (it == state.tenants.end()) continue;
    encoder.clear();
    encode_tenant(encoder, it->second);
    push(EntityKind::Tenant, id.value(), true);
  }
  for (const PhysicalDeviceId& id : changes.physical) {
    const auto it = state.physical.find(id);
    if (it == state.physical.end()) continue;
    encoder.clear();
    encode_physical(encoder, it->second);
    push(EntityKind::Physical, id.value(), true);
  }
  for (const BackingId& id : changes.backings) {
    const auto it = state.backings.find(id);
    if (it == state.backings.end()) continue;
    encoder.clear();
    encode_backing(encoder, it->second);
    push(EntityKind::Backing, id.value(), true);
  }
  for (const VirtualAcceleratorId& id : changes.virtuals) {
    const auto it = state.virtuals.find(id);
    if (it == state.virtuals.end()) continue;
    encoder.clear();
    encode_virtual(encoder, it->second);
    push(EntityKind::Virtual, id.value(), true);
  }
  for (const LeaseId& id : changes.leases) {
    const auto it = state.leases.find(id);
    if (it == state.leases.end()) continue;
    encoder.clear();
    encode_lease(encoder, it->second);
    push(EntityKind::Lease, id.value(), true);
  }
  for (const BackingAssignmentId& id : changes.assignments) {
    const auto it = state.assignments.find(id);
    if (it == state.assignments.end()) continue;
    encoder.clear();
    encode_assignment(encoder, it->second);
    push(EntityKind::Assignment, id.value(), true);
  }
  for (const MigrationId& id : changes.migrations) {
    const auto it = state.migrations.find(id);
    if (it == state.migrations.end()) continue;
    encoder.clear();
    encode_migration(encoder, it->second);
    push(EntityKind::Migration, id.value(), true);
  }
  for (const EvidenceId& id : changes.evidence) {
    const auto it = state.evidence.find(id);
    if (it == state.evidence.end()) continue;
    encoder.clear();
    encode_evidence(encoder, it->second);
    push(EntityKind::Evidence, id.value(), true);
  }
  for (const AuditEntry& entry : changes.audit) {
    encoder.clear();
    encode_audit(encoder, entry);
    push(EntityKind::Audit, entry.id.value(), true);
  }
  for (const Decision& decision : changes.decisions) {
    encoder.clear();
    encode_decision(encoder, decision);
    push(EntityKind::Decision, decision.id.value(), true);
  }
  for (const RequestOutcomeRecord& record : changes.requests) {
    encoder.clear();
    encode_request_outcome(encoder, record);
    push(EntityKind::Request, record.request.value(), true);
  }
  return out;
}

std::vector<Byte> frame_journal_record(const EncodedChange& change) {
  std::vector<Byte> payload;
  payload.reserve(change.body.size() + kJournalRecordPrefixSize);
  payload.push_back(static_cast<Byte>(static_cast<std::uint8_t>(change.kind)));
  put_u64(payload, change.id);
  payload.insert(payload.end(), change.body.begin(), change.body.end());

  std::vector<Byte> out;
  out.reserve(payload.size() + kJournalRecordHeaderSize);
  put_u32(out, static_cast<std::uint32_t>(payload.size()));
  put_u32(out, Crc32c::compute(payload.data(), payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::vector<Byte> encode_snapshot_file(const VirtualizationState& state) {
  const std::vector<Byte> payload = encode_snapshot(state);
  std::vector<Byte> out;
  out.reserve(payload.size() + kSnapshotHeaderSize);
  put_u32(out, kSnapshotMagic);
  put_u32(out, schema_version());
  put_u32(out, static_cast<std::uint32_t>(payload.size()));
  put_u32(out, Crc32c::compute(payload.data(), payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

Result<VirtualizationState> decode_snapshot_file(ByteSpan bytes) {
  if (bytes.size() < kSnapshotHeaderSize) {
    return Status(StatusCode::TruncatedState, "snapshot file is shorter than its header");
  }
  if (get_u32(bytes, 0) != kSnapshotMagic) {
    return Status(StatusCode::CorruptState, "snapshot file magic does not match");
  }
  if (get_u32(bytes, 4) != schema_version()) {
    return Status(StatusCode::CorruptState,
                  "snapshot schema " + std::to_string(get_u32(bytes, 4)) + " is not the supported schema " +
                      std::to_string(schema_version()));
  }
  const std::uint32_t length = get_u32(bytes, 8);
  const std::uint32_t crc = get_u32(bytes, 12);
  if (bytes.size() - kSnapshotHeaderSize != length) {
    return Status(StatusCode::TruncatedState, "snapshot declares " + std::to_string(length) +
                                                  " payload byte(s) but " +
                                                  std::to_string(bytes.size() - kSnapshotHeaderSize) +
                                                  " are present");
  }
  const ByteSpan payload = bytes.subspan(kSnapshotHeaderSize);
  if (Crc32c::compute(payload.data(), payload.size()) != crc) {
    return Status(StatusCode::IntegrityFailure, "snapshot payload failed its integrity check");
  }
  return decode_snapshot(payload);
}

class FileDurableStore final : public DurableStore {
 public:
  explicit FileDurableStore(StoreOptions options) : options_(std::move(options)) {
    snapshot_path_ = options_.directory + "/state.avs";
    journal_path_ = options_.directory + "/state.avj";
  }

  Status open() override {
    const Status created = ensure_directory(options_.directory);
    if (!created.ok()) return created;
    bool exists = false;
    auto snapshot = read_file_bytes(snapshot_path_, &exists);
    if (!snapshot.ok()) return snapshot.status();
    snapshot_present_ = exists;
    auto journal = read_file_bytes(journal_path_, &exists);
    if (!journal.ok()) return journal.status();
    journal_bytes_ = exists ? journal->size() : 0;
    journal_initialized_ = exists;
    opened_ = true;
    return Status{};
  }

  Status apply(const VirtualizationState& state, const ChangeSet& changes) override {
    if (!options_.enabled) return Status{};
    if (!opened_) return Status(StatusCode::NotReady, "durable store is not open");
    if (changes.empty()) return Status{};

    const std::vector<EncodedChange> encoded = encode_changes(state, changes);
    if (encoded.empty()) return Status{};

    if (!journal_initialized_) {
      const std::vector<Byte> header = journal_header_bytes();
      const Status written =
          write_file_atomic(journal_path_, ByteSpan{header.data(), header.size()}, options_.durable_sync);
      if (!written.ok()) return written;
      journal_initialized_ = true;
      journal_bytes_ = header.size();
    }

    // One append and one durable sync per mutation: every record of the
    // mutation is on disk before the operation reports success, and the cost is
    // one flush rather than one per record.
    std::vector<Byte> batch;
    for (const EncodedChange& change : encoded) {
      const std::vector<Byte> record = frame_journal_record(change);
      batch.insert(batch.end(), record.begin(), record.end());
    }
    const Status status = append_file_bytes(journal_path_, ByteSpan{batch.data(), batch.size()}, options_.durable_sync);
    if (!status.ok()) return status;
    write_count_ += encoded.size();
    bytes_written_ += batch.size();
    journal_bytes_ += batch.size();

    // Compaction rewrites the whole snapshot, so it is only worth doing once
    // the journal has grown past the snapshot it would replace. Without this
    // the write amplification of a large fleet is quadratic in the record
    // count; with it, journal growth stays proportional to the state size.
    const std::size_t threshold =
        std::max(options_.compaction_journal_bytes, last_snapshot_bytes_ * 2);
    if (journal_bytes_ > threshold) {
      const Status compacted = compact(state);
      if (!compacted.ok()) return compacted;
    }
    return Status{};
  }

  Status compact(const VirtualizationState& state) override {
    if (!options_.enabled) return Status{};
    if (!opened_) return Status(StatusCode::NotReady, "durable store is not open");
    const std::vector<Byte> bytes = encode_snapshot_file(state);
    const Status written =
        write_file_atomic(snapshot_path_, ByteSpan{bytes.data(), bytes.size()}, options_.durable_sync);
    if (!written.ok()) return written;
    snapshot_present_ = true;
    last_snapshot_bytes_ = bytes.size();
    ++write_count_;
    bytes_written_ += bytes.size();
    ++compactions_;

    const std::vector<Byte> header = journal_header_bytes();
    const Status truncated =
        write_file_atomic(journal_path_, ByteSpan{header.data(), header.size()}, options_.durable_sync);
    if (!truncated.ok()) return truncated;
    journal_initialized_ = true;
    journal_bytes_ = header.size();
    ++write_count_;
    bytes_written_ += header.size();
    return Status{};
  }

  Result<VirtualizationState> load() override {
    VirtualizationState state;
    state.schema = schema_version();
    if (!options_.enabled) return state;

    bool exists = false;
    bool loaded_anything = false;
    auto snapshot = read_file_bytes(snapshot_path_, &exists);
    if (!snapshot.ok()) return snapshot.status();
    if (exists) {
      auto decoded = decode_snapshot_file(ByteSpan{snapshot->data(), snapshot->size()});
      if (!decoded.ok()) return decoded.status();
      state = decoded.take();
      loaded_anything = true;
    }

    auto journal = read_file_bytes(journal_path_, &exists);
    if (!journal.ok()) return journal.status();
    if (exists && !journal->empty()) {
      bool discarded_tail = false;
      const Status replayed = replay_journal(state, ByteSpan{journal->data(), journal->size()}, discarded_tail);
      if (!replayed.ok()) return replayed;
      discarded_tail_ = discarded_tail;
      loaded_anything = true;
    }

    // A store that holds nothing yet is not corrupt: it is simply empty, and
    // the runtime assigns the first epoch when it starts.
    if (!loaded_anything) return state;
    const Status valid = validate_state(state);
    if (!valid.ok()) return valid;
    return state;
  }

  Status flush() override { return Status{}; }

  Status close() override {
    opened_ = false;
    return Status{};
  }

  std::string describe() const override {
    return "file-store dir=" + options_.directory + " snapshot=" + (snapshot_present_ ? "present" : "absent") +
           " journal_bytes=" + std::to_string(journal_bytes_) +
           " mode=" + (options_.deferred ? "deferred" : "immediate") + " torn_tail=" +
           (options_.torn_tail == StoreOptions::TornTail::Discard ? "discard" : "reject");
  }
  bool present() const override { return snapshot_present_ || journal_bytes_ > kJournalHeaderSize; }
  std::uint64_t bytes_written() const override { return bytes_written_; }
  std::uint64_t write_count() const override { return write_count_; }
  std::uint64_t compactions() const override { return compactions_; }
  std::size_t pending_changes() const override { return 0; }

 private:
  Status replay_journal(VirtualizationState& state, ByteSpan bytes, bool& discarded_tail) {
    if (bytes.size() < kJournalHeaderSize) {
      return Status(StatusCode::TruncatedState, "journal file is shorter than its header");
    }
    if (get_u32(bytes, 0) != kJournalMagic) {
      return Status(StatusCode::CorruptState, "journal file magic does not match");
    }
    if (get_u32(bytes, 4) != schema_version()) {
      return Status(StatusCode::CorruptState,
                    "journal schema " + std::to_string(get_u32(bytes, 4)) + " is not the supported schema " +
                        std::to_string(schema_version()));
    }
    std::size_t offset = kJournalHeaderSize;
    while (offset < bytes.size()) {
      const std::size_t remaining = bytes.size() - offset;
      if (remaining < kJournalRecordHeaderSize) {
        return handle_torn(discarded_tail, "journal ends inside a record header");
      }
      const std::uint32_t length = get_u32(bytes, offset);
      const std::uint32_t crc = get_u32(bytes, offset + 4);
      if (length < kJournalRecordPrefixSize || length > kMaxJournalRecord) {
        return Status(StatusCode::CorruptState,
                      "journal record declares an invalid length of " + std::to_string(length) + " byte(s)");
      }
      if (remaining - kJournalRecordHeaderSize < length) {
        return handle_torn(discarded_tail, "journal ends inside a record payload");
      }
      const ByteSpan payload = bytes.subspan(offset + kJournalRecordHeaderSize, length);
      if (Crc32c::compute(payload.data(), payload.size()) != crc) {
        return Status(StatusCode::IntegrityFailure,
                      "journal record at offset " + std::to_string(offset) + " failed its integrity check");
      }
      const auto kind_raw = static_cast<std::uint8_t>(payload[0]);
      if (kind_raw > static_cast<std::uint8_t>(EntityKind::Request)) {
        return Status(StatusCode::CorruptState, "journal record carries an out-of-domain entity kind");
      }
      Decoder body(payload.subspan(kJournalRecordPrefixSize));
      const Status applied = apply_record(state, static_cast<EntityKind>(kind_raw), body);
      if (!applied.ok()) return applied;
      offset += kJournalRecordHeaderSize + length;
    }
    return Status{};
  }

  Status handle_torn(bool& discarded_tail, const char* detail) {
    if (options_.torn_tail == StoreOptions::TornTail::Reject) {
      return Status(StatusCode::TruncatedState,
                    std::string(detail) + "; refusing to reinterpret an incomplete durable record");
    }
    discarded_tail = true;
    return Status{};
  }

  StoreOptions options_{};
  std::string snapshot_path_{};
  std::string journal_path_{};
  bool opened_{false};
  bool snapshot_present_{false};
  bool journal_initialized_{false};
  bool discarded_tail_{false};
  std::size_t journal_bytes_{0};
  std::size_t last_snapshot_bytes_{0};
  std::uint64_t bytes_written_{0};
  std::uint64_t write_count_{0};
  std::uint64_t compactions_{0};
};

// In-memory store used by tests and by short-lived observers. It applies the
// same encoded changes as the file store, so both paths exercise one codec.
class MemoryDurableStore final : public DurableStore {
 public:
  Status open() override {
    opened_ = true;
    state_.schema = schema_version();
    return Status{};
  }

  Status apply(const VirtualizationState& state, const ChangeSet& changes) override {
    if (!opened_) return Status(StatusCode::NotReady, "durable store is not open");
    const std::vector<EncodedChange> encoded = encode_changes(state, changes);
    for (const EncodedChange& change : encoded) {
      Decoder body(ByteSpan{change.body.data(), change.body.size()});
      const Status applied = apply_record(state_, change.kind, body);
      if (!applied.ok()) return applied;
    }
    present_ = true;
    ++writes_;
    return Status{};
  }

  Status compact(const VirtualizationState& state) override {
    state_ = state;
    present_ = true;
    ++writes_;
    ++compactions_;
    return Status{};
  }

  Result<VirtualizationState> load() override { return state_; }
  Status flush() override { return Status{}; }
  Status close() override {
    opened_ = false;
    return Status{};
  }

  std::string describe() const override {
    return "memory-store virtuals=" + std::to_string(state_.virtuals.size());
  }
  bool present() const override { return present_; }
  std::uint64_t bytes_written() const override { return 0; }
  std::uint64_t write_count() const override { return writes_; }
  std::uint64_t compactions() const override { return compactions_; }
  std::size_t pending_changes() const override { return 0; }

 private:
  VirtualizationState state_{};
  bool opened_{false};
  bool present_{false};
  std::uint64_t writes_{0};
  std::uint64_t compactions_{0};
};

}  // namespace

std::unique_ptr<DurableStore> make_file_store(StoreOptions options) {
  return std::make_unique<FileDurableStore>(std::move(options));
}

std::unique_ptr<DurableStore> make_memory_store() { return std::make_unique<MemoryDurableStore>(); }

}  // namespace av
