// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Framing and canonical field-map codec for the control plane.
//
// Every frame is length-prefixed and CRC-protected, so a truncated, oversized,
// reordered or corrupted frame is refused before any of its content is
// interpreted. Field maps are order-independent and forward compatible:
// unknown keys are ignored, duplicate keys and out-of-domain values are not.
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "av/hash.hpp"
#include "av/protocol.hpp"

namespace av {
namespace {

struct MessageInfo {
  MessageType type;
  std::string_view name;
  bool response;
  bool agent_directed;
};

constexpr MessageInfo kMessages[] = {
    {MessageType::Invalid, "INVALID", false, false},
    {MessageType::Hello, "HELLO", false, false},
    {MessageType::HelloAck, "HELLO_ACK", true, false},
    {MessageType::Goodbye, "GOODBYE", false, false},

    {MessageType::RegisterPhysical, "REGISTER_PHYSICAL", false, true},
    {MessageType::RegisterPhysicalAck, "REGISTER_PHYSICAL_ACK", true, true},
    {MessageType::RefreshPhysical, "REFRESH_PHYSICAL", false, true},
    {MessageType::RefreshPhysicalAck, "REFRESH_PHYSICAL_ACK", true, true},
    {MessageType::ListPhysical, "LIST_PHYSICAL", false, false},
    {MessageType::ListPhysicalAck, "LIST_PHYSICAL_ACK", true, false},
    {MessageType::PhysicalLost, "PHYSICAL_LOST", false, true},
    {MessageType::PhysicalLostAck, "PHYSICAL_LOST_ACK", true, true},

    {MessageType::CreateTenant, "CREATE_TENANT", false, false},
    {MessageType::CreateTenantAck, "CREATE_TENANT_ACK", true, false},
    {MessageType::ListTenants, "LIST_TENANTS", false, false},
    {MessageType::ListTenantsAck, "LIST_TENANTS_ACK", true, false},
    {MessageType::FenceTenant, "FENCE_TENANT", false, false},
    {MessageType::FenceTenantAck, "FENCE_TENANT_ACK", true, false},
    {MessageType::TransferOwnership, "TRANSFER_OWNERSHIP", false, false},
    {MessageType::TransferOwnershipAck, "TRANSFER_OWNERSHIP_ACK", true, false},

    {MessageType::CreateVirtual, "CREATE_VIRTUAL", false, false},
    {MessageType::CreateVirtualAck, "CREATE_VIRTUAL_ACK", true, false},
    {MessageType::UpdateContract, "UPDATE_CONTRACT", false, false},
    {MessageType::UpdateContractAck, "UPDATE_CONTRACT_ACK", true, false},
    {MessageType::AssignBacking, "ASSIGN_BACKING", false, false},
    {MessageType::AssignBackingAck, "ASSIGN_BACKING_ACK", true, false},
    {MessageType::ReplaceBacking, "REPLACE_BACKING", false, false},
    {MessageType::ReplaceBackingAck, "REPLACE_BACKING_ACK", true, false},
    {MessageType::RetireVirtual, "RETIRE_VIRTUAL", false, false},
    {MessageType::RetireVirtualAck, "RETIRE_VIRTUAL_ACK", true, false},
    {MessageType::FenceVirtual, "FENCE_VIRTUAL", false, false},
    {MessageType::FenceVirtualAck, "FENCE_VIRTUAL_ACK", true, false},
    {MessageType::ActivateVirtual, "ACTIVATE_VIRTUAL", false, false},
    {MessageType::ActivateVirtualAck, "ACTIVATE_VIRTUAL_ACK", true, false},
    {MessageType::SuspendVirtual, "SUSPEND_VIRTUAL", false, false},
    {MessageType::SuspendVirtualAck, "SUSPEND_VIRTUAL_ACK", true, false},
    {MessageType::ResumeVirtual, "RESUME_VIRTUAL", false, false},
    {MessageType::ResumeVirtualAck, "RESUME_VIRTUAL_ACK", true, false},
    {MessageType::DrainVirtual, "DRAIN_VIRTUAL", false, false},
    {MessageType::DrainVirtualAck, "DRAIN_VIRTUAL_ACK", true, false},

    {MessageType::Attach, "ATTACH", false, false},
    {MessageType::AttachAck, "ATTACH_ACK", true, false},
    {MessageType::Detach, "DETACH", false, false},
    {MessageType::DetachAck, "DETACH_ACK", true, false},
    {MessageType::RenewLease, "RENEW_LEASE", false, false},
    {MessageType::RenewLeaseAck, "RENEW_LEASE_ACK", true, false},
    {MessageType::Revoke, "REVOKE", false, false},
    {MessageType::RevokeAck, "REVOKE_ACK", true, false},

    {MessageType::Query, "QUERY", false, false},
    {MessageType::QueryAck, "QUERY_ACK", true, false},
    {MessageType::ListVirtual, "LIST_VIRTUAL", false, false},
    {MessageType::ListVirtualAck, "LIST_VIRTUAL_ACK", true, false},
    {MessageType::ListBackings, "LIST_BACKINGS", false, false},
    {MessageType::ListBackingsAck, "LIST_BACKINGS_ACK", true, false},
    {MessageType::CapabilityShow, "CAPABILITY_SHOW", false, false},
    {MessageType::CapabilityShowAck, "CAPABILITY_SHOW_ACK", true, false},
    {MessageType::ContractShow, "CONTRACT_SHOW", false, false},
    {MessageType::ContractShowAck, "CONTRACT_SHOW_ACK", true, false},
    {MessageType::IsolationExplain, "ISOLATION_EXPLAIN", false, false},
    {MessageType::IsolationExplainAck, "ISOLATION_EXPLAIN_ACK", true, false},
    {MessageType::MigrationExplain, "MIGRATION_EXPLAIN", false, false},
    {MessageType::MigrationExplainAck, "MIGRATION_EXPLAIN_ACK", true, false},
    {MessageType::ExplainDecisions, "EXPLAIN_DECISIONS", false, false},
    {MessageType::ExplainDecisionsAck, "EXPLAIN_DECISIONS_ACK", true, false},
    {MessageType::SetPolicy, "SET_POLICY", false, false},
    {MessageType::SetPolicyAck, "SET_POLICY_ACK", true, false},
    {MessageType::GetPolicy, "GET_POLICY", false, false},
    {MessageType::GetPolicyAck, "GET_POLICY_ACK", true, false},

    {MessageType::MigrationPlan, "MIGRATION_PLAN", false, false},
    {MessageType::MigrationPlanAck, "MIGRATION_PLAN_ACK", true, false},
    {MessageType::MigrationPrepare, "MIGRATION_PREPARE", false, false},
    {MessageType::MigrationPrepareAck, "MIGRATION_PREPARE_ACK", true, false},
    {MessageType::MigrationCommit, "MIGRATION_COMMIT", false, false},
    {MessageType::MigrationCommitAck, "MIGRATION_COMMIT_ACK", true, false},
    {MessageType::MigrationComplete, "MIGRATION_COMPLETE", false, false},
    {MessageType::MigrationCompleteAck, "MIGRATION_COMPLETE_ACK", true, false},
    {MessageType::MigrationAbort, "MIGRATION_ABORT", false, false},
    {MessageType::MigrationAbortAck, "MIGRATION_ABORT_ACK", true, false},

    {MessageType::Audit, "AUDIT", false, false},
    {MessageType::AuditAck, "AUDIT_ACK", true, false},
    {MessageType::Snapshot, "SNAPSHOT", false, false},
    {MessageType::SnapshotAck, "SNAPSHOT_ACK", true, false},
    {MessageType::Accounting, "ACCOUNTING", false, false},
    {MessageType::AccountingAck, "ACCOUNTING_ACK", true, false},
    {MessageType::Shutdown, "SHUTDOWN", false, false},
    {MessageType::ShutdownAck, "SHUTDOWN_ACK", true, false},

    {MessageType::AgentExecute, "AGENT_EXECUTE", false, true},
    {MessageType::AgentExecuteAck, "AGENT_EXECUTE_ACK", true, true},
    {MessageType::Heartbeat, "HEARTBEAT", false, true},
    {MessageType::HeartbeatAck, "HEARTBEAT_ACK", true, true},

    {MessageType::Execute, "EXECUTE", false, false},
    {MessageType::ExecuteAck, "EXECUTE_ACK", true, false},
    {MessageType::ResolveRecovery, "RESOLVE_RECOVERY", false, false},
    {MessageType::ResolveRecoveryAck, "RESOLVE_RECOVERY_ACK", true, false},

    {MessageType::Error, "ERROR", true, false},
};

constexpr std::pair<Role, std::string_view> kRoles[] = {
    {Role::Unknown, "UNKNOWN"},
    {Role::Client, "CLIENT"},
    {Role::Agent, "AGENT"},
    {Role::Observer, "OBSERVER"},
};

const MessageInfo* find_message(MessageType type) {
  for (const MessageInfo& info : kMessages) {
    if (info.type == type) return &info;
  }
  return nullptr;
}

}  // namespace

std::string_view message_name(MessageType type) noexcept {
  const MessageInfo* info = find_message(type);
  return info == nullptr ? std::string_view{"UNRECOGNIZED"} : info->name;
}

std::optional<MessageType> parse_message_name(std::string_view text) noexcept {
  for (const MessageInfo& info : kMessages) {
    if (info.name == text) return info.type;
  }
  return std::nullopt;
}

bool message_is_agent_directed(MessageType type) noexcept {
  const MessageInfo* info = find_message(type);
  return info != nullptr && info->agent_directed;
}

bool is_response(MessageType type) noexcept {
  const MessageInfo* info = find_message(type);
  return info != nullptr && info->response;
}

MessageType response_for(MessageType request) noexcept {
  if (is_response(request)) return MessageType::Error;
  const auto next = static_cast<MessageType>(static_cast<std::uint16_t>(request) + 1);
  return message_is_agent_directed(next) == message_is_agent_directed(request) && message_name(next) != "UNRECOGNIZED"
             ? next
             : MessageType::Error;
}

std::string_view role_name(Role role) noexcept {
  for (const auto& entry : kRoles) {
    if (entry.first == role) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<Role> parse_role(std::string_view text) noexcept {
  for (const auto& entry : kRoles) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

// ---- framing -------------------------------------------------------------

std::vector<Byte> encode_frame(const FrameHeader& header, ByteSpan payload) {
  std::vector<Byte> out;
  out.reserve(kFrameHeaderSize + payload.size());
  put_u32(out, header.magic);
  put_u16(out, header.version);
  put_u16(out, header.type);
  put_u32(out, header.flags);
  put_u64(out, header.request);
  put_u32(out, static_cast<std::uint32_t>(payload.size()));
  put_u32(out, Crc32c::compute(payload.data(), payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

Result<std::pair<FrameHeader, std::vector<Byte>>> decode_frame(ByteSpan bytes) {
  if (bytes.size() < kFrameHeaderSize) {
    return Status(StatusCode::TruncatedState, "frame is shorter than the frame header");
  }
  FrameHeader header;
  header.magic = get_u32(bytes, 0);
  header.version = get_u16(bytes, 4);
  header.type = get_u16(bytes, 6);
  header.flags = get_u32(bytes, 8);
  header.request = get_u64(bytes, 12);
  header.payload_length = get_u32(bytes, 20);
  header.payload_crc = get_u32(bytes, 24);
  if (header.magic != kFrameMagic) {
    return Status(StatusCode::MalformedFrame, "frame magic does not match");
  }
  if (bytes.size() - kFrameHeaderSize != header.payload_length) {
    return Status(StatusCode::MalformedFrame, "frame declares " + std::to_string(header.payload_length) +
                                                  " payload byte(s) but " +
                                                  std::to_string(bytes.size() - kFrameHeaderSize) + " are present");
  }
  const ByteSpan payload = bytes.subspan(kFrameHeaderSize);
  if (Crc32c::compute(payload.data(), payload.size()) != header.payload_crc) {
    return Status(StatusCode::IntegrityFailure, "frame payload failed its integrity check");
  }
  std::vector<Byte> copy(payload.begin(), payload.end());
  return std::make_pair(header, std::move(copy));
}

void FrameStream::compact() {
  if (consumed_ == 0) return;
  if (consumed_ >= buffer_.size()) {
    buffer_.clear();
    consumed_ = 0;
    return;
  }
  buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(consumed_));
  consumed_ = 0;
}

void FrameStream::reset() {
  buffer_.clear();
  consumed_ = 0;
}

Status FrameStream::feed(ByteSpan chunk, std::vector<Frame>& out) {
  if (buffered() + chunk.size() > static_cast<std::size_t>(max_payload_) + kFrameHeaderSize) {
    return Status(StatusCode::FrameTooLarge,
                  "buffered frame data would exceed the maximum frame size of " + std::to_string(max_payload_) +
                      " byte(s)");
  }
  buffer_.insert(buffer_.end(), chunk.begin(), chunk.end());

  for (;;) {
    const std::size_t available = buffered();
    if (available < kFrameHeaderSize) break;
    const ByteSpan view{buffer_.data() + consumed_, available};
    const std::uint32_t magic = get_u32(view, 0);
    if (magic != kFrameMagic) {
      return Status(StatusCode::MalformedFrame, "stream does not start with a valid frame magic");
    }
    const std::uint16_t version = get_u16(view, 4);
    if (version != protocol_version()) {
      return Status(StatusCode::VersionMismatch, "peer speaks protocol version " + std::to_string(version) +
                                                     " but this build speaks " +
                                                     std::to_string(protocol_version()));
    }
    const std::uint32_t length = get_u32(view, 20);
    const std::uint32_t crc = get_u32(view, 24);
    if (length > max_payload_) {
      return Status(StatusCode::FrameTooLarge, "frame declares " + std::to_string(length) +
                                                   " payload byte(s), exceeding the limit of " +
                                                   std::to_string(max_payload_));
    }
    if (available < kFrameHeaderSize + length) break;

    Frame frame;
    frame.header.magic = magic;
    frame.header.version = version;
    frame.header.type = get_u16(view, 6);
    frame.header.flags = get_u32(view, 8);
    frame.header.request = get_u64(view, 12);
    frame.header.payload_length = length;
    frame.header.payload_crc = crc;
    const ByteSpan payload = view.subspan(kFrameHeaderSize, length);
    if (Crc32c::compute(payload.data(), payload.size()) != crc) {
      return Status(StatusCode::IntegrityFailure, "frame payload failed its integrity check");
    }
    frame.payload.assign(payload.begin(), payload.end());
    out.push_back(std::move(frame));
    consumed_ += kFrameHeaderSize + length;
  }
  compact();
  return Status{};
}

// ---- field map -----------------------------------------------------------

namespace {

// A field map may carry at most one entry per key. Writing the same key twice
// replaces the previous value rather than producing a map the decoder would
// have to refuse.
void store_field(std::vector<FieldWriterEntry>& entries, std::uint16_t key, FieldType type,
                 std::vector<Byte> payload) {
  for (FieldWriterEntry& entry : entries) {
    if (entry.key != key) continue;
    entry.type = type;
    entry.payload = std::move(payload);
    return;
  }
  entries.push_back(FieldWriterEntry{key, type, std::move(payload)});
}

}  // namespace

FieldWriter& FieldWriter::u64(std::uint16_t key, std::uint64_t value) {
  std::vector<Byte> payload;
  put_u64(payload, value);
  store_field(entries_, key, FieldType::U64, std::move(payload));
  return *this;
}

FieldWriter& FieldWriter::i64(std::uint16_t key, std::int64_t value) {
  std::vector<Byte> payload;
  put_u64(payload, static_cast<std::uint64_t>(value));
  store_field(entries_, key, FieldType::I64, std::move(payload));
  return *this;
}

FieldWriter& FieldWriter::boolean(std::uint16_t key, bool value) {
  std::vector<Byte> payload;
  payload.push_back(static_cast<Byte>(value ? 1u : 0u));
  store_field(entries_, key, FieldType::Bool, std::move(payload));
  return *this;
}

FieldWriter& FieldWriter::str(std::uint16_t key, std::string_view value) {
  std::vector<Byte> payload;
  put_u32(payload, static_cast<std::uint32_t>(value.size()));
  const auto* begin = reinterpret_cast<const Byte*>(value.data());
  payload.insert(payload.end(), begin, begin + value.size());
  store_field(entries_, key, FieldType::Str, std::move(payload));
  return *this;
}

FieldWriter& FieldWriter::bytes(std::uint16_t key, ByteSpan value) {
  std::vector<Byte> payload;
  put_u32(payload, static_cast<std::uint32_t>(value.size()));
  payload.insert(payload.end(), value.begin(), value.end());
  store_field(entries_, key, FieldType::Bytes, std::move(payload));
  return *this;
}

FieldWriter& FieldWriter::list_u64(std::uint16_t key, const std::vector<std::uint64_t>& values) {
  std::vector<Byte> payload;
  put_u32(payload, static_cast<std::uint32_t>(values.size()));
  for (std::uint64_t value : values) put_u64(payload, value);
  store_field(entries_, key, FieldType::ListU64, std::move(payload));
  return *this;
}

FieldWriter& FieldWriter::list_str(std::uint16_t key, const std::vector<std::string>& values) {
  std::vector<Byte> payload;
  put_u32(payload, static_cast<std::uint32_t>(values.size()));
  for (const std::string& value : values) {
    put_u32(payload, static_cast<std::uint32_t>(value.size()));
    const auto* begin = reinterpret_cast<const Byte*>(value.data());
    payload.insert(payload.end(), begin, begin + value.size());
  }
  store_field(entries_, key, FieldType::ListStr, std::move(payload));
  return *this;
}

FieldWriter& FieldWriter::nested_list(std::uint16_t key, const std::vector<std::vector<Byte>>& items) {
  std::vector<Byte> payload;
  put_u32(payload, static_cast<std::uint32_t>(items.size()));
  for (const std::vector<Byte>& item : items) {
    put_u32(payload, static_cast<std::uint32_t>(item.size()));
    payload.insert(payload.end(), item.begin(), item.end());
  }
  store_field(entries_, key, FieldType::ListNested, std::move(payload));
  return *this;
}

bool FieldWriter::has(std::uint16_t key) const noexcept {
  for (const FieldWriterEntry& entry : entries_) {
    if (entry.key == key) return true;
  }
  return false;
}

std::vector<Byte> FieldWriter::take() const {
  std::vector<FieldWriterEntry> sorted = entries_;
  std::sort(sorted.begin(), sorted.end(),
            [](const FieldWriterEntry& a, const FieldWriterEntry& b) { return a.key < b.key; });
  Encoder out;
  out.u32(static_cast<std::uint32_t>(sorted.size()));
  for (const FieldWriterEntry& entry : sorted) {
    out.u16(entry.key);
    out.u8(static_cast<std::uint8_t>(entry.type));
    out.raw(ByteSpan{entry.payload.data(), entry.payload.size()});
  }
  return out.take();
}

Result<FieldReader> FieldReader::create(ByteSpan data, DecodeLimits limits) {
  FieldReader reader;
  reader.owned_.assign(data.begin(), data.end());
  Decoder in(ByteSpan{reader.owned_.data(), reader.owned_.size()}, limits);
  auto count = in.list_header(1024);
  if (!count.ok()) return count.status();
  for (std::size_t i = 0; i < *count; ++i) {
    auto key = in.u16();
    if (!key.ok()) return key.status();
    auto type = in.u8();
    if (!type.ok()) return type.status();
    if (*type < static_cast<std::uint8_t>(FieldType::U64) ||
        *type > static_cast<std::uint8_t>(FieldType::ListNested)) {
      return Status(StatusCode::MalformedFrame, "field type " + std::to_string(*type) + " is outside its domain");
    }
    auto payload = in.raw_field();
    if (!payload.ok()) return payload.status();
    if (reader.fields_.find(*key) != reader.fields_.end()) {
      return Status(StatusCode::ProtocolViolation, "field map repeats key " + std::to_string(*key));
    }
    reader.fields_.emplace(*key, Entry{static_cast<FieldType>(*type), *payload});
  }
  in.depth_leave();
  const Status end = in.require_end();
  if (!end.ok()) return end;
  return reader;
}

bool FieldReader::has(std::uint16_t key) const noexcept { return fields_.find(key) != fields_.end(); }

std::optional<std::uint64_t> FieldReader::u64(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::U64) return std::nullopt;
  return get_u64(it->second.payload, 0);
}

std::optional<std::int64_t> FieldReader::i64(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::I64) return std::nullopt;
  return static_cast<std::int64_t>(get_u64(it->second.payload, 0));
}

std::optional<bool> FieldReader::boolean(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::Bool) return std::nullopt;
  return static_cast<std::uint8_t>(it->second.payload[0]) != 0;
}

std::optional<std::string> FieldReader::str(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::Str) return std::nullopt;
  const std::uint32_t length = get_u32(it->second.payload, 0);
  if (length + 4u > it->second.payload.size()) return std::nullopt;
  return std::string(reinterpret_cast<const char*>(it->second.payload.data() + 4), length);
}

std::optional<ByteSpan> FieldReader::bytes(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::Bytes) return std::nullopt;
  const std::uint32_t length = get_u32(it->second.payload, 0);
  if (length + 4u > it->second.payload.size()) return std::nullopt;
  return it->second.payload.subspan(4, length);
}

std::optional<std::vector<std::uint64_t>> FieldReader::list_u64(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::ListU64) return std::nullopt;
  const std::uint32_t count = get_u32(it->second.payload, 0);
  if (static_cast<std::size_t>(count) * 8u + 4u != it->second.payload.size()) return std::nullopt;
  std::vector<std::uint64_t> out;
  out.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) out.push_back(get_u64(it->second.payload, 4u + i * 8u));
  return out;
}

std::optional<std::vector<std::string>> FieldReader::list_str(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::ListStr) return std::nullopt;
  const std::uint32_t count = get_u32(it->second.payload, 0);
  std::vector<std::string> out;
  out.reserve(count);
  std::size_t offset = 4;
  for (std::uint32_t i = 0; i < count; ++i) {
    if (offset + 4u > it->second.payload.size()) return std::nullopt;
    const std::uint32_t length = get_u32(it->second.payload, offset);
    offset += 4;
    if (offset + length > it->second.payload.size()) return std::nullopt;
    out.emplace_back(reinterpret_cast<const char*>(it->second.payload.data() + offset), length);
    offset += length;
  }
  if (offset != it->second.payload.size()) return std::nullopt;
  return out;
}

std::vector<Result<FieldReader>> FieldReader::nested_list(std::uint16_t key) const {
  std::vector<Result<FieldReader>> out;
  const auto it = fields_.find(key);
  if (it == fields_.end() || it->second.type != FieldType::ListNested) return out;
  const std::uint32_t count = get_u32(it->second.payload, 0);
  std::size_t offset = 4;
  for (std::uint32_t i = 0; i < count; ++i) {
    if (offset + 4u > it->second.payload.size()) break;
    const std::uint32_t length = get_u32(it->second.payload, offset);
    offset += 4;
    if (offset + length > it->second.payload.size()) break;
    out.push_back(FieldReader::create(it->second.payload.subspan(offset, length)));
    offset += length;
  }
  return out;
}

Result<std::uint64_t> FieldReader::require_u64(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) {
    return Status(StatusCode::ProtocolViolation, "required field " + std::to_string(key) + " is missing");
  }
  auto value = u64(key);
  if (!value.has_value()) {
    return Status(StatusCode::ProtocolViolation, "field " + std::to_string(key) + " is not a u64");
  }
  return *value;
}

Result<std::int64_t> FieldReader::require_i64(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) {
    return Status(StatusCode::ProtocolViolation, "required field " + std::to_string(key) + " is missing");
  }
  auto value = i64(key);
  if (!value.has_value()) {
    return Status(StatusCode::ProtocolViolation, "field " + std::to_string(key) + " is not an i64");
  }
  return *value;
}

Result<bool> FieldReader::require_bool(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) {
    return Status(StatusCode::ProtocolViolation, "required field " + std::to_string(key) + " is missing");
  }
  auto value = boolean(key);
  if (!value.has_value()) {
    return Status(StatusCode::ProtocolViolation, "field " + std::to_string(key) + " is not a boolean");
  }
  return *value;
}

Result<std::string> FieldReader::require_str(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) {
    return Status(StatusCode::ProtocolViolation, "required field " + std::to_string(key) + " is missing");
  }
  auto value = str(key);
  if (!value.has_value()) {
    return Status(StatusCode::ProtocolViolation, "field " + std::to_string(key) + " is not a string");
  }
  return *value;
}

Result<ByteSpan> FieldReader::require_bytes(std::uint16_t key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) {
    return Status(StatusCode::ProtocolViolation, "required field " + std::to_string(key) + " is missing");
  }
  auto value = bytes(key);
  if (!value.has_value()) {
    return Status(StatusCode::ProtocolViolation, "field " + std::to_string(key) + " is not a byte string");
  }
  return *value;
}

std::vector<std::uint16_t> FieldReader::keys() const {
  std::vector<std::uint16_t> out;
  out.reserve(fields_.size());
  for (const auto& entry : fields_) out.push_back(entry.first);
  return out;
}

std::vector<Byte> encode_error_payload(StatusCode code, std::string_view detail) {
  FieldWriter writer;
  writer.u64(kFieldStatus, static_cast<std::uint64_t>(code));
  writer.str(kFieldDetail, detail);
  return writer.take();
}

Result<std::pair<StatusCode, std::string>> decode_error_payload(ByteSpan payload) {
  auto reader = FieldReader::create(payload);
  if (!reader.ok()) return reader.status();
  auto code = reader->require_u64(kFieldStatus);
  if (!code.ok()) return code.status();
  auto detail = reader->str(kFieldDetail);
  return std::make_pair(static_cast<StatusCode>(*code), detail.has_value() ? *detail : std::string{});
}

}  // namespace av
