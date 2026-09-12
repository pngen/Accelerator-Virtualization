// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/codec.hpp"
#include "av/ids.hpp"
#include "av/status.hpp"
#include "av/version.hpp"

namespace av {

enum class MessageType : std::uint16_t {
  Invalid = 0,
  Hello = 1,
  HelloAck = 2,
  Goodbye = 3,

  RegisterPhysical = 10,
  RegisterPhysicalAck = 11,
  RefreshPhysical = 12,
  RefreshPhysicalAck = 13,
  ListPhysical = 14,
  ListPhysicalAck = 15,
  PhysicalLost = 18,
  PhysicalLostAck = 19,

  CreateTenant = 20,
  CreateTenantAck = 21,
  ListTenants = 22,
  ListTenantsAck = 23,
  FenceTenant = 24,
  FenceTenantAck = 25,
  TransferOwnership = 26,
  TransferOwnershipAck = 27,

  CreateVirtual = 30,
  CreateVirtualAck = 31,
  UpdateContract = 32,
  UpdateContractAck = 33,
  AssignBacking = 34,
  AssignBackingAck = 35,
  ReplaceBacking = 36,
  ReplaceBackingAck = 37,
  RetireVirtual = 38,
  RetireVirtualAck = 39,
  FenceVirtual = 40,
  FenceVirtualAck = 41,
  ActivateVirtual = 42,
  ActivateVirtualAck = 43,
  SuspendVirtual = 44,
  SuspendVirtualAck = 45,
  ResumeVirtual = 46,
  ResumeVirtualAck = 47,
  DrainVirtual = 48,
  DrainVirtualAck = 49,

  Attach = 50,
  AttachAck = 51,
  Detach = 52,
  DetachAck = 53,
  RenewLease = 54,
  RenewLeaseAck = 55,
  Revoke = 56,
  RevokeAck = 57,

  Query = 60,
  QueryAck = 61,
  ListVirtual = 62,
  ListVirtualAck = 63,
  ListBackings = 64,
  ListBackingsAck = 65,
  CapabilityShow = 66,
  CapabilityShowAck = 67,
  ContractShow = 68,
  ContractShowAck = 69,
  IsolationExplain = 70,
  IsolationExplainAck = 71,
  MigrationExplain = 72,
  MigrationExplainAck = 73,
  ExplainDecisions = 74,
  ExplainDecisionsAck = 75,
  SetPolicy = 76,
  SetPolicyAck = 77,
  GetPolicy = 78,
  GetPolicyAck = 79,

  MigrationPlan = 80,
  MigrationPlanAck = 81,
  MigrationPrepare = 82,
  MigrationPrepareAck = 83,
  MigrationCommit = 84,
  MigrationCommitAck = 85,
  MigrationComplete = 86,
  MigrationCompleteAck = 87,
  MigrationAbort = 88,
  MigrationAbortAck = 89,

  Audit = 90,
  AuditAck = 91,
  Snapshot = 92,
  SnapshotAck = 93,
  Accounting = 94,
  AccountingAck = 95,
  Shutdown = 96,
  ShutdownAck = 97,

  // Coordinator-directed operations executed by an agent.
  AgentExecute = 110,
  AgentExecuteAck = 111,
  Heartbeat = 114,
  HeartbeatAck = 115,

  // Client-facing execution against a virtual accelerator.
  Execute = 120,
  ExecuteAck = 121,
  ResolveRecovery = 122,
  ResolveRecoveryAck = 123,

  Error = 200,
};

std::string_view message_name(MessageType type) noexcept;
std::optional<MessageType> parse_message_name(std::string_view text) noexcept;
bool message_is_agent_directed(MessageType type) noexcept;
MessageType response_for(MessageType request) noexcept;
bool is_response(MessageType type) noexcept;

enum class Role : std::uint8_t {
  Unknown = 0,
  Client = 1,
  Agent = 2,
  Observer = 3,
};

std::string_view role_name(Role role) noexcept;
std::optional<Role> parse_role(std::string_view text) noexcept;

// ---- framing -------------------------------------------------------------
inline constexpr std::uint32_t kFrameMagic = 0x31465641u;  // "AVF1"
inline constexpr std::size_t kFrameHeaderSize = 28;
inline constexpr std::uint32_t kMaxFramePayload = 8u * 1024u * 1024u;
inline constexpr std::uint32_t kDefaultMaxFramePayload = 1u * 1024u * 1024u;

enum FrameFlags : std::uint32_t {
  kFlagNone = 0,
  kFlagResponse = 1u << 0,
  kFlagError = 1u << 1,
  kFlagAgentDirected = 1u << 2,
  kFlagShutdown = 1u << 3,
  kFlagReplay = 1u << 4,
};

struct FrameHeader {
  std::uint32_t magic{kFrameMagic};
  std::uint16_t version{protocol_version()};
  std::uint16_t type{0};
  std::uint32_t flags{0};
  std::uint64_t request{0};
  std::uint32_t payload_length{0};
  std::uint32_t payload_crc{0};
};

std::vector<Byte> encode_frame(const FrameHeader& header, ByteSpan payload);
// Decodes exactly one complete frame; trailing bytes are an error.
Result<std::pair<FrameHeader, std::vector<Byte>>> decode_frame(ByteSpan bytes);

// Streaming frame decoder. Bounds buffered bytes, rejects oversized
// declarations before allocating, and validates the payload CRC before the
// payload is ever exposed.
class FrameStream {
 public:
  explicit FrameStream(std::uint32_t max_payload = kDefaultMaxFramePayload) : max_payload_(max_payload) {}

  struct Frame {
    FrameHeader header{};
    std::vector<Byte> payload{};
  };

  Status feed(ByteSpan chunk, std::vector<Frame>& out);
  std::size_t buffered() const noexcept { return buffer_.size() - consumed_; }
  void reset();
  std::uint32_t max_payload() const noexcept { return max_payload_; }
  void set_max_payload(std::uint32_t value) { max_payload_ = value; }

 private:
  void compact();
  std::vector<Byte> buffer_{};
  std::size_t consumed_{0};
  std::uint32_t max_payload_{kDefaultMaxFramePayload};
};

// ---- canonical field map -------------------------------------------------
enum class FieldType : std::uint8_t {
  U64 = 1,
  I64 = 2,
  Bool = 3,
  Str = 4,
  Bytes = 5,
  ListU64 = 6,
  ListStr = 7,
  ListNested = 8,
};

// Field keys are stable wire identifiers.
enum FieldKey : std::uint16_t {
  kFieldStatus = 1,
  kFieldMessage = 2,
  kFieldRole = 3,
  kFieldAgentName = 4,
  kFieldAgentId = 5,
  kFieldBootId = 6,
  kFieldEpoch = 7,
  kFieldRequest = 8,
  kFieldProtocolVersion = 9,
  kFieldServerName = 10,
  kFieldConnectionId = 11,
  kFieldHeartbeat = 12,
  kFieldShutdown = 13,

  kFieldVirtualId = 20,
  kFieldVirtualGeneration = 21,
  kFieldVirtualName = 22,
  kFieldStateGeneration = 23,
  kFieldState = 24,
  kFieldStateReason = 25,
  kFieldTenantId = 26,
  kFieldTenantGeneration = 27,
  kFieldTenantName = 28,
  kFieldExternalSubject = 29,
  kFieldBackingId = 30,
  kFieldBackingGeneration = 31,
  kFieldPhysicalId = 32,
  kFieldPhysicalGeneration = 33,
  kFieldLeaseId = 34,
  kFieldLeaseGeneration = 35,
  kFieldPolicyGeneration = 36,
  kFieldMigrationId = 37,
  kFieldMigrationGeneration = 38,
  kFieldReason = 39,
  kFieldNewOwnerId = 40,
  kFieldNewOwnerGeneration = 41,

  kFieldContractBlob = 50,
  kFieldPolicyBlob = 51,
  kFieldProjectionBlob = 52,
  kFieldIsolationBlob = 53,
  kFieldViewBlob = 54,
  kFieldBackingBlob = 55,
  kFieldPhysicalBlob = 56,
  kFieldTenantBlob = 57,
  kFieldLeaseBlob = 58,
  kFieldMigrationBlob = 59,
  kFieldVirtualBlob = 60,
  kFieldDecisionBlob = 61,
  kFieldAuditBlob = 62,
  kFieldPlanBlob = 63,

  kFieldCount = 70,
  kFieldLimit = 71,
  kFieldBlobs = 72,
  kFieldText = 73,
  kFieldDetail = 74,
  kFieldClean = 75,
  kFieldViolations = 76,
  kFieldVirtualChecks = 77,
  kFieldDigest = 78,
  kFieldAccountingBlob = 79,

  kFieldOp = 90,
  kFieldHandle = 91,
  kFieldBytes = 92,
  kFieldData = 93,
  kFieldDeviceName = 94,
  kFieldDriverVersion = 95,
  kFieldDeviceMemoryTotal = 96,
  kFieldDeviceMemoryFree = 97,
  kFieldDiscovered = 98,
  kFieldDescriptorBlob = 99,
  kFieldStableKey = 100,
  kFieldPresent = 101,
  kFieldEvidenceId = 102,
  kFieldEvidenceGeneration = 103,

  kFieldTransparency = 110,
  kFieldAllocatedBytes = 111,
  kFieldActiveAttachments = 112,
  kFieldMigrationClass = 113,
  kFieldMigrationAllowed = 114,
  kFieldBackingClass = 115,
  kFieldMultiplexing = 116,
  kFieldIsolationClass = 117,
  kFieldProvenance = 118,
  kFieldMechanism = 119,
  kFieldLabel = 120,
  kFieldViolationCount = 121,
  kFieldExternallyManaged = 122,
  kFieldHandleCount = 123,
  kFieldHandles = 124,
  kFieldOffset = 125,

  kFieldVendor = 130,
  kFieldModel = 131,
  kFieldArchitecture = 132,
  kFieldCapacityBytes = 133,
  kFieldComputeUnits = 134,
  kFieldCcMajor = 135,
  kFieldCcMinor = 136,
  kFieldHardwarePartitionCapable = 137,
  kFieldVirtualFunctionCapable = 138,
  kFieldMigCapable = 139,
  kFieldExclusive = 140,
  kFieldExternalPartitionRef = 141,
  kFieldCapabilitiesBlob = 142,
  kFieldBackings = 143,
};

struct FieldWriterEntry {
  std::uint16_t key;
  FieldType type;
  std::vector<Byte> payload;
};

class FieldWriter {
 public:
  FieldWriter& u64(std::uint16_t key, std::uint64_t value);
  FieldWriter& i64(std::uint16_t key, std::int64_t value);
  FieldWriter& boolean(std::uint16_t key, bool value);
  FieldWriter& str(std::uint16_t key, std::string_view value);
  FieldWriter& bytes(std::uint16_t key, ByteSpan value);
  FieldWriter& list_u64(std::uint16_t key, const std::vector<std::uint64_t>& values);
  FieldWriter& list_str(std::uint16_t key, const std::vector<std::string>& values);
  FieldWriter& nested_list(std::uint16_t key, const std::vector<std::vector<Byte>>& items);

  // Deterministic serialisation: entries are emitted in ascending key order
  // regardless of the order in which they were written. Const, so a prepared
  // message can be sent more than once.
  std::vector<Byte> take() const;
  std::size_t size() const noexcept { return entries_.size(); }
  bool has(std::uint16_t key) const noexcept;

 private:
  std::vector<FieldWriterEntry> entries_{};
};

// A decoded field map. The reader owns a private copy of the encoded bytes,
// so it stays valid after the frame it was decoded from is gone. It is
// movable and deliberately not copyable, because the entries reference the
// owned buffer.
class FieldReader {
 public:
  FieldReader() = default;
  FieldReader(FieldReader&&) noexcept = default;
  FieldReader& operator=(FieldReader&&) noexcept = default;
  FieldReader(const FieldReader&) = delete;
  FieldReader& operator=(const FieldReader&) = delete;
  ~FieldReader() = default;

  static Result<FieldReader> create(ByteSpan data, DecodeLimits limits = {});

  bool has(std::uint16_t key) const noexcept;
  std::optional<std::uint64_t> u64(std::uint16_t key) const;
  std::optional<std::int64_t> i64(std::uint16_t key) const;
  std::optional<bool> boolean(std::uint16_t key) const;
  std::optional<std::string> str(std::uint16_t key) const;
  std::optional<ByteSpan> bytes(std::uint16_t key) const;
  std::optional<std::vector<std::uint64_t>> list_u64(std::uint16_t key) const;
  std::optional<std::vector<std::string>> list_str(std::uint16_t key) const;
  // Nested field maps are returned as independent readers over their own bytes.
  std::vector<Result<FieldReader>> nested_list(std::uint16_t key) const;

  Result<std::uint64_t> require_u64(std::uint16_t key) const;
  Result<std::int64_t> require_i64(std::uint16_t key) const;
  Result<bool> require_bool(std::uint16_t key) const;
  Result<std::string> require_str(std::uint16_t key) const;
  Result<ByteSpan> require_bytes(std::uint16_t key) const;

  std::vector<std::uint16_t> keys() const;
  std::size_t size() const noexcept { return fields_.size(); }

 private:
  struct Entry {
    FieldType type;
    ByteSpan payload;
  };
  std::vector<Byte> owned_{};
  std::map<std::uint16_t, Entry> fields_{};
};

// ---- error payload -------------------------------------------------------
std::vector<Byte> encode_error_payload(StatusCode code, std::string_view detail);
Result<std::pair<StatusCode, std::string>> decode_error_payload(ByteSpan payload);

}  // namespace av
