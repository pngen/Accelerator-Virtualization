// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/accounting.hpp"
#include "av/audit.hpp"
#include "av/backing.hpp"
#include "av/capability.hpp"
#include "av/contract.hpp"
#include "av/evidence.hpp"
#include "av/ids.hpp"
#include "av/isolation.hpp"
#include "av/lifecycle.hpp"
#include "av/migration.hpp"
#include "av/policy.hpp"
#include "av/status.hpp"
#include "av/taxonomy.hpp"
#include "av/time.hpp"
#include "av/version.hpp"

namespace av {

// Tenancy is explicit and generation-bound. Process identity is not tenant
// identity: external identity establishment may be delegated, but authority
// state is governed here.
struct TenantRecord {
  TenantId id{};
  TenantGeneration generation{};
  std::string name{};
  // Subject asserted by an external identity provider, if one participates.
  // Recorded for audit; never consulted as authority by this runtime.
  std::string external_subject{};
  UnixMicros created_at{0};
  UnixMicros updated_at{0};
  bool fenced{false};
  std::string fence_reason{};
  std::uint32_t active_attachments{0};
  std::vector<VirtualAcceleratorId> owned{};  // sorted
};

enum class LeaseState : std::uint8_t {
  Granted = 0,
  Active = 1,
  Revoked = 2,
  Expired = 3,
  Fenced = 4,
  Superseded = 5,
};

std::string_view lease_state_name(LeaseState value) noexcept;
std::optional<LeaseState> parse_lease_state(std::string_view text) noexcept;
bool lease_state_is_live(LeaseState state) noexcept;

// Access to a virtual accelerator is attachment/lease-bound. A lease has its
// own generation and is invalidated by any generation drift it was bound to.
struct LeaseRecord {
  LeaseId id{};
  LeaseGeneration generation{};

  VirtualAcceleratorId virtual_id{};
  VirtualAcceleratorGeneration virtual_generation{};
  TenantId tenant{};
  TenantGeneration tenant_generation{};

  BackingGeneration backing_generation{};
  PhysicalDeviceGeneration physical_generation{};
  PolicyGeneration policy_generation{};
  CoordinatorEpoch epoch{};
  RequestId grant_request{};

  LeaseState state{LeaseState::Granted};
  UnixMicros granted_at{0};
  UnixMicros renewed_at{0};
  UnixMicros expires_at{0};
  UnixMicros revoked_at{0};
  std::uint32_t renewals{0};
  std::string reason{};
};

// One entry per backing that has ever backed a virtual accelerator.
struct BackingHistoryEntry {
  BackingAssignmentId assignment{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  BackingClass klass{BackingClass::Unknown};
  MultiplexingMode multiplexing{MultiplexingMode::None};
  UnixMicros from{0};
  UnixMicros to{0};
  bool current{false};
  std::string reason{};
};

struct VirtualAcceleratorRecord {
  VirtualAcceleratorId id{};
  // Identity generation. Advances on every authoritative mutation of this
  // object. It is stable across legal backing replacement only in the sense
  // that the *identity* is stable; the generation advancing is how observers
  // learn that something authoritative changed.
  VirtualAcceleratorGeneration generation{};

  std::string name{};
  TenantId owner{};
  TenantGeneration owner_generation{};

  VirtualLifecycleState state{VirtualLifecycleState::Created};
  // The generation at which the current lifecycle state became authoritative.
  VirtualAcceleratorGeneration state_generation{};
  std::string state_reason{};

  ResourceContract contract{};
  CapabilityProjection projection{};

  BackingAssignmentId assignment{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  BackingClass backing_class{BackingClass::Unknown};

  MultiplexingMode multiplexing{MultiplexingMode::None};
  IsolationClass isolation_class{IsolationClass::Unknown};
  IsolationProfile isolation{};

  PolicyGeneration policy_generation{};
  CoordinatorEpoch epoch{};

  MigrationId migration{};
  MigrationGeneration migration_generation{};

  UnixMicros created_at{0};
  UnixMicros updated_at{0};
  UnixMicros retired_at{0};
  std::string retirement_reason{};

  // Software-enforced virtual accounting. Enforceable only where the backend
  // adapter routes allocation through this runtime.
  std::uint64_t allocated_bytes{0};
  std::uint64_t peak_allocated_bytes{0};
  std::uint64_t allocation_operations{0};
  std::uint64_t kernel_operations{0};

  std::uint32_t active_attachments{0};
  std::vector<LeaseId> leases{};  // sorted
  std::vector<BackingHistoryEntry> backing_history{};
};

// Recorded so that a replayed request is refused deterministically, including
// across a coordinator restart.
struct RequestOutcomeRecord {
  RequestId request{};
  // Request identities are scoped to the session that issued them: two
  // different clients may legitimately use the same small identity, while a
  // retry inside one session must be recognised as a replay.
  std::uint64_t session{0};
  std::string operation{};
  StatusCode outcome{StatusCode::Ok};
  UnixMicros at{0};
};

// Complete durable virtualization metadata. Every container is ordered so that
// iteration, serialization and rendering are deterministic.
struct VirtualizationState {
  std::uint32_t schema{schema_version()};
  std::uint64_t next_sequence{1};
  CoordinatorEpoch epoch{};

  VirtualizationPolicy policy{};
  PolicyGeneration policy_generation{};

  std::map<TenantId, TenantRecord> tenants{};
  std::map<PhysicalDeviceId, PhysicalDeviceRecord> physical{};
  std::map<BackingId, BackingRecord> backings{};
  std::map<VirtualAcceleratorId, VirtualAcceleratorRecord> virtuals{};
  std::map<LeaseId, LeaseRecord> leases{};
  std::map<BackingAssignmentId, BackingAssignment> assignments{};
  std::map<MigrationId, MigrationRecord> migrations{};
  std::map<EvidenceId, EvidenceRecord> evidence{};

  AccountingCounters accounting{};
  std::vector<AuditEntry> audit{};              // bounded tail, deterministic order
  std::vector<Decision> decisions{};            // bounded tail, deterministic order
  std::vector<RequestOutcomeRecord> requests{}; // bounded replay-prevention window

  std::size_t virtual_count() const noexcept { return virtuals.size(); }
};

inline constexpr std::size_t kDecisionCapacity = 4096;
inline constexpr std::size_t kRequestWindowCapacity = 2048;

// Deterministic canonical rendering of durable state, used by snapshot verify.
std::string render_snapshot(const VirtualizationState& state);
std::uint64_t state_fingerprint(const VirtualizationState& state);

// Live (non-durable) agent session state. Never persisted: process-local
// authority does not survive a coordinator restart.
struct AgentSession {
  AgentId id{};
  AgentBootId boot{};
  std::string name{};
  std::string endpoint{};
  bool connected{false};
  UnixMicros connected_at{0};
  UnixMicros last_seen{0};
  std::uint64_t connection_id{0};
  std::vector<PhysicalDeviceId> devices{};  // sorted
};

}  // namespace av
