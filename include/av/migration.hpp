// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/backing.hpp"
#include "av/ids.hpp"
#include "av/status.hpp"
#include "av/taxonomy.hpp"
#include "av/time.hpp"

namespace av {

// Explicit migration lifecycle. The authority cutover point is exactly the
// Planned..CommitReady -> Committed edge: before it the source backing is
// authoritative, after it the destination is, never both.
enum class MigrationState : std::uint8_t {
  Planned = 0,
  Prepared = 1,
  SourceDraining = 2,
  DestinationPrepared = 3,
  StateTransferPending = 4,
  StateTransferred = 5,
  CommitReady = 6,
  Committed = 7,
  SourceRevoked = 8,
  Completed = 9,
  Aborted = 10,
  RecoveryRequired = 11,
  Failed = 12,
};

std::string_view migration_state_name(MigrationState value) noexcept;
std::optional<MigrationState> parse_migration_state(std::string_view text) noexcept;
std::vector<MigrationState> all_migration_states();

bool is_legal_migration_transition(MigrationState from, MigrationState to) noexcept;
Status check_migration_transition(MigrationState from, MigrationState to);
std::vector<MigrationState> allowed_migration_transitions_from(MigrationState from);
bool migration_state_is_terminal(MigrationState state) noexcept;
bool migration_state_holds_authority(MigrationState state) noexcept;
// True once the destination backing owns authority and the source must not.
bool migration_state_after_cutover(MigrationState state) noexcept;

// A migration plan is bound to every generation that participated in its
// construction. Any drift invalidates it before the next commit-affecting
// phase.
struct MigrationPlan {
  MigrationId id{};
  MigrationGeneration generation{};

  VirtualAcceleratorId virtual_id{};
  VirtualAcceleratorGeneration virtual_generation{};

  BackingId source_backing{};
  BackingGeneration source_backing_generation{};
  BackingId destination_backing{};
  BackingGeneration destination_backing_generation{};

  PhysicalDeviceId source_physical{};
  PhysicalDeviceGeneration source_physical_generation{};
  PhysicalDeviceId destination_physical{};
  PhysicalDeviceGeneration destination_physical_generation{};

  TenantId tenant{};
  TenantGeneration tenant_generation{};
  ResourceContractGeneration contract_generation{};
  CapabilityProjectionGeneration projection_generation{};
  PolicyGeneration policy_generation{};
  CoordinatorEpoch epoch{};

  MigrationClass klass{MigrationClass::Unknown};
  bool state_transfer_required{false};
  bool live_state_movement{false};
  std::string rationale{};
};

struct MigrationRecord {
  MigrationPlan plan{};
  MigrationState state{MigrationState::Planned};

  bool source_authoritative{true};
  bool destination_authoritative{false};
  bool state_transfer_performed{false};

  BackingAssignmentId source_assignment{};
  BackingAssignmentId destination_assignment{};
  CapabilityProjectionGeneration destination_projection_generation{};

  UnixMicros planned_at{0};
  UnixMicros prepared_at{0};
  UnixMicros committed_at{0};
  UnixMicros completed_at{0};
  std::string note{};

  std::string canonical() const;
};

}  // namespace av
