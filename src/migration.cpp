// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/migration.hpp"

namespace av {
namespace {

constexpr std::pair<MigrationState, std::string_view> kNames[] = {
    {MigrationState::Planned, "Planned"},
    {MigrationState::Prepared, "Prepared"},
    {MigrationState::SourceDraining, "SourceDraining"},
    {MigrationState::DestinationPrepared, "DestinationPrepared"},
    {MigrationState::StateTransferPending, "StateTransferPending"},
    {MigrationState::StateTransferred, "StateTransferred"},
    {MigrationState::CommitReady, "CommitReady"},
    {MigrationState::Committed, "Committed"},
    {MigrationState::SourceRevoked, "SourceRevoked"},
    {MigrationState::Completed, "Completed"},
    {MigrationState::Aborted, "Aborted"},
    {MigrationState::RecoveryRequired, "RecoveryRequired"},
    {MigrationState::Failed, "Failed"},
};

constexpr std::uint32_t bit(MigrationState state) { return 1u << static_cast<unsigned>(state); }

constexpr std::uint32_t allowed_mask(MigrationState from) {
  using S = MigrationState;
  switch (from) {
    case S::Planned:
      return bit(S::Prepared) | bit(S::Aborted) | bit(S::Failed);
    case S::Prepared:
      return bit(S::SourceDraining) | bit(S::Aborted) | bit(S::RecoveryRequired) | bit(S::Failed);
    case S::SourceDraining:
      return bit(S::DestinationPrepared) | bit(S::Aborted) | bit(S::RecoveryRequired) | bit(S::Failed);
    case S::DestinationPrepared:
      return bit(S::StateTransferPending) | bit(S::CommitReady) | bit(S::Aborted) | bit(S::RecoveryRequired) |
             bit(S::Failed);
    case S::StateTransferPending:
      return bit(S::StateTransferred) | bit(S::Aborted) | bit(S::RecoveryRequired) | bit(S::Failed);
    case S::StateTransferred:
      return bit(S::CommitReady) | bit(S::RecoveryRequired) | bit(S::Failed);
    case S::CommitReady:
      // The single commit edge. Everything before this leaves the source
      // authoritative; the Committed edge moves authority to the destination.
      return bit(S::Committed) | bit(S::Aborted) | bit(S::RecoveryRequired) | bit(S::Failed);
    case S::Committed:
      return bit(S::SourceRevoked) | bit(S::RecoveryRequired);
    case S::SourceRevoked:
      return bit(S::Completed) | bit(S::RecoveryRequired);
    case S::Completed:
    case S::Aborted:
    case S::RecoveryRequired:
    case S::Failed:
    default:
      return 0;
  }
}

}  // namespace

std::string_view migration_state_name(MigrationState value) noexcept {
  for (const auto& entry : kNames) {
    if (entry.first == value) return entry.second;
  }
  return "Unknown";
}

std::optional<MigrationState> parse_migration_state(std::string_view text) noexcept {
  for (const auto& entry : kNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::vector<MigrationState> all_migration_states() {
  std::vector<MigrationState> out;
  out.reserve(std::size(kNames));
  for (const auto& entry : kNames) out.push_back(entry.first);
  return out;
}

bool is_legal_migration_transition(MigrationState from, MigrationState to) noexcept {
  if (from == to) return false;
  return (allowed_mask(from) & bit(to)) != 0;
}

Status check_migration_transition(MigrationState from, MigrationState to) {
  if (from == to) {
    return Status(StatusCode::InvalidTransition,
                  std::string("migration is already in state ") + std::string(migration_state_name(from)));
  }
  if (is_legal_migration_transition(from, to)) return Status{};
  return Status(StatusCode::InvalidTransition, std::string("illegal migration transition ") +
                                                   std::string(migration_state_name(from)) + " -> " +
                                                   std::string(migration_state_name(to)));
}

std::vector<MigrationState> allowed_migration_transitions_from(MigrationState from) {
  std::vector<MigrationState> out;
  for (const auto& entry : kNames) {
    if (is_legal_migration_transition(from, entry.first)) out.push_back(entry.first);
  }
  return out;
}

bool migration_state_is_terminal(MigrationState state) noexcept {
  switch (state) {
    case MigrationState::Completed:
    case MigrationState::Aborted:
    case MigrationState::Failed:
      return true;
    default:
      return false;
  }
}

bool migration_state_holds_authority(MigrationState state) noexcept {
  return !migration_state_is_terminal(state) && state != MigrationState::RecoveryRequired;
}

bool migration_state_after_cutover(MigrationState state) noexcept {
  switch (state) {
    case MigrationState::Committed:
    case MigrationState::SourceRevoked:
    case MigrationState::Completed:
      return true;
    default:
      return false;
  }
}

std::string MigrationRecord::canonical() const {
  std::string out;
  out.reserve(512);
  out.append("migration=").append(plan.id.str()).append("\n");
  out.append("generation=").append(plan.generation.str()).append("\n");
  out.append("virtual=").append(plan.virtual_id.str()).append("\n");
  out.append("virtual_generation=").append(plan.virtual_generation.str()).append("\n");
  out.append("state=").append(migration_state_name(state)).append("\n");
  out.append("class=").append(migration_class_name(plan.klass)).append("\n");
  out.append("source_backing=").append(plan.source_backing.str()).append("\n");
  out.append("source_backing_generation=").append(plan.source_backing_generation.str()).append("\n");
  out.append("destination_backing=").append(plan.destination_backing.str()).append("\n");
  out.append("destination_backing_generation=").append(plan.destination_backing_generation.str()).append("\n");
  out.append("source_physical=").append(plan.source_physical.str()).append("\n");
  out.append("source_physical_generation=").append(plan.source_physical_generation.str()).append("\n");
  out.append("destination_physical=").append(plan.destination_physical.str()).append("\n");
  out.append("destination_physical_generation=").append(plan.destination_physical_generation.str()).append("\n");
  out.append("tenant=").append(plan.tenant.str()).append("\n");
  out.append("tenant_generation=").append(plan.tenant_generation.str()).append("\n");
  out.append("contract_generation=").append(plan.contract_generation.str()).append("\n");
  out.append("projection_generation=").append(plan.projection_generation.str()).append("\n");
  out.append("policy_generation=").append(plan.policy_generation.str()).append("\n");
  out.append("epoch=").append(plan.epoch.str()).append("\n");
  out.append("state_transfer_required=").append(plan.state_transfer_required ? "true" : "false").append("\n");
  out.append("live_state_movement=").append(plan.live_state_movement ? "true" : "false").append("\n");
  out.append("source_authoritative=").append(source_authoritative ? "true" : "false").append("\n");
  out.append("destination_authoritative=").append(destination_authoritative ? "true" : "false").append("\n");
  out.append("state_transfer_performed=").append(state_transfer_performed ? "true" : "false").append("\n");
  out.append("rationale=").append(plan.rationale).append("\n");
  return out;
}

}  // namespace av
