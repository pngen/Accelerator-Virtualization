// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/lifecycle.hpp"

#include <array>

namespace av {
namespace {

constexpr std::size_t kStateCount = 10;

constexpr std::pair<VirtualLifecycleState, std::string_view> kNames[kStateCount] = {
    {VirtualLifecycleState::Created, "Created"},
    {VirtualLifecycleState::Provisioned, "Provisioned"},
    {VirtualLifecycleState::Attached, "Attached"},
    {VirtualLifecycleState::Active, "Active"},
    {VirtualLifecycleState::Draining, "Draining"},
    {VirtualLifecycleState::Suspended, "Suspended"},
    {VirtualLifecycleState::Migrating, "Migrating"},
    {VirtualLifecycleState::RecoveryRequired, "RecoveryRequired"},
    {VirtualLifecycleState::Fenced, "Fenced"},
    {VirtualLifecycleState::Retired, "Retired"},
};

constexpr std::uint16_t bit(VirtualLifecycleState state) {
  return static_cast<std::uint16_t>(1u << static_cast<unsigned>(state));
}

// Legal transitions of the virtual accelerator lifecycle.
//
//   Retired is terminal: a retired virtual accelerator is never returned to
//   service. Fenced accepts no mutation; it may only be recovered or retired.
//   Migrating is entered before the cutover and left only when the migration
//   resolves, so a crash during migration always leaves an explicit state.
constexpr std::uint16_t allowed_mask(VirtualLifecycleState from) {
  using S = VirtualLifecycleState;
  switch (from) {
    case S::Created:
      return bit(S::Provisioned) | bit(S::Fenced) | bit(S::RecoveryRequired) | bit(S::Retired);
    case S::Provisioned:
      return bit(S::Attached) | bit(S::Suspended) | bit(S::Migrating) | bit(S::Fenced) |
             bit(S::RecoveryRequired) | bit(S::Retired);
    case S::Attached:
      return bit(S::Active) | bit(S::Draining) | bit(S::Suspended) | bit(S::Provisioned) | bit(S::Migrating) |
             bit(S::Fenced) | bit(S::RecoveryRequired) | bit(S::Retired);
    case S::Active:
      // Active -> Provisioned is the legal edge when the last lease is
      // released: nothing is executing any more, so the virtual accelerator
      // cannot keep claiming to be active.
      return bit(S::Draining) | bit(S::Suspended) | bit(S::Provisioned) | bit(S::Migrating) | bit(S::Fenced) |
             bit(S::RecoveryRequired) | bit(S::Retired);
    case S::Draining:
      return bit(S::Provisioned) | bit(S::Suspended) | bit(S::Active) | bit(S::Migrating) | bit(S::Fenced) |
             bit(S::RecoveryRequired) | bit(S::Retired);
    case S::Suspended:
      return bit(S::Provisioned) | bit(S::Attached) | bit(S::Migrating) | bit(S::Fenced) |
             bit(S::RecoveryRequired) | bit(S::Retired);
    case S::Migrating:
      return bit(S::Attached) | bit(S::Active) | bit(S::Provisioned) | bit(S::RecoveryRequired) | bit(S::Fenced) |
             bit(S::Retired);
    case S::RecoveryRequired:
      return bit(S::Provisioned) | bit(S::Suspended) | bit(S::Fenced) | bit(S::Retired);
    case S::Fenced:
      return bit(S::RecoveryRequired) | bit(S::Retired);
    case S::Retired:
    default:
      return 0;
  }
}

}  // namespace

std::string_view lifecycle_name(VirtualLifecycleState value) noexcept {
  for (const auto& entry : kNames) {
    if (entry.first == value) return entry.second;
  }
  return "Unknown";
}

std::optional<VirtualLifecycleState> parse_lifecycle(std::string_view text) noexcept {
  for (const auto& entry : kNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::vector<VirtualLifecycleState> all_lifecycle_states() {
  std::vector<VirtualLifecycleState> out;
  out.reserve(kStateCount);
  for (const auto& entry : kNames) out.push_back(entry.first);
  return out;
}

bool is_legal_transition(VirtualLifecycleState from, VirtualLifecycleState to) noexcept {
  if (from == to) return false;
  return (allowed_mask(from) & bit(to)) != 0;
}

Status check_transition(VirtualLifecycleState from, VirtualLifecycleState to) {
  if (from == to) {
    return Status(StatusCode::InvalidTransition,
                  std::string("virtual accelerator is already in state ") + std::string(lifecycle_name(from)));
  }
  if (is_legal_transition(from, to)) return Status{};
  return Status(StatusCode::InvalidTransition, std::string("illegal lifecycle transition ") +
                                                   std::string(lifecycle_name(from)) + " -> " +
                                                   std::string(lifecycle_name(to)));
}

std::vector<VirtualLifecycleState> allowed_transitions_from(VirtualLifecycleState from) {
  std::vector<VirtualLifecycleState> out;
  for (const auto& entry : kNames) {
    if (is_legal_transition(from, entry.first)) out.push_back(entry.first);
  }
  return out;
}

bool lifecycle_is_terminal(VirtualLifecycleState state) noexcept {
  return state == VirtualLifecycleState::Retired;
}

bool lifecycle_accepts_mutation(VirtualLifecycleState state) noexcept {
  return state != VirtualLifecycleState::Fenced && state != VirtualLifecycleState::Retired;
}

bool lifecycle_requires_backing(VirtualLifecycleState state) noexcept {
  switch (state) {
    case VirtualLifecycleState::Attached:
    case VirtualLifecycleState::Active:
    case VirtualLifecycleState::Draining:
      return true;
    default:
      return false;
  }
}

bool lifecycle_allows_leases(VirtualLifecycleState state) noexcept {
  switch (state) {
    case VirtualLifecycleState::Attached:
    case VirtualLifecycleState::Active:
    case VirtualLifecycleState::Draining:
      return true;
    default:
      return false;
  }
}

}  // namespace av
