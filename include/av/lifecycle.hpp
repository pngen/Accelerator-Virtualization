// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/status.hpp"

namespace av {

// Definition of the virtual accelerator lifecycle states.
//
//   Created          object exists; no contract, no backing, not usable
//   Provisioned      contract + capability projection established; no backing
//   Attached         backing assigned and at least one lease granted
//   Active           executing work through the current backing
//   Draining         no new work accepted; existing work settling
//   Suspended        deliberately without an authoritative backing
//   Migrating        binding change in flight; cutover not yet performed
//   RecoveryRequired outcome of an interrupted authoritative operation is unknown
//   Fenced           explicitly sealed against mutation, still inspectable
//   Retired          terminal; identity preserved for history, never reusable
enum class VirtualLifecycleState : std::uint8_t {
  Created = 0,
  Provisioned = 1,
  Attached = 2,
  Active = 3,
  Draining = 4,
  Suspended = 5,
  Migrating = 6,
  RecoveryRequired = 7,
  Fenced = 8,
  Retired = 9,
};

std::string_view lifecycle_name(VirtualLifecycleState value) noexcept;
std::optional<VirtualLifecycleState> parse_lifecycle(std::string_view text) noexcept;
std::vector<VirtualLifecycleState> all_lifecycle_states();

bool is_legal_transition(VirtualLifecycleState from, VirtualLifecycleState to) noexcept;
Status check_transition(VirtualLifecycleState from, VirtualLifecycleState to);
std::vector<VirtualLifecycleState> allowed_transitions_from(VirtualLifecycleState from);

bool lifecycle_is_terminal(VirtualLifecycleState state) noexcept;
// Fenced and Retired never accept new mutations.
bool lifecycle_accepts_mutation(VirtualLifecycleState state) noexcept;
// States in which a backing assignment must exist if the state is reachable.
bool lifecycle_requires_backing(VirtualLifecycleState state) noexcept;
// States in which at least one live lease may exist.
bool lifecycle_allows_leases(VirtualLifecycleState state) noexcept;

}  // namespace av
