// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/backing.hpp"

namespace av {
namespace {

constexpr std::pair<AssignmentState, std::string_view> kAssignmentNames[] = {
    {AssignmentState::Proposed, "Proposed"},
    {AssignmentState::Validated, "Validated"},
    {AssignmentState::Prepared, "Prepared"},
    {AssignmentState::Committed, "Committed"},
    {AssignmentState::Active, "Active"},
    {AssignmentState::Draining, "Draining"},
    {AssignmentState::Revoked, "Revoked"},
    {AssignmentState::Superseded, "Superseded"},
    {AssignmentState::Failed, "Failed"},
};

}  // namespace

std::string_view assignment_state_name(AssignmentState value) noexcept {
  for (const auto& entry : kAssignmentNames) {
    if (entry.first == value) return entry.second;
  }
  return "Unknown";
}

std::optional<AssignmentState> parse_assignment_state(std::string_view text) noexcept {
  for (const auto& entry : kAssignmentNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

}  // namespace av
