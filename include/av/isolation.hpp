// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/ids.hpp"
#include "av/status.hpp"
#include "av/taxonomy.hpp"

namespace av {

// Isolation is multidimensional. A single boolean cannot express "separate
// buffers inside one shared address space".
enum class IsolationDimension : std::uint8_t {
  Memory = 0,
  ExecutionContext = 1,
  AddressSpace = 2,
  Fault = 3,
  Reset = 4,
  Performance = 5,
  Telemetry = 6,
  AdminControl = 7,
  PeerVisibility = 8,
  Dma = 9,
  TenantState = 10,
};

inline constexpr std::size_t kIsolationDimensionCount = 11;

std::string_view isolation_dimension_name(IsolationDimension value) noexcept;
std::optional<IsolationDimension> parse_isolation_dimension(std::string_view text) noexcept;
std::vector<IsolationDimension> all_isolation_dimensions();

// Ordered from weakest to strongest. UNKNOWN sits below SHARED because an
// unproven claim is never an upgrade: an unknown mechanism cannot satisfy a
// requirement for even the weakest proven sharing statement.
enum class IsolationState : std::uint8_t {
  Unsupported = 0,
  Unknown = 1,
  Shared = 2,
  Partial = 3,
  Isolated = 4,
};

std::string_view isolation_state_name(IsolationState value) noexcept;
std::optional<IsolationState> parse_isolation_state(std::string_view text) noexcept;

struct IsolationClaim {
  IsolationDimension dimension{IsolationDimension::Memory};
  IsolationState state{IsolationState::Unknown};
  EvidenceId evidence{};
  EvidenceGeneration evidence_gen{};
  std::string mechanism{};   // e.g. "cuda-runtime-shared-context"
  std::string rationale{};   // why this state is the truthful one
};

// One claim per dimension, always. A missing dimension is treated as UNKNOWN
// and can never satisfy a requirement.
class IsolationProfile {
 public:
  IsolationProfile() = default;

  void set(IsolationClaim claim);
  const IsolationClaim* find(IsolationDimension dimension) const noexcept;
  IsolationState state_of(IsolationDimension dimension) const noexcept;

  const std::vector<IsolationClaim>& claims() const noexcept { return claims_; }
  bool empty() const noexcept { return claims_.empty(); }

  // Canonical, deterministic rendering. Sorted by dimension.
  std::string canonical() const;
  std::uint64_t fingerprint() const;

  // Every dimension is present with an explicit state.
  static IsolationProfile uniform(IsolationState state, std::string mechanism, std::string rationale);

 private:
  std::vector<IsolationClaim> claims_;  // kept sorted by dimension
};

struct IsolationRequirement {
  IsolationDimension dimension{IsolationDimension::Memory};
  IsolationState minimum{IsolationState::Shared};
};

// Result of evaluating requirements against a profile. Deterministic ordering.
struct IsolationEvaluation {
  bool satisfied{false};
  std::vector<IsolationRequirement> unmet;   // sorted by dimension
};

IsolationEvaluation evaluate_isolation(const IsolationProfile& profile,
                                       const std::vector<IsolationRequirement>& requirements);

// Strictly stronger than. Used to reject attempts to upgrade UNKNOWN.
bool isolation_state_at_least(IsolationState have, IsolationState required) noexcept;

// Normative description of what each state means for a dimension.
std::string_view isolation_state_meaning(IsolationState state) noexcept;

}  // namespace av
