// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/isolation.hpp"

#include <algorithm>

#include "av/hash.hpp"

namespace av {
namespace {

constexpr std::pair<IsolationDimension, std::string_view> kDimensionNames[] = {
    {IsolationDimension::Memory, "MEMORY"},
    {IsolationDimension::ExecutionContext, "EXECUTION_CONTEXT"},
    {IsolationDimension::AddressSpace, "ADDRESS_SPACE"},
    {IsolationDimension::Fault, "FAULT"},
    {IsolationDimension::Reset, "RESET"},
    {IsolationDimension::Performance, "PERFORMANCE"},
    {IsolationDimension::Telemetry, "TELEMETRY"},
    {IsolationDimension::AdminControl, "ADMIN_CONTROL"},
    {IsolationDimension::PeerVisibility, "PEER_VISIBILITY"},
    {IsolationDimension::Dma, "DMA"},
    {IsolationDimension::TenantState, "TENANT_STATE"},
};

constexpr std::pair<IsolationState, std::string_view> kStateNames[] = {
    {IsolationState::Unsupported, "UNSUPPORTED"},
    {IsolationState::Unknown, "UNKNOWN"},
    {IsolationState::Shared, "SHARED"},
    {IsolationState::Partial, "PARTIAL"},
    {IsolationState::Isolated, "ISOLATED"},
};

}  // namespace

std::string_view isolation_dimension_name(IsolationDimension value) noexcept {
  for (const auto& entry : kDimensionNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<IsolationDimension> parse_isolation_dimension(std::string_view text) noexcept {
  for (const auto& entry : kDimensionNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::vector<IsolationDimension> all_isolation_dimensions() {
  std::vector<IsolationDimension> out;
  out.reserve(std::size(kDimensionNames));
  for (const auto& entry : kDimensionNames) out.push_back(entry.first);
  return out;
}

std::string_view isolation_state_name(IsolationState value) noexcept {
  for (const auto& entry : kStateNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<IsolationState> parse_isolation_state(std::string_view text) noexcept {
  for (const auto& entry : kStateNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::string_view isolation_state_meaning(IsolationState state) noexcept {
  switch (state) {
    case IsolationState::Unsupported:
      return "the backing mechanism cannot provide this isolation dimension at all";
    case IsolationState::Unknown:
      return "the runtime cannot prove the state of this dimension; consumers must fail closed";
    case IsolationState::Shared:
      return "no isolation on this dimension: state is shared with other virtual accelerators";
    case IsolationState::Partial:
      return "isolation is provided only partially, or is provided for a subset of the mechanism";
    case IsolationState::Isolated:
      return "this dimension is isolated and the claim is supported by evidence";
    default:
      return "unrecognised isolation state";
  }
}

void IsolationProfile::set(IsolationClaim claim) {
  const auto dimension = claim.dimension;
  const auto it = std::lower_bound(claims_.begin(), claims_.end(), dimension,
                                   [](const IsolationClaim& lhs, IsolationDimension rhs) {
                                     return static_cast<std::uint8_t>(lhs.dimension) < static_cast<std::uint8_t>(rhs);
                                   });
  if (it != claims_.end() && it->dimension == dimension) {
    *it = std::move(claim);
    return;
  }
  claims_.insert(it, std::move(claim));
}

const IsolationClaim* IsolationProfile::find(IsolationDimension dimension) const noexcept {
  for (const IsolationClaim& claim : claims_) {
    if (claim.dimension == dimension) return &claim;
  }
  return nullptr;
}

IsolationState IsolationProfile::state_of(IsolationDimension dimension) const noexcept {
  const IsolationClaim* claim = find(dimension);
  return claim == nullptr ? IsolationState::Unknown : claim->state;
}

std::string IsolationProfile::canonical() const {
  std::string out;
  for (IsolationDimension dimension : all_isolation_dimensions()) {
    const IsolationClaim* claim = find(dimension);
    out.append(isolation_dimension_name(dimension));
    out.append("=");
    out.append(claim == nullptr ? "UNKNOWN" : isolation_state_name(claim->state));
    out.append(" mechanism=");
    out.append(claim == nullptr ? std::string_view{"-" } : std::string_view{claim->mechanism});
    out.append(" rationale=");
    out.append(claim == nullptr ? std::string_view{"-" } : std::string_view{claim->rationale});
    out.append("\n");
  }
  return out;
}

std::uint64_t IsolationProfile::fingerprint() const {
  Fnv1a64 hash;
  for (IsolationDimension dimension : all_isolation_dimensions()) {
    const IsolationClaim* claim = find(dimension);
    hash.update(isolation_dimension_name(dimension));
    hash.update("=");
    hash.update(claim == nullptr ? std::string_view{"UNKNOWN"} : isolation_state_name(claim->state));
    hash.update("|");
  }
  return hash.value();
}

IsolationProfile IsolationProfile::uniform(IsolationState state, std::string mechanism, std::string rationale) {
  IsolationProfile profile;
  for (IsolationDimension dimension : all_isolation_dimensions()) {
    IsolationClaim claim;
    claim.dimension = dimension;
    claim.state = state;
    claim.mechanism = mechanism;
    claim.rationale = rationale;
    profile.set(std::move(claim));
  }
  return profile;
}

bool isolation_state_at_least(IsolationState have, IsolationState required) noexcept {
  return static_cast<std::uint8_t>(have) >= static_cast<std::uint8_t>(required);
}

IsolationEvaluation evaluate_isolation(const IsolationProfile& profile,
                                       const std::vector<IsolationRequirement>& requirements) {
  IsolationEvaluation evaluation;
  evaluation.satisfied = true;
  std::vector<IsolationRequirement> sorted = requirements;
  std::sort(sorted.begin(), sorted.end(), [](const IsolationRequirement& a, const IsolationRequirement& b) {
    return static_cast<std::uint8_t>(a.dimension) < static_cast<std::uint8_t>(b.dimension);
  });
  for (const IsolationRequirement& requirement : sorted) {
    const IsolationState have = profile.state_of(requirement.dimension);
    if (!isolation_state_at_least(have, requirement.minimum)) {
      evaluation.satisfied = false;
      evaluation.unmet.push_back(requirement);
    }
  }
  return evaluation;
}

}  // namespace av
