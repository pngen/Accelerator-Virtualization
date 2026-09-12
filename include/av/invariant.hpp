// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "av/ids.hpp"
#include "av/model.hpp"

namespace av {

// Stable machine-readable invariant identifiers. The CLI audit output and the
// test suite both depend on these names.
namespace invariant {
inline constexpr std::string_view kVirtualIdentityUnique = "virtual_identity_unique";
inline constexpr std::string_view kVirtualGenerationMonotonic = "virtual_generation_monotonic";
inline constexpr std::string_view kLifecycleLegal = "lifecycle_legal";
inline constexpr std::string_view kTenantReferenceValid = "tenant_reference_valid";
inline constexpr std::string_view kBackingReferenceValid = "backing_reference_valid";
inline constexpr std::string_view kPhysicalGenerationValid = "physical_generation_valid";
inline constexpr std::string_view kNoStaleBackingActive = "no_stale_backing_active";
inline constexpr std::string_view kRetiredHoldsNoLease = "retired_holds_no_lease";
inline constexpr std::string_view kFencedTenantNoAuthority = "fenced_tenant_no_authority";
inline constexpr std::string_view kLeaseGenerationBound = "lease_generation_bound";
inline constexpr std::string_view kProjectionConsistent = "capability_projection_consistent";
inline constexpr std::string_view kContractValid = "resource_contract_valid";
inline constexpr std::string_view kMigrationEndpointsPresent = "migration_endpoints_present";
inline constexpr std::string_view kSingleAuthoritativeBacking = "single_authoritative_backing";
inline constexpr std::string_view kNoSourceAuthorityAfterCutover = "no_source_authority_after_cutover";
inline constexpr std::string_view kPolicyGenerationConsistent = "policy_generation_consistent";
inline constexpr std::string_view kEpochConsistent = "coordinator_epoch_consistent";
inline constexpr std::string_view kPersistenceIntegrity = "persistence_integrity";
inline constexpr std::string_view kAccountingClosure = "accounting_closure";
inline constexpr std::string_view kBackingHolderConsistent = "backing_holder_consistent";
inline constexpr std::string_view kIsolationTruthful = "isolation_truthful";
inline constexpr std::string_view kAttachmentCountConsistent = "attachment_count_consistent";
}  // namespace invariant

struct InvariantViolation {
  std::string code{};
  std::string detail{};
  VirtualAcceleratorId virtual_id{};
  TenantId tenant{};
  LeaseId lease{};
  BackingId backing{};
  PhysicalDeviceId physical{};
  MigrationId migration{};
};

struct AuditReport {
  std::size_t virtuals_checked{0};
  std::size_t tenants_checked{0};
  std::size_t backings_checked{0};
  std::size_t leases_checked{0};
  std::size_t assignments_checked{0};
  std::size_t migrations_checked{0};
  std::size_t physical_checked{0};
  std::vector<InvariantViolation> violations{};
  std::uint64_t state_fingerprint{0};
  std::uint64_t epoch{0};

  bool clean() const noexcept { return violations.empty(); }
  std::string canonical() const;
};

AuditReport run_invariant_audit(const VirtualizationState& state);

}  // namespace av
