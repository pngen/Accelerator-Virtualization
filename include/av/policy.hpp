// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/capability.hpp"
#include "av/ids.hpp"
#include "av/isolation.hpp"
#include "av/status.hpp"
#include "av/taxonomy.hpp"

namespace av {

// How much of the physical backing a consumer is allowed to see.
enum class BackingTransparency : std::uint8_t {
  Opaque = 0,   // physical identity withheld entirely
  Summary = 1,  // class, provenance and mechanism only
  Full = 2,     // full physical identity and generations
};

std::string_view transparency_name(BackingTransparency value) noexcept;
std::optional<BackingTransparency> parse_transparency(std::string_view text) noexcept;

enum class TenantSharingPolicy : std::uint8_t {
  Exclusive = 0,  // a virtual accelerator holds its backing exclusively
  Shared = 1,     // multiple virtual accelerators may share one physical device
};

std::string_view tenant_sharing_name(TenantSharingPolicy value) noexcept;
std::optional<TenantSharingPolicy> parse_tenant_sharing(std::string_view text) noexcept;

// Recovery behaviour on restart. Conservative never revalidates process-local
// authority implicitly; optimistic is modelled but never silently assumed.
enum class RecoveryBehavior : std::uint8_t {
  Conservative = 0,
  Optimistic = 1,
};

std::string_view recovery_behavior_name(RecoveryBehavior value) noexcept;
std::optional<RecoveryBehavior> parse_recovery_behavior(std::string_view text) noexcept;

struct VirtualizationPolicy {
  PolicyId id{};
  PolicyGeneration generation{};

  std::vector<BackingClass> allowed_backing_classes{};
  TenantSharingPolicy tenant_sharing{TenantSharingPolicy::Shared};
  std::vector<IsolationRequirement> required_isolation{};
  bool oversubscription_allowed{false};
  BackingTransparency transparency{BackingTransparency::Summary};
  bool migration_allowed{true};
  std::vector<MigrationClass> allowed_migration_classes{};
  std::uint32_t max_attachments_per_virtual{8};
  std::uint64_t max_lease_duration_micros{0};  // 0 = leases do not expire by time
  std::vector<CapabilityKey> forbidden_capabilities{};  // sorted, deduplicated
  std::uint64_t max_memory_ceiling_bytes{1ull << 40};
  std::uint32_t max_compute_share_milli{1000};
  bool synthetic_backing_allowed{true};
  RecoveryBehavior recovery{RecoveryBehavior::Conservative};
  std::uint64_t evidence_max_age_micros{0};  // 0 = no freshness requirement
  std::uint32_t max_virtual_accelerators{100000};
  std::uint32_t max_tenants{10000};
  std::uint32_t max_leases{100000};
  std::uint32_t max_assignments{100000};
  std::uint32_t max_migrations{4096};
  std::uint32_t max_evidence_records{65536};

  Status validate() const;
  void normalize();
  std::string canonical() const;
  std::uint64_t fingerprint() const;

  bool permits_backing_class(BackingClass klass) const noexcept;
  bool permits_migration_class(MigrationClass klass) const noexcept;
  bool forbids_capability(CapabilityKey key) const noexcept;

  static VirtualizationPolicy default_policy();
};

}  // namespace av
