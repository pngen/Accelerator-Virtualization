// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/policy.hpp"

#include <algorithm>

#include "av/hash.hpp"

namespace av {
namespace {

template <class T>
void sort_unique(std::vector<T>& values) {
  std::sort(values.begin(), values.end(), [](T a, T b) {
    return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
  });
  values.erase(std::unique(values.begin(), values.end()), values.end());
}

constexpr std::pair<BackingTransparency, std::string_view> kTransparencyNames[] = {
    {BackingTransparency::Opaque, "OPAQUE"},
    {BackingTransparency::Summary, "SUMMARY"},
    {BackingTransparency::Full, "FULL"},
};

constexpr std::pair<TenantSharingPolicy, std::string_view> kSharingNames[] = {
    {TenantSharingPolicy::Exclusive, "EXCLUSIVE"},
    {TenantSharingPolicy::Shared, "SHARED"},
};

constexpr std::pair<RecoveryBehavior, std::string_view> kRecoveryNames[] = {
    {RecoveryBehavior::Conservative, "CONSERVATIVE"},
    {RecoveryBehavior::Optimistic, "OPTIMISTIC"},
};

}  // namespace

std::string_view transparency_name(BackingTransparency value) noexcept {
  for (const auto& entry : kTransparencyNames) {
    if (entry.first == value) return entry.second;
  }
  return "OPAQUE";
}

std::optional<BackingTransparency> parse_transparency(std::string_view text) noexcept {
  for (const auto& entry : kTransparencyNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::string_view tenant_sharing_name(TenantSharingPolicy value) noexcept {
  for (const auto& entry : kSharingNames) {
    if (entry.first == value) return entry.second;
  }
  return "SHARED";
}

std::optional<TenantSharingPolicy> parse_tenant_sharing(std::string_view text) noexcept {
  for (const auto& entry : kSharingNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::string_view recovery_behavior_name(RecoveryBehavior value) noexcept {
  for (const auto& entry : kRecoveryNames) {
    if (entry.first == value) return entry.second;
  }
  return "CONSERVATIVE";
}

std::optional<RecoveryBehavior> parse_recovery_behavior(std::string_view text) noexcept {
  for (const auto& entry : kRecoveryNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

VirtualizationPolicy VirtualizationPolicy::default_policy() {
  VirtualizationPolicy policy;
  for (BackingClass klass : all_backing_classes()) {
    if (klass != BackingClass::Unknown) policy.allowed_backing_classes.push_back(klass);
  }
  policy.allowed_migration_classes = {MigrationClass::RebindOnly, MigrationClass::DrainAndRestart,
                                      MigrationClass::StateReconstruction};
  // Tenancy governance state is isolated even when the physical device is
  // shared: separate virtual objects, separate authority, separate accounting.
  // Nothing here claims hardware isolation.
  policy.required_isolation.push_back(IsolationRequirement{IsolationDimension::TenantState, IsolationState::Partial});
  policy.required_isolation.push_back(IsolationRequirement{IsolationDimension::AdminControl, IsolationState::Partial});
  policy.normalize();
  return policy;
}

void VirtualizationPolicy::normalize() {
  sort_unique(allowed_backing_classes);
  sort_unique(allowed_migration_classes);
  std::sort(forbidden_capabilities.begin(), forbidden_capabilities.end(),
            [](CapabilityKey a, CapabilityKey b) { return static_cast<std::uint16_t>(a) < static_cast<std::uint16_t>(b); });
  forbidden_capabilities.erase(std::unique(forbidden_capabilities.begin(), forbidden_capabilities.end()),
                               forbidden_capabilities.end());
  std::sort(required_isolation.begin(), required_isolation.end(),
            [](const IsolationRequirement& a, const IsolationRequirement& b) {
              return static_cast<std::uint8_t>(a.dimension) < static_cast<std::uint8_t>(b.dimension);
            });
  required_isolation.erase(std::unique(required_isolation.begin(), required_isolation.end(),
                                       [](const IsolationRequirement& a, const IsolationRequirement& b) {
                                         return a.dimension == b.dimension;
                                       }),
                           required_isolation.end());
}

Status VirtualizationPolicy::validate() const {
  for (BackingClass klass : allowed_backing_classes) {
    if (klass == BackingClass::Unknown) {
      return Status(StatusCode::PolicyViolation, "allowed_backing_classes must not contain UNKNOWN");
    }
  }
  for (MigrationClass klass : allowed_migration_classes) {
    if (klass == MigrationClass::Unknown || klass == MigrationClass::Unsupported) {
      return Status(StatusCode::PolicyViolation,
                    std::string("allowed_migration_classes must not contain ") + std::string(migration_class_name(klass)));
    }
  }
  if (max_attachments_per_virtual == 0 || max_attachments_per_virtual > 4096) {
    return Status(StatusCode::PolicyViolation, "max_attachments_per_virtual must be between 1 and 4096");
  }
  if (max_compute_share_milli == 0 || max_compute_share_milli > 1000) {
    return Status(StatusCode::PolicyViolation, "max_compute_share_milli must be between 1 and 1000");
  }
  if (max_virtual_accelerators == 0 || max_virtual_accelerators > 10000000u) {
    return Status(StatusCode::PolicyViolation, "max_virtual_accelerators must be between 1 and 10000000");
  }
  if (max_tenants == 0 || max_tenants > 10000000u) {
    return Status(StatusCode::PolicyViolation, "max_tenants must be between 1 and 10000000");
  }
  if (max_memory_ceiling_bytes == 0) {
    return Status(StatusCode::PolicyViolation, "max_memory_ceiling_bytes must be greater than zero");
  }
  for (const IsolationRequirement& requirement : required_isolation) {
    if (requirement.minimum == IsolationState::Unsupported) {
      return Status(StatusCode::PolicyViolation,
                    std::string("required isolation for ") +
                        std::string(isolation_dimension_name(requirement.dimension)) + " is UNSUPPORTED");
    }
  }
  for (std::size_t i = 1; i < required_isolation.size(); ++i) {
    if (required_isolation[i - 1].dimension == required_isolation[i].dimension) {
      return Status(StatusCode::PolicyViolation, "required_isolation repeats a dimension");
    }
  }
  return Status{};
}

std::string VirtualizationPolicy::canonical() const {
  std::string out;
  out.reserve(1024);
  out.append("tenant_sharing=").append(tenant_sharing_name(tenant_sharing)).append("\n");
  out.append("oversubscription_allowed=").append(oversubscription_allowed ? "true" : "false").append("\n");
  out.append("transparency=").append(transparency_name(transparency)).append("\n");
  out.append("migration_allowed=").append(migration_allowed ? "true" : "false").append("\n");
  out.append("max_attachments_per_virtual=").append(std::to_string(max_attachments_per_virtual)).append("\n");
  out.append("max_lease_duration_micros=").append(std::to_string(max_lease_duration_micros)).append("\n");
  out.append("max_memory_ceiling_bytes=").append(std::to_string(max_memory_ceiling_bytes)).append("\n");
  out.append("max_compute_share_milli=").append(std::to_string(max_compute_share_milli)).append("\n");
  out.append("synthetic_backing_allowed=").append(synthetic_backing_allowed ? "true" : "false").append("\n");
  out.append("recovery=").append(recovery_behavior_name(recovery)).append("\n");
  out.append("evidence_max_age_micros=").append(std::to_string(evidence_max_age_micros)).append("\n");
  out.append("max_virtual_accelerators=").append(std::to_string(max_virtual_accelerators)).append("\n");
  out.append("max_tenants=").append(std::to_string(max_tenants)).append("\n");
  out.append("max_leases=").append(std::to_string(max_leases)).append("\n");
  out.append("max_assignments=").append(std::to_string(max_assignments)).append("\n");
  out.append("max_migrations=").append(std::to_string(max_migrations)).append("\n");
  out.append("max_evidence_records=").append(std::to_string(max_evidence_records)).append("\n");
  for (BackingClass klass : allowed_backing_classes) {
    out.append("allowed_backing_class=").append(backing_class_name(klass)).append("\n");
  }
  for (MigrationClass klass : allowed_migration_classes) {
    out.append("allowed_migration_class=").append(migration_class_name(klass)).append("\n");
  }
  for (const IsolationRequirement& requirement : required_isolation) {
    out.append("required_isolation=")
        .append(isolation_dimension_name(requirement.dimension))
        .append(">=")
        .append(isolation_state_name(requirement.minimum))
        .append("\n");
  }
  for (CapabilityKey key : forbidden_capabilities) {
    out.append("forbidden_capability=").append(capability_key_name(key)).append("\n");
  }
  return out;
}

std::uint64_t VirtualizationPolicy::fingerprint() const {
  return Fnv1a64::compute(canonical());
}

bool VirtualizationPolicy::permits_backing_class(BackingClass klass) const noexcept {
  return std::find(allowed_backing_classes.begin(), allowed_backing_classes.end(), klass) !=
         allowed_backing_classes.end();
}

bool VirtualizationPolicy::permits_migration_class(MigrationClass klass) const noexcept {
  if (!migration_allowed) return false;
  if (klass == MigrationClass::Unsupported || klass == MigrationClass::Unknown) return false;
  return std::find(allowed_migration_classes.begin(), allowed_migration_classes.end(), klass) !=
         allowed_migration_classes.end();
}

bool VirtualizationPolicy::forbids_capability(CapabilityKey key) const noexcept {
  return std::find(forbidden_capabilities.begin(), forbidden_capabilities.end(), key) != forbidden_capabilities.end();
}

}  // namespace av
