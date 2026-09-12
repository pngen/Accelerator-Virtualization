// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/audit.hpp"

#include <algorithm>

#include "av/hash.hpp"

namespace av {
namespace {

constexpr std::pair<AuditKind, std::string_view> kKindNames[] = {
    {AuditKind::Decision, "DECISION"},
    {AuditKind::Mutation, "MUTATION"},
    {AuditKind::AuthorityRefusal, "AUTHORITY_REFUSAL"},
    {AuditKind::LifecycleChange, "LIFECYCLE_CHANGE"},
    {AuditKind::BackingChange, "BACKING_CHANGE"},
    {AuditKind::MigrationChange, "MIGRATION_CHANGE"},
    {AuditKind::Recovery, "RECOVERY"},
    {AuditKind::Protocol, "PROTOCOL"},
    {AuditKind::Persistence, "PERSISTENCE"},
};

}  // namespace

std::string_view audit_kind_name(AuditKind value) noexcept {
  for (const auto& entry : kKindNames) {
    if (entry.first == value) return entry.second;
  }
  return "DECISION";
}

std::optional<AuditKind> parse_audit_kind(std::string_view text) noexcept {
  for (const auto& entry : kKindNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::string Decision::canonical() const {
  std::string out;
  out.reserve(512);
  out.append("operation=").append(operation).append("\n");
  out.append("outcome=").append(code_name(outcome)).append("\n");
  out.append("reason=").append(reason).append("\n");
  out.append("epoch=").append(epoch.str()).append("\n");
  out.append("virtual=").append(virtual_id.str()).append("\n");
  out.append("virtual_generation=").append(virtual_generation.str()).append("\n");
  out.append("tenant=").append(tenant.str()).append("\n");
  out.append("tenant_generation=").append(tenant_generation.str()).append("\n");
  out.append("backing=").append(backing.str()).append("\n");
  out.append("backing_generation=").append(backing_generation.str()).append("\n");
  out.append("physical=").append(physical.str()).append("\n");
  out.append("physical_generation=").append(physical_generation.str()).append("\n");
  out.append("lease=").append(lease.str()).append("\n");
  out.append("lease_generation=").append(lease_generation.str()).append("\n");
  out.append("policy_generation=").append(policy_generation.str()).append("\n");
  out.append("migration=").append(migration.str()).append("\n");
  out.append("migration_generation=").append(migration_generation.str()).append("\n");
  return out;
}

std::uint64_t Decision::fingerprint() const {
  return Fnv1a64::compute(canonical());
}

std::string AuditEntry::canonical() const {
  std::string out;
  out.reserve(384);
  out.append("kind=").append(audit_kind_name(kind)).append("\n");
  out.append("operation=").append(operation).append("\n");
  out.append("outcome=").append(code_name(outcome)).append("\n");
  out.append("detail=").append(detail).append("\n");
  out.append("id=").append(id.str()).append("\n");
  out.append("at=").append(std::to_string(at)).append("\n");
  out.append("epoch=").append(epoch.str()).append("\n");
  out.append("virtual=").append(virtual_id.str()).append("\n");
  out.append("virtual_generation=").append(virtual_generation.str()).append("\n");
  out.append("tenant=").append(tenant.str()).append("\n");
  out.append("tenant_generation=").append(tenant_generation.str()).append("\n");
  out.append("backing=").append(backing.str()).append("\n");
  out.append("backing_generation=").append(backing_generation.str()).append("\n");
  out.append("migration=").append(migration.str()).append("\n");
  out.append("migration_generation=").append(migration_generation.str()).append("\n");
  return out;
}

void AuditLog::append(AuditEntry entry) {
  entries_.push_back(std::move(entry));
  while (entries_.size() > kCapacity) entries_.pop_front();
}

std::vector<AuditEntry> AuditLog::tail(std::size_t count) const {
  std::vector<AuditEntry> out;
  const std::size_t take = std::min(count, entries_.size());
  out.reserve(take);
  const auto begin = entries_.end() - static_cast<std::ptrdiff_t>(take);
  for (auto it = begin; it != entries_.end(); ++it) out.push_back(*it);
  return out;
}

}  // namespace av
