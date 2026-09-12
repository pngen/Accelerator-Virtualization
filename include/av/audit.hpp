// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/ids.hpp"
#include "av/status.hpp"
#include "av/time.hpp"

namespace av {

enum class AuditKind : std::uint8_t {
  Decision = 0,
  Mutation = 1,
  AuthorityRefusal = 2,
  LifecycleChange = 3,
  BackingChange = 4,
  MigrationChange = 5,
  Recovery = 6,
  Protocol = 7,
  Persistence = 8,
};

std::string_view audit_kind_name(AuditKind value) noexcept;
std::optional<AuditKind> parse_audit_kind(std::string_view text) noexcept;

// Every authoritative decision produces exactly one deterministic record that
// names the generations that produced it.
struct Decision {
  DecisionId id{};
  UnixMicros at{0};
  std::string operation{};
  StatusCode outcome{StatusCode::Ok};
  std::string reason{};

  CoordinatorEpoch epoch{};
  VirtualAcceleratorId virtual_id{};
  VirtualAcceleratorGeneration virtual_generation{};
  TenantId tenant{};
  TenantGeneration tenant_generation{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  LeaseId lease{};
  LeaseGeneration lease_generation{};
  PolicyGeneration policy_generation{};
  MigrationId migration{};
  MigrationGeneration migration_generation{};
  RequestId request{};

  std::string canonical() const;
  std::uint64_t fingerprint() const;
};

struct AuditEntry {
  DecisionId id{};
  UnixMicros at{0};
  AuditKind kind{AuditKind::Decision};
  std::string operation{};
  StatusCode outcome{StatusCode::Ok};
  std::string detail{};

  CoordinatorEpoch epoch{};
  VirtualAcceleratorId virtual_id{};
  VirtualAcceleratorGeneration virtual_generation{};
  TenantId tenant{};
  TenantGeneration tenant_generation{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  MigrationId migration{};
  MigrationGeneration migration_generation{};

  std::string canonical() const;
};

// Bounded, deterministic, append-only in-memory audit log. The bound is a
// resource-discipline bound, not a semantic one; the durable journal carries
// the full history while this log carries the inspectable tail.
class AuditLog {
 public:
  static constexpr std::size_t kCapacity = 4096;

  void append(AuditEntry entry);
  std::size_t size() const noexcept { return entries_.size(); }
  const std::deque<AuditEntry>& entries() const noexcept { return entries_; }
  std::vector<AuditEntry> tail(std::size_t count) const;
  void clear() { entries_.clear(); }

 private:
  std::deque<AuditEntry> entries_;
};

}  // namespace av
