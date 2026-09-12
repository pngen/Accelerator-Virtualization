// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/capability.hpp"
#include "av/evidence.hpp"
#include "av/ids.hpp"
#include "av/isolation.hpp"
#include "av/taxonomy.hpp"
#include "av/time.hpp"

namespace av {

// A physical accelerator known to the runtime through an agent.
//
// Accelerator Virtualization consumes physical devices and pre-existing
// hardware partitions. It never creates, destroys, resizes or places a
// partition: that lifecycle belongs to Accelerator Partition Fabric.
struct PhysicalDeviceRecord {
  PhysicalDeviceId id{};
  PhysicalDeviceGeneration generation{};

  AgentId agent{};
  AgentBootId boot{};
  // Deterministic identity of the physical device: a stable key such as a PCI
  // bus address, never an enumeration ordinal, CUDA index or process id.
  std::string stable_key{};
  std::string vendor{};
  std::string model{};
  std::string driver_version{};
  std::string architecture{};

  Provenance provenance{Provenance::Unknown};
  std::uint64_t memory_total_bytes{0};
  std::uint32_t compute_units{0};
  std::uint32_t compute_capability_major{0};
  std::uint32_t compute_capability_minor{0};
  std::string mechanism{};

  // Capability flags are statements by the backend about what the platform
  // offers. They are not claims that this runtime implements the mechanism.
  bool hardware_partition_capable{false};
  bool virtual_function_capable{false};
  bool mig_capable{false};

  UnixMicros registered_at{0};
  UnixMicros evidence_at{0};
  EvidenceId evidence{};
  EvidenceGeneration evidence_generation{};
  bool present{false};

  std::vector<BackingId> backings{};  // sorted
};

enum class AssignmentState : std::uint8_t {
  Proposed = 0,
  Validated = 1,
  Prepared = 2,
  Committed = 3,
  Active = 4,
  Draining = 5,
  Revoked = 6,
  Superseded = 7,
  Failed = 8,
};

std::string_view assignment_state_name(AssignmentState value) noexcept;
std::optional<AssignmentState> parse_assignment_state(std::string_view text) noexcept;

// A backing assignment is an authoritative lifecycle object, not a mapping
// row. Exactly one assignment per virtual accelerator is authoritative at a
// time; the commit point moves that authority atomically.
struct BackingAssignment {
  BackingAssignmentId id{};
  VirtualAcceleratorId virtual_id{};
  VirtualAcceleratorGeneration virtual_generation{};

  BackingId backing{};
  BackingGeneration backing_generation{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};

  TenantId tenant{};
  TenantGeneration tenant_generation{};
  PolicyGeneration policy_generation{};
  ResourceContractGeneration contract_generation{};
  CapabilityProjectionGeneration projection_generation{};
  CoordinatorEpoch epoch{};

  AssignmentState state{AssignmentState::Proposed};
  bool authoritative{false};
  UnixMicros proposed_at{0};
  UnixMicros committed_at{0};
  UnixMicros revoked_at{0};
  std::string reason{};
};

// A backing target: the mechanism through which a virtual accelerator can use
// physical accelerator resources.
struct BackingRecord {
  BackingId id{};
  BackingGeneration generation{};

  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  BackingClass klass{BackingClass::Unknown};
  Provenance provenance{Provenance::Unknown};
  std::string label{};
  std::string mechanism{};

  MultiplexingMode multiplexing{MultiplexingMode::None};
  IsolationClass isolation_class{IsolationClass::Unknown};
  IsolationProfile isolation{};
  // Evidence-backed statements by the backend about this mechanism. The
  // capability projection draws from here and never invents entries.
  CapabilitySurface capabilities{};

  std::uint64_t capacity_bytes{0};
  std::uint32_t compute_units{0};
  std::uint32_t capability_rank{0};

  EvidenceId evidence{};
  EvidenceGeneration evidence_generation{};
  UnixMicros evidence_at{0};
  bool evidence_fresh{true};

  bool available{false};
  bool exclusive{true};

  // Set when this backing represents a hardware partition whose lifecycle is
  // owned by Accelerator Partition Fabric. This runtime only consumes it.
  bool externally_lifecycle_managed{false};
  std::string external_partition_ref{};

  // Current authoritative holder, if any.
  VirtualAcceleratorId assigned_to{};
  BackingAssignmentId active_assignment{};
  BackingGeneration assigned_generation{};
};

}  // namespace av
