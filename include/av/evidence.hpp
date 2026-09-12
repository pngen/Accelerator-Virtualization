// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "av/ids.hpp"
#include "av/taxonomy.hpp"
#include "av/time.hpp"

namespace av {

enum class EvidenceKind : std::uint8_t {
  Unknown = 0,
  DeviceDiscovery = 1,
  CapabilityQuery = 2,
  IsolationProbe = 3,
  BackingRefresh = 4,
  SyntheticAttestation = 5,
  MigrationProbe = 6,
  RecoveryRevalidation = 7,
};

std::string_view evidence_kind_name(EvidenceKind value) noexcept;
std::optional<EvidenceKind> parse_evidence_kind(std::string_view text) noexcept;

// Every authoritative statement about a physical device, a backing or an
// isolation claim is backed by an evidence record that names who produced it,
// on which boot, for which physical generation, using which mechanism.
struct EvidenceRecord {
  EvidenceId id{};
  EvidenceGeneration generation{};
  EvidenceKind kind{EvidenceKind::Unknown};
  Provenance provenance{Provenance::Unknown};
  AgentId agent{};
  AgentBootId boot{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  UnixMicros produced_at{0};
  std::uint64_t payload_fingerprint{0};
  std::string mechanism{};
  std::string detail{};
};

}  // namespace av
