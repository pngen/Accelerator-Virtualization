// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/ids.hpp"
#include "av/status.hpp"

namespace av {

// Keys describe what a virtual accelerator advertises. Adding a key is a
// compatible change; the numeric value is part of the durable schema.
enum class CapabilityKey : std::uint16_t {
  Unknown = 0,
  MemoryBudgetBytes = 1,
  MemoryTotalBytes = 2,
  ComputeShareMilli = 3,
  MaxStreams = 4,
  MaxConcurrentKernels = 5,
  ArchitectureFamily = 6,
  IsaVersion = 7,
  ComputeCapabilityMajor = 8,
  ComputeCapabilityMinor = 9,
  SmCount = 10,
  PrecisionFp16 = 11,
  PrecisionFp32 = 12,
  PrecisionFp64 = 13,
  PrecisionBf16 = 14,
  PrecisionInt8 = 15,
  PrecisionFp8 = 16,
  AsyncCopy = 17,
  UnifiedMemory = 18,
  PeerAccess = 19,
  PeerAccessScope = 20,
  ResetBehavior = 21,
  MigrationSupport = 22,
  PerformanceEnvelopeClass = 23,
  VirtualizationMechanism = 24,
  MemoryBandwidthBytesPerSecond = 25,
  ConcurrencyMode = 26,
  TransferCapability = 27,
  VendorVisible = 28,
};

std::string_view capability_key_name(CapabilityKey value) noexcept;
std::optional<CapabilityKey> parse_capability_key(std::string_view text) noexcept;
std::vector<CapabilityKey> all_capability_keys();

// A capability is never merely present or absent: it may be proven supported,
// proven unsupported, deliberately hidden, or simply unprovable.
enum class CapabilityVerdict : std::uint8_t {
  Unknown = 0,       // the runtime cannot prove behaviour; consumers must fail closed
  Supported = 1,
  Unsupported = 2,
  Constrained = 3,   // supported only within the projected limit carried by value/text
};

std::string_view capability_verdict_name(CapabilityVerdict value) noexcept;
std::optional<CapabilityVerdict> parse_capability_verdict(std::string_view text) noexcept;

struct CapabilityEntry {
  CapabilityKey key{CapabilityKey::Unknown};
  CapabilityVerdict verdict{CapabilityVerdict::Unknown};
  std::uint64_t value{0};
  std::string text{};
  std::string provenance{};  // evidence mechanism that produced this statement
};

// Deterministic, sorted by key, at most one entry per key.
class CapabilitySurface {
 public:
  void set(CapabilityEntry entry);
  const CapabilityEntry* find(CapabilityKey key) const noexcept;
  bool supported(CapabilityKey key) const noexcept;
  std::uint64_t value_or(CapabilityKey key, std::uint64_t fallback) const noexcept;

  const std::vector<CapabilityEntry>& entries() const noexcept { return entries_; }
  std::size_t size() const noexcept { return entries_.size(); }

  std::string canonical() const;
  std::uint64_t fingerprint() const;

 private:
  std::vector<CapabilityEntry> entries_;  // kept sorted by key
};

struct CapabilityProjection {
  CapabilityProjectionId id{};
  CapabilityProjectionGeneration generation{};
  CapabilitySurface surface{};
  // Capabilities the backing supports but this projection withholds.
  std::vector<CapabilityKey> hidden{};
  // Capabilities whose behaviour the runtime cannot prove for this backing.
  std::vector<CapabilityKey> unknown{};
  // Binding: a projection is only valid for these generations.
  BackingGeneration backing_generation{};
  PhysicalDeviceGeneration physical_generation{};
  PolicyGeneration policy_generation{};
  ResourceContractGeneration contract_generation{};
  std::uint64_t fingerprint{0};
  std::string mechanism{};

  void seal();  // recompute fingerprint over the canonical surface
};

}  // namespace av
