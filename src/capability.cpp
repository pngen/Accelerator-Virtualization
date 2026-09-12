// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/capability.hpp"

#include <algorithm>

#include "av/hash.hpp"

namespace av {
namespace {

constexpr std::pair<CapabilityKey, std::string_view> kKeyNames[] = {
    {CapabilityKey::Unknown, "UNKNOWN"},
    {CapabilityKey::MemoryBudgetBytes, "MEMORY_BUDGET_BYTES"},
    {CapabilityKey::MemoryTotalBytes, "MEMORY_TOTAL_BYTES"},
    {CapabilityKey::ComputeShareMilli, "COMPUTE_SHARE_MILLI"},
    {CapabilityKey::MaxStreams, "MAX_STREAMS"},
    {CapabilityKey::MaxConcurrentKernels, "MAX_CONCURRENT_KERNELS"},
    {CapabilityKey::ArchitectureFamily, "ARCHITECTURE_FAMILY"},
    {CapabilityKey::IsaVersion, "ISA_VERSION"},
    {CapabilityKey::ComputeCapabilityMajor, "COMPUTE_CAPABILITY_MAJOR"},
    {CapabilityKey::ComputeCapabilityMinor, "COMPUTE_CAPABILITY_MINOR"},
    {CapabilityKey::SmCount, "SM_COUNT"},
    {CapabilityKey::PrecisionFp16, "PRECISION_FP16"},
    {CapabilityKey::PrecisionFp32, "PRECISION_FP32"},
    {CapabilityKey::PrecisionFp64, "PRECISION_FP64"},
    {CapabilityKey::PrecisionBf16, "PRECISION_BF16"},
    {CapabilityKey::PrecisionInt8, "PRECISION_INT8"},
    {CapabilityKey::PrecisionFp8, "PRECISION_FP8"},
    {CapabilityKey::AsyncCopy, "ASYNC_COPY"},
    {CapabilityKey::UnifiedMemory, "UNIFIED_MEMORY"},
    {CapabilityKey::PeerAccess, "PEER_ACCESS"},
    {CapabilityKey::PeerAccessScope, "PEER_ACCESS_SCOPE"},
    {CapabilityKey::ResetBehavior, "RESET_BEHAVIOR"},
    {CapabilityKey::MigrationSupport, "MIGRATION_SUPPORT"},
    {CapabilityKey::PerformanceEnvelopeClass, "PERFORMANCE_ENVELOPE_CLASS"},
    {CapabilityKey::VirtualizationMechanism, "VIRTUALIZATION_MECHANISM"},
    {CapabilityKey::MemoryBandwidthBytesPerSecond, "MEMORY_BANDWIDTH_BYTES_PER_SECOND"},
    {CapabilityKey::ConcurrencyMode, "CONCURRENCY_MODE"},
    {CapabilityKey::TransferCapability, "TRANSFER_CAPABILITY"},
    {CapabilityKey::VendorVisible, "VENDOR_VISIBLE"},
};

constexpr std::pair<CapabilityVerdict, std::string_view> kVerdictNames[] = {
    {CapabilityVerdict::Unknown, "UNKNOWN"},
    {CapabilityVerdict::Supported, "SUPPORTED"},
    {CapabilityVerdict::Unsupported, "UNSUPPORTED"},
    {CapabilityVerdict::Constrained, "CONSTRAINED"},
};

}  // namespace

std::string_view capability_key_name(CapabilityKey value) noexcept {
  for (const auto& entry : kKeyNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<CapabilityKey> parse_capability_key(std::string_view text) noexcept {
  for (const auto& entry : kKeyNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

std::vector<CapabilityKey> all_capability_keys() {
  std::vector<CapabilityKey> out;
  out.reserve(std::size(kKeyNames));
  for (const auto& entry : kKeyNames) out.push_back(entry.first);
  return out;
}

std::string_view capability_verdict_name(CapabilityVerdict value) noexcept {
  for (const auto& entry : kVerdictNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<CapabilityVerdict> parse_capability_verdict(std::string_view text) noexcept {
  for (const auto& entry : kVerdictNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

void CapabilitySurface::set(CapabilityEntry entry) {
  const CapabilityKey key = entry.key;
  const auto it = std::lower_bound(entries_.begin(), entries_.end(), key,
                                   [](const CapabilityEntry& lhs, CapabilityKey rhs) { return lhs.key < rhs; });
  if (it != entries_.end() && it->key == key) {
    *it = std::move(entry);
    return;
  }
  entries_.insert(it, std::move(entry));
}

const CapabilityEntry* CapabilitySurface::find(CapabilityKey key) const noexcept {
  for (const CapabilityEntry& entry : entries_) {
    if (entry.key == key) return &entry;
  }
  return nullptr;
}

bool CapabilitySurface::supported(CapabilityKey key) const noexcept {
  const CapabilityEntry* entry = find(key);
  return entry != nullptr && (entry->verdict == CapabilityVerdict::Supported ||
                              entry->verdict == CapabilityVerdict::Constrained);
}

std::uint64_t CapabilitySurface::value_or(CapabilityKey key, std::uint64_t fallback) const noexcept {
  const CapabilityEntry* entry = find(key);
  if (entry == nullptr || entry->verdict == CapabilityVerdict::Unknown ||
      entry->verdict == CapabilityVerdict::Unsupported) {
    return fallback;
  }
  return entry->value;
}

std::string CapabilitySurface::canonical() const {
  std::string out;
  for (const CapabilityEntry& entry : entries_) {
    out.append(capability_key_name(entry.key));
    out.append("=");
    out.append(capability_verdict_name(entry.verdict));
    out.append(":");
    out.append(std::to_string(entry.value));
    if (!entry.text.empty()) {
      out.append(":");
      out.append(entry.text);
    }
    out.append(" [");
    out.append(entry.provenance);
    out.append("]\n");
  }
  return out;
}

std::uint64_t CapabilitySurface::fingerprint() const {
  Fnv1a64 hash;
  for (const CapabilityEntry& entry : entries_) {
    hash.update(capability_key_name(entry.key));
    hash.update("=");
    hash.update(capability_verdict_name(entry.verdict));
    hash.update(":");
    const std::uint64_t value = entry.value;
    hash.update(&value, sizeof(value));
    hash.update(entry.text);
    hash.update("|");
  }
  return hash.value();
}

void CapabilityProjection::seal() {
  std::sort(hidden.begin(), hidden.end());
  hidden.erase(std::unique(hidden.begin(), hidden.end()), hidden.end());
  std::sort(unknown.begin(), unknown.end());
  unknown.erase(std::unique(unknown.begin(), unknown.end()), unknown.end());

  Fnv1a64 hash;
  hash.update(surface.canonical());
  for (CapabilityKey key : hidden) hash.update(capability_key_name(key));
  hash.update("#");
  for (CapabilityKey key : unknown) hash.update(capability_key_name(key));
  hash.update("#");
  hash.update(mechanism);
  const std::uint64_t binding[4] = {backing_generation.value(), physical_generation.value(),
                                    policy_generation.value(), contract_generation.value()};
  hash.update(binding, sizeof(binding));
  fingerprint = hash.value();
}

}  // namespace av
