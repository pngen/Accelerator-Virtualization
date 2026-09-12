// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "av/ids.hpp"
#include "av/isolation.hpp"
#include "av/status.hpp"
#include "av/taxonomy.hpp"

namespace av {

// The resource contract states what virtualization promises for one virtual
// accelerator. It is a promise, not a quota engine: scarce-resource
// arbitration belongs to adjacent runtimes (Resource Broker, Quota Fabric).
// A virtual accelerator may never advertise a contract stronger than its
// backing mechanism can currently satisfy.
struct ResourceContract {
  ResourceContractId id{};
  ResourceContractGeneration generation{};

  std::uint64_t memory_ceiling_bytes{0};            // 0 = unspecified
  std::uint32_t compute_share_milli{0};             // thousandths of one device, 1..1000; 0 = unspecified
  std::uint32_t max_streams{0};                     // 0 = unspecified
  std::uint32_t max_concurrency{0};                 // 0 = unspecified
  std::uint64_t bandwidth_allowance_bytes_per_second{0};  // externally provided; 0 = unspecified
  bool exclusivity_required{false};
  std::uint32_t minimum_backing_rank{0};
  std::vector<BackingClass> allowed_backing_classes{};        // empty = policy decides
  std::vector<MultiplexingMode> allowed_multiplexing_modes{}; // empty = policy decides
  std::vector<IsolationRequirement> required_isolation{};     // sorted by dimension
  bool migration_allowed{false};
  std::vector<MigrationClass> allowed_migration_classes{};    // sorted
  bool oversubscription_allowed{false};
  // Burst is delegated: this runtime records the allowance, another system enforces it.
  bool burst_allowed{false};

  Status validate() const;
  std::string canonical() const;
  std::uint64_t fingerprint() const;

  // Sorted, deduplicated normalisation applied before validation and storage.
  void normalize();

  bool permits_backing_class(BackingClass klass) const noexcept;
  bool permits_multiplexing(MultiplexingMode mode) const noexcept;
  bool permits_migration_class(MigrationClass klass) const noexcept;
};

}  // namespace av
