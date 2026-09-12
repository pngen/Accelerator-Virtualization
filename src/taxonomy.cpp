// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/taxonomy.hpp"

#include <algorithm>

namespace av {
namespace {

template <class Enum, std::size_t N>
std::optional<Enum> parse_from(std::string_view text, const std::pair<Enum, std::string_view> (&table)[N]) {
  for (const auto& entry : table) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

constexpr std::pair<Provenance, std::string_view> kProvenanceNames[] = {
    {Provenance::Unknown, "UNKNOWN"},
    {Provenance::Real, "REAL"},
    {Provenance::Synthetic, "SYNTHETIC"},
    {Provenance::Unsupported, "UNSUPPORTED"},
};

constexpr std::pair<MultiplexingMode, std::string_view> kMultiplexingNames[] = {
    {MultiplexingMode::None, "NONE"},
    {MultiplexingMode::Dedicated, "DEDICATED"},
    {MultiplexingMode::HardwarePartitioned, "HARDWARE_PARTITIONED"},
    {MultiplexingMode::VirtualFunction, "VIRTUAL_FUNCTION"},
    {MultiplexingMode::ProcessIsolated, "PROCESS_ISOLATED"},
    {MultiplexingMode::ContextIsolated, "CONTEXT_ISOLATED"},
    {MultiplexingMode::TimeSliced, "TIME_SLICED"},
    {MultiplexingMode::CooperativeShared, "COOPERATIVE_SHARED"},
    {MultiplexingMode::Synthetic, "SYNTHETIC"},
};

constexpr std::pair<BackingClass, std::string_view> kBackingClassNames[] = {
    {BackingClass::Unknown, "UNKNOWN"},
    {BackingClass::DedicatedPhysical, "DEDICATED_PHYSICAL"},
    {BackingClass::HardwarePartition, "HARDWARE_PARTITION"},
    {BackingClass::VirtualFunction, "VIRTUAL_FUNCTION"},
    {BackingClass::ProcessIsolatedShare, "PROCESS_ISOLATED_SHARE"},
    {BackingClass::ContextIsolatedShare, "CONTEXT_ISOLATED_SHARE"},
    {BackingClass::TimeMultiplexedShare, "TIME_MULTIPLEXED_SHARE"},
    {BackingClass::CooperativeShared, "COOPERATIVE_SHARED"},
    {BackingClass::SyntheticHardwarePartition, "SYNTHETIC_HARDWARE_PARTITION"},
    {BackingClass::SyntheticVendorVirtualFunction, "SYNTHETIC_VENDOR_VIRTUAL_FUNCTION"},
    {BackingClass::SyntheticRemote, "SYNTHETIC_REMOTE"},
    {BackingClass::SyntheticMigratable, "SYNTHETIC_MIGRATABLE"},
};

constexpr std::pair<IsolationClass, std::string_view> kIsolationClassNames[] = {
    {IsolationClass::Unknown, "UNKNOWN"},
    {IsolationClass::None, "NONE"},
    {IsolationClass::Logical, "LOGICAL"},
    {IsolationClass::Process, "PROCESS"},
    {IsolationClass::VendorContext, "VENDOR_CONTEXT"},
    {IsolationClass::HardwarePartition, "HARDWARE_PARTITION"},
    {IsolationClass::DedicatedHardware, "DEDICATED_HARDWARE"},
    {IsolationClass::Synthetic, "SYNTHETIC"},
};

constexpr std::pair<MigrationClass, std::string_view> kMigrationClassNames[] = {
    {MigrationClass::Unknown, "UNKNOWN"},
    {MigrationClass::Unsupported, "UNSUPPORTED"},
    {MigrationClass::RebindOnly, "REBIND_ONLY"},
    {MigrationClass::DrainAndRestart, "DRAIN_AND_RESTART"},
    {MigrationClass::CheckpointRestore, "CHECKPOINT_RESTORE"},
    {MigrationClass::StateReconstruction, "STATE_RECONSTRUCTION"},
    {MigrationClass::LiveStateTransfer, "LIVE_STATE_TRANSFER"},
};

constexpr MultiplexingSemantics kSemantics[] = {
    {MultiplexingMode::None,
     "not usable; no backing assigned",
     "no device memory is owned",
     "no compute capacity is provided",
     "no scheduling relationship exists",
     "no isolation is provided because nothing is backed",
     "not applicable",
     "not applicable",
     "not applicable",
     "the virtual accelerator must be provisioned and assigned a backing first"},

    {MultiplexingMode::Dedicated,
     "one virtual accelerator holds the whole physical device; concurrent use by another virtual accelerator is refused, not merely discouraged",
     "the virtual accelerator owns the device memory the runtime grants it; no other virtual accelerator is assigned the device",
     "the full compute capacity of the device is available to the single holder",
     "no scheduler mediates sharing because there is no sharing",
     "device-level exclusivity. This is physical exclusivity for the assignment, not a hardware partitioning guarantee",
     "a device fault affects only the single holder, which is the whole blast radius by construction",
     "predictable within device-level variance; no neighbour interference from this runtime",
     "a reset affects the only holder",
     "rebinding to a different device preserves virtual identity; execution state does not move unless a state-moving migration class is used"},

    {MultiplexingMode::HardwarePartitioned,
     "each virtual accelerator holds a distinct physical partition; concurrency is bounded by the partition count",
     "memory is owned per hardware partition as configured by the partition owner",
     "compute units are owned per partition",
     "the partition mechanism schedules; this runtime does not",
     "isolation is whatever the partition mechanism proves; this runtime records the claim and its evidence and never strengthens it",
     "faults may or may not be contained by the partition; the recorded isolation evidence states what is known",
     "depends on the partition mechanism and on neighbour activity inside other partitions",
     "reset isolation depends on the partition mechanism and is recorded per dimension",
     "the virtual accelerator may be rebound to a different existing partition; creating partitions is outside this runtime"},

    {MultiplexingMode::VirtualFunction,
     "each virtual accelerator holds a distinct virtual function presented by the platform",
     "memory is owned by the virtual function's own device context",
     "compute capacity is owned according to the platform's virtual function configuration",
     "the platform and its driver schedule virtual functions",
     "isolation is what the virtual function implementation proves, which this runtime never assumes from the mere existence of a virtual function",
     "fault containment depends on the platform implementation and is recorded as unknown unless proven",
     "depends on platform scheduling of virtual functions",
     "reset isolation depends on the platform implementation",
     "the virtual accelerator may be rebound to a different existing virtual function"},

    {MultiplexingMode::ProcessIsolated,
     "multiple virtual accelerators use the device from separate OS processes",
     "each process owns the device memory it allocates; the device has one shared physical memory pool",
     "compute capacity is shared by the device scheduler, not divided by this runtime",
     "the operating system and the device driver schedule the processes",
     "address space and execution context separation come from the OS process boundary; memory, fault, reset and performance isolation do NOT follow from it",
     "a device fault is not contained by the process boundary",
     "low: other processes on the same device affect throughput",
     "a device reset affects every process using the device",
     "rebinding preserves virtual identity; process restart is implied"},

    {MultiplexingMode::ContextIsolated,
     "multiple virtual accelerators use distinct vendor execution contexts that may live in one process",
     "device memory is allocated per context but drawn from one physical pool",
     "the vendor runtime schedules contexts on the device",
     "the vendor runtime's context scheduler",
     "context separation is a vendor-level scheduling boundary, not a hardware isolation guarantee. Memory is not hardware-partitioned",
     "a device fault affects all contexts on the device",
     "low: contexts contend for the same execution resources",
     "a device reset destroys every context",
     "rebinding preserves virtual identity; contexts must be recreated"},

    {MultiplexingMode::TimeSliced,
     "multiple virtual accelerators are serialized over time on one shared device context",
     "one shared physical memory pool; per-virtual budgets are enforced by this runtime's accounting, not by hardware",
     "compute capacity is time-shared and therefore variable",
     "a software scheduler inside the device runtime",
     "logical and governance isolation only: separate virtual objects, separate authority, separate accounting. No hardware memory, fault, reset, performance or DMA isolation",
     "a fault in one workload can affect every workload sharing the device context",
     "low: performance depends on neighbour activity and is not bounded",
     "a device reset affects every virtual accelerator sharing the device",
     "rebinding preserves virtual identity; in-flight work is lost unless the migration class moves state"},

    {MultiplexingMode::CooperativeShared,
     "workloads share a device context by convention and are expected to cooperate",
     "one shared physical memory pool with no enforced ownership boundary",
     "compute capacity is shared without arbitration by this runtime",
     "the participating workloads and whatever external scheduler they use",
     "no isolation is claimed. Cooperation is a convention, not a boundary",
     "a fault in one workload can affect the others",
     "not predictable; neighbours are not isolated",
     "a reset affects every participant",
     "rebinding preserves virtual identity; cooperation must be re-established"},

    {MultiplexingMode::Synthetic,
     "semantics are defined by the synthetic model, not by hardware",
     "synthetic memory accounting only",
     "synthetic compute accounting only",
     "the synthetic backend's deterministic model",
     "whatever the synthetic backend is constructed to model. It is always labelled SYNTHETIC and never used as evidence of hardware behaviour",
     "not applicable to hardware",
     "not applicable to hardware",
     "not applicable to hardware",
     "used to exercise generic identity, authority, lifecycle and migration semantics"},
};

}  // namespace

std::string_view provenance_name(Provenance value) noexcept {
  for (const auto& entry : kProvenanceNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<Provenance> parse_provenance(std::string_view text) noexcept {
  return parse_from(text, kProvenanceNames);
}

std::string_view multiplexing_name(MultiplexingMode value) noexcept {
  for (const auto& entry : kMultiplexingNames) {
    if (entry.first == value) return entry.second;
  }
  return "NONE";
}

std::optional<MultiplexingMode> parse_multiplexing(std::string_view text) noexcept {
  return parse_from(text, kMultiplexingNames);
}

const MultiplexingSemantics& multiplexing_semantics(MultiplexingMode mode) noexcept {
  for (const auto& entry : kSemantics) {
    if (entry.mode == mode) return entry;
  }
  return kSemantics[0];
}

std::vector<MultiplexingMode> all_multiplexing_modes() {
  std::vector<MultiplexingMode> out;
  out.reserve(std::size(kMultiplexingNames));
  for (const auto& entry : kMultiplexingNames) out.push_back(entry.first);
  return out;
}

std::string_view backing_class_name(BackingClass value) noexcept {
  for (const auto& entry : kBackingClassNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<BackingClass> parse_backing_class(std::string_view text) noexcept {
  return parse_from(text, kBackingClassNames);
}

std::vector<BackingClass> all_backing_classes() {
  std::vector<BackingClass> out;
  out.reserve(std::size(kBackingClassNames));
  for (const auto& entry : kBackingClassNames) out.push_back(entry.first);
  return out;
}

MultiplexingMode default_multiplexing_for(BackingClass klass) noexcept {
  switch (klass) {
    case BackingClass::DedicatedPhysical:
      return MultiplexingMode::Dedicated;
    case BackingClass::HardwarePartition:
    case BackingClass::SyntheticHardwarePartition:
      return MultiplexingMode::HardwarePartitioned;
    case BackingClass::VirtualFunction:
    case BackingClass::SyntheticVendorVirtualFunction:
      return MultiplexingMode::VirtualFunction;
    case BackingClass::ProcessIsolatedShare:
      return MultiplexingMode::ProcessIsolated;
    case BackingClass::ContextIsolatedShare:
      return MultiplexingMode::ContextIsolated;
    case BackingClass::TimeMultiplexedShare:
      return MultiplexingMode::TimeSliced;
    case BackingClass::CooperativeShared:
      return MultiplexingMode::CooperativeShared;
    case BackingClass::SyntheticRemote:
    case BackingClass::SyntheticMigratable:
      return MultiplexingMode::Synthetic;
    case BackingClass::Unknown:
    default:
      return MultiplexingMode::None;
  }
}

Provenance class_native_provenance(BackingClass klass) noexcept {
  switch (klass) {
    case BackingClass::DedicatedPhysical:
    case BackingClass::HardwarePartition:
    case BackingClass::VirtualFunction:
    case BackingClass::ProcessIsolatedShare:
    case BackingClass::ContextIsolatedShare:
    case BackingClass::TimeMultiplexedShare:
    case BackingClass::CooperativeShared:
      return Provenance::Real;
    case BackingClass::SyntheticHardwarePartition:
    case BackingClass::SyntheticVendorVirtualFunction:
    case BackingClass::SyntheticRemote:
    case BackingClass::SyntheticMigratable:
      return Provenance::Synthetic;
    case BackingClass::Unknown:
    default:
      return Provenance::Unknown;
  }
}

std::uint32_t backing_class_rank(BackingClass klass) noexcept {
  switch (klass) {
    case BackingClass::DedicatedPhysical:
      return 100;
    case BackingClass::HardwarePartition:
      return 90;
    case BackingClass::VirtualFunction:
      return 80;
    case BackingClass::ProcessIsolatedShare:
      return 60;
    case BackingClass::ContextIsolatedShare:
      return 50;
    case BackingClass::TimeMultiplexedShare:
      return 30;
    case BackingClass::CooperativeShared:
      return 20;
    case BackingClass::SyntheticHardwarePartition:
    case BackingClass::SyntheticVendorVirtualFunction:
      return 12;
    case BackingClass::SyntheticRemote:
    case BackingClass::SyntheticMigratable:
      return 10;
    case BackingClass::Unknown:
    default:
      return 0;
  }
}

std::string_view isolation_class_name(IsolationClass value) noexcept {
  for (const auto& entry : kIsolationClassNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<IsolationClass> parse_isolation_class(std::string_view text) noexcept {
  return parse_from(text, kIsolationClassNames);
}

std::string_view migration_class_name(MigrationClass value) noexcept {
  for (const auto& entry : kMigrationClassNames) {
    if (entry.first == value) return entry.second;
  }
  return "UNKNOWN";
}

std::optional<MigrationClass> parse_migration_class(std::string_view text) noexcept {
  return parse_from(text, kMigrationClassNames);
}

std::vector<MigrationClass> all_migration_classes() {
  std::vector<MigrationClass> out;
  out.reserve(std::size(kMigrationClassNames));
  for (const auto& entry : kMigrationClassNames) out.push_back(entry.first);
  return out;
}

bool migration_moves_live_state(MigrationClass klass) noexcept {
  return klass == MigrationClass::LiveStateTransfer;
}

bool migration_requires_drain(MigrationClass klass) noexcept {
  switch (klass) {
    case MigrationClass::RebindOnly:
      return false;
    case MigrationClass::DrainAndRestart:
    case MigrationClass::CheckpointRestore:
    case MigrationClass::StateReconstruction:
    case MigrationClass::LiveStateTransfer:
      return true;
    case MigrationClass::Unknown:
    case MigrationClass::Unsupported:
    default:
      return true;
  }
}

}  // namespace av
