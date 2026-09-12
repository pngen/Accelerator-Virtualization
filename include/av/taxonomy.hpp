// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace av {

// ---------------------------------------------------------------------------
// REAL / SYNTHETIC / UNSUPPORTED classification.
//
// Nothing in this runtime may relabel SYNTHETIC as REAL. Provenance travels
// with every physical device, backing and evidence record and is rendered in
// every inspection surface.
// ---------------------------------------------------------------------------
enum class Provenance : std::uint8_t {
  Unknown = 0,
  Real = 1,
  Synthetic = 2,
  Unsupported = 3,
};

std::string_view provenance_name(Provenance value) noexcept;
std::optional<Provenance> parse_provenance(std::string_view text) noexcept;

// ---------------------------------------------------------------------------
// Multiplexing modes.
//
// These describe how a physical device is shared between virtual accelerators.
// Time slicing is not partitioning. Process separation is not hardware
// isolation. A shared device context is not a tenant isolation mechanism.
// ---------------------------------------------------------------------------
enum class MultiplexingMode : std::uint8_t {
  None = 0,
  Dedicated = 1,             // the whole physical device backs exactly one virtual accelerator
  HardwarePartitioned = 2,   // a physical partition (for example MIG-like) backs the virtual accelerator
  VirtualFunction = 3,       // an SR-IOV / vendor virtual function backs the virtual accelerator
  ProcessIsolated = 4,       // a separate OS process owns the device context
  ContextIsolated = 5,       // a distinct vendor execution context, same process/owner
  TimeSliced = 6,            // software time multiplexing over one shared device context
  CooperativeShared = 7,     // cooperating workloads share one context by convention, not by isolation
  Synthetic = 8,             // synthetic backing used to prove generic semantics only
};

std::string_view multiplexing_name(MultiplexingMode value) noexcept;
std::optional<MultiplexingMode> parse_multiplexing(std::string_view text) noexcept;

// Truthful description of what a multiplexing mode does and does not provide.
struct MultiplexingSemantics {
  MultiplexingMode mode;
  std::string_view concurrent_use;        // expectation for simultaneous use
  std::string_view memory_ownership;      // who owns device memory
  std::string_view compute_sharing;       // how compute capacity is divided
  std::string_view scheduling_dependency; // what must schedule the sharing
  std::string_view isolation_guarantee;   // what is actually guaranteed
  std::string_view failure_coupling;      // blast radius of a fault
  std::string_view performance_predictability;
  std::string_view reset_coupling;        // does one reset affect the others
  std::string_view migration_implication;
};

const MultiplexingSemantics& multiplexing_semantics(MultiplexingMode mode) noexcept;
std::vector<MultiplexingMode> all_multiplexing_modes();

// ---------------------------------------------------------------------------
// Backing classes.
//
// A backing class names the mechanism that makes a physical accelerator
// usable by a virtual accelerator. Classes are not equivalent: a dedicated
// whole device has different isolation and performance semantics from software
// time slicing, and this runtime never pretends otherwise.
// ---------------------------------------------------------------------------
enum class BackingClass : std::uint8_t {
  Unknown = 0,
  DedicatedPhysical = 1,
  HardwarePartition = 2,
  VirtualFunction = 3,
  ProcessIsolatedShare = 4,
  ContextIsolatedShare = 5,
  TimeMultiplexedShare = 6,
  CooperativeShared = 7,
  SyntheticHardwarePartition = 8,
  SyntheticVendorVirtualFunction = 9,
  SyntheticRemote = 10,
  SyntheticMigratable = 11,
};

std::string_view backing_class_name(BackingClass value) noexcept;
std::optional<BackingClass> parse_backing_class(std::string_view text) noexcept;
std::vector<BackingClass> all_backing_classes();

// The multiplexing mode a backing class implies when nothing overrides it.
MultiplexingMode default_multiplexing_for(BackingClass klass) noexcept;
// Relative strength of the mechanism, 0..100. Used to enforce a contract's
// "minimum backing capability" requirement. Never used to claim equivalence.
std::uint32_t backing_class_rank(BackingClass klass) noexcept;
// Physicality of the mechanism, independent of how it is used.
Provenance class_native_provenance(BackingClass klass) noexcept;

// ---------------------------------------------------------------------------
// Isolation class: a one-line summary of the strongest isolation the backing
// mechanism provides. The authoritative statement is the per-dimension
// IsolationProfile, never this summary.
// ---------------------------------------------------------------------------
enum class IsolationClass : std::uint8_t {
  Unknown = 0,
  None = 1,                 // no isolation claim at all
  Logical = 2,              // separate governance objects over one shared device
  Process = 3,              // separate OS process ownership
  VendorContext = 4,        // distinct vendor execution context
  HardwarePartition = 5,    // hardware partition boundary
  DedicatedHardware = 6,    // whole physical device exclusively assigned
  Synthetic = 7,            // synthetic mechanism, semantics proven by construction only
};

std::string_view isolation_class_name(IsolationClass value) noexcept;
std::optional<IsolationClass> parse_isolation_class(std::string_view text) noexcept;

// ---------------------------------------------------------------------------
// Migration classes.
//
// Virtual identity continuity, execution-state continuity, memory-state
// continuity and live migration are four different things.
// ---------------------------------------------------------------------------
enum class MigrationClass : std::uint8_t {
  Unknown = 0,
  Unsupported = 1,
  RebindOnly = 2,            // identity survives; no state moves; the workload restarts
  DrainAndRestart = 3,       // drain old backing, restart on the new one
  CheckpointRestore = 4,     // external checkpoint/restore participates
  StateReconstruction = 5,   // state is rebuilt from durable metadata, not transferred
  LiveStateTransfer = 6,     // actual live state movement; only when implemented and proven
};

std::string_view migration_class_name(MigrationClass value) noexcept;
std::optional<MigrationClass> parse_migration_class(std::string_view text) noexcept;
std::vector<MigrationClass> all_migration_classes();

// True only for classes that actually move live execution state.
bool migration_moves_live_state(MigrationClass klass) noexcept;
// True for classes that require the virtual accelerator to stop executing.
bool migration_requires_drain(MigrationClass klass) noexcept;

}  // namespace av
