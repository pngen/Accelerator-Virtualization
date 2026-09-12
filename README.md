# Accelerator Virtualization

Open-source, vendor-neutral C++20 runtime for governing virtual accelerator identity, tenancy,
isolation, multiplexing, backing assignment, migration, and lifecycle across physical accelerators.

**Version 1.0.0.** Copyright 2026 Summon Software Labs. Apache License 2.0.

## The question this runtime answers

> How can workloads consume accelerators through *stable virtual device identities* while physical
> devices, tenants, backing assignments, lifecycle state and execution authority change underneath
> them, without confusing logical identity with physical hardware?

The governing principle is that **virtual identity is not physical identity**:

* a backing device may change without changing virtual identity;
* a physical device may host several virtual accelerators without making their authority
  interchangeable;
* a virtual accelerator may expose only a *constrained* capability surface even when the physical
  device supports more;
* a virtual accelerator must never claim isolation its underlying mechanism cannot provide;
* a backing assignment is not authority merely because a mapping exists;
* a tenant is not authorized merely because it knows a virtual device identifier;
* `UNKNOWN` remains first-class and is never upgraded into a claim by assumption.

## Systems boundary

Accelerator Virtualization owns semantics equivalent to: virtual accelerator identity and
generations; tenant identity and tenant-to-virtual-device authority; virtual-device lifecycle;
physical backing assignment and backing-generation fencing; virtual capability projection; virtual
resource contracts; multiplexing policy; exposure policy; leases; attach/detach;
activation/deactivation; drain; suspend/resume; backing replacement; migration planning, migration
lifecycle and migration commit authority; virtual-device inspection; isolation claims and evidence;
stale-authority rejection; restart and recovery semantics; durable virtualization metadata; and a
deterministic audit.

It governs the relationship between a *virtual* accelerator and the *physical* accelerator resources
that currently back it. It does not require every backend to offer the same virtualization mechanism,
and it describes the differences truthfully.

### What this is not

Accelerator Virtualization is **not** a general scheduler, a cluster manager, a resource broker, a
CUDA or ROCm replacement, a device driver, a hypervisor, a container runtime, a VM manager, a general
operating-system device namespace, a memory virtualization system, a generic quota engine, a general
admission controller, a hardware capability registry, a physical topology authority, a GPU reset
service, a MIG configuration manager, a physical partition allocator, or a partition-fragmentation
optimizer.

### Adjacent runtimes

* **Heterogeneous Accelerator Federation** decides workload/device compatibility across fleets.
* **Coherence Fabric** governs authority and currentness across replicated memory state.
* **Resource Broker** owns scarce-resource reservation and arbitration.
* **Quota Fabric** owns multidimensional tenant entitlements.
* **Scheduler runtimes** decide placement and execution order.
* **Hardware Capability Registry** may own canonical device capability knowledge.
* **Accelerator Partition Fabric** (when it exists) owns physical/MIG-like partition lifecycle:
  creating, destroying and reconfiguring partitions, partition fragmentation, partition admission and
  partition placement.

**This runtime never creates, destroys, resizes or places a partition.** A hardware partition is one
possible *backing mechanism* for a virtual accelerator; the virtual accelerator is the stable logical
object above it. Where a backing represents an externally managed partition, the record says so
(`externally_lifecycle_managed`, `external_partition_ref`) and this runtime only consumes it.

## Architecture

| Layer | Contents |
| --- | --- |
| `av_core` | Vendor-neutral C++20 library: identities, taxonomy, isolation, capability projection, resource contracts, policy, lifecycle, backing model, migration, durable store, control-plane protocol, TCP transport, runtime engine |
| `av_cuda` (optional) | The only translation unit that includes a vendor SDK header. Real discovery, allocation, transfers and kernel execution |
| `av_coordinator` | Owns virtualization authority; persists durable state; routes device work to agents |
| `av_agent` | Host integration: presents physical devices, executes authorized device operations |
| `av_cli` | Inspection, explanation and proof |

The core never includes CUDA, ROCm, Level Zero, MIG, SR-IOV, hypervisor or proprietary
device-management headers. Everything vendor-specific sits behind `av::BackendAdapter`.

## Virtual identity model

Identities are strongly typed and carry different authority semantics; they are not interchangeable
with each other or with raw integers:

```
VirtualAcceleratorId / VirtualAcceleratorGeneration   TenantId / TenantGeneration
CoordinatorEpoch                                      AgentId / AgentBootId
PhysicalDeviceId / PhysicalDeviceGeneration           BackingId / BackingGeneration
BackingAssignmentId                                   LeaseId / LeaseGeneration
CapabilityProjectionId / ...Generation                ResourceContractId / ...Generation
PolicyId / PolicyGeneration                           MigrationId / MigrationGeneration
IsolationDomainId                                     EvidenceId / EvidenceGeneration
DecisionId                                            RequestId
```

A **stable physical identity is never an enumeration ordinal, a device index or a process id**. A
bare-numeric stable key is rejected outright (`invalid_argument`): those values are reused by
different devices and would resurrect stale virtual authority. The CUDA adapter keys devices by their
PCI bus address; synthetic backends use descriptive namespaced keys.

A virtual accelerator keeps its `VirtualAcceleratorId` across legal backing replacement while its
*backing binding generation* advances. Every authoritative mutation advances the identity generation,
so an observer always learns that something authoritative changed.

## Lifecycle

```
Created -> Provisioned -> Attached -> Active -> Draining -> Suspended
                                    \-> Migrating -> ... -> recovered
any (non-terminal) -> Fenced | RecoveryRequired | Retired
```

* `Provisioned`: contract and capability projection established.
* `Attached`: an authoritative backing is assigned **and** at least one lease is live.
* `Active`: executing through the current backing. `Active` with no valid backing is impossible.
* `Migrating`: a binding change is in flight and the cutover has not happened.
* `RecoveryRequired`: the outcome of an interrupted authoritative operation is unknown.
* `Fenced`: sealed against operational mutation; retirement is the one step that may still
  follow, so a sealed accelerator always remains reclaimable.
* `Retired`: terminal. `Retired -> Active` and every other revival is refused with
  `invalid_transition`.

Transitions are validated against an explicit table; self-transitions and impossible edges are
refused. Lifecycle state is generation-bound: each transition records the generation at which it
became authoritative.

## Tenancy

`TenantId` is a governance identity, not a process identity. A tenant gets authority only through
an explicit grant of ownership, and every mutation validates the tenant *and* its generation. A
tenant that merely knows a `VirtualAcceleratorId` receives `not_authorized`.

Supported: tenant registration, ownership, generation-bound authorization, attachment leases,
revocation, explicit governed ownership transfer, tenant fencing, and stale-tenant-generation
rejection. This is not a full IAM system: `TenantRecord::external_subject` records a subject
asserted by an external identity provider for audit, and is **never** consulted as authority. The
core governs authorization state once identity has been established elsewhere.

## Virtual capability projection

Every virtual accelerator carries an explicit, deterministic, generation-bound capability surface.
Each entry is `SUPPORTED`, `CONSTRAINED`, `UNSUPPORTED` or `UNKNOWN`, and the
projection separately lists the capabilities it **withheld** from the backing and the ones it could
not prove. The projection is derived from the resource contract, the policy and the evidence-backed
backing capabilities; a capability the backing reports as `UNKNOWN` stays `UNKNOWN` and is
never advertised. When the backing or the contract changes, the projection generation advances and
dependent decisions are invalidated.

## Resource contract

The contract states what virtualization promises: memory ceiling, compute share, queue/stream and
concurrency limits, externally provided bandwidth allowance, exclusivity requirement, minimum backing
capability rank, allowed backing classes, allowed multiplexing modes, required isolation, migration
allowance, oversubscription allowance and delegated burst allowance.

It is a promise, not an arbitration engine: scarce-resource arbitration belongs to adjacent runtimes.
**A virtual accelerator can never advertise a stronger contract than its backing mechanism can
currently satisfy.** A contract update the current backing cannot honour is refused, and an
assignment that would break the contract is refused before it commits.

## Multiplexing modes

`DEDICATED`, `HARDWARE_PARTITIONED`, `VIRTUAL_FUNCTION`, `PROCESS_ISOLATED`,
`CONTEXT_ISOLATED`, `TIME_SLICED`, `COOPERATIVE_SHARED`, `SYNTHETIC`.

Only modelled modes are exposed. For every mode the runtime publishes concurrent-use expectations,
memory ownership assumptions, compute-sharing assumptions, scheduling dependency, the isolation it
actually guarantees, failure coupling, performance predictability, reset/fault coupling and migration
implications. Time slicing is never called partitioning, process separation is never called hardware
isolation, and a shared device context is never described as a tenant-isolation mechanism.

## Isolation model

Isolation is multidimensional, typed and evidence-backed, never one boolean:

`MEMORY`, `EXECUTION_CONTEXT`, `ADDRESS_SPACE`, `FAULT`, `RESET`,
`PERFORMANCE`, `TELEMETRY`, `ADMIN_CONTROL`, `PEER_VISIBILITY`, `DMA`,
`TENANT_STATE`.

Each dimension is `ISOLATED`, `PARTIAL`, `SHARED`, `UNKNOWN` or
`UNSUPPORTED`, ordered weakest to strongest as
`UNSUPPORTED < UNKNOWN < SHARED < PARTIAL < ISOLATED`. Because `UNKNOWN` sits *below*
`SHARED`, an unproven dimension cannot satisfy any requirement above `UNKNOWN`: the runtime
fails closed with `isolation_unknown_mandatory`.

The CUDA backing in this repository reports, truthfully, `MEMORY` and `FAULT` as
`SHARED`, `TELEMETRY` and `DMA` as `UNKNOWN`, `ADMIN_CONTROL` as
`PARTIAL` and `TENANT_STATE` as `ISOLATED`. **No hardware memory isolation, fault
containment, reset isolation or DMA isolation is claimed for it.**

## Leases and attachment authority

Access is lease-bound: attach request, tenant validation, lifecycle validation, policy validation,
lease grant, use, renew where supported, detach/revoke/fence. A lease has its own generation and is
bound to the virtual generation, backing generation, physical generation, tenant generation, policy
generation and coordinator epoch.

A stale lease fails after a virtual-generation change, a tenant-generation change, a backing
migration, a backing-generation change, a policy invalidation, a coordinator restart, or an explicit
revocation. A process restart does not silently regain an old lease.

## Authority model

Every authoritative mutation validates the combination of coordinator epoch, virtual generation,
tenant generation, backing generation, physical generation, lease generation, policy generation and
migration generation that applies to it, and fails with a typed, machine-readable code:
`stale_epoch`, `stale_virtual_generation`, `stale_tenant`, `stale_backing`,
`stale_physical_device`, `stale_lease`, `stale_policy`, `stale_migration`,
`stale_agent_boot`, `stale_assignment`, `not_authorized`, `not_attached`,
`already_attached`, `backing_unavailable`, `isolation_unsatisfied`,
`capability_projection_mismatch`, `invalid_transition`, `unsupported`,
`unknown`, `integrity_failure`, `protocol_violation`.

Every decision is recorded with the generations that produced it, so `av_cli decisions` can
explain exactly why an operation was refused.

## Migration

Virtual identity continuity is **not** execution-state continuity, memory-state continuity or live
migration. The runtime implements and claims exactly two classes:

* `REBIND_ONLY`: identity survives; no execution or memory state moves.
* `DRAIN_AND_RESTART`: as above, and the caller stops and restarts the workload.

`CHECKPOINT_RESTORE`, `STATE_RECONSTRUCTION` and `LIVE_STATE_TRANSFER` are refused
with `migration_unsupported` because this runtime does not perform the state movement they
imply. `live_state_movement` is always false in every plan and every record.

A plan binds the virtual identity and generation, source and destination backing and physical
generations, tenant generation, contract generation, projection generation, policy generation,
coordinator epoch and migration generation. Staleness is re-checked before **every** commit-affecting
phase.

Migration lifecycle: `Planned -> Prepared -> SourceDraining -> DestinationPrepared -> StateTransferPending -> StateTransferred -> CommitReady -> Committed -> SourceRevoked -> Completed`
with `Aborted`, `Failed` and `RecoveryRequired` for the unhappy paths.

The cutover point is exact: before the `CommitReady -> Committed` edge the source is
authoritative; after it the destination is, and the source authority is revoked inside the same
durable record set. No restart can observe both as authoritative. Rollback before the cutover leaves
the source authoritative; after it, the migration can no longer be aborted.

## Failure and recovery semantics

Defined and tested: tenant process death, agent process death, physical-device disappearance, backing
invalidation and reset, coordinator death, disconnect during assignment, disconnect during migration,
death after destination prepare but before commit, death after commit but before acknowledgement, stale
source reconnect, stale destination completion, and physical device generation change.

Outcomes are never invented: `RECOVERY_REQUIRED`, `MIGRATION_ABORTED`,
`MIGRATION_COMMITTED`, `OUTCOME_UNKNOWN`, `BACKING_LOST` and
`REATTACH_REQUIRED` are represented explicitly.

On restart the runtime advances the coordinator epoch, restores durable virtual identities, restores
backing relationships conservatively but marks their dynamic evidence stale, invalidates every
process-local lease and session, classifies in-flight migrations from durable evidence, and requires
dynamic backing evidence to be refreshed before a backing can be used again.

## Persistence

A versioned schema (`schema=1`), deterministic serialization, CRC-32C integrity, atomic replace
through a temporary file plus rename, corruption and truncation detection, defensive bounds checking,
and no attacker-controlled unbounded allocation.

Layout inside the state directory: `state.avs` (atomic full snapshot) and `state.avj`
(append-only journal of per-record changes). A mutation appends one bounded record per changed entity
and performs **one** durable sync; recovery replays the journal over the last snapshot; compaction
rewrites the snapshot atomically and truncates the journal only once the journal has outgrown the
snapshot it would replace, which keeps write amplification proportional to state size rather than
quadratic in the record count.

An incomplete trailing journal record is a torn write. The default policy refuses to start
(`truncated_state`); `--torn-tail discard` discards exactly the incomplete record instead.

Process-local lease authority is never restored.

## Distributed control plane

A real framed TCP control plane provides `av_coordinator`, `av_agent` and `av_cli`.
Frames carry a magic, a protocol version, a message type, flags, a request identity and a CRC-32C over
the payload. Message bodies are canonical, order-independent field maps; unknown fields are ignored,
while duplicate fields, out-of-domain enumerations, missing required fields and trailing bytes are
refused.

Operations include `HELLO`, `REGISTER_PHYSICAL`, `REFRESH_PHYSICAL`,
`PHYSICAL_LOST`, `CREATE_TENANT`, `CREATE_VIRTUAL`, `UPDATE_CONTRACT`,
`ASSIGN_BACKING`, `REPLACE_BACKING`, `ATTACH`, `DETACH`, `REVOKE`,
`QUERY`, `MIGRATION_PLAN/PREPARE/COMMIT/COMPLETE/ABORT`, `FENCE`, `SNAPSHOT`,
`AUDIT`, `EXECUTE` and `SHUTDOWN`.

Defences: truncated frames, malformed lengths, oversized payloads, invalid enumerations, duplicate
identities, duplicate messages, stale epochs, stale agent boots, stale virtual and backing
generations, stale leases, replayed migration commits, connection loss, half-open connections,
replacement connections, connection ceilings and coordinator restart. Request identities are scoped to
a session assigned by the coordinator, so a peer cannot claim another session's replay window, and the
replay window is cleared on restart because the sessions of the previous process no longer exist.

## CUDA backend (REAL)

`av_cuda` discovers the physical device, identifies it by PCI bus address, queries its real
capabilities, and performs real device allocation, host-to-device and device-to-host transfers and a
real vector-add kernel with host/CPU parity verification.

Two backings are offered for one device:

* `cuda-dedicated`: `DEDICATED_PHYSICAL`, exclusive, whole device.
* `cuda-shared-context`: `COOPERATIVE_SHARED`, software-governed multiplexing over one
  shared CUDA context.

### Software sharing limitations, stated plainly

Two virtual accelerators on one physical device through this adapter share one CUDA context and one
physical memory pool. That is **software multiplexing with logical separation**, and the runtime says
so: separate virtual object identity, separate tenant authority, independent lifecycle, allocation
budget accounting, stale-lease fencing, operation routing and logical namespace separation are
provided. Hardware memory isolation, fault containment, reset isolation, performance isolation,
side-channel resistance, QoS guarantees and DMA isolation are **not** provided and are **not**
claimed. This is not MIG, not SR-IOV, and not hardware multi-tenancy.

## REAL / SYNTHETIC / UNSUPPORTED

**REAL** in this environment: Windows process behaviour; TCP loopback; durable persistence; agent kill
and restart; coordinator restart; real RTX 5090 discovery (PCI `0000:01:00.0`, 32 GB, sm_120);
CUDA allocation; real kernel execution with verified CPU parity; software-governed virtual identities;
independent tenant and lease authority; virtual resource-contract enforcement; and two virtual
identities backed by one physical GPU.

**SYNTHETIC** (always labelled `SYNTHETIC` everywhere and never used as evidence of hardware
behaviour): hardware-partition backing, vendor virtual-function backing, remote backing, migratable
backing, an unproven-isolation device, and an unavailable-mechanism device.

**UNSUPPORTED**: NVIDIA MIG on unsupported hardware; physical multi-GPU migration; cross-vendor live
migration; real SR-IOV accelerator virtual functions; hardware tenant isolation not available on the
host; reset isolation; DMA isolation; physical fault-containment guarantees. The synthetic
"unavailable mechanism" device carries `Provenance::UNSUPPORTED` and can never back a virtual
accelerator.

A `SYNTHETIC` mechanism may never name a real backing class: attempting it is refused with
`integrity_failure`.

## CLI

```
av_coordinator --port 0 --state-dir DIR [--transparency OPAQUE|SUMMARY|FULL] [--no-synthetic]
av_agent --coordinator HOST:PORT [--backends synthetic,cuda]
av_cli --coordinator HOST:PORT <command>
```

Commands: `version`, `policy show|set`, `tenant create|list|fence`,
`virtual create|list|show|activate|drain|suspend|resume|fence|retire|resolve-recovery`,
`contract show|update`, `capability show`, `backing list|assign|replace`,
`physical list`, `attach`, `detach`, `revoke`, `renew`,
`isolation explain`, `migration explain|plan|prepare|commit|complete|abort`, `execute`,
`cuda proof`, `decisions`, `audit`, `snapshot`, `accounting`,
`shutdown`.

No command pretends an unsupported physical hardware operation exists.

## Examples

Each example is a real program that drives the runtime; none of them prints hardcoded results.

| Example | Shows |
| --- | --- |
| `example_create_and_attach` | create, assign, attach, activate, query |
| `example_capability_projection` | a constrained surface, withheld and unknown capabilities |
| `example_two_virtuals_one_device` | two identities, one shared backing, separate authority |
| `example_backing_replacement` | identity preserved across replacement, binding history |
| `example_stale_authority` | stale epoch/tenant/policy/generation, replay refusal |
| `example_synthetic_migration` | plan, prepare, commit, complete, single authority after cutover |
| `example_restart_recovery` | durable identity, epoch advance, lease invalidation |
| `example_cuda_virtual_backing` | a real GPU behind a virtual identity, contract enforcement |
| `example_control_plane_client` | driving a running coordinator over TCP |

## Benchmarks

`av_bench` measures **completed** work: every operation is timed only after it has been committed
and persisted, at fleets of 10, 100, 1,000 and 10,000 virtual accelerators. It reports total and
per-operation times for creation, lookup, assignment, attach, detach, contract and capability
inspection, isolation explanation, invariant audit, snapshot rendering and compaction.

Algorithmic complexity is reported as measured: creation, assignment, attach and detach are
`O(changed records)` per mutation with the journal appending and never rewriting; lookup is
`O(log n)` in the identity index; audit, snapshot and compaction are `O(total records)` and
are measured at every scale.

## Build

Requirements: CMake 3.21+, a C++20 compiler, and (optionally) a CUDA toolkit for the real backend.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Options: `AV_BUILD_APPS`, `AV_BUILD_TESTS`, `AV_BUILD_EXAMPLES`,
`AV_BUILD_BENCHMARKS`, `AV_ENABLE_CUDA`, `AV_ENABLE_ASAN`,
`AV_WARNINGS_AS_ERRORS`.

Strict warnings are applied per first-party target (`/W4 /permissive- /WX`) with no global
suppressions, so exported targets never impose this project's warning policy on a consumer. Release
and Debug both build with zero first-party warnings.

## Test

```
ctest --test-dir build --output-on-failure
build/bin/av_test_unit_runtime --case runtime.migration_cutover_leaves_one_authoritative_backing
```

Every case has a stable name, prints a flushed `BEGIN` line, flushed phase markers and a flushed
`PASS`/`FAIL`/`SKIP` line, and is selectable with `--case` or `--suite`,
so a hang or a failure can be localised to an exact case and phase.

Suites: `unit_core`, `unit_runtime`, `property` (seeded randomised),
`concurrency`, `adversarial`, `scale` (10,000 virtual accelerators),
`multiprocess` (real coordinator and agent processes over TCP loopback) and
`cuda_hardware` (real device).

## Install and consume

```
cmake --install build --prefix /some/clean/prefix
# in an independent project:
find_package(AcceleratorVirtualization CONFIG REQUIRED)
target_link_libraries(app PRIVATE AcceleratorVirtualization::av_core)
```

The install provides exported namespaced targets, a version package, a config package and the public
headers; a downstream consumer that uses only the installed package is built and run as part of
release validation.

## AddressSanitizer

The project builds with genuine MSVC x64 AddressSanitizer (`-DAV_ENABLE_ASAN=ON`). The
instrumented suites are run against frozen sources, and instrumentation is verified by checking that
the produced binaries import the ASan runtime rather than by assuming the flags took effect.
LeakSanitizer is not available on MSVC; that gap is stated rather than papered over.

## Determinism

Equivalent state plus policy plus evidence yields equivalent decisions. No externally meaningful
behaviour depends on unordered container iteration, pointer values, process scheduling, thread timing,
filesystem order, physical-device enumeration order, random-device output or connection order.
Containers are ordered, records are canonicalized before hashing and serialization, and randomised
tests record their seeds so a failure is reproducible.

Wall-clock timestamps are recorded for observability and are the only field that differs between two
otherwise identical runs; with a fixed clock even those are byte-identical, which the test suite
asserts.

## Known limitations

* Migration implements `REBIND_ONLY` and `DRAIN_AND_RESTART` only. No live state transfer,
  no checkpoint/restore, no cross-device memory movement.
* The CUDA backing is software multiplexing over one shared context. No hardware partitioning, no MIG,
  no SR-IOV, no hardware memory or fault isolation.
* The CUDA adapter identifies devices by PCI bus address. A device moved to a different slot is a
  different physical generation and forces revalidation, which is the intended conservative behaviour.
* Isolation evidence for the CUDA backing is a static, honest profile produced by the adapter; the
  runtime does not run active isolation probes.
* Tenant identity is established externally. This runtime governs authority once identity exists and
  does not authenticate subjects.
* Oversubscription of a shared backing is refused by default and only permitted explicitly by policy
  or contract; it is never enabled silently.
* The persistent store is a single-node snapshot plus journal. There is no replication and no
  distributed consensus.
* The control plane is unauthenticated at the transport level and is intended for a trusted host or a
  protected network; it is a governance protocol, not a security boundary.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.