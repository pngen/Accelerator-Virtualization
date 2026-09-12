// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/accounting.hpp"
#include "av/audit.hpp"
#include "av/backend.hpp"
#include "av/codec.hpp"
#include "av/invariant.hpp"
#include "av/model.hpp"
#include "av/persistence.hpp"
#include "av/policy.hpp"
#include "av/status.hpp"
#include "av/time.hpp"

namespace av {

// The authority a caller presents for one operation. Every field is optional
// so that "not presented" is distinguishable from "presented as the zero
// value"; each operation validates exactly the fields it needs.
struct Authority {
  std::optional<CoordinatorEpoch> epoch{};
  std::optional<TenantId> tenant{};
  std::optional<TenantGeneration> tenant_generation{};
  std::optional<VirtualAcceleratorId> virtual_id{};
  std::optional<VirtualAcceleratorGeneration> virtual_generation{};
  std::optional<BackingId> backing{};
  std::optional<BackingGeneration> backing_generation{};
  std::optional<PhysicalDeviceId> physical{};
  std::optional<PhysicalDeviceGeneration> physical_generation{};
  std::optional<LeaseId> lease{};
  std::optional<LeaseGeneration> lease_generation{};
  std::optional<PolicyGeneration> policy_generation{};
  std::optional<MigrationId> migration{};
  std::optional<MigrationGeneration> migration_generation{};
  std::optional<RequestId> request{};
  // Session that issued the request. Assigned by the coordinator, never by the
  // caller, so a peer cannot impersonate another session's replay window.
  std::optional<std::uint64_t> session{};

  std::string canonical() const;
};

struct RuntimeOptions {
  std::string name{"av-coordinator"};
  bool persist{true};
  bool deferred_persistence{false};
  std::size_t deferred_threshold{256};
  std::uint32_t max_connections{64};
  // Refuse allocations that exceed the virtual memory budget before the
  // backend is ever asked, so device OOM is never the enforcement mechanism.
  bool enforce_memory_budget{true};
};

// What a consumer sees for one virtual accelerator. Backing disclosure is
// policy-controlled; virtual identity never depends on physical identity.
struct VirtualView {
  VirtualAcceleratorId id{};
  VirtualAcceleratorGeneration generation{};
  std::string name{};
  VirtualLifecycleState state{VirtualLifecycleState::Created};
  VirtualAcceleratorGeneration state_generation{};
  std::string state_reason{};

  TenantId owner{};
  TenantGeneration owner_generation{};
  bool owner_is_caller{false};

  ResourceContract contract{};
  CapabilityProjection projection{};
  MultiplexingMode multiplexing{MultiplexingMode::None};
  IsolationClass isolation_class{IsolationClass::Unknown};

  BackingTransparency transparency{BackingTransparency::Opaque};
  bool backing_disclosed{false};
  BackingClass backing_class{BackingClass::Unknown};
  Provenance backing_provenance{Provenance::Unknown};
  std::string backing_mechanism{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  std::string physical_stable_key{};
  std::string physical_model{};

  std::uint32_t active_attachments{0};
  bool attached_to_caller{false};
  LeaseId caller_lease{};
  LeaseGeneration caller_lease_generation{};

  MigrationClass migration_class{MigrationClass::Unknown};
  bool migration_supported{false};
  bool has_active_migration{false};

  std::uint64_t allocated_bytes{0};
  UnixMicros created_at{0};
  UnixMicros updated_at{0};

  std::string canonical() const;
};

struct IsolationExplanation {
  VirtualAcceleratorId id{};
  VirtualAcceleratorGeneration generation{};
  IsolationClass isolation_class{IsolationClass::Unknown};
  Provenance provenance{Provenance::Unknown};
  std::string mechanism{};
  MultiplexingMode multiplexing{MultiplexingMode::None};
  std::vector<IsolationClaim> claims{};
  std::vector<IsolationClaim> isolated{};
  std::vector<IsolationClaim> partial{};
  std::vector<IsolationClaim> shared{};
  std::vector<IsolationClaim> unknown{};
  std::vector<IsolationClaim> unsupported{};
  std::vector<IsolationRequirement> unmet_requirements{};
  bool satisfies_policy{false};
  std::string canonical() const;
};

struct MigrationExplanation {
  VirtualAcceleratorId id{};
  bool supported{false};
  MigrationClass klass{MigrationClass::Unknown};
  std::string reason{};
  bool state_transfer_required{false};
  bool live_state_movement{false};
  bool has_active_migration{false};
  MigrationState state{MigrationState::Planned};
  std::string canonical() const;
};

// Canonical wire encodings for the read-only inspection surfaces. The same
// codec serves the CLI, the control plane and the tests.
std::vector<Byte> encode_view(const VirtualView& view);
Result<VirtualView> decode_view(ByteSpan bytes);
std::vector<Byte> encode_isolation_explanation(const IsolationExplanation& value);
Result<IsolationExplanation> decode_isolation_explanation(ByteSpan bytes);
std::vector<Byte> encode_migration_explanation(const MigrationExplanation& value);
Result<MigrationExplanation> decode_migration_explanation(ByteSpan bytes);
std::vector<Byte> encode_audit_entry(const AuditEntry& entry);
Result<AuditEntry> decode_audit_entry(ByteSpan bytes);
std::vector<Byte> encode_decision_record(const Decision& decision);
Result<Decision> decode_decision_record(ByteSpan bytes);
std::vector<Byte> encode_accounting(const AccountingCounters& counters);
Result<AccountingCounters> decode_accounting(ByteSpan bytes);
std::vector<Byte> encode_backing_record(const BackingRecord& record);
Result<BackingRecord> decode_backing_record(ByteSpan bytes);
std::vector<Byte> encode_physical_record(const PhysicalDeviceRecord& record);
Result<PhysicalDeviceRecord> decode_physical_record(ByteSpan bytes);
std::vector<Byte> encode_tenant_record(const TenantRecord& record);
Result<TenantRecord> decode_tenant_record(ByteSpan bytes);
std::vector<Byte> encode_lease_record(const LeaseRecord& record);
Result<LeaseRecord> decode_lease_record(ByteSpan bytes);
std::vector<Byte> encode_migration_record(const MigrationRecord& record);
Result<MigrationRecord> decode_migration_record(ByteSpan bytes);
std::vector<Byte> encode_virtual_record(const VirtualAcceleratorRecord& record);
Result<VirtualAcceleratorRecord> decode_virtual_record(ByteSpan bytes);
std::vector<Byte> encode_policy_blob(const VirtualizationPolicy& policy);
Result<VirtualizationPolicy> decode_policy_blob(ByteSpan bytes);
std::vector<Byte> encode_plan_blob(const MigrationPlan& plan);
Result<MigrationPlan> decode_plan_blob(ByteSpan bytes);

// The authoritative virtualization runtime.
//
// Virtual identity is not physical identity: a virtual accelerator keeps its
// VirtualAcceleratorId across legal backing replacement while its
// BackingGeneration advances.
//
// Thread safety: every public method is safe to call concurrently. Internally
// one mutex guards the durable state; mutate -> persist -> externally visible
// success is the enforced order, so a client never observes committed backing
// authority that a restarted coordinator cannot recover.
class VirtualizationRuntime {
 public:
  VirtualizationRuntime(RuntimeOptions options, std::unique_ptr<DurableStore> store,
                        std::shared_ptr<Clock> clock);
  ~VirtualizationRuntime();

  VirtualizationRuntime(const VirtualizationRuntime&) = delete;
  VirtualizationRuntime& operator=(const VirtualizationRuntime&) = delete;

  // ---- runtime lifecycle ------------------------------------------------
  Status start();
  Status shutdown();
  bool running() const;

  CoordinatorEpoch epoch() const;
  PolicyGeneration policy_generation() const;
  const RuntimeOptions& options() const;
  std::shared_ptr<Clock> clock() const;

  // Authority carrying only the current coordinator epoch.
  Authority current_authority() const;
  // Authority carrying the current epoch plus an identity/generation pair.
  Authority virtual_authority(VirtualAcceleratorId id, VirtualAcceleratorGeneration generation) const;

  // ---- agents -----------------------------------------------------------
  Result<AgentSession> register_agent(std::string name, std::string endpoint,
                                      std::uint64_t connection_id, AgentId requested);
  Status agent_heartbeat(AgentId id, AgentBootId boot);
  Status agent_disconnected(AgentId id, AgentBootId boot);
  std::vector<AgentSession> list_agents() const;
  Result<AgentSession> find_agent(AgentId id) const;

  // ---- physical devices -------------------------------------------------
  Result<PhysicalDeviceRecord> register_physical(const Authority& auth, AgentId agent, AgentBootId boot,
                                                 const PhysicalDeviceDescriptor& descriptor);
  Result<PhysicalDeviceRecord> refresh_physical(const Authority& auth, PhysicalDeviceId id,
                                                PhysicalDeviceGeneration generation,
                                                const PhysicalDeviceDescriptor& descriptor);
  Result<PhysicalDeviceRecord> get_physical(PhysicalDeviceId id) const;
  std::vector<PhysicalDeviceRecord> list_physical() const;
  Status physical_lost(PhysicalDeviceId id, PhysicalDeviceGeneration generation, std::string reason);

  // ---- policy -----------------------------------------------------------
  Result<VirtualizationPolicy> set_policy(const Authority& auth, VirtualizationPolicy policy);
  VirtualizationPolicy policy() const;

  // ---- tenancy ----------------------------------------------------------
  Result<TenantRecord> create_tenant(const Authority& auth, std::string name, std::string external_subject);
  Result<TenantRecord> get_tenant(TenantId id) const;
  std::vector<TenantRecord> list_tenants() const;
  Status fence_tenant(const Authority& auth, TenantId id, TenantGeneration generation, std::string reason);
  Result<TenantRecord> transfer_ownership(const Authority& auth, TenantId new_owner,
                                          TenantGeneration new_owner_generation);

  // ---- virtual accelerators --------------------------------------------
  Result<VirtualAcceleratorRecord> create_virtual(const Authority& auth, std::string name, TenantId owner,
                                                  TenantGeneration owner_generation, ResourceContract contract);
  Result<VirtualAcceleratorRecord> update_contract(const Authority& auth, ResourceContract contract);
  Result<VirtualAcceleratorRecord> activate(const Authority& auth);
  Result<VirtualAcceleratorRecord> suspend(const Authority& auth, std::string reason);
  Result<VirtualAcceleratorRecord> resume(const Authority& auth, std::string reason);
  // Leaves RecoveryRequired once the ambiguity has been resolved explicitly.
  Result<VirtualAcceleratorRecord> resolve_recovery(const Authority& auth, std::string reason);
  Result<VirtualAcceleratorRecord> drain(const Authority& auth, std::string reason);
  Result<VirtualAcceleratorRecord> fence_virtual(const Authority& auth, std::string reason);
  Result<VirtualAcceleratorRecord> retire_virtual(const Authority& auth, std::string reason);

  // ---- backing assignment ----------------------------------------------
  Result<BackingAssignment> assign_backing(const Authority& auth, BackingId backing, std::string reason);
  Result<BackingAssignment> replace_backing(const Authority& auth, BackingId destination, std::string reason);
  Result<BackingRecord> get_backing(BackingId id) const;
  std::vector<BackingRecord> list_backings() const;
  std::vector<BackingAssignment> list_assignments() const;
  Result<BackingAssignment> get_assignment(BackingAssignmentId id) const;

  // ---- attachments and leases ------------------------------------------
  Result<LeaseRecord> attach(const Authority& auth);
  Result<LeaseRecord> renew_lease(const Authority& auth);
  Status detach(const Authority& auth);
  Status revoke_lease(const Authority& auth, std::string reason);
  Result<LeaseRecord> get_lease(LeaseId id) const;
  std::vector<LeaseRecord> list_leases() const;

  // ---- migration --------------------------------------------------------
  Result<MigrationRecord> plan_migration(const Authority& auth, BackingId destination, MigrationClass klass);
  Result<MigrationRecord> prepare_migration(const Authority& auth);
  Result<MigrationRecord> commit_migration(const Authority& auth);
  Result<MigrationRecord> complete_migration(const Authority& auth);
  Result<MigrationRecord> abort_migration(const Authority& auth, std::string reason);
  Result<MigrationRecord> get_migration(MigrationId id) const;
  std::vector<MigrationRecord> list_migrations() const;
  // Classifies in-flight migrations after a coordinator restart.
  Status classify_recovered_migrations();

  // ---- execution accounting --------------------------------------------
  Result<std::uint64_t> reserve_allocation(const Authority& auth, std::uint64_t bytes);
  // Reconciliation, not a new grant: it requires the caller's current tenant
  // authority and ownership but not a current virtual generation, so an
  // allocation that was in flight when the lifecycle moved can always be
  // settled instead of leaking.
  Status release_allocation(const Authority& auth, std::uint64_t bytes);
  Status account_kernel(const Authority& auth, std::uint32_t count);

  // ---- queries and explainability --------------------------------------
  Result<VirtualView> query_virtual(const Authority& auth, VirtualAcceleratorId id) const;
  std::vector<VirtualView> list_virtual(const Authority& auth) const;
  Result<VirtualAcceleratorRecord> raw_virtual(VirtualAcceleratorId id) const;
  Result<CapabilityProjection> get_projection(VirtualAcceleratorId id) const;
  Result<ResourceContract> get_contract(VirtualAcceleratorId id) const;
  Result<IsolationExplanation> explain_isolation(VirtualAcceleratorId id) const;
  Result<MigrationExplanation> explain_migration(VirtualAcceleratorId id) const;
  std::vector<Decision> explain_decisions(VirtualAcceleratorId id, std::size_t limit) const;
  std::vector<AuditEntry> audit_tail(std::size_t limit) const;
  AccountingCounters accounting() const;
  AuditReport audit() const;

  // ---- persistence ------------------------------------------------------
  Status flush();
  Status compact();
  Result<VirtualizationState> snapshot_state() const;
  std::string snapshot_text() const;
  std::uint64_t state_fingerprint() const;
  bool store_present() const;
  std::string store_description() const;
  std::uint64_t persistence_bytes() const;
  std::uint64_t persistence_writes() const;
  std::size_t pending_persistence_changes() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Convenience factory: builds the store described by store_options and starts
// the runtime.
Result<std::unique_ptr<VirtualizationRuntime>> make_runtime(RuntimeOptions runtime_options,
                                                            StoreOptions store_options,
                                                            std::shared_ptr<Clock> clock);

}  // namespace av
