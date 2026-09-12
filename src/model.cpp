// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/model.hpp"

#include <algorithm>

#include "av/hash.hpp"

namespace av {
namespace {

constexpr std::pair<LeaseState, std::string_view> kLeaseNames[] = {
    {LeaseState::Granted, "Granted"},
    {LeaseState::Active, "Active"},
    {LeaseState::Revoked, "Revoked"},
    {LeaseState::Expired, "Expired"},
    {LeaseState::Fenced, "Fenced"},
    {LeaseState::Superseded, "Superseded"},
};

void append_id(std::string& out, std::string_view name, std::string_view value) {
  out.append(name);
  out.push_back('=');
  out.append(value);
  out.push_back('\n');
}

}  // namespace

std::string_view lease_state_name(LeaseState value) noexcept {
  for (const auto& entry : kLeaseNames) {
    if (entry.first == value) return entry.second;
  }
  return "Unknown";
}

std::optional<LeaseState> parse_lease_state(std::string_view text) noexcept {
  for (const auto& entry : kLeaseNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

bool lease_state_is_live(LeaseState state) noexcept {
  return state == LeaseState::Granted || state == LeaseState::Active;
}

std::string render_snapshot(const VirtualizationState& state) {
  std::string out;
  out.reserve(4096 + state.virtuals.size() * 512);

  out.append("accelerator-virtualization snapshot\n");
  append_id(out, "schema", std::to_string(state.schema));
  append_id(out, "next_sequence", std::to_string(state.next_sequence));
  append_id(out, "coordinator_epoch", state.epoch.str());
  append_id(out, "policy_id", state.policy.id.str());
  append_id(out, "policy_generation", state.policy_generation.str());
  append_id(out, "policy_fingerprint", std::to_string(state.policy.fingerprint()));

  out.append("physical_devices=").append(std::to_string(state.physical.size())).append("\n");
  for (const auto& [id, record] : state.physical) {
    append_id(out, "  physical", id.str());
    append_id(out, "    stable_key", record.stable_key);
    append_id(out, "    generation", record.generation.str());
    append_id(out, "    provenance", provenance_name(record.provenance));
    append_id(out, "    model", record.model);
    append_id(out, "    memory_total_bytes", std::to_string(record.memory_total_bytes));
    append_id(out, "    present", record.present ? "true" : "false");
    append_id(out, "    agent", record.agent.str());
    append_id(out, "    boot", record.boot.str());
  }

  out.append("backings=").append(std::to_string(state.backings.size())).append("\n");
  for (const auto& [id, record] : state.backings) {
    append_id(out, "  backing", id.str());
    append_id(out, "    generation", record.generation.str());
    append_id(out, "    class", backing_class_name(record.klass));
    append_id(out, "    provenance", provenance_name(record.provenance));
    append_id(out, "    multiplexing", multiplexing_name(record.multiplexing));
    append_id(out, "    isolation_class", isolation_class_name(record.isolation_class));
    append_id(out, "    physical", record.physical.str());
    append_id(out, "    physical_generation", record.physical_generation.str());
    append_id(out, "    available", record.available ? "true" : "false");
    append_id(out, "    assigned_to", record.assigned_to.str());
    append_id(out, "    isolation_fingerprint", std::to_string(record.isolation.fingerprint()));
  }

  out.append("tenants=").append(std::to_string(state.tenants.size())).append("\n");
  for (const auto& [id, record] : state.tenants) {
    append_id(out, "  tenant", id.str());
    append_id(out, "    name", record.name);
    append_id(out, "    generation", record.generation.str());
    append_id(out, "    fenced", record.fenced ? "true" : "false");
    append_id(out, "    active_attachments", std::to_string(record.active_attachments));
  }

  out.append("virtual_accelerators=").append(std::to_string(state.virtuals.size())).append("\n");
  for (const auto& [id, record] : state.virtuals) {
    append_id(out, "  virtual", id.str());
    append_id(out, "    name", record.name);
    append_id(out, "    generation", record.generation.str());
    append_id(out, "    state", lifecycle_name(record.state));
    append_id(out, "    state_generation", record.state_generation.str());
    append_id(out, "    owner", record.owner.str());
    append_id(out, "    owner_generation", record.owner_generation.str());
    append_id(out, "    backing", record.backing.str());
    append_id(out, "    backing_generation", record.backing_generation.str());
    append_id(out, "    backing_class", backing_class_name(record.backing_class));
    append_id(out, "    physical", record.physical.str());
    append_id(out, "    physical_generation", record.physical_generation.str());
    append_id(out, "    multiplexing", multiplexing_name(record.multiplexing));
    append_id(out, "    isolation_class", isolation_class_name(record.isolation_class));
    append_id(out, "    policy_generation", record.policy_generation.str());
    append_id(out, "    contract_generation", record.contract.generation.str());
    append_id(out, "    contract_fingerprint", std::to_string(record.contract.fingerprint()));
    append_id(out, "    projection_generation", record.projection.generation.str());
    append_id(out, "    projection_fingerprint", std::to_string(record.projection.fingerprint));
    append_id(out, "    migration", record.migration.str());
    append_id(out, "    migration_generation", record.migration_generation.str());
    append_id(out, "    active_attachments", std::to_string(record.active_attachments));
    append_id(out, "    allocated_bytes", std::to_string(record.allocated_bytes));
    append_id(out, "    history_entries", std::to_string(record.backing_history.size()));
  }

  out.append("leases=").append(std::to_string(state.leases.size())).append("\n");
  for (const auto& [id, record] : state.leases) {
    append_id(out, "  lease", id.str());
    append_id(out, "    generation", record.generation.str());
    append_id(out, "    state", lease_state_name(record.state));
    append_id(out, "    virtual", record.virtual_id.str());
    append_id(out, "    virtual_generation", record.virtual_generation.str());
    append_id(out, "    tenant", record.tenant.str());
    append_id(out, "    tenant_generation", record.tenant_generation.str());
    append_id(out, "    backing_generation", record.backing_generation.str());
  }

  out.append("assignments=").append(std::to_string(state.assignments.size())).append("\n");
  for (const auto& [id, record] : state.assignments) {
    append_id(out, "  assignment", id.str());
    append_id(out, "    virtual", record.virtual_id.str());
    append_id(out, "    backing", record.backing.str());
    append_id(out, "    backing_generation", record.backing_generation.str());
    append_id(out, "    state", assignment_state_name(record.state));
    append_id(out, "    authoritative", record.authoritative ? "true" : "false");
  }

  out.append("migrations=").append(std::to_string(state.migrations.size())).append("\n");
  for (const auto& [id, record] : state.migrations) {
    append_id(out, "  migration", id.str());
    append_id(out, "    state", migration_state_name(record.state));
    append_id(out, "    class", migration_class_name(record.plan.klass));
    append_id(out, "    virtual", record.plan.virtual_id.str());
    append_id(out, "    source_backing", record.plan.source_backing.str());
    append_id(out, "    destination_backing", record.plan.destination_backing.str());
    append_id(out, "    source_authoritative", record.source_authoritative ? "true" : "false");
    append_id(out, "    destination_authoritative", record.destination_authoritative ? "true" : "false");
  }

  out.append("evidence=").append(std::to_string(state.evidence.size())).append("\n");
  out.append(accounting_canonical(state.accounting));

  out.append("audit_entries=").append(std::to_string(state.audit.size())).append("\n");
  for (const AuditEntry& entry : state.audit) {
    out.append("  audit ");
    out.append(entry.id.str());
    out.push_back(' ');
    out.append(audit_kind_name(entry.kind));
    out.push_back(' ');
    out.append(entry.operation);
    out.push_back(' ');
    out.append(code_name(entry.outcome));
    out.push_back('\n');
  }

  out.append("decisions=").append(std::to_string(state.decisions.size())).append("\n");
  for (const Decision& decision : state.decisions) {
    out.append("  decision ");
    out.append(decision.id.str());
    out.push_back(' ');
    out.append(decision.operation);
    out.push_back(' ');
    out.append(code_name(decision.outcome));
    out.push_back('\n');
  }

  out.append("requests=").append(std::to_string(state.requests.size())).append("\n");
  for (const RequestOutcomeRecord& record : state.requests) {
    out.append("  request ");
    out.append(record.request.str());
    out.push_back(' ');
    out.append(std::to_string(record.session));
    out.push_back(' ');
    out.append(record.operation);
    out.push_back(' ');
    out.append(code_name(record.outcome));
    out.push_back('\n');
  }
  return out;
}

}  // namespace av
