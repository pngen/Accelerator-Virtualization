// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/accounting.hpp"

namespace av {

std::string accounting_canonical(const AccountingCounters& counters) {
  std::string out;
  out.reserve(2048);
  auto line = [&out](std::string_view name, std::uint64_t value) {
    out.append(name);
    out.push_back('=');
    out.append(std::to_string(value));
    out.push_back('\n');
  };
  line("coordinator_boots", counters.coordinator_boots);
  line("agent_boots", counters.agent_boots);
  line("physical_registered", counters.physical_registered);
  line("physical_lost", counters.physical_lost);
  line("virtual_created", counters.virtual_created);
  line("virtual_retired", counters.virtual_retired);
  line("virtual_active", counters.virtual_active);
  line("leases_issued", counters.leases_issued);
  line("leases_renewed", counters.leases_renewed);
  line("leases_revoked", counters.leases_revoked);
  line("leases_fenced", counters.leases_fenced);
  line("attachments_active", counters.attachments_active);
  line("peak_attachments_active", counters.peak_attachments_active);
  line("detaches", counters.detaches);
  line("backing_assignments", counters.backing_assignments);
  line("backing_replacements", counters.backing_replacements);
  line("backing_revocations", counters.backing_revocations);
  line("migrations_planned", counters.migrations_planned);
  line("migrations_prepared", counters.migrations_prepared);
  line("migrations_committed", counters.migrations_committed);
  line("migrations_aborted", counters.migrations_aborted);
  line("stale_authority_refusals", counters.stale_authority_refusals);
  line("authority_refusals", counters.authority_refusals);
  line("lifecycle_refusals", counters.lifecycle_refusals);
  line("contract_violation_refusals", counters.contract_violation_refusals);
  line("isolation_refusals", counters.isolation_refusals);
  line("capability_refusals", counters.capability_refusals);
  line("oversubscription_denials", counters.oversubscription_denials);
  line("protocol_violations", counters.protocol_violations);
  line("duplicate_request_refusals", counters.duplicate_request_refusals);
  line("policy_updates", counters.policy_updates);
  line("evidence_records", counters.evidence_records);
  line("allocation_operations", counters.allocation_operations);
  line("kernel_operations", counters.kernel_operations);
  line("bytes_allocated_current", counters.bytes_allocated_current);
  line("bytes_allocated_peak", counters.bytes_allocated_peak);
  line("persistence_writes", counters.persistence_writes);
  line("persistence_bytes", counters.persistence_bytes);
  line("persistence_compactions", counters.persistence_compactions);
  return out;
}

}  // namespace av
