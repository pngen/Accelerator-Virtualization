// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <string>

namespace av {

// Virtualization accounting. Accounting never grants authority: no counter in
// this structure may be consulted to decide whether an operation is allowed.
struct AccountingCounters {
  std::uint64_t coordinator_boots{0};
  std::uint64_t agent_boots{0};
  std::uint64_t physical_registered{0};
  std::uint64_t physical_lost{0};

  std::uint64_t virtual_created{0};
  std::uint64_t virtual_retired{0};
  std::uint64_t virtual_active{0};

  std::uint64_t leases_issued{0};
  std::uint64_t leases_renewed{0};
  std::uint64_t leases_revoked{0};
  std::uint64_t leases_fenced{0};
  std::uint64_t attachments_active{0};
  std::uint64_t peak_attachments_active{0};
  std::uint64_t detaches{0};

  std::uint64_t backing_assignments{0};
  std::uint64_t backing_replacements{0};
  std::uint64_t backing_revocations{0};

  std::uint64_t migrations_planned{0};
  std::uint64_t migrations_prepared{0};
  std::uint64_t migrations_committed{0};
  std::uint64_t migrations_aborted{0};

  std::uint64_t stale_authority_refusals{0};
  std::uint64_t authority_refusals{0};
  std::uint64_t lifecycle_refusals{0};
  std::uint64_t contract_violation_refusals{0};
  std::uint64_t isolation_refusals{0};
  std::uint64_t capability_refusals{0};
  std::uint64_t oversubscription_denials{0};
  std::uint64_t protocol_violations{0};
  std::uint64_t duplicate_request_refusals{0};

  std::uint64_t policy_updates{0};
  std::uint64_t evidence_records{0};

  std::uint64_t allocation_operations{0};
  std::uint64_t kernel_operations{0};
  std::uint64_t bytes_allocated_current{0};
  std::uint64_t bytes_allocated_peak{0};

  std::uint64_t persistence_writes{0};
  std::uint64_t persistence_bytes{0};
  std::uint64_t persistence_compactions{0};
};

std::string accounting_canonical(const AccountingCounters& counters);

}  // namespace av
