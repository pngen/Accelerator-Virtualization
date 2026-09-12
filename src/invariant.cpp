// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/invariant.hpp"

#include <algorithm>
#include <map>
#include <string>

namespace av {
namespace {

void add(InvariantViolation& violation, std::string code, std::string detail) {
  violation.code = std::move(code);
  violation.detail = std::move(detail);
}

}  // namespace

std::string AuditReport::canonical() const {
  std::string out;
  out.reserve(1024);
  out.append("virtuals_checked=").append(std::to_string(virtuals_checked)).append("\n");
  out.append("tenants_checked=").append(std::to_string(tenants_checked)).append("\n");
  out.append("backings_checked=").append(std::to_string(backings_checked)).append("\n");
  out.append("leases_checked=").append(std::to_string(leases_checked)).append("\n");
  out.append("assignments_checked=").append(std::to_string(assignments_checked)).append("\n");
  out.append("migrations_checked=").append(std::to_string(migrations_checked)).append("\n");
  out.append("physical_checked=").append(std::to_string(physical_checked)).append("\n");
  out.append("state_fingerprint=").append(std::to_string(state_fingerprint)).append("\n");
  out.append("epoch=").append(std::to_string(epoch)).append("\n");
  out.append("violation_count=").append(std::to_string(violations.size())).append("\n");
  for (const InvariantViolation& violation : violations) {
    out.append("violation=").append(violation.code).append(" ").append(violation.detail).append("\n");
  }
  return out;
}

AuditReport run_invariant_audit(const VirtualizationState& state) {
  AuditReport report;
  report.virtuals_checked = state.virtuals.size();
  report.tenants_checked = state.tenants.size();
  report.backings_checked = state.backings.size();
  report.leases_checked = state.leases.size();
  report.assignments_checked = state.assignments.size();
  report.migrations_checked = state.migrations.size();
  report.physical_checked = state.physical.size();

  auto fail = [&report](std::string_view code, std::string detail, const VirtualAcceleratorRecord* record) {
    InvariantViolation violation;
    add(violation, std::string(code), std::move(detail));
    if (record != nullptr) {
      violation.virtual_id = record->id;
      violation.tenant = record->owner;
      violation.backing = record->backing;
      violation.physical = record->physical;
    }
    report.violations.push_back(std::move(violation));
  };

  // ---- identity uniqueness and generation monotonicity -------------------
  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    if (record.id != entry.first || !record.id.valid()) {
      fail(invariant::kVirtualIdentityUnique,
           "virtual accelerator map key does not match the record identity", &record);
    }
    if (!record.generation.valid()) {
      fail(invariant::kVirtualGenerationMonotonic,
           "virtual accelerator " + record.id.str() + " has no generation", &record);
    }
    if (record.state_generation.valid() && record.state_generation.value() > record.generation.value()) {
      fail(invariant::kVirtualGenerationMonotonic,
           "state generation " + record.state_generation.str() + " is ahead of identity generation " +
               record.generation.str(),
           &record);
    }
    if (!record.state_generation.valid()) {
      fail(invariant::kLifecycleLegal, "virtual accelerator " + record.id.str() + " has no state generation", &record);
    }
    if (lifecycle_is_terminal(record.state) && record.state != VirtualLifecycleState::Retired) {
      fail(invariant::kLifecycleLegal, "unexpected terminal lifecycle state", &record);
    }
  }

  // ---- tenant references -------------------------------------------------
  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    const auto owner = state.tenants.find(record.owner);
    if (owner == state.tenants.end()) {
      fail(invariant::kTenantReferenceValid,
           "virtual accelerator " + record.id.str() + " references missing tenant " + record.owner.str(), &record);
      continue;
    }
    if (record.owner_generation != owner->second.generation) {
      fail(invariant::kTenantReferenceValid,
           "virtual accelerator " + record.id.str() + " is bound to tenant generation " +
               record.owner_generation.str() + " but tenant " + owner->first.str() + " is at " +
               owner->second.generation.str(),
           &record);
    }
    if (owner->second.fenced) {
      if (record.active_attachments != 0) {
        fail(invariant::kFencedTenantNoAuthority,
             "fenced tenant " + owner->first.str() + " retains " + std::to_string(record.active_attachments) +
                 " active attachment(s)",
             &record);
      }
      for (LeaseId lease_id : record.leases) {
        const auto lease = state.leases.find(lease_id);
        if (lease != state.leases.end() && lease_state_is_live(lease->second.state)) {
          fail(invariant::kFencedTenantNoAuthority,
               "fenced tenant " + owner->first.str() + " retains live lease " + lease_id.str(), &record);
        }
      }
    }
  }

  // ---- physical device references ---------------------------------------
  for (const auto& entry : state.backings) {
    const BackingRecord& backing = entry.second;
    const auto physical = state.physical.find(backing.physical);
    if (physical == state.physical.end()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kPhysicalGenerationValid),
          "backing " + backing.id.str() + " references missing physical device " + backing.physical.str());
      violation.backing = backing.id;
      violation.physical = backing.physical;
      report.violations.push_back(std::move(violation));
      continue;
    }
    if (backing.physical_generation != physical->second.generation) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kPhysicalGenerationValid),
          "backing " + backing.id.str() + " records physical generation " + backing.physical_generation.str() +
              " but the device is at generation " + physical->second.generation.str());
      violation.backing = backing.id;
      violation.physical = backing.physical;
      report.violations.push_back(std::move(violation));
    }
    if (!backing.generation.valid()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kBackingReferenceValid),
          "backing " + backing.id.str() + " has no generation");
      violation.backing = backing.id;
      report.violations.push_back(std::move(violation));
    }
  }

  // ---- backing and assignment references ---------------------------------
  std::map<VirtualAcceleratorId, int> authoritative_assignments;
  std::map<BackingId, int> backing_holders;
  for (const auto& entry : state.assignments) {
    const BackingAssignment& assignment = entry.second;
    if (assignment.id != entry.first || !assignment.id.valid()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kBackingReferenceValid),
          "assignment map key does not match the record identity");
      report.violations.push_back(std::move(violation));
    }
    const auto virtual_record = state.virtuals.find(assignment.virtual_id);
    if (virtual_record == state.virtuals.end()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kBackingReferenceValid),
          "assignment " + assignment.id.str() + " references missing virtual accelerator " +
              assignment.virtual_id.str());
      violation.virtual_id = assignment.virtual_id;
      report.violations.push_back(std::move(violation));
      continue;
    }
    if (state.backings.find(assignment.backing) == state.backings.end()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kBackingReferenceValid),
          "assignment " + assignment.id.str() + " references missing backing " + assignment.backing.str());
      violation.virtual_id = assignment.virtual_id;
      violation.backing = assignment.backing;
      report.violations.push_back(std::move(violation));
    }
    if (assignment.authoritative) {
      authoritative_assignments[assignment.virtual_id] += 1;
      backing_holders[assignment.backing] += 1;
    }
  }
  for (const auto& entry : authoritative_assignments) {
    if (entry.second > 1) {
      const auto record = state.virtuals.find(entry.first);
      fail(invariant::kSingleAuthoritativeBacking,
           "virtual accelerator " + entry.first.str() + " holds " + std::to_string(entry.second) +
               " authoritative backing assignments",
           record != state.virtuals.end() ? &record->second : nullptr);
    }
  }
  for (const auto& entry : backing_holders) {
    if (entry.second <= 1) continue;
    // A shared mechanism may host several virtual accelerators; only an
    // exclusive mechanism is allowed exactly one authoritative holder.
    const auto backing = state.backings.find(entry.first);
    if (backing != state.backings.end() && !backing->second.exclusive) continue;
    InvariantViolation violation;
    add(violation, std::string(invariant::kSingleAuthoritativeBacking),
        "exclusive backing " + entry.first.str() + " is the authoritative holder for " +
            std::to_string(entry.second) + " virtual accelerators");
    violation.backing = entry.first;
    report.violations.push_back(std::move(violation));
  }

  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    if (record.backing.valid()) {
      const auto backing = state.backings.find(record.backing);
      if (backing == state.backings.end()) {
        fail(invariant::kBackingReferenceValid,
             "virtual accelerator " + record.id.str() + " references missing backing " + record.backing.str(),
             &record);
      } else if (backing->second.exclusive && backing->second.assigned_to.valid() &&
                 backing->second.assigned_to != record.id) {
        fail(invariant::kBackingHolderConsistent,
             "backing " + backing->first.str() + " records " + backing->second.assigned_to.str() +
                 " as its holder but " + record.id.str() + " still references it",
             &record);
      }
    }
    if (record.assignment.valid()) {
      const auto assignment = state.assignments.find(record.assignment);
      if (assignment == state.assignments.end()) {
        fail(invariant::kBackingReferenceValid,
             "virtual accelerator " + record.id.str() + " references missing assignment " +
                 record.assignment.str(),
             &record);
      } else if (assignment->second.authoritative != true) {
        if (lifecycle_requires_backing(record.state)) {
          fail(invariant::kNoStaleBackingActive,
               "virtual accelerator " + record.id.str() + " is " +
                   std::string(lifecycle_name(record.state)) + " but its assignment is not authoritative",
               &record);
        }
      }
    } else if (lifecycle_requires_backing(record.state)) {
      fail(invariant::kNoStaleBackingActive,
           "virtual accelerator " + record.id.str() + " is " + std::string(lifecycle_name(record.state)) +
               " without any assignment",
           &record);
    }
    if (record.backing.valid() && record.backing_generation.value() == 0) {
      fail(invariant::kNoStaleBackingActive,
           "virtual accelerator " + record.id.str() + " has a backing but no backing generation", &record);
    }
  }

  // ---- lifecycle consistency --------------------------------------------
  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    if (record.state == VirtualLifecycleState::Retired) {
      if (record.active_attachments != 0) {
        fail(invariant::kRetiredHoldsNoLease,
             "retired virtual accelerator " + record.id.str() + " still reports active attachments", &record);
      }
      if (record.backing.valid() || record.assignment.valid()) {
        fail(invariant::kRetiredHoldsNoLease,
             "retired virtual accelerator " + record.id.str() + " still holds a backing binding", &record);
      }
    }
  }

  // ---- leases ------------------------------------------------------------
  for (const auto& entry : state.leases) {
    const LeaseRecord& lease = entry.second;
    const auto record = state.virtuals.find(lease.virtual_id);
    if (record == state.virtuals.end()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kLeaseGenerationBound),
          "lease " + lease.id.str() + " references missing virtual accelerator " + lease.virtual_id.str());
      violation.lease = lease.id;
      report.violations.push_back(std::move(violation));
      continue;
    }
    if (!lease.generation.valid()) {
      fail(invariant::kLeaseGenerationBound, "lease " + lease.id.str() + " has no generation", &record->second);
    }
    if (state.tenants.find(lease.tenant) == state.tenants.end()) {
      fail(invariant::kTenantReferenceValid,
           "lease " + lease.id.str() + " references missing tenant " + lease.tenant.str(), &record->second);
    }
    if (!lease_state_is_live(lease.state)) continue;
    if (lease.virtual_generation != record->second.generation) {
      fail(invariant::kLeaseGenerationBound,
           "live lease " + lease.id.str() + " is bound to virtual generation " + lease.virtual_generation.str() +
               " but the virtual accelerator is at " + record->second.generation.str(),
           &record->second);
    }
    if (lease.backing_generation != record->second.backing_generation) {
      fail(invariant::kLeaseGenerationBound,
           "live lease " + lease.id.str() + " is bound to backing generation " + lease.backing_generation.str() +
               " but the current binding generation is " + record->second.backing_generation.str(),
           &record->second);
    }
    if (lease.policy_generation != state.policy_generation) {
      fail(invariant::kPolicyGenerationConsistent,
           "live lease " + lease.id.str() + " was granted under policy generation " + lease.policy_generation.str() +
               " but the current generation is " + state.policy_generation.str(),
           &record->second);
    }
    if (lease.epoch != state.epoch) {
      fail(invariant::kEpochConsistent,
           "live lease " + lease.id.str() + " was granted under epoch " + lease.epoch.str() +
               " but the current epoch is " + state.epoch.str(),
           &record->second);
    }
    if (!lifecycle_allows_leases(record->second.state)) {
      fail(invariant::kLeaseGenerationBound,
           "virtual accelerator " + record->first.str() + " is " +
               std::string(lifecycle_name(record->second.state)) + " but holds live lease " + lease.id.str(),
           &record->second);
    }
  }

  // ---- projections and contracts ----------------------------------------
  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    Status contract_status = record.contract.validate();
    if (!contract_status.ok()) {
      fail(invariant::kContractValid,
           "virtual accelerator " + record.id.str() + " holds an invalid contract: " + contract_status.to_string(),
           &record);
    }
    if (!record.contract.generation.valid()) {
      fail(invariant::kContractValid, "virtual accelerator " + record.id.str() + " has no contract generation",
           &record);
    }
    if (!record.projection.generation.valid()) {
      fail(invariant::kProjectionConsistent,
           "virtual accelerator " + record.id.str() + " has no capability projection generation", &record);
    }
    if (record.projection.contract_generation != record.contract.generation) {
      fail(invariant::kProjectionConsistent,
           "capability projection of " + record.id.str() + " is bound to contract generation " +
               record.projection.contract_generation.str() + " but the contract is at " +
               record.contract.generation.str(),
           &record);
    }
    if (record.projection.backing_generation != record.backing_generation) {
      fail(invariant::kProjectionConsistent,
           "capability projection of " + record.id.str() + " is bound to backing generation " +
               record.projection.backing_generation.str() + " but the binding generation is " +
               record.backing_generation.str(),
           &record);
    }
    if (record.state != VirtualLifecycleState::Retired &&
        record.projection.policy_generation != state.policy_generation) {
      fail(invariant::kPolicyGenerationConsistent,
           "capability projection of " + record.id.str() + " is bound to policy generation " +
               record.projection.policy_generation.str() + " but the current generation is " +
               state.policy_generation.str(),
           &record);
    }
    // The projection may never advertise a hardened capability that its
    // backing does not support.
    if (record.backing.valid()) {
      const auto backing = state.backings.find(record.backing);
      if (backing != state.backings.end()) {
        for (const CapabilityEntry& capability : record.projection.surface.entries()) {
          if (capability.verdict != CapabilityVerdict::Supported) continue;
          const CapabilityEntry* source = backing->second.capabilities.find(capability.key);
          if (source == nullptr) continue;
          if (source->verdict == CapabilityVerdict::Unsupported) {
            fail(invariant::kProjectionConsistent,
                 "capability " + std::string(capability_key_name(capability.key)) + " is advertised as supported by " +
                     record.id.str() + " but the backing reports it as unsupported",
                 &record);
          }
          if (source->verdict == CapabilityVerdict::Unknown) {
            fail(invariant::kProjectionConsistent,
                 "capability " + std::string(capability_key_name(capability.key)) +
                     " is advertised as supported by " + record.id.str() + " but the backing reports it as unknown",
                 &record);
          }
        }
      }
    }
    if (record.policy_generation.value() > state.policy_generation.value()) {
      fail(invariant::kPolicyGenerationConsistent,
           "virtual accelerator " + record.id.str() + " references a future policy generation", &record);
    }
    if (record.epoch.value() > state.epoch.value()) {
      fail(invariant::kEpochConsistent,
           "virtual accelerator " + record.id.str() + " references a future coordinator epoch", &record);
    }
  }

  // ---- isolation truthfulness -------------------------------------------
  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    for (const IsolationClaim& claim : record.isolation.claims()) {
      if (claim.state != IsolationState::Unknown && claim.mechanism.empty()) {
        fail(invariant::kIsolationTruthful,
             "isolation claim for " + std::string(isolation_dimension_name(claim.dimension)) + " on " +
                 record.id.str() + " asserts " + std::string(isolation_state_name(claim.state)) +
                 " without naming a mechanism",
             &record);
      }
    }
    if (record.isolation_class == IsolationClass::HardwarePartition) {
      const auto backing = state.backings.find(record.backing);
      if (backing == state.backings.end() || backing->second.klass != BackingClass::HardwarePartition) {
        fail(invariant::kIsolationTruthful,
             "virtual accelerator " + record.id.str() +
                 " claims a hardware partition isolation class without a hardware partition backing",
             &record);
      }
    }
  }

  // ---- migrations --------------------------------------------------------
  for (const auto& entry : state.migrations) {
    const MigrationRecord& migration = entry.second;
    if (migration.plan.id != entry.first || !migration.plan.id.valid()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kMigrationEndpointsPresent),
          "migration map key does not match the plan identity");
      report.violations.push_back(std::move(violation));
      continue;
    }
    const auto record = state.virtuals.find(migration.plan.virtual_id);
    if (record == state.virtuals.end()) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kMigrationEndpointsPresent),
          "migration " + migration.plan.id.str() + " references missing virtual accelerator");
      violation.migration = migration.plan.id;
      report.violations.push_back(std::move(violation));
      continue;
    }
    if (state.backings.find(migration.plan.source_backing) == state.backings.end()) {
      fail(invariant::kMigrationEndpointsPresent,
           "migration " + migration.plan.id.str() + " has no source backing", &record->second);
    }
    if (state.backings.find(migration.plan.destination_backing) == state.backings.end()) {
      fail(invariant::kMigrationEndpointsPresent,
           "migration " + migration.plan.id.str() + " has no destination backing", &record->second);
    }
    if (migration.plan.klass == MigrationClass::LiveStateTransfer && !migration.plan.live_state_movement) {
      fail(invariant::kMigrationEndpointsPresent,
           "migration " + migration.plan.id.str() +
               " claims LIVE_STATE_TRANSFER without live state movement being performed",
           &record->second);
    }
    if (migration_state_after_cutover(migration.state)) {
      if (migration.source_authoritative) {
        fail(invariant::kNoSourceAuthorityAfterCutover,
             "migration " + migration.plan.id.str() + " crossed the cutover but still marks the source authoritative",
             &record->second);
      }
      const auto source = state.assignments.find(migration.source_assignment);
      if (source != state.assignments.end() && source->second.authoritative) {
        fail(invariant::kNoSourceAuthorityAfterCutover,
             "migration " + migration.plan.id.str() + " crossed the cutover but the source assignment is still "
             "authoritative",
             &record->second);
      }
      const auto destination = state.assignments.find(migration.destination_assignment);
      if (destination != state.assignments.end() && !destination->second.authoritative) {
        fail(invariant::kSingleAuthoritativeBacking,
             "migration " + migration.plan.id.str() +
                 " crossed the cutover but the destination assignment is not authoritative",
             &record->second);
      }
    }
    if (!migration_state_after_cutover(migration.state) && !migration_state_is_terminal(migration.state) &&
        migration.destination_authoritative) {
      fail(invariant::kSingleAuthoritativeBacking,
           "migration " + migration.plan.id.str() +
               " marks the destination authoritative before the cutover",
           &record->second);
    }
  }

  // ---- accounting closure ------------------------------------------------
  std::uint64_t expected_active = 0;
  std::uint64_t expected_attachments = 0;
  std::uint64_t expected_bytes = 0;
  for (const auto& entry : state.virtuals) {
    const VirtualAcceleratorRecord& record = entry.second;
    if (record.state != VirtualLifecycleState::Retired && record.state != VirtualLifecycleState::Suspended &&
        record.state != VirtualLifecycleState::Fenced) {
      expected_active += 1;
    }
    expected_attachments += record.active_attachments;
    expected_bytes += record.allocated_bytes;
    std::uint32_t live = 0;
    for (LeaseId lease_id : record.leases) {
      const auto lease = state.leases.find(lease_id);
      if (lease != state.leases.end() && lease_state_is_live(lease->second.state)) ++live;
    }
    if (live != record.active_attachments) {
      fail(invariant::kAttachmentCountConsistent,
           "virtual accelerator " + record.id.str() + " reports " + std::to_string(record.active_attachments) +
               " active attachment(s) but has " + std::to_string(live) + " live lease(s)",
           &record);
    }
  }
  for (const auto& entry : state.tenants) {
    const TenantRecord& tenant = entry.second;
    std::uint32_t expected = 0;
    for (VirtualAcceleratorId owned : tenant.owned) {
      const auto record = state.virtuals.find(owned);
      if (record == state.virtuals.end()) {
        InvariantViolation violation;
        add(violation, std::string(invariant::kTenantReferenceValid),
            "tenant " + tenant.id.str() + " claims ownership of missing virtual accelerator " + owned.str());
        violation.tenant = tenant.id;
        report.violations.push_back(std::move(violation));
        continue;
      }
      if (record->second.owner != tenant.id) {
        InvariantViolation violation;
        add(violation, std::string(invariant::kTenantReferenceValid),
            "tenant " + tenant.id.str() + " claims " + owned.str() + " but the record names " +
                record->second.owner.str());
        violation.tenant = tenant.id;
        violation.virtual_id = owned;
        report.violations.push_back(std::move(violation));
      }
      expected += record->second.active_attachments;
    }
    if (expected != tenant.active_attachments) {
      InvariantViolation violation;
      add(violation, std::string(invariant::kAttachmentCountConsistent),
          "tenant " + tenant.id.str() + " reports " + std::to_string(tenant.active_attachments) +
              " active attachment(s) but its virtual accelerators account for " + std::to_string(expected));
      violation.tenant = tenant.id;
      report.violations.push_back(std::move(violation));
    }
  }
  if (state.accounting.virtual_active != expected_active) {
    InvariantViolation violation;
    add(violation, std::string(invariant::kAccountingClosure),
        "accounting reports " + std::to_string(state.accounting.virtual_active) +
            " active virtual accelerators but the records account for " + std::to_string(expected_active));
    report.violations.push_back(std::move(violation));
  }
  if (state.accounting.attachments_active != expected_attachments) {
    InvariantViolation violation;
    add(violation, std::string(invariant::kAccountingClosure),
        "accounting reports " + std::to_string(state.accounting.attachments_active) +
            " active attachments but the records account for " + std::to_string(expected_attachments));
    report.violations.push_back(std::move(violation));
  }
  if (state.accounting.bytes_allocated_current != expected_bytes) {
    InvariantViolation violation;
    add(violation, std::string(invariant::kAccountingClosure),
        "accounting reports " + std::to_string(state.accounting.bytes_allocated_current) +
            " allocated byte(s) but the records account for " + std::to_string(expected_bytes));
    report.violations.push_back(std::move(violation));
  }

  report.state_fingerprint = state_fingerprint(state);
  report.epoch = state.epoch.value();
  return report;
}

}  // namespace av
