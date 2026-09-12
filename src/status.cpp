// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/status.hpp"

namespace av {
namespace {

struct CodeName {
  StatusCode code;
  std::string_view name;
};

constexpr CodeName kCodeNames[] = {
    {StatusCode::Ok, "ok"},
    {StatusCode::InvalidArgument, "invalid_argument"},
    {StatusCode::NotFound, "not_found"},
    {StatusCode::AlreadyExists, "already_exists"},
    {StatusCode::DuplicateIdentity, "duplicate_identity"},
    {StatusCode::LimitExceeded, "limit_exceeded"},
    {StatusCode::ResourceExhausted, "resource_exhausted"},
    {StatusCode::Conflict, "conflict"},
    {StatusCode::StaleEpoch, "stale_epoch"},
    {StatusCode::StaleVirtualGeneration, "stale_virtual_generation"},
    {StatusCode::StaleTenant, "stale_tenant"},
    {StatusCode::StaleBacking, "stale_backing"},
    {StatusCode::StalePhysicalDevice, "stale_physical_device"},
    {StatusCode::StaleLease, "stale_lease"},
    {StatusCode::StalePolicy, "stale_policy"},
    {StatusCode::StaleMigration, "stale_migration"},
    {StatusCode::StaleAgentBoot, "stale_agent_boot"},
    {StatusCode::StaleAssignment, "stale_assignment"},
    {StatusCode::NotAuthorized, "not_authorized"},
    {StatusCode::TenantFenced, "tenant_fenced"},
    {StatusCode::VirtualFenced, "virtual_fenced"},
    {StatusCode::VirtualRetired, "virtual_retired"},
    {StatusCode::NotAttached, "not_attached"},
    {StatusCode::AlreadyAttached, "already_attached"},
    {StatusCode::LeaseExpired, "lease_expired"},
    {StatusCode::LeaseRevoked, "lease_revoked"},
    {StatusCode::AttachLimitReached, "attach_limit_reached"},
    {StatusCode::InvalidTransition, "invalid_transition"},
    {StatusCode::RecoveryRequired, "recovery_required"},
    {StatusCode::Draining, "draining"},
    {StatusCode::MigrationInProgress, "migration_in_progress"},
    {StatusCode::NoActiveMigration, "no_active_migration"},
    {StatusCode::BackingUnavailable, "backing_unavailable"},
    {StatusCode::BackingBusy, "backing_busy"},
    {StatusCode::BackingClassNotAllowed, "backing_class_not_allowed"},
    {StatusCode::BackingTransparencyViolation, "backing_transparency_violation"},
    {StatusCode::OversubscriptionDenied, "oversubscription_denied"},
    {StatusCode::CapabilityProjectionMismatch, "capability_projection_mismatch"},
    {StatusCode::CapabilityUnknown, "capability_unknown"},
    {StatusCode::ContractViolation, "contract_violation"},
    {StatusCode::ContractInvalid, "contract_invalid"},
    {StatusCode::IsolationUnsatisfied, "isolation_unsatisfied"},
    {StatusCode::IsolationUnknownMandatory, "isolation_unknown_mandatory"},
    {StatusCode::PolicyViolation, "policy_violation"},
    {StatusCode::MigrationUnsupported, "migration_unsupported"},
    {StatusCode::MigrationClassNotAllowed, "migration_class_not_allowed"},
    {StatusCode::ProtocolViolation, "protocol_violation"},
    {StatusCode::VersionMismatch, "version_mismatch"},
    {StatusCode::MalformedFrame, "malformed_frame"},
    {StatusCode::FrameTooLarge, "frame_too_large"},
    {StatusCode::UnsupportedMessage, "unsupported_message"},
    {StatusCode::ConnectionLost, "connection_lost"},
    {StatusCode::Timeout, "timeout"},
    {StatusCode::DuplicateRequest, "duplicate_request"},
    {StatusCode::Shutdown, "shutdown"},
    {StatusCode::NotReady, "not_ready"},
    {StatusCode::IntegrityFailure, "integrity_failure"},
    {StatusCode::CorruptState, "corrupt_state"},
    {StatusCode::TruncatedState, "truncated_state"},
    {StatusCode::IoFailure, "io_failure"},
    {StatusCode::SerializationFailure, "serialization_failure"},
    {StatusCode::Unsupported, "unsupported"},
    {StatusCode::Unknown, "unknown"},
    {StatusCode::Internal, "internal"},
    {StatusCode::NotImplemented, "not_implemented"},
    {StatusCode::OutcomeUnknown, "outcome_unknown"},
};

}  // namespace

std::string_view code_name(StatusCode code) noexcept {
  for (const CodeName& entry : kCodeNames) {
    if (entry.code == code) return entry.name;
  }
  return "unrecognized";
}

bool is_stale_code(StatusCode code) noexcept {
  const auto value = static_cast<std::uint32_t>(code);
  return value >= 100u && value < 200u;
}

bool is_authority_code(StatusCode code) noexcept {
  const auto value = static_cast<std::uint32_t>(code);
  return value >= 200u && value < 300u;
}

bool is_integrity_code(StatusCode code) noexcept {
  const auto value = static_cast<std::uint32_t>(code);
  return (value >= 700u && value < 710u) || (value >= 800u && value < 900u);
}

std::string Status::to_string() const {
  std::string out;
  out.reserve(32 + detail_.size());
  out.append(code_name(code_));
  if (!detail_.empty()) {
    out.append(": ");
    out.append(detail_);
  }
  return out;
}

}  // namespace av
