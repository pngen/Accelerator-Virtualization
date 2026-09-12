// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace av {

// Stable machine-readable failure taxonomy. Numeric values are part of the wire
// protocol and of the durable audit log; never renumber an existing enumerator.
enum class StatusCode : std::uint32_t {
  Ok = 0,

  // argument / lookup
  InvalidArgument = 10,
  NotFound = 11,
  AlreadyExists = 12,
  DuplicateIdentity = 13,
  LimitExceeded = 14,
  ResourceExhausted = 15,
  Conflict = 16,

  // authority / staleness
  StaleEpoch = 100,
  StaleVirtualGeneration = 101,
  StaleTenant = 102,
  StaleBacking = 103,
  StalePhysicalDevice = 104,
  StaleLease = 105,
  StalePolicy = 106,
  StaleMigration = 107,
  StaleAgentBoot = 108,
  StaleAssignment = 109,

  // authorization
  NotAuthorized = 200,
  TenantFenced = 201,
  VirtualFenced = 202,
  VirtualRetired = 203,
  NotAttached = 204,
  AlreadyAttached = 205,
  LeaseExpired = 206,
  LeaseRevoked = 207,
  AttachLimitReached = 208,

  // lifecycle
  InvalidTransition = 300,
  RecoveryRequired = 301,
  Draining = 302,
  MigrationInProgress = 303,
  NoActiveMigration = 304,

  // backing
  BackingUnavailable = 400,
  BackingBusy = 401,
  BackingClassNotAllowed = 402,
  BackingTransparencyViolation = 403,
  OversubscriptionDenied = 404,

  // capability / contract / isolation
  CapabilityProjectionMismatch = 500,
  CapabilityUnknown = 501,
  ContractViolation = 502,
  ContractInvalid = 503,
  IsolationUnsatisfied = 504,
  IsolationUnknownMandatory = 505,
  PolicyViolation = 506,

  // migration
  MigrationUnsupported = 600,
  MigrationClassNotAllowed = 601,

  // protocol / transport
  ProtocolViolation = 700,
  VersionMismatch = 701,
  MalformedFrame = 702,
  FrameTooLarge = 703,
  UnsupportedMessage = 704,
  ConnectionLost = 705,
  Timeout = 706,
  DuplicateRequest = 707,
  Shutdown = 708,
  NotReady = 709,

  // integrity / io
  IntegrityFailure = 800,
  CorruptState = 801,
  TruncatedState = 802,
  IoFailure = 803,
  SerializationFailure = 804,

  // generic
  Unsupported = 900,
  Unknown = 901,
  Internal = 902,
  NotImplemented = 903,
  OutcomeUnknown = 904,
};

// Stable lower_snake_case name. Part of the public contract: CLI output, audit
// records and machine consumers depend on it.
std::string_view code_name(StatusCode code) noexcept;

// True for every failure that means "the caller presented authority that a
// newer generation has superseded".
bool is_stale_code(StatusCode code) noexcept;

// True for failures caused by the caller lacking required authority.
bool is_authority_code(StatusCode code) noexcept;

// True for failures that indicate damaged or untrusted input.
bool is_integrity_code(StatusCode code) noexcept;

class Status {
 public:
  Status() noexcept = default;
  Status(StatusCode code) noexcept : code_(code) {}
  Status(StatusCode code, std::string detail) : code_(code), detail_(std::move(detail)) {}

  bool ok() const noexcept { return code_ == StatusCode::Ok; }
  explicit operator bool() const noexcept { return ok(); }

  StatusCode code() const noexcept { return code_; }
  const std::string& detail() const noexcept { return detail_; }

  void set_detail(std::string detail) { detail_ = std::move(detail); }
  Status& with_detail(std::string detail) {
    detail_ = std::move(detail);
    return *this;
  }

  std::string to_string() const;

 private:
  StatusCode code_{StatusCode::Ok};
  std::string detail_{};
};

inline Status OkStatus() noexcept { return Status{}; }

template <class T>
class Result {
 public:
  Result(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)

  bool ok() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return ok(); }
  const Status& status() const noexcept { return status_; }

  const T& value() const noexcept { return *value_; }
  T& value() noexcept { return *value_; }
  const T* operator->() const noexcept { return &*value_; }
  T* operator->() noexcept { return &*value_; }
  const T& operator*() const noexcept { return *value_; }
  T& operator*() noexcept { return *value_; }
  T take() noexcept { return std::move(*value_); }

 private:
  Status status_{};
  std::optional<T> value_{};
};

template <>
class Result<void> {
 public:
  Result(Status status = Status{}) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  bool ok() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return ok(); }
  const Status& status() const noexcept { return status_; }

 private:
  Status status_{};
};

}  // namespace av
