// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/contract.hpp"

#include <algorithm>

#include "av/hash.hpp"

namespace av {
namespace {

template <class T>
void sort_unique(std::vector<T>& values) {
  std::sort(values.begin(), values.end(), [](T a, T b) {
    return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
  });
  values.erase(std::unique(values.begin(), values.end()), values.end());
}

}  // namespace

void ResourceContract::normalize() {
  sort_unique(allowed_backing_classes);
  sort_unique(allowed_multiplexing_modes);
  sort_unique(allowed_migration_classes);
  std::sort(required_isolation.begin(), required_isolation.end(),
            [](const IsolationRequirement& a, const IsolationRequirement& b) {
              return static_cast<std::uint8_t>(a.dimension) < static_cast<std::uint8_t>(b.dimension);
            });
  required_isolation.erase(std::unique(required_isolation.begin(), required_isolation.end(),
                                       [](const IsolationRequirement& a, const IsolationRequirement& b) {
                                         return a.dimension == b.dimension;
                                       }),
                           required_isolation.end());
}

Status ResourceContract::validate() const {
  if (compute_share_milli > 1000u) {
    return Status(StatusCode::ContractInvalid,
                  "compute share " + std::to_string(compute_share_milli) + " milli exceeds 1000 milli (one device)");
  }
  if (max_streams > 65536u) {
    return Status(StatusCode::ContractInvalid, "max_streams exceeds the supported bound of 65536");
  }
  if (max_concurrency > 65536u) {
    return Status(StatusCode::ContractInvalid, "max_concurrency exceeds the supported bound of 65536");
  }
  for (BackingClass klass : allowed_backing_classes) {
    if (klass == BackingClass::Unknown) {
      return Status(StatusCode::ContractInvalid, "allowed_backing_classes must not contain UNKNOWN");
    }
  }
  for (MultiplexingMode mode : allowed_multiplexing_modes) {
    if (mode == MultiplexingMode::None) {
      return Status(StatusCode::ContractInvalid, "allowed_multiplexing_modes must not contain NONE");
    }
  }
  for (MigrationClass klass : allowed_migration_classes) {
    if (klass == MigrationClass::Unknown) {
      return Status(StatusCode::ContractInvalid, "allowed_migration_classes must not contain UNKNOWN");
    }
    if (klass == MigrationClass::Unsupported) {
      return Status(StatusCode::ContractInvalid, "allowed_migration_classes must not contain UNSUPPORTED");
    }
  }
  if (exclusivity_required && oversubscription_allowed) {
    return Status(StatusCode::ContractInvalid,
                  "an exclusive contract cannot also allow oversubscription of the same backing");
  }
  for (const IsolationRequirement& requirement : required_isolation) {
    if (requirement.minimum == IsolationState::Unsupported) {
      return Status(StatusCode::ContractInvalid,
                    std::string("isolation requirement for ") +
                        std::string(isolation_dimension_name(requirement.dimension)) +
                        " asks for UNSUPPORTED, which can never be satisfied");
    }
  }
  // Duplicates indicate an unnormalised contract; refuse rather than silently
  // reinterpreting the caller's intent.
  for (std::size_t i = 1; i < required_isolation.size(); ++i) {
    if (required_isolation[i - 1].dimension == required_isolation[i].dimension) {
      return Status(StatusCode::ContractInvalid, "required_isolation repeats a dimension");
    }
  }
  return Status{};
}

std::string ResourceContract::canonical() const {
  std::string out;
  out.reserve(512);
  out.append("memory_ceiling_bytes=").append(std::to_string(memory_ceiling_bytes)).append("\n");
  out.append("compute_share_milli=").append(std::to_string(compute_share_milli)).append("\n");
  out.append("max_streams=").append(std::to_string(max_streams)).append("\n");
  out.append("max_concurrency=").append(std::to_string(max_concurrency)).append("\n");
  out.append("bandwidth_allowance=").append(std::to_string(bandwidth_allowance_bytes_per_second)).append("\n");
  out.append("exclusivity_required=").append(exclusivity_required ? "true" : "false").append("\n");
  out.append("minimum_backing_rank=").append(std::to_string(minimum_backing_rank)).append("\n");
  out.append("migration_allowed=").append(migration_allowed ? "true" : "false").append("\n");
  out.append("oversubscription_allowed=").append(oversubscription_allowed ? "true" : "false").append("\n");
  out.append("burst_allowed=").append(burst_allowed ? "true" : "false").append("\n");
  for (BackingClass klass : allowed_backing_classes) {
    out.append("allowed_backing_class=").append(backing_class_name(klass)).append("\n");
  }
  for (MultiplexingMode mode : allowed_multiplexing_modes) {
    out.append("allowed_multiplexing=").append(multiplexing_name(mode)).append("\n");
  }
  for (const IsolationRequirement& requirement : required_isolation) {
    out.append("required_isolation=")
        .append(isolation_dimension_name(requirement.dimension))
        .append(">=")
        .append(isolation_state_name(requirement.minimum))
        .append("\n");
  }
  for (MigrationClass klass : allowed_migration_classes) {
    out.append("allowed_migration_class=").append(migration_class_name(klass)).append("\n");
  }
  return out;
}

std::uint64_t ResourceContract::fingerprint() const {
  return Fnv1a64::compute(canonical());
}

bool ResourceContract::permits_backing_class(BackingClass klass) const noexcept {
  if (allowed_backing_classes.empty()) return true;
  return std::find(allowed_backing_classes.begin(), allowed_backing_classes.end(), klass) !=
         allowed_backing_classes.end();
}

bool ResourceContract::permits_multiplexing(MultiplexingMode mode) const noexcept {
  if (allowed_multiplexing_modes.empty()) return true;
  return std::find(allowed_multiplexing_modes.begin(), allowed_multiplexing_modes.end(), mode) !=
         allowed_multiplexing_modes.end();
}

bool ResourceContract::permits_migration_class(MigrationClass klass) const noexcept {
  if (!migration_allowed) return false;
  if (allowed_migration_classes.empty()) return true;
  return std::find(allowed_migration_classes.begin(), allowed_migration_classes.end(), klass) !=
         allowed_migration_classes.end();
}

}  // namespace av
