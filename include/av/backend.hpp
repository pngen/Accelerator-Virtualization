// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "av/capability.hpp"
#include "av/ids.hpp"
#include "av/isolation.hpp"
#include "av/status.hpp"
#include "av/taxonomy.hpp"

namespace av {

struct BackingDescriptor {
  std::string label{};
  BackingClass klass{BackingClass::Unknown};
  MultiplexingMode multiplexing{MultiplexingMode::None};
  IsolationClass isolation_class{IsolationClass::Unknown};
  std::uint64_t capacity_bytes{0};
  std::uint32_t compute_units{0};
  std::string mechanism{};
  std::vector<IsolationClaim> isolation{};  // one claim per dimension
  CapabilitySurface capabilities{};
  bool exclusive{true};
  // True when the object exists because another runtime owns its lifecycle.
  // Accelerator Virtualization consumes it and never creates or destroys it.
  bool externally_lifecycle_managed{false};
  std::string external_partition_ref{};
};

struct PhysicalDeviceDescriptor {
  std::string stable_key{};  // deterministic identity, never an ordinal
  std::string vendor{};
  std::string model{};
  std::string driver_version{};
  std::string architecture{};
  Provenance provenance{Provenance::Unknown};
  std::uint64_t memory_total_bytes{0};
  std::uint32_t compute_units{0};
  std::uint32_t compute_capability_major{0};
  std::uint32_t compute_capability_minor{0};
  std::string mechanism{};
  bool hardware_partition_capable{false};
  bool virtual_function_capable{false};
  bool mig_capable{false};
  std::vector<BackingDescriptor> backings{};
};

enum class ExecutionOp : std::uint8_t {
  Unknown = 0,
  Allocate = 1,
  Free = 2,
  Upload = 3,
  Download = 4,
  KernelVectorAdd = 5,
  Synchronize = 6,
  DeviceInfo = 7,
};

std::string_view execution_op_name(ExecutionOp value) noexcept;
std::optional<ExecutionOp> parse_execution_op(std::string_view text) noexcept;

struct ExecutionRequest {
  ExecutionOp op{ExecutionOp::Unknown};
  // Deterministic physical identity the operation must target. An agent
  // resolves this key to whatever local handle the platform requires; a local
  // handle is never an identity.
  std::string stable_key{};
  PhysicalDeviceId physical{};
  PhysicalDeviceGeneration physical_generation{};
  BackingId backing{};
  BackingGeneration backing_generation{};
  VirtualAcceleratorId virtual_id{};
  VirtualAcceleratorGeneration virtual_generation{};
  std::uint64_t handle{0};
  // Multi-operand kernel handles; a single-handle operation uses handle.
  std::vector<std::uint64_t> handles{};
  std::uint64_t bytes{0};
  std::uint32_t count{0};
  std::vector<std::uint8_t> data{};
};

struct ExecutionResult {
  StatusCode status{StatusCode::Ok};
  std::string detail{};
  std::uint64_t handle{0};
  std::uint64_t bytes{0};
  std::vector<std::uint8_t> data{};
  std::string device_name{};
  std::string driver_version{};
  std::uint64_t total_memory{0};
  std::uint64_t free_memory{0};
};

// Narrow vendor/platform seam. The vendor-neutral core never includes a vendor
// SDK header; every integration lives behind this interface.
class BackendAdapter {
 public:
  virtual ~BackendAdapter() = default;

  virtual std::string name() const = 0;
  virtual Provenance provenance() const = 0;
  virtual std::vector<BackingClass> supported_backing_classes() const = 0;

  virtual Result<std::vector<PhysicalDeviceDescriptor>> discover() = 0;
  virtual Result<PhysicalDeviceDescriptor> probe(std::string_view stable_key) = 0;
  virtual Result<ExecutionResult> execute(const ExecutionRequest& request) = 0;
};

}  // namespace av
