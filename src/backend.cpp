// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/backend.hpp"

namespace av {
namespace {

constexpr std::pair<ExecutionOp, std::string_view> kOperationNames[] = {
    {ExecutionOp::Unknown, "unknown"},
    {ExecutionOp::Allocate, "allocate"},
    {ExecutionOp::Free, "free"},
    {ExecutionOp::Upload, "upload"},
    {ExecutionOp::Download, "download"},
    {ExecutionOp::KernelVectorAdd, "vector-add"},
    {ExecutionOp::Synchronize, "sync"},
    {ExecutionOp::DeviceInfo, "info"},
};

}  // namespace

std::string_view execution_op_name(ExecutionOp value) noexcept {
  for (const auto& entry : kOperationNames) {
    if (entry.first == value) return entry.second;
  }
  return "unknown";
}

std::optional<ExecutionOp> parse_execution_op(std::string_view text) noexcept {
  for (const auto& entry : kOperationNames) {
    if (entry.second == text) return entry.first;
  }
  return std::nullopt;
}

}  // namespace av
