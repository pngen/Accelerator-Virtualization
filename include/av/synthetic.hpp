// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <memory>
#include <string_view>
#include <vector>

#include "av/backend.hpp"

namespace av {

// Deterministic synthetic backends for virtualization mechanisms that are not
// available on the host. Everything they produce is labelled SYNTHETIC and may
// never be used as evidence of physical hardware behaviour.
//
// They exist to exercise the generic identity, authority, lifecycle, isolation
// and migration semantics of the runtime.
struct SyntheticBackendOptions {
  // Number of hardware-partition backings the synthetic partition device offers.
  std::uint32_t partition_count{4};
  // Total device memory advertised by each synthetic device.
  std::uint64_t memory_bytes{16ull * 1024ull * 1024ull * 1024ull};
};

std::vector<std::unique_ptr<BackendAdapter>> make_synthetic_backends();
std::vector<std::unique_ptr<BackendAdapter>> make_synthetic_backends(const SyntheticBackendOptions& options);

// Names of the synthetic adapters, in registration order. Stable identifiers
// used by the CLI and the tests.
std::vector<std::string_view> synthetic_adapter_names();

}  // namespace av
