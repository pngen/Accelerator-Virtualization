// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <memory>

#include "av/backend.hpp"

namespace av {

// Narrow CUDA adapter. This is the only place in the project that includes a
// vendor SDK header; the vendor-neutral core never does.
//
// What it provides truthfully: real device discovery, real device memory
// allocation, real host/device transfers and real kernel execution against the
// physical device.
//
// What it does not provide: hardware partitioning, MIG, SR-IOV, hardware
// memory isolation, fault containment or reset isolation. Backings created by
// this adapter are REAL physical mechanisms whose isolation is reported per
// dimension and never upgraded.
std::unique_ptr<BackendAdapter> make_cuda_backend();

}  // namespace av
