// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <memory>

namespace av {

using UnixMicros = std::int64_t;

// Time is recorded for observability only. No externally meaningful decision
// may depend on it: equivalent state + policy + evidence must yield equivalent
// decisions regardless of when they were evaluated.
class Clock {
 public:
  virtual ~Clock() = default;
  virtual UnixMicros now_micros() const = 0;
};

class SystemClock final : public Clock {
 public:
  UnixMicros now_micros() const override;
};

// Deterministic clock for tests and reproducible snapshots.
class ManualClock final : public Clock {
 public:
  explicit ManualClock(UnixMicros start = 1700000000000000LL) : now_(start) {}
  UnixMicros now_micros() const override { return now_; }
  void advance(UnixMicros delta) { now_ += delta; }
  void set(UnixMicros value) { now_ = value; }

 private:
  UnixMicros now_;
};

}  // namespace av
