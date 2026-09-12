// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace av {

// CRC-32C (Castagnoli), reflected, polynomial 0x82F63B78. Used for frame and
// persistence integrity. Deterministic and dependency free.
class Crc32c {
 public:
  void update(const void* data, std::size_t len) noexcept {
    const auto* p = static_cast<const unsigned char*>(data);
    std::uint32_t crc = state_;
    for (std::size_t i = 0; i < len; ++i) {
      crc ^= p[i];
      for (int b = 0; b < 8; ++b) {
        const std::uint32_t mask = static_cast<std::uint32_t>(-(static_cast<std::int32_t>(crc & 1u)));
        crc = (crc >> 1) ^ (0x82F63B78u & mask);
      }
    }
    state_ = crc;
  }

  void update(std::string_view s) noexcept { update(s.data(), s.size()); }

  std::uint32_t value() const noexcept { return state_ ^ 0xFFFFFFFFu; }

  static std::uint32_t compute(const void* data, std::size_t len) noexcept {
    Crc32c c;
    c.update(data, len);
    return c.value();
  }
  static std::uint32_t compute(std::string_view s) noexcept { return compute(s.data(), s.size()); }

 private:
  std::uint32_t state_{0xFFFFFFFFu};
};

// FNV-1a 64. Used for deterministic decision fingerprints.
class Fnv1a64 {
 public:
  void update(const void* data, std::size_t len) noexcept {
    const auto* p = static_cast<const unsigned char*>(data);
    for (std::size_t i = 0; i < len; ++i) {
      state_ ^= p[i];
      state_ *= 0x100000001B3ull;
    }
  }
  void update(std::string_view s) noexcept { update(s.data(), s.size()); }
  std::uint64_t value() const noexcept { return state_; }
  static std::uint64_t compute(std::string_view s) noexcept {
    Fnv1a64 f;
    f.update(s);
    return f.value();
  }

 private:
  std::uint64_t state_{0xCBF29CE484222325ull};
};

}  // namespace av
