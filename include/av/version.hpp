// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <string_view>

#define AV_VERSION_MAJOR 1
#define AV_VERSION_MINOR 0
#define AV_VERSION_PATCH 0
#define AV_VERSION_STRING "1.0.0"

namespace av {

struct Version {
  int major;
  int minor;
  int patch;
};

inline constexpr Version version() noexcept { return Version{AV_VERSION_MAJOR, AV_VERSION_MINOR, AV_VERSION_PATCH}; }
inline constexpr std::string_view version_string() noexcept { return std::string_view{AV_VERSION_STRING}; }

// Protocol framing version. Bumped only on incompatible wire changes.
inline constexpr std::uint16_t protocol_version() noexcept { return 1; }
// Durable on-disk schema version. Bumped only on incompatible persistence changes.
inline constexpr std::uint32_t schema_version() noexcept { return 1; }

}  // namespace av
