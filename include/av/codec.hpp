// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "av/status.hpp"

namespace av {

using Byte = std::byte;
using ByteSpan = std::span<const Byte>;
using MutableByteSpan = std::span<Byte>;

// Bounds every decode path. Nothing a peer or a file can say may cause an
// unbounded allocation, so counts are validated against both a per-field limit
// and the number of bytes actually remaining.
struct DecodeLimits {
  std::size_t max_string = 64u * 1024u;
  std::size_t max_bytes = 1024u * 1024u;
  std::size_t max_items = 65536u;
  std::size_t max_depth = 16u;
};

// Canonical little-endian encoder. The byte stream is a pure function of the
// values written, so identical state always produces identical bytes.
class Encoder {
 public:
  void u8(std::uint8_t value) { buf_.push_back(static_cast<Byte>(value)); }
  void boolean(bool value) { u8(value ? 1u : 0u); }
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }
  void str(std::string_view value);
  void raw(ByteSpan value);

  template <class T, class Fn>
  void list(const std::vector<T>& items, Fn&& encode_item) {
    u32(static_cast<std::uint32_t>(items.size()));
    for (const T& item : items) encode_item(*this, item);
  }

  ByteSpan data() const noexcept { return ByteSpan{buf_.data(), buf_.size()}; }
  const std::vector<Byte>& buffer() const noexcept { return buf_; }
  std::vector<Byte> take() { return std::move(buf_); }
  std::size_t size() const noexcept { return buf_.size(); }
  void clear() noexcept { buf_.clear(); }

 private:
  std::vector<Byte> buf_;
};

class Decoder {
 public:
  explicit Decoder(ByteSpan data, DecodeLimits limits = {}) noexcept : data_(data), limits_(limits) {}
  explicit Decoder(const std::vector<Byte>& data, DecodeLimits limits = {}) noexcept
      : data_(ByteSpan{data.data(), data.size()}), limits_(limits) {}

  Result<std::uint8_t> u8();
  Result<bool> boolean();
  Result<std::uint16_t> u16();
  Result<std::uint32_t> u32();
  Result<std::uint64_t> u64();
  Result<std::int64_t> i64();
  Result<std::string> str();
  Result<ByteSpan> raw_field();

  // Reads a container header and validates it against limits and the bytes
  // that can still possibly be present.
  Result<std::size_t> list_header(std::size_t max_allowed);
  Result<std::size_t> depth_enter();
  void depth_leave() noexcept { --depth_; }

  std::size_t remaining() const noexcept { return data_.size() - pos_; }
  bool at_end() const noexcept { return pos_ >= data_.size(); }
  std::size_t position() const noexcept { return pos_; }
  Status require_end() const;
  const DecodeLimits& limits() const noexcept { return limits_; }

 private:
  Result<ByteSpan> take(std::size_t n);

  ByteSpan data_{};
  std::size_t pos_{0};
  std::size_t depth_{0};
  DecodeLimits limits_{};
};

// Reinterpreting helpers so callers never have to spell out the byte cast.
inline ByteSpan byte_span(const void* data, std::size_t size) noexcept {
  return ByteSpan{static_cast<const Byte*>(data), size};
}
template <class T>
inline ByteSpan byte_span(const std::vector<T>& values) noexcept {
  return ByteSpan{reinterpret_cast<const Byte*>(values.data()), values.size() * sizeof(T)};
}
inline std::vector<std::uint8_t> to_byte_values(ByteSpan data) {
  std::vector<std::uint8_t> out(data.size());
  for (std::size_t i = 0; i < data.size(); ++i) out[i] = static_cast<std::uint8_t>(data[i]);
  return out;
}

// Deterministic scalar encodings used by persistence and by frame headers.
void put_u16(std::vector<Byte>& out, std::uint16_t value);
void put_u32(std::vector<Byte>& out, std::uint32_t value);
void put_u64(std::vector<Byte>& out, std::uint64_t value);
std::uint16_t get_u16(ByteSpan data, std::size_t offset);
std::uint32_t get_u32(ByteSpan data, std::size_t offset);
std::uint64_t get_u64(ByteSpan data, std::size_t offset);

}  // namespace av
