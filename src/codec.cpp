// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/codec.hpp"

#include <cstring>

namespace av {

// ---- Encoder -------------------------------------------------------------

void Encoder::u16(std::uint16_t value) {
  u8(static_cast<std::uint8_t>(value & 0xFFu));
  u8(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
}

void Encoder::u32(std::uint32_t value) {
  for (int i = 0; i < 4; ++i) u8(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
}

void Encoder::u64(std::uint64_t value) {
  for (int i = 0; i < 8; ++i) u8(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
}

void Encoder::str(std::string_view value) {
  if (value.size() > 0xFFFFFFFFull) return;  // unreachable for real inputs
  u32(static_cast<std::uint32_t>(value.size()));
  const auto* bytes = reinterpret_cast<const Byte*>(value.data());
  buf_.insert(buf_.end(), bytes, bytes + value.size());
}

void Encoder::raw(ByteSpan value) {
  if (value.size() > 0xFFFFFFFFull) return;
  u32(static_cast<std::uint32_t>(value.size()));
  buf_.insert(buf_.end(), value.begin(), value.end());
}

// ---- Decoder -------------------------------------------------------------

Result<ByteSpan> Decoder::take(std::size_t count) {
  if (count > remaining()) {
    return Status(StatusCode::TruncatedState,
                  "field extends past the end of the buffer: need " + std::to_string(count) + " byte(s), " +
                      std::to_string(remaining()) + " remaining");
  }
  const ByteSpan out{data_.data() + pos_, count};
  pos_ += count;
  return out;
}

Result<std::uint8_t> Decoder::u8() {
  auto span = take(1);
  if (!span.ok()) return span.status();
  return static_cast<std::uint8_t>((*span)[0]);
}

Result<std::uint16_t> Decoder::u16() {
  auto span = take(2);
  if (!span.ok()) return span.status();
  const std::uint16_t low = static_cast<std::uint16_t>((*span)[0]);
  const std::uint16_t high = static_cast<std::uint16_t>((*span)[1]);
  return static_cast<std::uint16_t>(low | (high << 8u));
}

Result<std::uint32_t> Decoder::u32() {
  auto span = take(4);
  if (!span.ok()) return span.status();
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) value |= static_cast<std::uint32_t>((*span)[static_cast<std::size_t>(i)]) << (8 * i);
  return value;
}

Result<std::uint64_t> Decoder::u64() {
  auto span = take(8);
  if (!span.ok()) return span.status();
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>((*span)[static_cast<std::size_t>(i)]) << (8 * i);
  return value;
}

Result<std::int64_t> Decoder::i64() {
  auto value = u64();
  if (!value.ok()) return value.status();
  return static_cast<std::int64_t>(*value);
}

Result<bool> Decoder::boolean() {
  auto value = u8();
  if (!value.ok()) return value.status();
  if (*value > 1u) {
    return Status(StatusCode::MalformedFrame, "boolean field carried value " + std::to_string(*value));
  }
  return *value == 1u;
}

Result<std::string> Decoder::str() {
  auto length = u32();
  if (!length.ok()) return length.status();
  if (*length > limits_.max_string) {
    return Status(StatusCode::LimitExceeded,
                  "string field length " + std::to_string(*length) + " exceeds limit " +
                      std::to_string(limits_.max_string));
  }
  auto span = take(*length);
  if (!span.ok()) return span.status();
  return std::string(reinterpret_cast<const char*>(span->data()), span->size());
}

Result<ByteSpan> Decoder::raw_field() {
  auto length = u32();
  if (!length.ok()) return length.status();
  if (*length > limits_.max_bytes) {
    return Status(StatusCode::LimitExceeded,
                  "blob field length " + std::to_string(*length) + " exceeds limit " +
                      std::to_string(limits_.max_bytes));
  }
  return take(*length);
}

Result<std::size_t> Decoder::list_header(std::size_t max_allowed) {
  auto entry = depth_enter();
  if (!entry.ok()) return entry.status();
  auto count = u32();
  if (!count.ok()) return count.status();
  const std::size_t value = *count;
  if (value > max_allowed) {
    return Status(StatusCode::LimitExceeded,
                  "container holds " + std::to_string(value) + " item(s), limit " + std::to_string(max_allowed));
  }
  if (value > limits_.max_items) {
    return Status(StatusCode::LimitExceeded,
                  "container holds " + std::to_string(value) + " item(s), decode limit " +
                      std::to_string(limits_.max_items));
  }
  // Every encoded item occupies at least one byte, so a container can never
  // claim more items than there are bytes left to describe them.
  if (value > remaining()) {
    return Status(StatusCode::MalformedFrame,
                  "container declares " + std::to_string(value) + " item(s) but only " +
                      std::to_string(remaining()) + " byte(s) remain");
  }
  return value;
}

Result<std::size_t> Decoder::depth_enter() {
  if (depth_ + 1 > limits_.max_depth) {
    return Status(StatusCode::LimitExceeded, "container nesting exceeds depth limit " + std::to_string(limits_.max_depth));
  }
  ++depth_;
  return depth_;
}

Status Decoder::require_end() const {
  if (!at_end()) {
    return Status(StatusCode::ProtocolViolation,
                  std::to_string(remaining()) + " unexpected trailing byte(s) after the final field");
  }
  return Status{};
}

// ---- scalar helpers ------------------------------------------------------

void put_u16(std::vector<Byte>& out, std::uint16_t value) {
  out.push_back(static_cast<Byte>(value & 0xFFu));
  out.push_back(static_cast<Byte>((value >> 8u) & 0xFFu));
}

void put_u32(std::vector<Byte>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xFFu));
}

void put_u64(std::vector<Byte>& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xFFu));
}

std::uint16_t get_u16(ByteSpan data, std::size_t offset) {
  if (offset + 2 > data.size()) return 0;
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[offset]) |
                                    (static_cast<std::uint16_t>(data[offset + 1]) << 8u));
}

std::uint32_t get_u32(ByteSpan data, std::size_t offset) {
  if (offset + 4 > data.size()) return 0;
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) value |= static_cast<std::uint32_t>(data[offset + static_cast<std::size_t>(i)]) << (8 * i);
  return value;
}

std::uint64_t get_u64(ByteSpan data, std::size_t offset) {
  if (offset + 8 > data.size()) return 0;
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(data[offset + static_cast<std::size_t>(i)]) << (8 * i);
  return value;
}

}  // namespace av
