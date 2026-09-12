// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/ids.hpp"

#include <array>
#include <charconv>

namespace av {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

std::string to_hex16(std::uint64_t value) {
  std::array<char, 16> digits{};
  for (std::size_t i = 0; i < digits.size(); ++i) {
    digits[digits.size() - 1 - i] = kHexDigits[value & 0xFu];
    value >>= 4u;
  }
  return std::string(digits.data(), digits.size());
}

std::optional<std::uint64_t> from_hex(std::string_view text) {
  if (text.empty() || text.size() > 16) return std::nullopt;
  std::uint64_t value = 0;
  for (char c : text) {
    const int digit = hex_value(c);
    if (digit < 0) return std::nullopt;
    value = (value << 4u) | static_cast<std::uint64_t>(digit);
  }
  return value;
}

std::optional<std::uint64_t> parse_generation_text(std::string_view text) {
  if (text.empty() || text.size() > 20) return std::nullopt;
  std::uint64_t value = 0;
  const char* first = text.data();
  const char* last = text.data() + text.size();
  const auto result = std::from_chars(first, last, value);
  if (result.ec != std::errc{} || result.ptr != last) return std::nullopt;
  return value;
}

std::string render_strong_id(std::string_view prefix, std::uint64_t value) {
  std::string out;
  out.reserve(prefix.size() + 17);
  out.append(prefix);
  out.push_back('-');
  out.append(to_hex16(value));
  return out;
}

std::optional<std::uint64_t> parse_strong_id(std::string_view prefix, std::string_view text) {
  std::string_view digits = text;
  if (!prefix.empty()) {
    if (text.size() < prefix.size() + 1) return std::nullopt;
    if (text.substr(0, prefix.size()) != prefix) return std::nullopt;
    if (text[prefix.size()] != '-') return std::nullopt;
    digits = text.substr(prefix.size() + 1);
  }
  return from_hex(digits);
}

}  // namespace av
