// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <compare>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace av {

// Free functions so that the templates below need no out-of-line
// instantiation: "va-0000000000000001" for identities, decimal for
// generations. Canonical hex rendering is shared by snapshots, CLI output and
// audit records.
std::string to_hex16(std::uint64_t value);
std::optional<std::uint64_t> from_hex(std::string_view text);
std::optional<std::uint64_t> parse_generation_text(std::string_view text);
std::string render_strong_id(std::string_view prefix, std::uint64_t value);
std::optional<std::uint64_t> parse_strong_id(std::string_view prefix, std::string_view text);

// ---------------------------------------------------------------------------
// Strongly typed identities.
//
// Identities carry different authority semantics, so they are different types
// and are not interchangeable with integers or with each other. Two values are
// only comparable when they name the same identity space.
// ---------------------------------------------------------------------------

template <class Tag>
class Id {
 public:
  using tag_type = Tag;
  using value_type = std::uint64_t;

  constexpr Id() noexcept = default;
  constexpr explicit Id(std::uint64_t value) noexcept : value_(value) {}

  static constexpr Id from_value(std::uint64_t value) noexcept { return Id(value); }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool valid() const noexcept { return value_ != 0; }
  static constexpr std::string_view prefix() noexcept { return Tag::kPrefix; }

  std::string str() const { return render_strong_id(Tag::kPrefix, value_); }
  static std::optional<Id> parse(std::string_view text) {
    std::optional<std::uint64_t> v = parse_strong_id(Tag::kPrefix, text);
    if (!v.has_value()) return std::nullopt;
    return Id(*v);
  }

  friend constexpr bool operator==(Id a, Id b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(Id a, Id b) noexcept { return a.value_ <=> b.value_; }

 private:
  std::uint64_t value_{0};
};

// Generations are monotonic counters bound to a specific identity space. Zero
// means "no generation" (unset); assigned generations start at one.
template <class Tag>
class Generation {
 public:
  using tag_type = Tag;
  using value_type = std::uint64_t;

  constexpr Generation() noexcept = default;
  constexpr explicit Generation(std::uint64_t value) noexcept : value_(value) {}

  static constexpr Generation from_value(std::uint64_t value) noexcept { return Generation(value); }
  static constexpr Generation initial() noexcept { return Generation(1); }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool valid() const noexcept { return value_ != 0; }

  Generation next() const noexcept { return Generation(value_ + 1); }

  std::string str() const { return std::to_string(value_); }
  static std::optional<Generation> parse(std::string_view text) {
    return parse_generation_text(text);
  }

  friend constexpr bool operator==(Generation a, Generation b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(Generation a, Generation b) noexcept {
    return a.value_ <=> b.value_;
  }

 private:
  std::uint64_t value_{0};
};

// ---------------------------------------------------------------------------
// Tags. The prefix is the stable textual namespace of the identity.
// ---------------------------------------------------------------------------
#define AV_DECLARE_TAG(tag_name, prefix_literal)          \
  struct tag_name {                                        \
    static constexpr std::string_view kPrefix = prefix_literal; \
  }

AV_DECLARE_TAG(VirtualAcceleratorIdTag, "va");
AV_DECLARE_TAG(VirtualAcceleratorGenerationTag, "vag");
AV_DECLARE_TAG(TenantIdTag, "tn");
AV_DECLARE_TAG(TenantGenerationTag, "tng");
AV_DECLARE_TAG(CoordinatorEpochTag, "epoch");
AV_DECLARE_TAG(AgentIdTag, "ag");
AV_DECLARE_TAG(AgentBootIdTag, "boot");
AV_DECLARE_TAG(PhysicalDeviceIdTag, "pd");
AV_DECLARE_TAG(PhysicalDeviceGenerationTag, "pdg");
AV_DECLARE_TAG(BackingIdTag, "bk");
AV_DECLARE_TAG(BackingGenerationTag, "bkg");
AV_DECLARE_TAG(BackingAssignmentIdTag, "as");
AV_DECLARE_TAG(LeaseIdTag, "ls");
AV_DECLARE_TAG(LeaseGenerationTag, "lsg");
AV_DECLARE_TAG(CapabilityProjectionIdTag, "cp");
AV_DECLARE_TAG(CapabilityProjectionGenerationTag, "cpg");
AV_DECLARE_TAG(ResourceContractIdTag, "rc");
AV_DECLARE_TAG(ResourceContractGenerationTag, "rcg");
AV_DECLARE_TAG(PolicyIdTag, "pol");
AV_DECLARE_TAG(PolicyGenerationTag, "polg");
AV_DECLARE_TAG(MigrationIdTag, "mg");
AV_DECLARE_TAG(MigrationGenerationTag, "mgg");
AV_DECLARE_TAG(IsolationDomainIdTag, "iso");
AV_DECLARE_TAG(EvidenceIdTag, "ev");
AV_DECLARE_TAG(EvidenceGenerationTag, "evg");
AV_DECLARE_TAG(DecisionIdTag, "dec");
AV_DECLARE_TAG(RequestIdTag, "rq");

#undef AV_DECLARE_TAG

using VirtualAcceleratorId = Id<VirtualAcceleratorIdTag>;
using TenantId = Id<TenantIdTag>;
using AgentId = Id<AgentIdTag>;
using AgentBootId = Id<AgentBootIdTag>;
using PhysicalDeviceId = Id<PhysicalDeviceIdTag>;
using BackingId = Id<BackingIdTag>;
using BackingAssignmentId = Id<BackingAssignmentIdTag>;
using LeaseId = Id<LeaseIdTag>;
using CapabilityProjectionId = Id<CapabilityProjectionIdTag>;
using ResourceContractId = Id<ResourceContractIdTag>;
using PolicyId = Id<PolicyIdTag>;
using MigrationId = Id<MigrationIdTag>;
using IsolationDomainId = Id<IsolationDomainIdTag>;
using EvidenceId = Id<EvidenceIdTag>;
using DecisionId = Id<DecisionIdTag>;
using RequestId = Id<RequestIdTag>;

using VirtualAcceleratorGeneration = Generation<VirtualAcceleratorGenerationTag>;
using TenantGeneration = Generation<TenantGenerationTag>;
using CoordinatorEpoch = Generation<CoordinatorEpochTag>;
using PhysicalDeviceGeneration = Generation<PhysicalDeviceGenerationTag>;
using BackingGeneration = Generation<BackingGenerationTag>;
using LeaseGeneration = Generation<LeaseGenerationTag>;
using CapabilityProjectionGeneration = Generation<CapabilityProjectionGenerationTag>;
using ResourceContractGeneration = Generation<ResourceContractGenerationTag>;
using PolicyGeneration = Generation<PolicyGenerationTag>;
using MigrationGeneration = Generation<MigrationGenerationTag>;
using EvidenceGeneration = Generation<EvidenceGenerationTag>;

template <class T>
struct is_strong_id : std::false_type {};
template <class Tag>
struct is_strong_id<Id<Tag>> : std::true_type {};
template <class Tag>
struct is_strong_id<Generation<Tag>> : std::true_type {};



}  // namespace av

namespace std {
template <class Tag>
struct hash<av::Id<Tag>> {
  std::size_t operator()(const av::Id<Tag>& id) const noexcept {
    return std::hash<std::uint64_t>{}(id.value());
  }
};
template <class Tag>
struct hash<av::Generation<Tag>> {
  std::size_t operator()(const av::Generation<Tag>& gen) const noexcept {
    return std::hash<std::uint64_t>{}(gen.value());
  }
};
}  // namespace std
