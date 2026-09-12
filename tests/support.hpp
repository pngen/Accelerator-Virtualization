// Accelerator Virtualization - shared test fixtures.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "av/runtime.hpp"
#include "av/synthetic.hpp"
#include "process.hpp"
#include "testkit.hpp"

namespace avtest {

// An in-process runtime with a manual clock and an in-memory store. Used by the
// unit, property, concurrency and adversarial suites.
class Fixture {
 public:
  explicit Fixture(bool persist = false, std::size_t deferred_threshold = 0);
  ~Fixture();

  av::VirtualizationRuntime& runtime() { return *runtime_; }
  av::ManualClock& clock() { return *clock_; }

  av::Authority authority() const { return runtime_->current_authority(); }
  av::Authority epoch_only() const;

  // Registers an in-process agent and returns its boot identity.
  void attach_agent(const std::string& name = "test-agent");
  av::AgentId agent_id() const { return agent_; }
  av::AgentBootId agent_boot() const { return boot_; }

  // Registers one synthetic physical device by adapter name and returns the
  // first backing the runtime materialised for it.
  av::PhysicalDeviceRecord register_synthetic(const std::string& adapter_name);
  av::PhysicalDeviceRecord register_descriptor(const av::PhysicalDeviceDescriptor& descriptor);
  std::vector<av::BackingRecord> backings_of(av::PhysicalDeviceId device) const;
  av::BackingRecord backing_by_label(av::PhysicalDeviceId device, const std::string& label) const;

  av::TenantRecord make_tenant(const std::string& name);
  av::VirtualAcceleratorRecord make_virtual(const std::string& name, av::TenantId owner,
                                            av::TenantGeneration owner_generation,
                                            av::ResourceContract contract);
  av::VirtualAcceleratorRecord make_virtual_with_backing(const std::string& name, av::TenantId owner,
                                                         av::TenantGeneration owner_generation,
                                                         av::ResourceContract contract, av::BackingId backing);

  av::Authority for_virtual(const av::VirtualAcceleratorRecord& record, av::TenantId tenant,
                            av::TenantGeneration tenant_generation) const;
  av::Authority for_lease(const av::VirtualAcceleratorRecord& record, const av::LeaseRecord& lease,
                          av::TenantId tenant, av::TenantGeneration tenant_generation) const;

  std::string scratch() const;

 private:
  std::unique_ptr<av::VirtualizationRuntime> runtime_;
  std::shared_ptr<av::ManualClock> clock_;
  av::AgentId agent_{};
  av::AgentBootId boot_{};
  std::vector<std::unique_ptr<av::BackendAdapter>> adapters_;
  std::string scratch_root_;
};

// A resource contract that is satisfiable by the synthetic and CUDA backings.
av::ResourceContract permissive_contract(std::uint64_t memory_bytes = 64ull * 1024ull * 1024ull);

// Deterministic pseudo-random generator: reproducible seeds, no library
// randomness anywhere in the test suite.
class Random {
 public:
  explicit Random(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}
  std::uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }
  std::uint32_t below(std::uint32_t bound) { return bound == 0 ? 0 : static_cast<std::uint32_t>(next() % bound); }
  bool chance(std::uint32_t percent) { return below(100) < percent; }

 private:
  std::uint64_t state_;
};

}  // namespace avtest
