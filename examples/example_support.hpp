// Accelerator Virtualization - shared example helpers.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "av/runtime.hpp"
#include "av/synthetic.hpp"

namespace avexample {

inline void say(const std::string& line) {
  std::printf("%s\n", line.c_str());
  std::fflush(stdout);
}

inline void fail(const std::string& message) {
  std::fprintf(stderr, "example failed: %s\n", message.c_str());
  std::fflush(stderr);
  std::exit(1);
}

inline void require(const av::Status& status) {
  if (!status.ok()) fail(status.to_string());
}

template <class T>
inline void require(const av::Result<T>& result) {
  if (!result.ok()) fail(result.status().to_string());
}

// Uniform extraction of an outcome from a Status or a Result<T>.
inline av::Status status_of(const av::Status& status) { return status; }
template <class T>
inline av::Status status_of(const av::Result<T>& result) {
  return result.status();
}
inline std::string describe(const av::Status& status) { return status.to_string(); }
template <class T>
inline std::string describe(const av::Result<T>& result) {
  return result.status().to_string();
}

template <class T>
inline T take(const av::Result<T>& result) {
  if (!result.ok()) fail(result.status().to_string());
  return result.value();
}

struct Runtime {
  std::unique_ptr<av::VirtualizationRuntime> instance;
  av::AgentId agent{};
  av::AgentBootId boot{};
  std::vector<std::unique_ptr<av::BackendAdapter>> adapters;
};

inline std::unique_ptr<Runtime> make_runtime(const std::string& state_directory = {}) {
  av::RuntimeOptions options;
  options.name = "example";
  av::StoreOptions store_options;
  store_options.directory = state_directory;
  store_options.enabled = !state_directory.empty();
  auto created = av::make_runtime(options, store_options, nullptr);
  if (!created.ok()) fail(created.status().to_string());
  auto runtime = std::make_unique<Runtime>();
  runtime->instance = created.take();
  runtime->adapters = av::make_synthetic_backends();
  auto session = runtime->instance->register_agent("example-agent", "in-process", 1, av::AgentId{});
  if (!session.ok()) fail(session.status().to_string());
  runtime->agent = session->id;
  runtime->boot = session->boot;
  return runtime;
}

inline av::PhysicalDeviceRecord register_device(Runtime& runtime, const std::string& adapter_name) {
  for (const auto& adapter : runtime.adapters) {
    if (adapter->name() != adapter_name) continue;
    auto found = adapter->discover();
    if (!found.ok()) fail(found.status().to_string());
    auto record = runtime.instance->register_physical(runtime.instance->current_authority(), runtime.agent,
                                                      runtime.boot, found->front());
    return take(record);
  }
  fail("adapter '" + adapter_name + "' is not available");
  return {};
}

inline av::ResourceContract contract(std::uint64_t memory_bytes, std::uint32_t share_milli = 500) {
  av::ResourceContract value;
  value.memory_ceiling_bytes = memory_bytes;
  value.compute_share_milli = share_milli;
  value.max_streams = 8;
  value.migration_allowed = true;
  value.allowed_migration_classes = {av::MigrationClass::RebindOnly, av::MigrationClass::DrainAndRestart};
  value.normalize();
  return value;
}

inline std::vector<av::BackingRecord> backings_of(av::VirtualizationRuntime& runtime,
                                                  av::PhysicalDeviceId device) {
  std::vector<av::BackingRecord> out;
  for (const av::BackingRecord& backing : runtime.list_backings()) {
    if (backing.physical == device) out.push_back(backing);
  }
  return out;
}

inline av::Authority authority_for(av::VirtualizationRuntime& runtime, const av::VirtualAcceleratorRecord& record,
                                   av::TenantId tenant, av::TenantGeneration generation) {
  av::Authority authority = runtime.current_authority();
  authority.tenant = tenant;
  authority.tenant_generation = generation;
  authority.virtual_id = record.id;
  authority.virtual_generation = record.generation;
  return authority;
}

}  // namespace avexample
