// Accelerator Virtualization - shared test fixtures.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "support.hpp"

#include <chrono>
#include <filesystem>

namespace avtest {

Fixture::Fixture(bool persist, std::size_t deferred_threshold) {
  clock_ = std::make_shared<av::ManualClock>();
  av::RuntimeOptions options;
  options.name = "test-coordinator";
  options.persist = true;  // the durable path is exercised even with a memory store
  options.deferred_persistence = deferred_threshold > 0;
  options.deferred_threshold = deferred_threshold > 0 ? deferred_threshold : 256;

  av::StoreOptions store_options;
  if (persist) {
    std::error_code ec;
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    scratch_root_ =
        (std::filesystem::temp_directory_path(ec) / ("av-fixture-" + std::to_string(unique))).string();
    std::filesystem::remove_all(scratch_root_, ec);
    std::filesystem::create_directories(scratch_root_, ec);
    store_options.directory = scratch_root_;
    store_options.enabled = true;
  }
  auto created = av::make_runtime(options, store_options, clock_);
  if (!created.ok()) {
    throw std::runtime_error("fixture failed to start: " + created.status().to_string());
  }
  runtime_ = created.take();
  adapters_ = av::make_synthetic_backends();
}

Fixture::~Fixture() {
  if (!scratch_root_.empty()) {
    std::error_code ec;
    std::filesystem::remove_all(scratch_root_, ec);
  }
}

av::Authority Fixture::epoch_only() const { return runtime_->current_authority(); }

std::string Fixture::scratch() const { return scratch_root_; }

void Fixture::attach_agent(const std::string& name) {
  auto session = runtime_->register_agent(name, "in-process", 1, av::AgentId{});
  if (!session.ok()) throw avtest::Failure("register_agent failed: " + session.status().to_string());
  agent_ = session->id;
  boot_ = session->boot;
}

av::PhysicalDeviceRecord Fixture::register_descriptor(const av::PhysicalDeviceDescriptor& descriptor) {
  auto record = runtime_->register_physical(runtime_->current_authority(), agent_, boot_, descriptor);
  if (!record.ok()) throw avtest::Failure("register_physical failed: " + record.status().to_string());
  return record.take();
}

av::PhysicalDeviceRecord Fixture::register_synthetic(const std::string& adapter_name) {
  for (const auto& adapter : adapters_) {
    if (adapter->name() != adapter_name) continue;
    auto found = adapter->discover();
    if (!found.ok()) throw avtest::Failure("synthetic discovery failed");
    if (found->empty()) throw avtest::Failure("synthetic adapter offered no device");
    return register_descriptor(found->front());
  }
  throw avtest::Failure("synthetic adapter '" + adapter_name + "' is not available");
}

std::vector<av::BackingRecord> Fixture::backings_of(av::PhysicalDeviceId device) const {
  std::vector<av::BackingRecord> out;
  for (const av::BackingRecord& backing : runtime_->list_backings()) {
    if (backing.physical == device) out.push_back(backing);
  }
  return out;
}

av::BackingRecord Fixture::backing_by_label(av::PhysicalDeviceId device, const std::string& label) const {
  for (const av::BackingRecord& backing : backings_of(device)) {
    if (backing.label == label) return backing;
  }
  throw avtest::Failure("backing '" + label + "' not found on device " + device.str());
}

av::TenantRecord Fixture::make_tenant(const std::string& name) {
  auto record = runtime_->create_tenant(runtime_->current_authority(), name, "subject:" + name);
  if (!record.ok()) throw avtest::Failure("create_tenant failed: " + record.status().to_string());
  return record.take();
}

av::VirtualAcceleratorRecord Fixture::make_virtual(const std::string& name, av::TenantId owner,
                                                   av::TenantGeneration owner_generation,
                                                   av::ResourceContract contract) {
  auto record =
      runtime_->create_virtual(runtime_->current_authority(), name, owner, owner_generation, contract);
  if (!record.ok()) throw avtest::Failure("create_virtual failed: " + record.status().to_string());
  return record.take();
}

av::VirtualAcceleratorRecord Fixture::make_virtual_with_backing(const std::string& name, av::TenantId owner,
                                                                av::TenantGeneration owner_generation,
                                                                av::ResourceContract contract,
                                                                av::BackingId backing) {
  av::VirtualAcceleratorRecord record = make_virtual(name, owner, owner_generation, contract);
  auto authority = for_virtual(record, owner, owner_generation);
  auto assigned = runtime_->assign_backing(authority, backing, "fixture");
  if (!assigned.ok()) throw avtest::Failure("assign_backing failed: " + assigned.status().to_string());
  auto refreshed = runtime_->raw_virtual(record.id);
  if (!refreshed.ok()) throw avtest::Failure("raw_virtual failed after assignment");
  return refreshed.take();
}

av::Authority Fixture::for_virtual(const av::VirtualAcceleratorRecord& record, av::TenantId tenant,
                                   av::TenantGeneration tenant_generation) const {
  av::Authority authority = runtime_->current_authority();
  authority.tenant = tenant;
  authority.tenant_generation = tenant_generation;
  authority.virtual_id = record.id;
  authority.virtual_generation = record.generation;
  return authority;
}

av::Authority Fixture::for_lease(const av::VirtualAcceleratorRecord& record, const av::LeaseRecord& lease,
                                 av::TenantId tenant, av::TenantGeneration tenant_generation) const {
  av::Authority authority = for_virtual(record, tenant, tenant_generation);
  authority.lease = lease.id;
  authority.lease_generation = lease.generation;
  return authority;
}

av::ResourceContract permissive_contract(std::uint64_t memory_bytes) {
  av::ResourceContract contract;
  contract.memory_ceiling_bytes = memory_bytes;
  contract.compute_share_milli = 1000;
  contract.max_streams = 16;
  contract.max_concurrency = 4;
  contract.migration_allowed = true;
  contract.allowed_migration_classes = {av::MigrationClass::RebindOnly, av::MigrationClass::DrainAndRestart};
  contract.normalize();
  return contract;
}

}  // namespace avtest
