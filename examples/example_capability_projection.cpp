// Example: a virtual capability surface that is smaller than the physical one.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "example_support.hpp"

int main() {
  using namespace avexample;

  say("== project a constrained capability surface ==");
  auto runtime = make_runtime();
  const av::PhysicalDeviceRecord device = register_device(*runtime, "synthetic-hardware-partition");
  const av::BackingRecord backing = backings_of(*runtime->instance, device.id).front();
  const av::TenantRecord tenant =
      take(runtime->instance->create_tenant(runtime->instance->current_authority(), "tenant-a", ""));

  // The policy withholds one capability from every virtual accelerator.
  av::VirtualizationPolicy policy = runtime->instance->policy();
  policy.forbidden_capabilities.push_back(av::CapabilityKey::PrecisionFp64);
  require(take(runtime->instance->set_policy(runtime->instance->current_authority(), policy)).validate());

  av::ResourceContract contract = avexample::contract(2u << 20, 250);
  contract.max_streams = 4;
  const av::VirtualAcceleratorRecord record = take(runtime->instance->create_virtual(
      runtime->instance->current_authority(), "va-caps", tenant.id, tenant.generation, contract));

  say("virtual " + record.id.str() + " projection generation " + record.projection.generation.str());
  say("-- advertised surface --");
  std::printf("%s", record.projection.surface.canonical().c_str());
  say("-- withheld by policy --");
  for (av::CapabilityKey key : record.projection.hidden) {
    say("hidden " + std::string(av::capability_key_name(key)));
  }
  say("-- unprovable and therefore UNKNOWN --");
  for (av::CapabilityKey key : record.projection.unknown) {
    say("unknown " + std::string(av::capability_key_name(key)));
  }
  say("fingerprint " + std::to_string(record.projection.fingerprint));

  say("== the same policy never upgrades an unknown into a supported capability ==");
  const av::CapabilityEntry* unproven = record.projection.surface.find(av::CapabilityKey::MemoryTotalBytes);
  say(std::string("MEMORY_TOTAL_BYTES verdict: ") +
      std::string(unproven != nullptr ? av::capability_verdict_name(unproven->verdict) : "absent"));
  (void)backing;
  return 0;
}
