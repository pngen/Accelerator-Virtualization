// Accelerator Virtualization - real multiprocess proof.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every case here starts real operating-system processes: the coordinator and
// the agent are separate executables communicating over TCP loopback. No
// thread is substituted for a process claim.
#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "av/client.hpp"
#include "av/persistence.hpp"
#include "av/socket.hpp"
#include "process.hpp"
#include "support.hpp"

namespace {

using av::Byte;
using av::ByteSpan;
using av::FieldReader;
using av::FieldWriter;
using av::StatusCode;
using av::Status;

struct Stack {
  avtest::ScratchDirectory scratch;
  avtest::ChildProcess coordinator;
  avtest::ChildProcess agent;
  std::uint16_t port{0};
  av::ControlClient client;

  explicit Stack(const std::string& label) : scratch(label) {}

  void start_coordinator(const std::vector<std::string>& extra = {}) {
    std::vector<std::string> arguments = {"--port", "0", "--state-dir", scratch.file("state"), "--name",
                                          "multiprocess"};
    arguments.insert(arguments.end(), extra.begin(), extra.end());
    auto spawned = avtest::ChildProcess::spawn(avtest::sibling_executable("av_coordinator"), arguments);
    if (!spawned.ok()) throw avtest::Failure("spawning the coordinator failed: " + spawned.status().to_string());
    coordinator = spawned.take();
    if (!coordinator.wait_for("AV_COORDINATOR READY", 30000)) {
      throw avtest::Failure("the coordinator did not become ready: " + coordinator.output());
    }
    const std::string marker = "port=";
    const std::size_t position = coordinator.output().find(marker);
    if (position == std::string::npos) throw avtest::Failure("no port in the coordinator banner");
    port = static_cast<std::uint16_t>(std::stoul(coordinator.output().substr(position + marker.size())));
  }

  void start_agent(const std::string& name = "agent") {
    auto spawned = avtest::ChildProcess::spawn(
        avtest::sibling_executable("av_agent"),
        {"--coordinator", "127.0.0.1:" + std::to_string(port), "--name", name, "--backends", "synthetic,cuda"});
    if (!spawned.ok()) throw avtest::Failure("spawning the agent failed: " + spawned.status().to_string());
    agent = spawned.take();
    if (!agent.wait_for("AV_AGENT READY", 60000)) {
      throw avtest::Failure("the agent did not become ready: " + agent.output());
    }
  }

  void connect(const std::string& name = "harness", av::Role role = av::Role::Client) {
    av::ClientOptions options;
    options.host = "127.0.0.1";
    options.port = port;
    options.name = name;
    options.role = role;
    auto connected = av::ControlClient::connect(options);
    if (!connected.ok()) throw avtest::Failure("connecting failed: " + connected.status().to_string());
    client = connected.take();
  }

  static void require(const av::Result<FieldReader>& result) {
    if (!result.ok()) throw avtest::Failure("call failed: " + result.status().to_string());
  }

  static Status expect_failure(const av::Result<FieldReader>& result, StatusCode code) {
    if (result.ok()) return Status(StatusCode::Internal, "expected a failure but the call succeeded");
    if (result.status().code() != code) {
      return Status(StatusCode::Internal, "expected " + std::string(av::code_name(code)) + " but got " +
                                              result.status().to_string());
    }
    return Status{};
  }

  av::Result<FieldReader> call(av::MessageType type, const FieldWriter& fields) {
    return client.call(type, fields);
  }

  void stop_agent() {
    if (agent.running()) {
      agent.kill();
      agent.wait();
    }
  }

  void shutdown() {
    if (client.open()) {
      FieldWriter fields;
      auto response = client.call(av::MessageType::Shutdown, fields);
      (void)response;
      client.close();
    }
    if (coordinator.running()) {
      if (!coordinator.wait_for("AV_COORDINATOR STOPPED", 15000)) coordinator.kill();
      coordinator.wait();
    }
    stop_agent();
  }

  ~Stack() { stop_agent(); }
};

av::VirtualAcceleratorId create_virtual(Stack& stack, const std::string& name, std::uint64_t tenant,
                                        std::uint64_t memory_bytes) {
  av::ResourceContract contract = avtest::permissive_contract(memory_bytes);
  const std::vector<Byte> blob = av::encode_contract_blob(contract);
  FieldWriter fields;
  fields.str(av::kFieldVirtualName, name);
  fields.u64(av::kFieldTenantId, tenant);
  fields.u64(av::kFieldTenantGeneration, 1);
  fields.bytes(av::kFieldContractBlob, ByteSpan{blob.data(), blob.size()});
  auto response = stack.call(av::MessageType::CreateVirtual, fields);
  Stack::require(response);
  return av::VirtualAcceleratorId::from_value(response->u64(av::kFieldVirtualId).value_or(0));
}

struct Remote {
  av::VirtualAcceleratorId id{};
  std::uint64_t generation{0};
  std::uint64_t backing_generation{0};
  av::BackingId backing{};
  av::VirtualLifecycleState state{av::VirtualLifecycleState::Created};
};

Remote fetch(Stack& stack, av::VirtualAcceleratorId id) {
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, id.value());
  auto response = stack.call(av::MessageType::Query, fields);
  Stack::require(response);
  auto blob = response->bytes(av::kFieldViewBlob);
  if (!blob.has_value()) throw avtest::Failure("no view was returned");
  auto view = av::decode_view(*blob);
  if (!view.ok()) throw avtest::Failure("view decode failed: " + view.status().to_string());
  Remote remote;
  remote.id = view->id;
  remote.generation = view->generation.value();
  remote.backing_generation = view->backing_generation.value();
  remote.backing = view->backing;
  remote.state = view->state;
  return remote;
}

std::vector<av::BackingRecord> list_backings(Stack& stack) {
  FieldWriter fields;
  auto response = stack.call(av::MessageType::ListBackings, fields);
  Stack::require(response);
  std::vector<av::BackingRecord> out;
  for (const auto& entry : response->nested_list(av::kFieldBlobs)) {
    if (!entry.ok()) continue;
    auto blob = entry->bytes(av::kFieldBackingBlob);
    if (!blob.has_value()) continue;
    auto record = av::decode_backing_record(*blob);
    if (record.ok()) out.push_back(record.take());
  }
  return out;
}

av::BackingRecord find_backing(const std::vector<av::BackingRecord>& backings, av::Provenance provenance,
                               av::BackingClass klass) {
  for (const av::BackingRecord& backing : backings) {
    if (backing.provenance == provenance && backing.klass == klass) return backing;
  }
  return av::BackingRecord{};
}

std::uint64_t create_tenant(Stack& stack, const std::string& name) {
  FieldWriter fields;
  fields.str(av::kFieldTenantName, name);
  auto response = stack.call(av::MessageType::CreateTenant, fields);
  Stack::require(response);
  return response->u64(av::kFieldTenantId).value_or(0);
}

}  // namespace

AV_TEST(multiprocess, lifecycle_tenancy_and_backing_replacement) {
  AV_PHASE("SETUP");
  Stack stack("lifecycle");
  stack.start_coordinator({"--transparency", "FULL"});
  stack.start_agent();
  stack.connect();
  AV_NOTE("coordinator_port=" + std::to_string(stack.port));

  AV_PHASE("REGISTER");
  const std::vector<av::BackingRecord> backings = list_backings(stack);
  AV_REQUIRE(backings.size() >= 4);
  const av::BackingRecord source =
      find_backing(backings, av::Provenance::Synthetic, av::BackingClass::SyntheticMigratable);
  AV_REQUIRE(source.id.valid());

  AV_PHASE("CREATE");
  const std::uint64_t a = create_tenant(stack, "tenant-a");
  const std::uint64_t b = create_tenant(stack, "tenant-b");
  AV_REQUIRE(a != b);
  const av::VirtualAcceleratorId virtual_id = create_virtual(stack, "va-a", a, 1u << 20);
  AV_REQUIRE(virtual_id.valid());

  FieldWriter assign;
  assign.u64(av::kFieldVirtualId, virtual_id.value());
  assign.u64(av::kFieldVirtualGeneration, 1);
  assign.u64(av::kFieldTenantId, a);
  assign.u64(av::kFieldTenantGeneration, 1);
  assign.u64(av::kFieldBackingId, source.id.value());
  auto assigned = stack.call(av::MessageType::AssignBacking, assign);
  Stack::require(assigned);
  AV_EQUAL(assigned->u64(av::kFieldBackingGeneration).value_or(0), 1ull);
  const std::uint64_t after_assign = assigned->u64(av::kFieldVirtualGeneration).value_or(0);

  AV_PHASE("ATTACH");
  FieldWriter attach;
  attach.u64(av::kFieldVirtualId, virtual_id.value());
  attach.u64(av::kFieldVirtualGeneration, after_assign);
  attach.u64(av::kFieldTenantId, a);
  attach.u64(av::kFieldTenantGeneration, 1);
  auto lease = stack.call(av::MessageType::Attach, attach);
  Stack::require(lease);
  const std::uint64_t lease_id = lease->u64(av::kFieldLeaseId).value_or(0);
  const std::uint64_t lease_generation = lease->u64(av::kFieldLeaseGeneration).value_or(0);
  const std::uint64_t after_attach = lease->u64(av::kFieldVirtualGeneration).value_or(0);
  AV_REQUIRE(lease_id != 0);

  AV_PHASE("VERIFY");
  Remote record = fetch(stack, virtual_id);
  AV_EQUAL(record.id.value(), virtual_id.value());

  // Tenant B must not be able to mutate or use tenant A's virtual accelerator.
  FieldWriter intruder;
  intruder.u64(av::kFieldVirtualId, virtual_id.value());
  intruder.u64(av::kFieldVirtualGeneration, after_attach);
  intruder.u64(av::kFieldTenantId, b);
  intruder.u64(av::kFieldTenantGeneration, 1);
  AV_OK(Stack::expect_failure(stack.call(av::MessageType::Detach, intruder), StatusCode::NotAuthorized));
  AV_OK(Stack::expect_failure(stack.call(av::MessageType::DrainVirtual, intruder), StatusCode::NotAuthorized));

  FieldWriter stale = attach;
  stale.u64(av::kFieldVirtualGeneration, after_assign);
  AV_OK(Stack::expect_failure(stack.call(av::MessageType::Attach, stale), StatusCode::StaleVirtualGeneration));

  AV_PHASE("MIGRATE");
  const av::BackingRecord destination =
      find_backing(backings, av::Provenance::Synthetic, av::BackingClass::SyntheticHardwarePartition);
  AV_REQUIRE(destination.id.valid());
  FieldWriter replace;
  replace.u64(av::kFieldVirtualId, virtual_id.value());
  replace.u64(av::kFieldVirtualGeneration, after_attach);
  replace.u64(av::kFieldTenantId, a);
  replace.u64(av::kFieldTenantGeneration, 1);
  replace.u64(av::kFieldBackingId, destination.id.value());
  replace.str(av::kFieldReason, "replacement proof");
  auto replaced = stack.call(av::MessageType::ReplaceBacking, replace);
  Stack::require(replaced);
  AV_EQUAL(replaced->u64(av::kFieldBackingGeneration).value_or(0), 2ull);

  AV_PHASE("VERIFY");
  const Remote after = fetch(stack, virtual_id);
  AV_EQUAL(after.id.value(), virtual_id.value());
  AV_EQUAL(after.backing_generation, 2ull);
  AV_REQUIRE(after.backing == destination.id);

  // The lease granted before the replacement must be stale now.
  FieldWriter revoke;
  revoke.u64(av::kFieldVirtualId, virtual_id.value());
  revoke.u64(av::kFieldVirtualGeneration, after.generation);
  revoke.u64(av::kFieldTenantId, a);
  revoke.u64(av::kFieldTenantGeneration, 1);
  revoke.u64(av::kFieldLeaseId, lease_id);
  revoke.u64(av::kFieldLeaseGeneration, lease_generation);
  auto stale_lease = stack.call(av::MessageType::Revoke, revoke);
  AV_REQUIRE_MSG(!stale_lease.ok(), "a lease granted before the replacement was still accepted");
  AV_REQUIRE_MSG(stale_lease.status().code() == StatusCode::StaleLease ||
                     stale_lease.status().code() == StatusCode::LeaseRevoked ||
                     stale_lease.status().code() == StatusCode::StaleVirtualGeneration,
                 "unexpected refusal code: " + stale_lease.status().to_string());

  FieldWriter audit;
  auto report = stack.call(av::MessageType::Audit, audit);
  Stack::require(report);
  AV_REQUIRE_MSG(report->boolean(av::kFieldClean).value_or(false), report->str(av::kFieldText).value_or(""));
  AV_EQUAL(report->u64(av::kFieldViolationCount).value_or(99), 0ull);

  AV_PHASE("SHUTDOWN");
  stack.shutdown();
}

AV_TEST(multiprocess, agent_kill_and_restart_under_a_fresh_boot) {
  AV_PHASE("SETUP");
  Stack stack("agentkill");
  stack.start_coordinator();
  stack.start_agent("first-agent");
  stack.connect();

  AV_PHASE("REGISTER");
  const std::vector<av::BackingRecord> backings = list_backings(stack);
  AV_REQUIRE(!backings.empty());

  AV_PHASE("KILL");
  stack.stop_agent();
  AV_REQUIRE(!stack.agent.running());

  AV_PHASE("RESTART");
  stack.start_agent("first-agent");

  AV_PHASE("VERIFY");
  FieldWriter audit;
  auto report = stack.call(av::MessageType::Audit, audit);
  Stack::require(report);
  AV_REQUIRE(report->boolean(av::kFieldClean).value_or(false));

  AV_PHASE("SHUTDOWN");
  stack.shutdown();
}

AV_TEST(multiprocess, coordinator_restart_advances_epoch_and_restores_identity) {
  AV_PHASE("SETUP");
  Stack stack("restart");
  stack.start_coordinator();
  stack.start_agent();
  stack.connect();

  AV_PHASE("CREATE");
  const std::uint64_t tenant_id = create_tenant(stack, "tenant-a");
  const av::VirtualAcceleratorId virtual_id = create_virtual(stack, "va-a", tenant_id, 1u << 20);
  const std::vector<av::BackingRecord> backings = list_backings(stack);
  const av::BackingRecord source =
      find_backing(backings, av::Provenance::Synthetic, av::BackingClass::SyntheticMigratable);
  AV_REQUIRE(source.id.valid());

  FieldWriter assign;
  assign.u64(av::kFieldVirtualId, virtual_id.value());
  assign.u64(av::kFieldVirtualGeneration, 1);
  assign.u64(av::kFieldTenantId, tenant_id);
  assign.u64(av::kFieldTenantGeneration, 1);
  assign.u64(av::kFieldBackingId, source.id.value());
  auto assigned = stack.call(av::MessageType::AssignBacking, assign);
  Stack::require(assigned);
  const std::uint64_t generation = assigned->u64(av::kFieldVirtualGeneration).value_or(0);

  FieldWriter attach;
  attach.u64(av::kFieldVirtualId, virtual_id.value());
  attach.u64(av::kFieldVirtualGeneration, generation);
  attach.u64(av::kFieldTenantId, tenant_id);
  attach.u64(av::kFieldTenantGeneration, 1);
  auto lease = stack.call(av::MessageType::Attach, attach);
  Stack::require(lease);
  const std::uint64_t lease_id = lease->u64(av::kFieldLeaseId).value_or(0);
  const std::uint64_t lease_generation = lease->u64(av::kFieldLeaseGeneration).value_or(0);
  const std::uint64_t after_attach = lease->u64(av::kFieldVirtualGeneration).value_or(0);
  const std::uint64_t epoch_before = stack.client.epoch().value();

  AV_PHASE("SHUTDOWN");
  FieldWriter down;
  auto stopped = stack.call(av::MessageType::Shutdown, down);
  Stack::require(stopped);
  stack.client.close();
  AV_REQUIRE(stack.coordinator.wait_for("AV_COORDINATOR STOPPED", 15000));
  stack.coordinator.wait();

  AV_PHASE("RESTART");
  stack.start_coordinator();
  stack.start_agent("second-agent");
  stack.connect();

  AV_PHASE("RECOVER");
  const std::uint64_t epoch_after = stack.client.epoch().value();
  AV_REQUIRE(epoch_after > epoch_before);
  const Remote record = fetch(stack, virtual_id);
  AV_EQUAL(record.id.value(), virtual_id.value());
  AV_EQUAL(record.state, av::VirtualLifecycleState::Provisioned);

  FieldWriter stale;
  stale.u64(av::kFieldVirtualId, virtual_id.value());
  stale.u64(av::kFieldVirtualGeneration, after_attach);
  stale.u64(av::kFieldTenantId, tenant_id);
  stale.u64(av::kFieldTenantGeneration, 1);
  stale.u64(av::kFieldLeaseId, lease_id);
  stale.u64(av::kFieldLeaseGeneration, lease_generation);
  auto refused = stack.call(av::MessageType::Detach, stale);
  AV_REQUIRE_MSG(!refused.ok(), "a pre-restart authority was accepted after the restart");
  AV_REQUIRE_MSG(refused.status().code() == StatusCode::StaleEpoch ||
                     refused.status().code() == StatusCode::StaleVirtualGeneration ||
                     refused.status().code() == StatusCode::LeaseExpired ||
                     refused.status().code() == StatusCode::StaleLease,
                 "unexpected refusal code: " + refused.status().to_string());

  AV_PHASE("VERIFY");
  FieldWriter audit;
  auto report = stack.call(av::MessageType::Audit, audit);
  Stack::require(report);
  AV_REQUIRE_MSG(report->boolean(av::kFieldClean).value_or(false), report->str(av::kFieldText).value_or(""));

  AV_PHASE("SHUTDOWN");
  stack.shutdown();
}

AV_TEST(multiprocess, real_accelerator_backing_executes_and_multiplexes) {
  AV_PHASE("SETUP");
  Stack stack("cuda");
  stack.start_coordinator({"--transparency", "FULL"});
  stack.start_agent("cuda-agent");
  stack.connect();

  AV_PHASE("REGISTER");
  const std::vector<av::BackingRecord> backings = list_backings(stack);
  const av::BackingRecord dedicated =
      find_backing(backings, av::Provenance::Real, av::BackingClass::DedicatedPhysical);
  const av::BackingRecord shared =
      find_backing(backings, av::Provenance::Real, av::BackingClass::CooperativeShared);
  if (!dedicated.id.valid() || !shared.id.valid()) {
    stack.shutdown();
    AV_SKIP("no real accelerator is present on this host, so the CUDA path cannot be exercised");
  }

  AV_PHASE("CREATE");
  const std::uint64_t tenant_id = create_tenant(stack, "cuda-tenant");
  const av::VirtualAcceleratorId first = create_virtual(stack, "cuda-va-1", tenant_id, 8u << 20);
  const av::VirtualAcceleratorId second = create_virtual(stack, "cuda-va-2", tenant_id, 8u << 20);
  AV_REQUIRE(!(first == second));

  AV_PHASE("ASSIGN");
  auto assign_virtual = [&stack, tenant_id](av::VirtualAcceleratorId id, av::BackingId backing,
                                            std::uint64_t generation) {
    FieldWriter assign;
    assign.u64(av::kFieldVirtualId, id.value());
    assign.u64(av::kFieldVirtualGeneration, generation);
    assign.u64(av::kFieldTenantId, tenant_id);
    assign.u64(av::kFieldTenantGeneration, 1);
    assign.u64(av::kFieldBackingId, backing.value());
    return stack.call(av::MessageType::AssignBacking, assign);
  };
  auto first_assign = assign_virtual(first, dedicated.id, 1);
  Stack::require(first_assign);
  auto second_assign = assign_virtual(second, shared.id, 1);
  Stack::require(second_assign);

  AV_PHASE("ATTACH");
  auto attach_virtual = [&stack, tenant_id](av::VirtualAcceleratorId id, std::uint64_t generation) {
    FieldWriter attach;
    attach.u64(av::kFieldVirtualId, id.value());
    attach.u64(av::kFieldVirtualGeneration, generation);
    attach.u64(av::kFieldTenantId, tenant_id);
    attach.u64(av::kFieldTenantGeneration, 1);
    return stack.call(av::MessageType::Attach, attach);
  };
  auto first_lease = attach_virtual(first, first_assign->u64(av::kFieldVirtualGeneration).value_or(0));
  Stack::require(first_lease);
  auto second_lease = attach_virtual(second, second_assign->u64(av::kFieldVirtualGeneration).value_or(0));
  Stack::require(second_lease);

  struct Target {
    av::VirtualAcceleratorId id;
    std::uint64_t generation;
    std::uint64_t lease;
    std::uint64_t lease_generation;
  };
  const Target one{first, first_lease->u64(av::kFieldVirtualGeneration).value_or(0),
                   first_lease->u64(av::kFieldLeaseId).value_or(0),
                   first_lease->u64(av::kFieldLeaseGeneration).value_or(0)};
  const Target two{second, second_lease->u64(av::kFieldVirtualGeneration).value_or(0),
                   second_lease->u64(av::kFieldLeaseId).value_or(0),
                   second_lease->u64(av::kFieldLeaseGeneration).value_or(0)};

  auto execute = [&stack, tenant_id](const Target& target, av::ExecutionOp op, std::uint64_t bytes,
                                     std::uint64_t handle, std::uint32_t count,
                                     const std::vector<std::uint64_t>& handles,
                                     const std::vector<std::uint8_t>& data) {
    FieldWriter fields;
    fields.u64(av::kFieldOp, static_cast<std::uint64_t>(op));
    fields.u64(av::kFieldEpoch, stack.client.epoch().value());
    fields.u64(av::kFieldVirtualId, target.id.value());
    fields.u64(av::kFieldVirtualGeneration, target.generation);
    fields.u64(av::kFieldTenantId, tenant_id);
    fields.u64(av::kFieldTenantGeneration, 1);
    fields.u64(av::kFieldLeaseId, target.lease);
    fields.u64(av::kFieldLeaseGeneration, target.lease_generation);
    fields.u64(av::kFieldBytes, bytes);
    fields.u64(av::kFieldHandle, handle);
    fields.u64(av::kFieldCount, count);
    fields.list_u64(av::kFieldHandles, handles);
    if (!data.empty()) fields.bytes(av::kFieldData, av::byte_span(data));
    return stack.call(av::MessageType::Execute, fields);
  };

  AV_PHASE("EXECUTE");
  constexpr std::uint32_t kElements = 4096;
  const std::uint64_t buffer_bytes = static_cast<std::uint64_t>(kElements) * sizeof(float);
  auto info = execute(one, av::ExecutionOp::DeviceInfo, 0, 0, 0, {}, {});
  Stack::require(info);
  AV_REQUIRE(info->u64(av::kFieldDeviceMemoryTotal).value_or(0) > 0);

  auto allocate = [&execute](const Target& target, std::uint64_t bytes) {
    auto response = execute(target, av::ExecutionOp::Allocate, bytes, 0, 0, {}, {});
    if (!response.ok()) throw avtest::Failure("allocate failed: " + response.status().to_string());
    return response->u64(av::kFieldHandle).value_or(0);
  };
  const std::uint64_t handle_a = allocate(one, buffer_bytes);
  const std::uint64_t handle_b = allocate(one, buffer_bytes);
  const std::uint64_t handle_c = allocate(one, buffer_bytes);
  AV_REQUIRE(handle_a != 0 && handle_b != 0 && handle_c != 0);

  std::vector<std::uint8_t> host_a(buffer_bytes);
  std::vector<std::uint8_t> host_b(buffer_bytes);
  auto* floats_a = reinterpret_cast<float*>(host_a.data());
  auto* floats_b = reinterpret_cast<float*>(host_b.data());
  for (std::uint32_t index = 0; index < kElements; ++index) {
    floats_a[index] = static_cast<float>(index);
    floats_b[index] = static_cast<float>(2 * index);
  }
  Stack::require(execute(one, av::ExecutionOp::Upload, 0, handle_a, 0, {}, host_a));
  Stack::require(execute(one, av::ExecutionOp::Upload, 0, handle_b, 0, {}, host_b));
  Stack::require(
      execute(one, av::ExecutionOp::KernelVectorAdd, 0, 0, kElements, {handle_a, handle_b, handle_c}, {}));

  std::vector<std::uint8_t> requested(buffer_bytes);
  auto downloaded = execute(one, av::ExecutionOp::Download, 0, handle_c, 0, {}, requested);
  Stack::require(downloaded);
  auto payload = downloaded->bytes(av::kFieldData);
  AV_REQUIRE(payload.has_value());
  AV_EQUAL(payload->size(), static_cast<std::size_t>(buffer_bytes));
  const auto* floats_c = reinterpret_cast<const float*>(payload->data());
  std::uint64_t mismatches = 0;
  for (std::uint32_t index = 0; index < kElements; ++index) {
    if (floats_c[index] != floats_a[index] + floats_b[index]) ++mismatches;
  }
  AV_EQUAL(mismatches, 0ull);

  AV_PHASE("VERIFY");
  auto over = execute(one, av::ExecutionOp::Allocate, 64u << 20, 0, 0, {}, {});
  AV_REQUIRE(!over.ok());
  AV_EQUAL(over.status().code(), StatusCode::ContractViolation);

  auto other_info = execute(two, av::ExecutionOp::DeviceInfo, 0, 0, 0, {}, {});
  Stack::require(other_info);
  AV_REQUIRE(other_info->u64(av::kFieldDeviceMemoryTotal).value_or(0) > 0);

  FieldWriter cross;
  cross.u64(av::kFieldVirtualId, first.value());
  cross.u64(av::kFieldVirtualGeneration, one.generation);
  cross.u64(av::kFieldTenantId, tenant_id);
  cross.u64(av::kFieldTenantGeneration, 1);
  cross.u64(av::kFieldLeaseId, two.lease);
  cross.u64(av::kFieldLeaseGeneration, two.lease_generation);
  auto cross_revoke = stack.call(av::MessageType::Revoke, cross);
  AV_REQUIRE(!cross_revoke.ok());

  AV_PHASE("EXECUTE");
  Stack::require(execute(one, av::ExecutionOp::Free, buffer_bytes, handle_a, 0, {}, {}));
  Stack::require(execute(one, av::ExecutionOp::Free, buffer_bytes, handle_b, 0, {}, {}));
  Stack::require(execute(one, av::ExecutionOp::Free, buffer_bytes, handle_c, 0, {}, {}));

  AV_PHASE("VERIFY");
  FieldWriter audit;
  auto report = stack.call(av::MessageType::Audit, audit);
  Stack::require(report);
  AV_REQUIRE_MSG(report->boolean(av::kFieldClean).value_or(false), report->str(av::kFieldText).value_or(""));

  AV_PHASE("SHUTDOWN");
  stack.shutdown();
}