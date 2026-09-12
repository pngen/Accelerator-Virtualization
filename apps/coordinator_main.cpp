// Accelerator Virtualization coordinator.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The coordinator owns virtualization authority. It never executes accelerator
// work itself: it validates authority, mutates and persists durable state, and
// routes device operations to the agent that owns the backing device.
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#include "av/client.hpp"
#include "av/persistence.hpp"
#include "av/runtime.hpp"
#include "av/socket.hpp"
#include "proto_util.hpp"

namespace {

using av::Byte;
using av::ByteSpan;
using av::FieldReader;
using av::FieldWriter;
using av::StatusCode;
using av::Status;
using av::app::Response;

struct Options {
  std::string bind{"127.0.0.1"};
  std::uint16_t port{0};
  std::string state_dir{};
  std::string name{"av-coordinator"};
  bool persist{true};
  bool deferred{false};
  std::size_t deferred_threshold{256};
  std::string torn_tail{"reject"};
  std::string transparency{};
  std::uint32_t max_connections{64};
  bool allow_synthetic{true};
  std::uint64_t evidence_max_age_micros{0};
};

void print_usage() {
  std::fputs(
      "av_coordinator - Accelerator Virtualization control plane\n"
      "\n"
      "  --bind ADDR                 bind address (default 127.0.0.1)\n"
      "  --port N                    TCP port, 0 selects an ephemeral port\n"
      "  --state-dir DIR             durable metadata directory\n"
      "  --name NAME                 coordinator name\n"
      "  --no-persist                run without durable state\n"
      "  --deferred                  coalesce journal writes\n"
      "  --deferred-threshold N      records buffered before a deferred flush\n"
      "  --torn-tail reject|discard  how an incomplete journal tail is treated\n"
      "  --transparency MODE         OPAQUE | SUMMARY | FULL\n"
      "  --max-connections N         concurrent connection ceiling\n"
      "  --no-synthetic              refuse synthetic backings by policy\n"
      "  --evidence-max-age-us N     treat older backing evidence as stale\n",
      stderr);
}

bool parse_options(int argc, char** argv, Options& options) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto next = [&](std::string& out) {
      if (i + 1 >= argc) return false;
      out = argv[++i];
      return true;
    };
    auto next_u64 = [&](std::uint64_t& out) {
      if (i + 1 >= argc) return false;
      out = std::strtoull(argv[++i], nullptr, 10);
      return true;
    };
    if (arg == "--help" || arg == "-h") {
      print_usage();
      return false;
    }
    if (arg == "--bind") {
      if (!next(options.bind)) return false;
    } else if (arg == "--port") {
      std::uint64_t value = 0;
      if (!next_u64(value) || value > 65535) return false;
      options.port = static_cast<std::uint16_t>(value);
    } else if (arg == "--state-dir") {
      if (!next(options.state_dir)) return false;
    } else if (arg == "--name") {
      if (!next(options.name)) return false;
    } else if (arg == "--no-persist") {
      options.persist = false;
    } else if (arg == "--deferred") {
      options.deferred = true;
    } else if (arg == "--deferred-threshold") {
      std::uint64_t value = 0;
      if (!next_u64(value) || value == 0 || value > 1000000) return false;
      options.deferred_threshold = static_cast<std::size_t>(value);
    } else if (arg == "--torn-tail") {
      if (!next(options.torn_tail)) return false;
    } else if (arg == "--transparency") {
      if (!next(options.transparency)) return false;
    } else if (arg == "--max-connections") {
      std::uint64_t value = 0;
      if (!next_u64(value) || value == 0 || value > 4096) return false;
      options.max_connections = static_cast<std::uint32_t>(value);
    } else if (arg == "--no-synthetic") {
      options.allow_synthetic = false;
    } else if (arg == "--evidence-max-age-us") {
      if (!next_u64(options.evidence_max_age_micros)) return false;
    } else {
      std::fprintf(stderr, "av_coordinator: unrecognised argument '%s'\n", argv[i]);
      return false;
    }
  }
  return true;
}

// One agent connection. Requests are correlated by request identity, so a
// response can never be matched to the wrong outstanding request.
class AgentLink {
 public:
  AgentLink(av::AgentId id, av::AgentBootId boot, std::string name, av::FrameChannel channel)
      : id_(id), boot_(boot), name_(std::move(name)), channel_(std::move(channel)) {}

  av::AgentId id() const { return id_; }
  av::AgentBootId boot() const { return boot_; }
  const std::string& name() const { return name_; }
  bool alive() const { return alive_.load(); }
  av::FrameChannel& channel() { return channel_; }

  void note_device(av::PhysicalDeviceId id, std::string stable_key) {
    std::lock_guard<std::mutex> lock(device_mutex_);
    devices_[id] = std::move(stable_key);
  }

  bool owns(av::PhysicalDeviceId id) const {
    std::lock_guard<std::mutex> lock(device_mutex_);
    return devices_.find(id) != devices_.end();
  }

  std::string stable_key_for(av::PhysicalDeviceId id) const {
    std::lock_guard<std::mutex> lock(device_mutex_);
    const auto it = devices_.find(id);
    return it == devices_.end() ? std::string{} : it->second;
  }

  Response request(av::MessageType type, const FieldWriter& fields) {
    if (!alive_.load()) {
      return Response::failure(StatusCode::ConnectionLost, "the agent link is closed");
    }
    const std::uint64_t identity = next_request_.fetch_add(1);
    auto promise = std::make_shared<std::promise<Response>>();
    std::future<Response> future = promise->get_future();
    {
      std::lock_guard<std::mutex> lock(mutex_);
      pending_[identity] = promise;
    }
    const std::vector<Byte> payload = fields.take();
    const Status sent = channel_.send(static_cast<std::uint16_t>(type), av::RequestId::from_value(identity),
                                      ByteSpan{payload.data(), payload.size()}, av::kFlagAgentDirected);
    if (!sent.ok()) {
      {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.erase(identity);
      }
      alive_.store(false);
      return Response::failure(sent);
    }
    future.wait();
    return future.get();
  }

  void deliver(std::uint64_t identity, Response response) {
    std::shared_ptr<std::promise<Response>> promise;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto it = pending_.find(identity);
      if (it == pending_.end()) return;
      promise = it->second;
      pending_.erase(it);
    }
    promise->set_value(std::move(response));
  }

  void fail_all(const Status& status) {
    alive_.store(false);
    std::vector<std::shared_ptr<std::promise<Response>>> promises;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& entry : pending_) promises.push_back(entry.second);
      pending_.clear();
    }
    for (auto& promise : promises) promise->set_value(Response::failure(status));
  }

 private:
  av::AgentId id_{};
  av::AgentBootId boot_{};
  std::string name_{};
  av::FrameChannel channel_;
  std::mutex mutex_;
  std::map<std::uint64_t, std::shared_ptr<std::promise<Response>>> pending_{};
  std::atomic<std::uint64_t> next_request_{1};
  std::atomic<bool> alive_{true};

  mutable std::mutex device_mutex_;
  std::map<av::PhysicalDeviceId, std::string> devices_{};
};

class AgentLink;

struct Server {
  // Stops accepting work and unblocks every connection thread, so shutdown
  // never depends on a peer sending another message.
  void begin_stop();

  Options options;
  std::unique_ptr<av::VirtualizationRuntime> runtime;
  std::mutex agents_mutex;
  std::map<av::AgentId, std::shared_ptr<AgentLink>> agents;
  std::atomic<bool> stopping{false};
  std::atomic<bool> shutdown_requested{false};
  std::atomic<std::uint32_t> connections{0};
  std::atomic<std::uint64_t> next_session{1};
  std::uint16_t port{0};
  av::Listener* listener{nullptr};
};

void Server::begin_stop() {
  if (stopping.exchange(true)) return;
  if (listener != nullptr) listener->close();
  std::vector<std::shared_ptr<AgentLink>> links;
  {
    std::lock_guard<std::mutex> lock(agents_mutex);
    for (const auto& entry : agents) links.push_back(entry.second);
  }
  for (const auto& link : links) link->channel().interrupt();
}

// ---- helpers -------------------------------------------------------------

Response ok_epoch(Server& server, FieldWriter& writer) {
  writer.u64(av::kFieldEpoch, server.runtime->epoch().value());
  return av::app::blob_response(writer);
}

Response blobs_response(const std::vector<std::vector<Byte>>& items) {
  FieldWriter writer;
  writer.nested_list(av::kFieldBlobs, items);
  return av::app::blob_response(writer);
}

std::shared_ptr<AgentLink> find_agent_for(Server& server, av::PhysicalDeviceId device) {
  std::lock_guard<std::mutex> lock(server.agents_mutex);
  for (const auto& entry : server.agents) {
    if (entry.second->owns(device)) return entry.second;
  }
  return nullptr;
}

// ---- agent-originated requests ------------------------------------------

Response handle_agent_request(Server& server, const FieldReader& reader, av::MessageType type,
                              av::RequestId request, std::uint64_t session) {
  auto& runtime = *server.runtime;
  switch (type) {
    case av::MessageType::RegisterPhysical:
    case av::MessageType::RefreshPhysical: {
      auto descriptor_blob = reader.require_bytes(av::kFieldDescriptorBlob);
      if (!descriptor_blob.ok()) return Response::failure(descriptor_blob.status());
      auto descriptor_reader = FieldReader::create(*descriptor_blob);
      if (!descriptor_reader.ok()) return Response::failure(descriptor_reader.status());
      auto descriptor = av::app::decode_physical_descriptor(descriptor_reader.value());
      if (!descriptor.ok()) return Response::failure(descriptor.status());
      auto agent_id = reader.require_u64(av::kFieldAgentId);
      if (!agent_id.ok()) return Response::failure(agent_id.status());
      auto boot = reader.require_u64(av::kFieldBootId);
      if (!boot.ok()) return Response::failure(boot.status());
      const av::AgentId id = av::AgentId::from_value(*agent_id);
      const av::AgentBootId boot_id = av::AgentBootId::from_value(*boot);

      av::Authority authority = runtime.current_authority();
      authority.request = request;
      authority.session = session;
      auto record = runtime.register_physical(authority, id, boot_id, descriptor.value());
      if (!record.ok()) return Response::failure(record.status());
      {
        std::lock_guard<std::mutex> lock(server.agents_mutex);
        const auto it = server.agents.find(id);
        if (it != server.agents.end()) it->second->note_device(record->id, descriptor->stable_key);
      }
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_physical_record(record.value());
      writer.bytes(av::kFieldPhysicalBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldPhysicalId, record->id.value());
      writer.u64(av::kFieldPhysicalGeneration, record->generation.value());
      writer.str(av::kFieldStableKey, record->stable_key);
      return ok_epoch(server, writer);
    }
    case av::MessageType::PhysicalLost: {
      auto id = reader.require_u64(av::kFieldPhysicalId);
      if (!id.ok()) return Response::failure(id.status());
      auto generation = reader.require_u64(av::kFieldPhysicalGeneration);
      if (!generation.ok()) return Response::failure(generation.status());
      std::string reason = "physical device is no longer present";
      if (auto value = reader.str(av::kFieldReason); value.has_value()) reason = *value;
      const Status status = runtime.physical_lost(av::PhysicalDeviceId::from_value(*id),
                                                  av::PhysicalDeviceGeneration::from_value(*generation), reason);
      if (!status.ok()) return Response::failure(status);
      FieldWriter writer;
      return ok_epoch(server, writer);
    }
    case av::MessageType::Heartbeat: {
      auto id = reader.require_u64(av::kFieldAgentId);
      if (!id.ok()) return Response::failure(id.status());
      auto boot = reader.require_u64(av::kFieldBootId);
      if (!boot.ok()) return Response::failure(boot.status());
      const Status status = runtime.agent_heartbeat(av::AgentId::from_value(*id),
                                                    av::AgentBootId::from_value(*boot));
      if (!status.ok()) return Response::failure(status);
      FieldWriter writer;
      return ok_epoch(server, writer);
    }
    default:
      return Response::failure(StatusCode::UnsupportedMessage,
                               "message " + std::string(av::message_name(type)) +
                                   " is not handled on an agent connection");
  }
}

// ---- client-originated requests -----------------------------------------

Response execute_request(Server& server, const FieldReader& reader, av::RequestId request,
                           std::uint64_t session) {
  auto& runtime = *server.runtime;
  auto op_value = reader.require_u64(av::kFieldOp);
  if (!op_value.ok()) return Response::failure(op_value.status());
  if (*op_value > static_cast<std::uint64_t>(av::ExecutionOp::DeviceInfo)) {
    return Response::failure(StatusCode::ProtocolViolation, "execution operation is outside its domain");
  }
  const auto op = static_cast<av::ExecutionOp>(*op_value);

  auto virtual_id = reader.require_u64(av::kFieldVirtualId);
  if (!virtual_id.ok()) return Response::failure(virtual_id.status());
  const av::VirtualAcceleratorId target = av::VirtualAcceleratorId::from_value(*virtual_id);

  auto record = runtime.raw_virtual(target);
  if (!record.ok()) return Response::failure(record.status());
  if (!record->physical.valid()) {
    return Response::failure(StatusCode::BackingUnavailable, "the virtual accelerator has no backing device");
  }

  const std::uint64_t bytes = reader.u64(av::kFieldBytes).value_or(0);
  const std::uint64_t handle = reader.u64(av::kFieldHandle).value_or(0);
  const std::uint64_t count = reader.u64(av::kFieldCount).value_or(0);
  std::vector<std::uint64_t> handles;
  if (auto values = reader.list_u64(av::kFieldHandles); values.has_value()) handles = *values;
  std::vector<std::uint8_t> data;
  if (auto blob = reader.bytes(av::kFieldData); blob.has_value()) data = av::to_byte_values(*blob);

  av::Authority authority = av::app::read_authority(reader);
  authority.request = request;
  authority.session = session;
  if (!authority.epoch.has_value()) {
    // Execution is authorised work, so the caller must present the epoch it
    // believes is current; the runtime then fences it if that is no longer true.
    return Response::failure(StatusCode::InvalidArgument,
                             "an execution request must carry the coordinator epoch");
  }

  bool reserved = false;
  if (op == av::ExecutionOp::Allocate) {
    auto reservation = runtime.reserve_allocation(authority, bytes);
    if (!reservation.ok()) return Response::failure(reservation.status());
    reserved = true;
  }

  const std::shared_ptr<AgentLink> link = find_agent_for(server, record->physical);
  if (link == nullptr || !link->alive()) {
    if (reserved) {
      const Status ignored = runtime.release_allocation(authority, bytes);
      (void)ignored;
    }
    return Response::failure(StatusCode::BackingUnavailable,
                             "no live agent owns physical device " + record->physical.str());
  }

  FieldWriter fields;
  fields.u64(av::kFieldOp, static_cast<std::uint64_t>(op));
  fields.str(av::kFieldStableKey, link->stable_key_for(record->physical));
  fields.u64(av::kFieldPhysicalId, record->physical.value());
  fields.u64(av::kFieldBytes, bytes);
  fields.u64(av::kFieldHandle, handle);
  fields.u64(av::kFieldCount, count);
  fields.list_u64(av::kFieldHandles, handles);
  if (!data.empty()) fields.bytes(av::kFieldData, av::byte_span(data));

  const Response agent_response = link->request(av::MessageType::AgentExecute, fields);
  if ((agent_response.flags & av::kFlagError) != 0) {
    if (reserved) {
      const Status ignored = runtime.release_allocation(authority, bytes);
      (void)ignored;
    }
    return agent_response;
  }
  auto agent_fields = FieldReader::create(ByteSpan{agent_response.payload.data(), agent_response.payload.size()});
  if (!agent_fields.ok()) {
    if (reserved) {
      const Status ignored = runtime.release_allocation(authority, bytes);
      (void)ignored;
    }
    return Response::failure(agent_fields.status());
  }

  if (op == av::ExecutionOp::KernelVectorAdd) {
    const Status accounted = runtime.account_kernel(authority, static_cast<std::uint32_t>(count));
    if (!accounted.ok()) return Response::failure(accounted);
  }
  if (op == av::ExecutionOp::Free) {
    const std::uint64_t released = agent_fields->u64(av::kFieldBytes).value_or(0);
    if (released > 0) {
      const Status ignored = runtime.release_allocation(authority, released);
      (void)ignored;
    }
  }

  FieldWriter response;
  response.u64(av::kFieldStatus, static_cast<std::uint64_t>(StatusCode::Ok));
  if (auto value = agent_fields->u64(av::kFieldHandle); value.has_value()) {
    response.u64(av::kFieldHandle, *value);
  }
  if (auto value = agent_fields->u64(av::kFieldBytes); value.has_value()) {
    response.u64(av::kFieldBytes, *value);
  }
  if (auto value = agent_fields->u64(av::kFieldDeviceMemoryTotal); value.has_value()) {
    response.u64(av::kFieldDeviceMemoryTotal, *value);
  }
  if (auto value = agent_fields->u64(av::kFieldDeviceMemoryFree); value.has_value()) {
    response.u64(av::kFieldDeviceMemoryFree, *value);
  }
  if (auto value = agent_fields->str(av::kFieldDetail); value.has_value()) {
    response.str(av::kFieldDetail, *value);
  }
  if (auto value = agent_fields->bytes(av::kFieldData); value.has_value()) {
    response.bytes(av::kFieldData, *value);
  }
  return ok_epoch(server, response);
}

Response handle_client_request(Server& server, const FieldReader& reader, av::MessageType type,
                               av::RequestId request, std::uint64_t session) {
  auto& runtime = *server.runtime;
  av::Authority authority = av::app::read_authority(reader);
  if (!authority.epoch.has_value()) authority.epoch = runtime.epoch();
  authority.request = request;
  // The session is assigned by the coordinator, never chosen by the peer, so a
  // connection cannot claim another connection's replay window.
  authority.session = session;

  switch (type) {
    case av::MessageType::CreateTenant: {
      std::string name;
      std::string subject;
      if (auto value = reader.str(av::kFieldTenantName); value.has_value()) name = *value;
      if (auto value = reader.str(av::kFieldExternalSubject); value.has_value()) subject = *value;
      auto created = runtime.create_tenant(authority, name, subject);
      if (!created.ok()) return Response::failure(created.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_tenant_record(created.value());
      writer.bytes(av::kFieldTenantBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldTenantId, created->id.value());
      writer.u64(av::kFieldTenantGeneration, created->generation.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::ListTenants: {
      std::vector<std::vector<Byte>> blobs;
      for (const av::TenantRecord& record : runtime.list_tenants()) {
        blobs.push_back(av::app::wrap_blob(av::kFieldTenantBlob, av::encode_tenant_record(record)));
      }
      return blobs_response(blobs);
    }
    case av::MessageType::FenceTenant: {
      auto id = reader.require_u64(av::kFieldTenantId);
      if (!id.ok()) return Response::failure(id.status());
      auto generation = reader.require_u64(av::kFieldTenantGeneration);
      if (!generation.ok()) return Response::failure(generation.status());
      std::string reason = "fenced by operator";
      if (auto value = reader.str(av::kFieldReason); value.has_value()) reason = *value;
      const Status status = runtime.fence_tenant(authority, av::TenantId::from_value(*id),
                                                 av::TenantGeneration::from_value(*generation), reason);
      if (!status.ok()) return Response::failure(status);
      FieldWriter writer;
      return ok_epoch(server, writer);
    }
    case av::MessageType::TransferOwnership: {
      auto owner = reader.require_u64(av::kFieldNewOwnerId);
      if (!owner.ok()) return Response::failure(owner.status());
      auto generation = reader.require_u64(av::kFieldNewOwnerGeneration);
      if (!generation.ok()) return Response::failure(generation.status());
      auto transferred = runtime.transfer_ownership(authority, av::TenantId::from_value(*owner),
                                                    av::TenantGeneration::from_value(*generation));
      if (!transferred.ok()) return Response::failure(transferred.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_tenant_record(transferred.value());
      writer.bytes(av::kFieldTenantBlob, ByteSpan{blob.data(), blob.size()});
      return ok_epoch(server, writer);
    }
    case av::MessageType::CreateVirtual: {
      std::string name;
      if (auto value = reader.str(av::kFieldVirtualName); value.has_value()) name = *value;
      auto owner = reader.require_u64(av::kFieldTenantId);
      if (!owner.ok()) return Response::failure(owner.status());
      auto generation = reader.require_u64(av::kFieldTenantGeneration);
      if (!generation.ok()) return Response::failure(generation.status());
      auto contract_blob = reader.require_bytes(av::kFieldContractBlob);
      if (!contract_blob.ok()) return Response::failure(contract_blob.status());
      auto contract = av::decode_contract_blob(*contract_blob);
      if (!contract.ok()) return Response::failure(contract.status());
      auto created = runtime.create_virtual(authority, name, av::TenantId::from_value(*owner),
                                            av::TenantGeneration::from_value(*generation), contract.take());
      if (!created.ok()) return Response::failure(created.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_virtual_record(created.value());
      writer.bytes(av::kFieldVirtualBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldVirtualId, created->id.value());
      writer.u64(av::kFieldVirtualGeneration, created->generation.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::UpdateContract: {
      auto contract_blob = reader.require_bytes(av::kFieldContractBlob);
      if (!contract_blob.ok()) return Response::failure(contract_blob.status());
      auto contract = av::decode_contract_blob(*contract_blob);
      if (!contract.ok()) return Response::failure(contract.status());
      auto updated = runtime.update_contract(authority, contract.take());
      if (!updated.ok()) return Response::failure(updated.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_virtual_record(updated.value());
      writer.bytes(av::kFieldVirtualBlob, ByteSpan{blob.data(), blob.size()});
      return ok_epoch(server, writer);
    }
    case av::MessageType::AssignBacking:
    case av::MessageType::ReplaceBacking: {
      auto backing = reader.require_u64(av::kFieldBackingId);
      if (!backing.ok()) return Response::failure(backing.status());
      std::string reason = "operator request";
      if (auto value = reader.str(av::kFieldReason); value.has_value()) reason = *value;
      const bool replacing = type == av::MessageType::ReplaceBacking;
      auto assigned = replacing ? runtime.replace_backing(authority, av::BackingId::from_value(*backing), reason)
                                : runtime.assign_backing(authority, av::BackingId::from_value(*backing), reason);
      if (!assigned.ok()) return Response::failure(assigned.status());
      FieldWriter writer;
      writer.u64(av::kFieldBackingId, assigned->backing.value());
      writer.u64(av::kFieldBackingGeneration, assigned->backing_generation.value());
      writer.u64(av::kFieldVirtualGeneration, assigned->virtual_generation.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::ActivateVirtual:
    case av::MessageType::SuspendVirtual:
    case av::MessageType::ResumeVirtual:
    case av::MessageType::DrainVirtual:
    case av::MessageType::ResolveRecovery:
    case av::MessageType::FenceVirtual:
    case av::MessageType::RetireVirtual: {
      std::string reason = "operator request";
      if (auto value = reader.str(av::kFieldReason); value.has_value()) reason = *value;
      av::Result<av::VirtualAcceleratorRecord> outcome = Status(StatusCode::Unsupported);
      switch (type) {
        case av::MessageType::ActivateVirtual:
          outcome = runtime.activate(authority);
          break;
        case av::MessageType::SuspendVirtual:
          outcome = runtime.suspend(authority, reason);
          break;
        case av::MessageType::ResumeVirtual:
          outcome = runtime.resume(authority, reason);
          break;
        case av::MessageType::DrainVirtual:
          outcome = runtime.drain(authority, reason);
          break;
        case av::MessageType::ResolveRecovery:
          outcome = runtime.resolve_recovery(authority, reason);
          break;
        case av::MessageType::FenceVirtual:
          outcome = runtime.fence_virtual(authority, reason);
          break;
        case av::MessageType::RetireVirtual:
          outcome = runtime.retire_virtual(authority, reason);
          break;
        default:
          break;
      }
      if (!outcome.ok()) return Response::failure(outcome.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_virtual_record(outcome.value());
      writer.bytes(av::kFieldVirtualBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldVirtualGeneration, outcome->generation.value());
      writer.u64(av::kFieldStateGeneration, outcome->state_generation.value());
      writer.u64(av::kFieldState, static_cast<std::uint64_t>(outcome->state));
      return ok_epoch(server, writer);
    }
    case av::MessageType::Attach: {
      auto lease = runtime.attach(authority);
      if (!lease.ok()) return Response::failure(lease.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_lease_record(lease.value());
      writer.bytes(av::kFieldLeaseBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldLeaseId, lease->id.value());
      writer.u64(av::kFieldLeaseGeneration, lease->generation.value());
      writer.u64(av::kFieldVirtualGeneration, lease->virtual_generation.value());
      writer.u64(av::kFieldBackingGeneration, lease->backing_generation.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::RenewLease: {
      auto lease = runtime.renew_lease(authority);
      if (!lease.ok()) return Response::failure(lease.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_lease_record(lease.value());
      writer.bytes(av::kFieldLeaseBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldLeaseGeneration, lease->generation.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::Detach: {
      const Status status = runtime.detach(authority);
      if (!status.ok()) return Response::failure(status);
      FieldWriter writer;
      return ok_epoch(server, writer);
    }
    case av::MessageType::Revoke: {
      std::string reason = "revoked by operator";
      if (auto value = reader.str(av::kFieldReason); value.has_value()) reason = *value;
      const Status status = runtime.revoke_lease(authority, reason);
      if (!status.ok()) return Response::failure(status);
      FieldWriter writer;
      return ok_epoch(server, writer);
    }
    case av::MessageType::Query: {
      auto id = reader.require_u64(av::kFieldVirtualId);
      if (!id.ok()) return Response::failure(id.status());
      auto view = runtime.query_virtual(authority, av::VirtualAcceleratorId::from_value(*id));
      if (!view.ok()) return Response::failure(view.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_view(view.value());
      writer.bytes(av::kFieldViewBlob, ByteSpan{blob.data(), blob.size()});
      return ok_epoch(server, writer);
    }
    case av::MessageType::ListVirtual: {
      std::vector<std::vector<Byte>> blobs;
      for (const av::VirtualView& view : runtime.list_virtual(authority)) {
        blobs.push_back(av::app::wrap_blob(av::kFieldViewBlob, av::encode_view(view)));
      }
      return blobs_response(blobs);
    }
    case av::MessageType::ListBackings: {
      std::vector<std::vector<Byte>> blobs;
      for (const av::BackingRecord& backing : runtime.list_backings()) {
        blobs.push_back(av::app::wrap_blob(av::kFieldBackingBlob, av::encode_backing_record(backing)));
      }
      return blobs_response(blobs);
    }
    case av::MessageType::ListPhysical: {
      std::vector<std::vector<Byte>> blobs;
      for (const av::PhysicalDeviceRecord& record : runtime.list_physical()) {
        blobs.push_back(av::app::wrap_blob(av::kFieldPhysicalBlob, av::encode_physical_record(record)));
      }
      return blobs_response(blobs);
    }
    case av::MessageType::CapabilityShow: {
      auto id = reader.require_u64(av::kFieldVirtualId);
      if (!id.ok()) return Response::failure(id.status());
      auto projection = runtime.get_projection(av::VirtualAcceleratorId::from_value(*id));
      if (!projection.ok()) return Response::failure(projection.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::app::encode_projection_blob(projection.value());
      writer.bytes(av::kFieldProjectionBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldVirtualId, id.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::ContractShow: {
      auto id = reader.require_u64(av::kFieldVirtualId);
      if (!id.ok()) return Response::failure(id.status());
      auto contract = runtime.get_contract(av::VirtualAcceleratorId::from_value(*id));
      if (!contract.ok()) return Response::failure(contract.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_contract_blob(contract.value());
      writer.bytes(av::kFieldContractBlob, ByteSpan{blob.data(), blob.size()});
      return ok_epoch(server, writer);
    }
    case av::MessageType::IsolationExplain: {
      auto id = reader.require_u64(av::kFieldVirtualId);
      if (!id.ok()) return Response::failure(id.status());
      auto explanation = runtime.explain_isolation(av::VirtualAcceleratorId::from_value(*id));
      if (!explanation.ok()) return Response::failure(explanation.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_isolation_explanation(explanation.value());
      writer.bytes(av::kFieldIsolationBlob, ByteSpan{blob.data(), blob.size()});
      return ok_epoch(server, writer);
    }
    case av::MessageType::MigrationExplain: {
      auto id = reader.require_u64(av::kFieldVirtualId);
      if (!id.ok()) return Response::failure(id.status());
      auto explanation = runtime.explain_migration(av::VirtualAcceleratorId::from_value(*id));
      if (!explanation.ok()) return Response::failure(explanation.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_migration_explanation(explanation.value());
      writer.bytes(av::kFieldMigrationBlob, ByteSpan{blob.data(), blob.size()});
      return ok_epoch(server, writer);
    }
    case av::MessageType::ExplainDecisions: {
      auto id = reader.require_u64(av::kFieldVirtualId);
      if (!id.ok()) return Response::failure(id.status());
      const std::uint64_t limit = reader.u64(av::kFieldLimit).value_or(16);
      std::vector<std::vector<Byte>> blobs;
      for (const av::Decision& decision :
           runtime.explain_decisions(av::VirtualAcceleratorId::from_value(*id), static_cast<std::size_t>(limit))) {
        blobs.push_back(av::app::wrap_blob(av::kFieldDecisionBlob, av::encode_decision_record(decision)));
      }
      return blobs_response(blobs);
    }
    case av::MessageType::SetPolicy: {
      auto blob = reader.require_bytes(av::kFieldPolicyBlob);
      if (!blob.ok()) return Response::failure(blob.status());
      auto policy = av::decode_policy_blob(*blob);
      if (!policy.ok()) return Response::failure(policy.status());
      auto updated = runtime.set_policy(authority, policy.take());
      if (!updated.ok()) return Response::failure(updated.status());
      FieldWriter writer;
      const std::vector<Byte> encoded = av::encode_policy_blob(updated.value());
      writer.bytes(av::kFieldPolicyBlob, ByteSpan{encoded.data(), encoded.size()});
      writer.u64(av::kFieldPolicyGeneration, updated->generation.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::GetPolicy: {
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_policy_blob(runtime.policy());
      writer.bytes(av::kFieldPolicyBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldPolicyGeneration, runtime.policy_generation().value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::MigrationPlan: {
      auto backing = reader.require_u64(av::kFieldBackingId);
      if (!backing.ok()) return Response::failure(backing.status());
      auto klass_value = reader.require_u64(av::kFieldMigrationClass);
      if (!klass_value.ok()) return Response::failure(klass_value.status());
      if (*klass_value > static_cast<std::uint64_t>(av::MigrationClass::LiveStateTransfer)) {
        return Response::failure(StatusCode::ProtocolViolation, "migration class is outside its domain");
      }
      auto planned = runtime.plan_migration(authority, av::BackingId::from_value(*backing),
                                            static_cast<av::MigrationClass>(*klass_value));
      if (!planned.ok()) return Response::failure(planned.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_migration_record(planned.value());
      writer.bytes(av::kFieldMigrationBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldMigrationId, planned->plan.id.value());
      writer.u64(av::kFieldMigrationGeneration, planned->plan.generation.value());
      return ok_epoch(server, writer);
    }
    case av::MessageType::MigrationPrepare:
    case av::MessageType::MigrationCommit:
    case av::MessageType::MigrationComplete:
    case av::MessageType::MigrationAbort: {
      std::string reason = "operator request";
      if (auto value = reader.str(av::kFieldReason); value.has_value()) reason = *value;
      av::Result<av::MigrationRecord> outcome = Status(StatusCode::Unsupported);
      switch (type) {
        case av::MessageType::MigrationPrepare:
          outcome = runtime.prepare_migration(authority);
          break;
        case av::MessageType::MigrationCommit:
          outcome = runtime.commit_migration(authority);
          break;
        case av::MessageType::MigrationComplete:
          outcome = runtime.complete_migration(authority);
          break;
        case av::MessageType::MigrationAbort:
          outcome = runtime.abort_migration(authority, reason);
          break;
        default:
          break;
      }
      if (!outcome.ok()) return Response::failure(outcome.status());
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_migration_record(outcome.value());
      writer.bytes(av::kFieldMigrationBlob, ByteSpan{blob.data(), blob.size()});
      writer.u64(av::kFieldMigrationId, outcome->plan.id.value());
      writer.u64(av::kFieldMigrationGeneration, outcome->plan.generation.value());
      writer.u64(av::kFieldState, static_cast<std::uint64_t>(outcome->state));
      return ok_epoch(server, writer);
    }
    case av::MessageType::Audit: {
      const av::AuditReport report = runtime.audit();
      FieldWriter writer;
      writer.str(av::kFieldText, report.canonical());
      writer.boolean(av::kFieldClean, report.clean());
      writer.u64(av::kFieldViolationCount, report.violations.size());
      writer.u64(av::kFieldDigest, report.state_fingerprint);
      return ok_epoch(server, writer);
    }
    case av::MessageType::Snapshot: {
      FieldWriter writer;
      writer.str(av::kFieldText, runtime.snapshot_text());
      writer.u64(av::kFieldDigest, runtime.state_fingerprint());
      writer.str(av::kFieldDetail, runtime.store_description());
      writer.u64(av::kFieldBytes, runtime.persistence_bytes());
      writer.u64(av::kFieldCount, runtime.persistence_writes());
      return ok_epoch(server, writer);
    }
    case av::MessageType::Accounting: {
      FieldWriter writer;
      const std::vector<Byte> blob = av::encode_accounting(runtime.accounting());
      writer.bytes(av::kFieldAccountingBlob, ByteSpan{blob.data(), blob.size()});
      writer.str(av::kFieldText, av::accounting_canonical(runtime.accounting()));
      return ok_epoch(server, writer);
    }
    case av::MessageType::Execute:
      return execute_request(server, reader, request, session);
    case av::MessageType::Shutdown: {
      FieldWriter writer;
      writer.boolean(av::kFieldShutdown, true);
      Response response = ok_epoch(server, writer);
      server.shutdown_requested.store(true);
      return response;
    }
    default:
      return Response::failure(StatusCode::UnsupportedMessage,
                               "message " + std::string(av::message_name(type)) +
                                   " is not handled on a client connection");
  }
}

// ---- connection handling -------------------------------------------------

void serve_agent(Server& server, std::shared_ptr<AgentLink> link) {
  auto& runtime = *server.runtime;
  while (!server.stopping.load() && link->alive()) {
    auto frame = link->channel().receive();
    if (!frame.ok()) break;
    if ((frame->header.flags & av::kFlagResponse) != 0) {
      Response response;
      response.flags = frame->header.flags;
      response.payload = frame->payload;
      link->deliver(frame->header.request, std::move(response));
      continue;
    }
    auto reader = FieldReader::create(ByteSpan{frame->payload.data(), frame->payload.size()});
    Response response = reader.ok()
                            ? handle_agent_request(server, reader.value(),
                                                   static_cast<av::MessageType>(frame->header.type),
                                                   av::RequestId::from_value(frame->header.request),
                                                   link->id().value())
                            : Response::failure(reader.status());
    const Status sent =
        link->channel().send(static_cast<std::uint16_t>(av::response_for(static_cast<av::MessageType>(frame->header.type))),
                             av::RequestId::from_value(frame->header.request),
                             ByteSpan{response.payload.data(), response.payload.size()},
                             response.flags | av::kFlagResponse);
    if (!sent.ok()) break;
  }
  link->fail_all(Status(StatusCode::ConnectionLost, "the agent connection ended"));
  {
    std::lock_guard<std::mutex> lock(server.agents_mutex);
    server.agents.erase(link->id());
  }
  const Status status = runtime.agent_disconnected(link->id(), link->boot());
  (void)status;
  std::printf("AV_COORDINATOR AGENT_GONE agent=%s boot=%s\n", link->id().str().c_str(), link->boot().str().c_str());
  std::fflush(stdout);
}

void serve_connection(Server& server, av::Socket socket) {
  av::FrameChannel channel(std::move(socket));
  auto hello = channel.receive();
  if (!hello.ok()) {
    channel.close();
    return;
  }
  const auto declared = static_cast<av::MessageType>(hello->header.type);
  if (declared != av::MessageType::Hello) {
    const std::vector<Byte> payload =
        av::encode_error_payload(StatusCode::ProtocolViolation, "the first message must be HELLO");
    const Status ignored = channel.send(static_cast<std::uint16_t>(av::MessageType::Error), av::RequestId{},
                                        ByteSpan{payload.data(), payload.size()}, av::kFlagError);
    (void)ignored;
    channel.close();
    return;
  }
  auto hello_fields = FieldReader::create(ByteSpan{hello->payload.data(), hello->payload.size()});
  if (!hello_fields.ok()) {
    channel.close();
    return;
  }
  const std::uint64_t role_value = hello_fields->u64(av::kFieldRole).value_or(0);
  if (role_value > static_cast<std::uint64_t>(av::Role::Observer)) {
    const std::vector<Byte> payload =
        av::encode_error_payload(StatusCode::ProtocolViolation, "role is outside its domain");
    const Status ignored = channel.send(static_cast<std::uint16_t>(av::MessageType::Error), av::RequestId{},
                                        ByteSpan{payload.data(), payload.size()}, av::kFlagError);
    (void)ignored;
    channel.close();
    return;
  }
  const auto role = static_cast<av::Role>(role_value);
  const std::uint64_t client_protocol = hello_fields->u64(av::kFieldProtocolVersion).value_or(0);
  if (client_protocol != av::protocol_version()) {
    const std::vector<Byte> payload = av::encode_error_payload(
        StatusCode::VersionMismatch, "protocol version " + std::to_string(client_protocol) + " is not supported");
    const Status ignored = channel.send(static_cast<std::uint16_t>(av::MessageType::Error), av::RequestId{},
                                        ByteSpan{payload.data(), payload.size()}, av::kFlagError);
    (void)ignored;
    channel.close();
    return;
  }
  std::string name = "av-client";
  if (auto value = hello_fields->str(av::kFieldAgentName); value.has_value()) name = *value;

  if (role == av::Role::Agent) {
    auto session = server.runtime->register_agent(name, channel.peer(), 0, av::AgentId{});
    if (!session.ok()) {
      const std::vector<Byte> payload = av::encode_error_payload(session.status().code(), session.status().detail());
      const Status ignored = channel.send(static_cast<std::uint16_t>(av::MessageType::Error), av::RequestId{},
                                          ByteSpan{payload.data(), payload.size()}, av::kFlagError);
      (void)ignored;
      channel.close();
      return;
    }
    auto link = std::make_shared<AgentLink>(session->id, session->boot, name, std::move(channel));
    {
      std::lock_guard<std::mutex> lock(server.agents_mutex);
      server.agents[link->id()] = link;
    }
    FieldWriter ack;
    ack.u64(av::kFieldProtocolVersion, av::protocol_version());
    ack.u64(av::kFieldRole, static_cast<std::uint64_t>(av::Role::Agent));
    ack.u64(av::kFieldAgentId, session->id.value());
    ack.u64(av::kFieldBootId, session->boot.value());
    ack.u64(av::kFieldEpoch, server.runtime->epoch().value());
    ack.u64(av::kFieldConnectionId, session->connection_id);
    const std::vector<Byte> payload = ack.take();
    const Status sent = link->channel().send(static_cast<std::uint16_t>(av::MessageType::HelloAck),
                                             av::RequestId::from_value(hello->header.request),
                                             ByteSpan{payload.data(), payload.size()}, av::kFlagResponse);
    if (!sent.ok()) {
      link->fail_all(sent);
      std::lock_guard<std::mutex> lock(server.agents_mutex);
      server.agents.erase(link->id());
      return;
    }
    std::printf("AV_COORDINATOR AGENT_ATTACHED agent=%s boot=%s name=%s\n", session->id.str().c_str(),
                session->boot.str().c_str(), name.c_str());
    std::fflush(stdout);
    serve_agent(server, link);
    return;
  }

  const std::uint64_t session = server.next_session.fetch_add(1);
  {
    FieldWriter ack;
    ack.u64(av::kFieldProtocolVersion, av::protocol_version());
    ack.u64(av::kFieldRole, static_cast<std::uint64_t>(role));
    ack.u64(av::kFieldEpoch, server.runtime->epoch().value());
    ack.u64(av::kFieldConnectionId, session);
    ack.str(av::kFieldServerName, server.options.name);
    const std::vector<Byte> payload = ack.take();
    const Status sent = channel.send(static_cast<std::uint16_t>(av::MessageType::HelloAck),
                                     av::RequestId::from_value(hello->header.request),
                                     ByteSpan{payload.data(), payload.size()}, av::kFlagResponse);
    if (!sent.ok()) {
      channel.close();
      return;
    }
  }

  while (!server.stopping.load()) {
    auto frame = channel.receive();
    if (!frame.ok()) break;
    auto reader = FieldReader::create(ByteSpan{frame->payload.data(), frame->payload.size()});
    const auto type = static_cast<av::MessageType>(frame->header.type);
    Response response = reader.ok() ? handle_client_request(server, reader.value(), type,
                                                           av::RequestId::from_value(frame->header.request), session)
                                    : Response::failure(reader.status());
    const Status sent =
        channel.send(static_cast<std::uint16_t>(av::response_for(type)),
                     av::RequestId::from_value(frame->header.request),
                     ByteSpan{response.payload.data(), response.payload.size()},
                     response.flags | av::kFlagResponse);
    if (!sent.ok()) break;
    if (server.shutdown_requested.load()) {
      server.begin_stop();
      break;
    }
  }
  channel.close();
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!parse_options(argc, argv, options)) return 2;

  av::StoreOptions store_options;
  store_options.directory = options.state_dir;
  store_options.enabled = options.persist && !options.state_dir.empty();
  store_options.deferred = options.deferred;
  store_options.deferred_threshold = options.deferred_threshold;
  store_options.torn_tail = options.torn_tail == "discard" ? av::StoreOptions::TornTail::Discard
                                                           : av::StoreOptions::TornTail::Reject;

  av::RuntimeOptions runtime_options;
  runtime_options.name = options.name;
  runtime_options.persist = options.persist;
  runtime_options.deferred_persistence = options.deferred;
  runtime_options.deferred_threshold = options.deferred_threshold;
  runtime_options.max_connections = options.max_connections;

  auto runtime = av::make_runtime(runtime_options, store_options, nullptr);
  if (!runtime.ok()) {
    std::fprintf(stderr, "av_coordinator: %s\n", runtime.status().to_string().c_str());
    return 1;
  }

  Server server;
  server.options = options;
  server.runtime = runtime.take();

  if (!options.transparency.empty() || !options.allow_synthetic || options.evidence_max_age_micros != 0) {
    av::VirtualizationPolicy policy = server.runtime->policy();
    if (!options.transparency.empty()) {
      auto mode = av::parse_transparency(options.transparency);
      if (!mode.has_value()) {
        std::fprintf(stderr, "av_coordinator: unknown transparency mode '%s'\n", options.transparency.c_str());
        return 2;
      }
      policy.transparency = *mode;
    }
    policy.synthetic_backing_allowed = options.allow_synthetic;
    policy.evidence_max_age_micros = options.evidence_max_age_micros;
    auto updated = server.runtime->set_policy(server.runtime->current_authority(), policy);
    if (!updated.ok()) {
      std::fprintf(stderr, "av_coordinator: %s\n", updated.status().to_string().c_str());
      return 1;
    }
  }

  auto listener = av::Listener::bind(options.bind, options.port, 64);
  if (!listener.ok()) {
    std::fprintf(stderr, "av_coordinator: %s\n", listener.status().to_string().c_str());
    return 1;
  }
  server.listener = &listener.value();
  server.port = listener->port();

#ifdef _WIN32
  const int process_id = ::_getpid();
#else
  const int process_id = static_cast<int>(::getpid());
#endif
  std::printf("AV_COORDINATOR READY port=%u epoch=%s name=%s pid=%d\n", static_cast<unsigned>(listener->port()),
              server.runtime->epoch().str().c_str(), options.name.c_str(), process_id);
  std::fflush(stdout);

  std::vector<std::thread> workers;
  while (!server.stopping.load()) {
    auto socket = listener->accept();
    if (!socket.ok()) {
      if (server.stopping.load()) break;
      std::fprintf(stderr, "av_coordinator: accept failed: %s\n", socket.status().to_string().c_str());
      break;
    }
    if (server.connections.load() >= options.max_connections) {
      av::FrameChannel rejected(std::move(socket.value()));
      const std::vector<Byte> payload =
          av::encode_error_payload(StatusCode::LimitExceeded, "the connection ceiling has been reached");
      const Status ignored = rejected.send(static_cast<std::uint16_t>(av::MessageType::Error), av::RequestId{},
                                           ByteSpan{payload.data(), payload.size()}, av::kFlagError);
      (void)ignored;
      rejected.close();
      continue;
    }
    server.connections.fetch_add(1);
    workers.emplace_back([&server, connection = std::move(socket.value())]() mutable {
      serve_connection(server, std::move(connection));
      server.connections.fetch_sub(1);
    });
  }

  listener->close();
  server.listener = nullptr;
  for (std::thread& worker : workers) {
    if (worker.joinable()) worker.join();
  }
  const Status stopped = server.runtime->shutdown();
  if (!stopped.ok()) {
    std::fprintf(stderr, "av_coordinator: shutdown reported %s\n", stopped.to_string().c_str());
    return 1;
  }
  std::printf("AV_COORDINATOR STOPPED epoch=%s clean=true\n", server.runtime->epoch().str().c_str());
  std::fflush(stdout);
  return 0;
}
