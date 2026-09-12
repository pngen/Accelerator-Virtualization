// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/client.hpp"

#include <string>
#include <utility>
#include <vector>

namespace av {

ControlClient::~ControlClient() {
  if (channel_.open()) {
    const Status ignored = channel_.close();
    (void)ignored;
  }
}

ControlClient::ControlClient(ControlClient&& other) noexcept
    : channel_(std::move(other.channel_)),
      next_request_(other.next_request_),
      epoch_(other.epoch_),
      server_name_(std::move(other.server_name_)),
      client_name_(std::move(other.client_name_)),
      role_(other.role_),
      agent_id_(other.agent_id_),
      boot_id_(other.boot_id_) {
  other.next_request_ = 1;
  other.epoch_ = CoordinatorEpoch{};
  other.role_ = Role::Unknown;
  other.agent_id_ = AgentId{};
  other.boot_id_ = AgentBootId{};
}

ControlClient& ControlClient::operator=(ControlClient&& other) noexcept {
  if (this != &other) {
    channel_ = std::move(other.channel_);
    next_request_ = other.next_request_;
    epoch_ = other.epoch_;
    server_name_ = std::move(other.server_name_);
    client_name_ = std::move(other.client_name_);
    role_ = other.role_;
    agent_id_ = other.agent_id_;
    boot_id_ = other.boot_id_;
    other.next_request_ = 1;
    other.epoch_ = CoordinatorEpoch{};
    other.role_ = Role::Unknown;
    other.agent_id_ = AgentId{};
    other.boot_id_ = AgentBootId{};
  }
  return *this;
}

RequestId ControlClient::next_request() {
  const RequestId id = RequestId::from_value(next_request_);
  ++next_request_;
  return id;
}

Result<ControlClient> ControlClient::connect(const ClientOptions& options) {
  const Status ready = network_init();
  if (!ready.ok()) return ready;
  if (options.port == 0) return Status(StatusCode::InvalidArgument, "a coordinator port is required");
  if (options.name.empty()) return Status(StatusCode::InvalidArgument, "a client name is required");

  auto socket = Socket::connect(options.host, options.port);
  if (!socket.ok()) return socket.status();

  ControlClient client;
  client.client_name_ = options.name;
  client.role_ = options.role == Role::Unknown ? Role::Client : options.role;
  client.channel_ = FrameChannel(socket.take());
  const Status handshake_status = client.handshake();
  if (!handshake_status.ok()) {
    client.close();
    return handshake_status;
  }
  return client;
}

Status ControlClient::handshake() {
  FieldWriter fields;
  fields.u64(kFieldProtocolVersion, protocol_version());
  fields.u64(kFieldRole, static_cast<std::uint64_t>(role_ == Role::Unknown ? Role::Client : role_));
  fields.str(kFieldAgentName, client_name_);

  const RequestId request = next_request();
  const std::vector<Byte> payload = fields.take();
  const Status sent = channel_.send(static_cast<std::uint16_t>(MessageType::Hello), request,
                                    ByteSpan{payload.data(), payload.size()}, 0);
  if (!sent.ok()) return sent;

  auto frame = channel_.receive();
  if (!frame.ok()) return frame.status();
  if (frame->header.request != request.value()) {
    return Status(StatusCode::ProtocolViolation, "handshake response carried an unrelated request identity");
  }
  const MessageType declared = static_cast<MessageType>(frame->header.type);
  if (declared != MessageType::HelloAck) {
    return Status(StatusCode::ProtocolViolation,
                  "expected HELLO_ACK but received " + std::string(message_name(declared)));
  }
  if ((frame->header.flags & kFlagError) != 0) {
    auto decoded = decode_error_payload(ByteSpan{frame->payload.data(), frame->payload.size()});
    if (!decoded.ok()) return decoded.status();
    return Status(decoded->first, decoded->second);
  }
  auto reader = FieldReader::create(ByteSpan{frame->payload.data(), frame->payload.size()});
  if (!reader.ok()) return reader.status();
  auto version = reader->require_u64(kFieldProtocolVersion);
  if (!version.ok()) return version.status();
  if (*version != protocol_version()) {
    return Status(StatusCode::VersionMismatch, "coordinator speaks protocol version " + std::to_string(*version) +
                                                   " but this client speaks " +
                                                   std::to_string(protocol_version()));
  }
  if (auto epoch = reader->u64(kFieldEpoch); epoch.has_value()) {
    epoch_ = CoordinatorEpoch::from_value(*epoch);
  }
  if (auto name = reader->str(kFieldServerName); name.has_value()) server_name_ = *name;
  if (auto role = reader->u64(kFieldRole); role.has_value() &&
      *role <= static_cast<std::uint64_t>(Role::Observer)) {
    role_ = static_cast<Role>(*role);
  }
  if (auto value = reader->u64(kFieldAgentId); value.has_value()) {
    agent_id_ = AgentId::from_value(*value);
  }
  if (auto value = reader->u64(kFieldBootId); value.has_value()) {
    boot_id_ = AgentBootId::from_value(*value);
  }
  return Status{};
}

void ControlClient::close() {
  const Status ignored = channel_.close();
  (void)ignored;
}

Status ControlClient::goodbye() {
  if (!channel_.open()) return Status{};
  FieldWriter fields;
  const RequestId request = next_request();
  const std::vector<Byte> payload = fields.take();
  const Status sent = channel_.send(static_cast<std::uint16_t>(MessageType::Goodbye), request,
                                    ByteSpan{payload.data(), payload.size()}, 0);
  const Status closed = channel_.close();
  if (!sent.ok()) return sent;
  return closed;
}

Result<FieldReader> ControlClient::call(MessageType type, const FieldWriter& fields, RequestId request) {
  if (is_response(type)) {
    return Status(StatusCode::InvalidArgument, "cannot send a response message as a request");
  }
  if (!channel_.open()) return Status(StatusCode::ConnectionLost, "client is not connected");
  const std::vector<Byte> payload = fields.take();
  const Status sent = channel_.send(static_cast<std::uint16_t>(type), request, ByteSpan{payload.data(), payload.size()}, 0);
  if (!sent.ok()) return sent;

  for (;;) {
    auto frame = channel_.receive();
    if (!frame.ok()) return frame.status();
    if ((frame->header.flags & kFlagResponse) == 0) {
      // A request arrived while one of our own requests was outstanding.
      if (!inbound_) {
        return Status(StatusCode::ProtocolViolation,
                      "received request " +
                          std::string(message_name(static_cast<MessageType>(frame->header.type))) +
                          " while awaiting a response, and no inbound handler is installed");
      }
      inbound_(*frame);
      continue;
    }
    if (frame->header.request != request.value()) {
      return Status(StatusCode::ProtocolViolation,
                    "response carried request identity " + std::to_string(frame->header.request) + " while " +
                        std::to_string(request.value()) + " was outstanding");
    }
    const MessageType declared = static_cast<MessageType>(frame->header.type);
    if (declared != response_for(type)) {
      return Status(StatusCode::ProtocolViolation,
                    "response message " + std::string(message_name(declared)) + " does not answer request " +
                        std::string(message_name(type)));
    }
    if ((frame->header.flags & kFlagError) != 0) {
      auto decoded = decode_error_payload(ByteSpan{frame->payload.data(), frame->payload.size()});
      if (!decoded.ok()) return decoded.status();
      return Status(decoded->first, decoded->second);
    }
    return FieldReader::create(ByteSpan{frame->payload.data(), frame->payload.size()});
  }
}

Result<FieldReader> ControlClient::call(MessageType type, const FieldWriter& fields) {
  return call(type, fields, next_request());
}

std::string render_virtual_view(const VirtualView& view) {
  std::string out;
  out.reserve(1024);
  auto line = [&out](std::string_view key, std::string_view value) {
    out.append("  ");
    out.append(key);
    out.append(": ");
    out.append(value);
    out.push_back('\n');
  };
  out.append("virtual ").append(view.id.str()).push_back('\n');
  line("name", view.name);
  line("generation", view.generation.str());
  line("lifecycle", lifecycle_name(view.state));
  line("state_generation", view.state_generation.str());
  line("state_reason", view.state_reason);
  line("owner", view.owner.str());
  line("owner_generation", view.owner_generation.str());
  line("multiplexing", multiplexing_name(view.multiplexing));
  line("isolation_class", isolation_class_name(view.isolation_class));
  line("attachments", std::to_string(view.active_attachments));
  line("allocated_bytes", std::to_string(view.allocated_bytes));
  line("transparency", transparency_name(view.transparency));
  line("backing_disclosed", view.backing_disclosed ? "true" : "false");
  line("backing_class", backing_class_name(view.backing_class));
  line("backing_provenance", provenance_name(view.backing_provenance));
  line("backing_mechanism", view.backing_mechanism);
  line("backing_generation", view.backing_generation.str());
  if (view.backing_disclosed && view.backing.valid()) line("backing", view.backing.str());
  line("physical_generation", view.physical_generation.str());
  if (view.backing_disclosed && view.physical.valid()) line("physical", view.physical.str());
  if (!view.physical_stable_key.empty()) line("physical_stable_key", view.physical_stable_key);
  if (!view.physical_model.empty()) line("physical_model", view.physical_model);
  line("migration_class", migration_class_name(view.migration_class));
  line("migration_supported", view.migration_supported ? "true" : "false");
  line("has_active_migration", view.has_active_migration ? "true" : "false");
  line("contract_generation", view.contract.generation.str());
  line("contract_memory_ceiling_bytes", std::to_string(view.contract.memory_ceiling_bytes));
  line("contract_compute_share_milli", std::to_string(view.contract.compute_share_milli));
  line("projection_generation", view.projection.generation.str());
  line("projection_fingerprint", std::to_string(view.projection.fingerprint));
  return out;
}

std::string render_accounting(const AccountingCounters& counters) { return accounting_canonical(counters); }

std::string render_audit_report(const AuditReport& report) { return report.canonical(); }

}  // namespace av
