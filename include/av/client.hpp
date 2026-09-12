// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "av/accounting.hpp"
#include "av/audit.hpp"
#include "av/invariant.hpp"
#include "av/model.hpp"
#include "av/protocol.hpp"
#include "av/runtime.hpp"
#include "av/socket.hpp"
#include "av/status.hpp"

namespace av {

struct ClientOptions {
  std::string host{"127.0.0.1"};
  std::uint16_t port{0};
  Role role{Role::Client};
  std::string name{"av-cli"};
};

// Control-plane client. Every call is request/response with an explicit
// request identity, so a response can never be matched to the wrong request.
class ControlClient {
 public:
  ControlClient() = default;
  ~ControlClient();
  ControlClient(ControlClient&&) noexcept;
  ControlClient& operator=(ControlClient&&) noexcept;
  ControlClient(const ControlClient&) = delete;
  ControlClient& operator=(const ControlClient&) = delete;

  static Result<ControlClient> connect(const ClientOptions& options);

  // Performs HELLO. Validates protocol version and records the epoch.
  Status handshake();

  // Sends a request and waits for its response. On a StatusCode failure the
  // returned Result carries that code and the server's detail string.
  Result<FieldReader> call(MessageType type, const FieldWriter& fields, RequestId request);
  Result<FieldReader> call(MessageType type, const FieldWriter& fields);

  Status goodbye();
  void close();
  bool open() const noexcept { return channel_.open(); }

  // Installed by an agent so coordinator-directed requests can be answered
  // while one of the agent's own requests is outstanding. The handler owns the
  // reply and may call channel().send(...) itself.
  using InboundHandler = std::function<void(const FrameStream::Frame&)>;
  void set_inbound_handler(InboundHandler handler) { inbound_ = std::move(handler); }

  FrameChannel& channel() noexcept { return channel_; }

  CoordinatorEpoch epoch() const noexcept { return epoch_; }
  const std::string& server_name() const noexcept { return server_name_; }
  Role role() const noexcept { return role_; }
  AgentId agent_id() const noexcept { return agent_id_; }
  AgentBootId boot_id() const noexcept { return boot_id_; }
  std::string peer() const { return channel_.peer(); }
  RequestId next_request();
  std::size_t frames_sent() const noexcept { return channel_.frames_sent(); }
  std::size_t frames_received() const noexcept { return channel_.frames_received(); }

 private:
  FrameChannel channel_{};
  std::uint64_t next_request_{1};
  CoordinatorEpoch epoch_{};
  std::string server_name_{};
  std::string client_name_{};
  Role role_{Role::Unknown};
  AgentId agent_id_{};
  AgentBootId boot_id_{};
  InboundHandler inbound_{};
};

// Shared helpers used by the CLI and by the tests to render records
// deterministically.
std::string render_virtual_view(const VirtualView& view);
std::string render_accounting(const AccountingCounters& counters);
std::string render_audit_report(const AuditReport& report);

}  // namespace av
