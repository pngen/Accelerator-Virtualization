// Accelerator Virtualization agent.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// An agent owns accelerator-bearing host integrations. It presents physical
// devices to the coordinator and executes device operations the coordinator
// has already authorised. It holds no virtualization authority of its own.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "av/client.hpp"
#include "av/persistence.hpp"
#include "av/socket.hpp"
#include "av/synthetic.hpp"
#include "proto_util.hpp"

#ifdef AV_WITH_CUDA
#include "av/cuda.hpp"
#endif

namespace {

using av::Byte;
using av::ByteSpan;
using av::FieldReader;
using av::FieldWriter;
using av::StatusCode;
using av::Status;
using av::app::Response;

struct Options {
  std::string host{"127.0.0.1"};
  std::uint16_t port{0};
  std::string name{"av-agent"};
  std::string backends{"synthetic"};
  bool probe_only{false};
};

void print_usage() {
  std::fputs(
      "av_agent - Accelerator Virtualization host integration\n"
      "\n"
      "  --coordinator HOST:PORT   coordinator endpoint (required)\n"
      "  --name NAME               agent name\n"
      "  --backends LIST           comma separated: synthetic, cuda\n"
      "  --probe-only              discover and print devices, then exit\n",
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
    if (arg == "--help" || arg == "-h") {
      print_usage();
      return false;
    }
    if (arg == "--coordinator") {
      std::string endpoint;
      if (!next(endpoint)) return false;
      const std::size_t colon = endpoint.rfind(':');
      if (colon == std::string::npos) {
        std::fprintf(stderr, "av_agent: --coordinator expects HOST:PORT\n");
        return false;
      }
      options.host = endpoint.substr(0, colon);
      options.port = static_cast<std::uint16_t>(std::strtoul(endpoint.c_str() + colon + 1, nullptr, 10));
    } else if (arg == "--name") {
      if (!next(options.name)) return false;
    } else if (arg == "--backends") {
      if (!next(options.backends)) return false;
    } else if (arg == "--probe-only") {
      options.probe_only = true;
    } else {
      std::fprintf(stderr, "av_agent: unrecognised argument '%s'\n", argv[i]);
      return false;
    }
  }
  if (options.port == 0) {
    std::fprintf(stderr, "av_agent: --coordinator HOST:PORT is required\n");
    return false;
  }
  return true;
}

std::vector<std::string> split_list(const std::string& text) {
  std::vector<std::string> out;
  std::string current;
  for (char c : text) {
    if (c == ',') {
      if (!current.empty()) out.push_back(current);
      current.clear();
    } else if (c != ' ') {
      current.push_back(c);
    }
  }
  if (!current.empty()) out.push_back(current);
  return out;
}

// The agent answers execution requests with device work only. It never decides
// whether an operation is authorised: the coordinator decided that already.
Response execute_on_backend(av::BackendAdapter& backend, const FieldReader& reader) {
  av::ExecutionRequest request;
  auto op_value = reader.require_u64(av::kFieldOp);
  if (!op_value.ok()) return Response::failure(op_value.status());
  if (*op_value > static_cast<std::uint64_t>(av::ExecutionOp::DeviceInfo)) {
    return Response::failure(StatusCode::ProtocolViolation, "execution operation is outside its domain");
  }
  request.op = static_cast<av::ExecutionOp>(*op_value);
  if (auto value = reader.str(av::kFieldStableKey); value.has_value()) request.stable_key = *value;
  if (auto value = reader.u64(av::kFieldPhysicalId); value.has_value()) {
    request.physical = av::PhysicalDeviceId::from_value(*value);
  }
  if (auto value = reader.u64(av::kFieldBytes); value.has_value()) request.bytes = *value;
  if (auto value = reader.u64(av::kFieldHandle); value.has_value()) request.handle = *value;
  if (auto value = reader.u64(av::kFieldCount); value.has_value()) {
    request.count = static_cast<std::uint32_t>(*value);
  }
  if (auto values = reader.list_u64(av::kFieldHandles); values.has_value()) request.handles = *values;
  if (auto blob = reader.bytes(av::kFieldData); blob.has_value()) request.data = av::to_byte_values(*blob);

  auto outcome = backend.execute(request);
  if (!outcome.ok()) return Response::failure(outcome.status());
  if (outcome->status != StatusCode::Ok) {
    return Response::failure(outcome->status, outcome->detail);
  }
  FieldWriter writer;
  writer.u64(av::kFieldStatus, static_cast<std::uint64_t>(outcome->status));
  writer.u64(av::kFieldHandle, outcome->handle);
  writer.u64(av::kFieldBytes, outcome->bytes);
  if (outcome->total_memory != 0) writer.u64(av::kFieldDeviceMemoryTotal, outcome->total_memory);
  if (outcome->free_memory != 0) writer.u64(av::kFieldDeviceMemoryFree, outcome->free_memory);
  if (!outcome->detail.empty()) writer.str(av::kFieldDetail, outcome->detail);
  if (!outcome->data.empty()) {
    writer.bytes(av::kFieldData, av::byte_span(outcome->data));
  }
  return av::app::blob_response(writer);
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!parse_options(argc, argv, options)) return 2;

  std::vector<std::unique_ptr<av::BackendAdapter>> adapters;
  for (const std::string& name : split_list(options.backends)) {
    if (name == "synthetic") {
      auto created = av::make_synthetic_backends();
      for (auto& adapter : created) adapters.push_back(std::move(adapter));
    } else if (name == "cuda") {
#ifdef AV_WITH_CUDA
      adapters.push_back(av::make_cuda_backend());
#else
      std::fprintf(stderr, "av_agent: this build has no CUDA adapter; 'cuda' was not compiled in\n");
      return 2;
#endif
    } else {
      std::fprintf(stderr, "av_agent: unknown backend '%s'\n", name.c_str());
      return 2;
    }
  }
  if (adapters.empty()) {
    std::fprintf(stderr, "av_agent: no backend was selected\n");
    return 2;
  }

  struct Discovery {
    av::BackendAdapter* adapter{nullptr};
    av::PhysicalDeviceDescriptor descriptor{};
  };
  std::vector<Discovery> discoveries;
  std::map<std::string, av::BackendAdapter*> by_key;
  for (auto& adapter : adapters) {
    auto found = adapter->discover();
    if (!found.ok()) {
      std::fprintf(stderr, "av_agent: %s discovery failed: %s\n", adapter->name().c_str(),
                   found.status().to_string().c_str());
      continue;
    }
    for (const av::PhysicalDeviceDescriptor& descriptor : found.value()) {
      discoveries.push_back(Discovery{adapter.get(), descriptor});
      by_key[descriptor.stable_key] = adapter.get();
    }
  }
  for (const Discovery& discovery : discoveries) {
    std::printf("AV_AGENT DEVICE key=%s provenance=%s model=%s memory=%llu backings=%zu\n",
                discovery.descriptor.stable_key.c_str(),
                std::string(av::provenance_name(discovery.descriptor.provenance)).c_str(),
                discovery.descriptor.model.c_str(),
                static_cast<unsigned long long>(discovery.descriptor.memory_total_bytes),
                discovery.descriptor.backings.size());
  }
  std::fflush(stdout);
  if (options.probe_only) return discoveries.empty() ? 1 : 0;

  av::ClientOptions client_options;
  client_options.host = options.host;
  client_options.port = options.port;
  client_options.role = av::Role::Agent;
  client_options.name = options.name;

  auto client_result = av::ControlClient::connect(client_options);
  if (!client_result.ok()) {
    std::fprintf(stderr, "av_agent: %s\n", client_result.status().to_string().c_str());
    return 1;
  }
  av::ControlClient client = client_result.take();

  const av::AgentId agent_id = client.agent_id();
  const av::AgentBootId boot_id = client.boot_id();
  if (!agent_id.valid() || !boot_id.valid()) {
    std::fprintf(stderr, "av_agent: the coordinator did not issue an agent boot identity\n");
    return 1;
  }

  auto respond = [&client](const av::FrameStream::Frame& frame, const Response& response) {
    const Status sent = client.channel().send(
        static_cast<std::uint16_t>(
            av::response_for(static_cast<av::MessageType>(frame.header.type))),
        av::RequestId::from_value(frame.header.request),
        ByteSpan{response.payload.data(), response.payload.size()}, response.flags | av::kFlagResponse);
    return sent;
  };

  auto handle_inbound = [&](const av::FrameStream::Frame& frame) {
    const auto type = static_cast<av::MessageType>(frame.header.type);
    Response response;
    if (type == av::MessageType::AgentExecute) {
      auto reader = FieldReader::create(ByteSpan{frame.payload.data(), frame.payload.size()});
      if (!reader.ok()) {
        response = Response::failure(reader.status());
      } else {
        const std::string key = reader->str(av::kFieldStableKey).value_or(std::string{});
        const auto it = by_key.find(key);
        if (it == by_key.end()) {
          response = Response::failure(StatusCode::BackingUnavailable,
                                       "this agent does not own physical device '" + key + "'");
        } else {
          response = execute_on_backend(*it->second, reader.value());
        }
      }
    } else if (type == av::MessageType::Heartbeat) {
      FieldWriter writer;
      writer.u64(av::kFieldEpoch, client.epoch().value());
      response = av::app::blob_response(writer);
    } else {
      response = Response::failure(StatusCode::UnsupportedMessage,
                                   "message " + std::string(av::message_name(type)) +
                                       " is not handled by an agent");
    }
    const Status ignored = respond(frame, response);
    (void)ignored;
  };

  client.set_inbound_handler(handle_inbound);

  std::printf("AV_AGENT CONNECTED name=%s agent=%s boot=%s epoch=%s peer=%s\n", options.name.c_str(),
              agent_id.str().c_str(), boot_id.str().c_str(), client.epoch().str().c_str(),
              client.peer().c_str());
  std::fflush(stdout);

  std::size_t registered = 0;
  for (const Discovery& discovery : discoveries) {
    FieldWriter fields;
    fields.u64(av::kFieldAgentId, agent_id.value());
    fields.u64(av::kFieldBootId, boot_id.value());
    const std::vector<Byte> blob = av::app::encode_physical_descriptor(discovery.descriptor);
    fields.bytes(av::kFieldDescriptorBlob, ByteSpan{blob.data(), blob.size()});
    auto response = client.call(av::MessageType::RegisterPhysical, fields);
    if (!response.ok()) {
      std::fprintf(stderr, "av_agent: registering %s failed: %s\n", discovery.descriptor.stable_key.c_str(),
                   response.status().to_string().c_str());
      continue;
    }
    ++registered;
    std::printf("AV_AGENT REGISTERED key=%s physical=%s generation=%s\n", discovery.descriptor.stable_key.c_str(),
                std::to_string(response->u64(av::kFieldPhysicalId).value_or(0)).c_str(),
                std::to_string(response->u64(av::kFieldPhysicalGeneration).value_or(0)).c_str());
    std::fflush(stdout);
  }
  if (registered == 0) {
    std::fprintf(stderr, "av_agent: no physical device could be registered\n");
    return 1;
  }
  std::printf("AV_AGENT READY registered=%zu\n", registered);
  std::fflush(stdout);

  for (;;) {
    auto frame = client.channel().receive();
    if (!frame.ok()) {
      std::printf("AV_AGENT DISCONNECTED reason=%s\n", frame.status().to_string().c_str());
      std::fflush(stdout);
      break;
    }
    if ((frame->header.flags & av::kFlagResponse) != 0) {
      // Nothing in this agent is synchronous at this point, so a stray
      // response means the coordinator answered something already settled.
      continue;
    }
    const auto type = static_cast<av::MessageType>(frame->header.type);
    if (type == av::MessageType::Goodbye) break;
    if (type == av::MessageType::Shutdown) {
      FieldWriter writer;
      const std::vector<Byte> payload = writer.take();
      const Status ignored = respond(*frame, Response::ok(payload));
      (void)ignored;
      std::printf("AV_AGENT SHUTDOWN\n");
      std::fflush(stdout);
      break;
    }
    handle_inbound(*frame);
  }
  client.close();
  return 0;
}
