// Example: drive a running coordinator over the control plane.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Usage: example_control_plane_client --coordinator HOST:PORT
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "av/client.hpp"
#include "av/persistence.hpp"
#include "av/socket.hpp"

namespace {

void say(const std::string& line) {
  std::printf("%s\n", line.c_str());
  std::fflush(stdout);
}

int fail(const std::string& message) {
  std::fprintf(stderr, "example failed: %s\n", message.c_str());
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--coordinator" && i + 1 < argc) {
      const std::string endpoint = argv[++i];
      const std::size_t colon = endpoint.rfind(':');
      if (colon == std::string::npos) return fail("--coordinator expects HOST:PORT");
      host = endpoint.substr(0, colon);
      port = static_cast<std::uint16_t>(std::strtoul(endpoint.c_str() + colon + 1, nullptr, 10));
    }
  }
  if (port == 0) return fail("--coordinator HOST:PORT is required");

  av::ClientOptions options;
  options.host = host;
  options.port = port;
  options.name = "example-client";
  auto connected = av::ControlClient::connect(options);
  if (!connected.ok()) return fail(connected.status().to_string());
  av::ControlClient client = connected.take();
  say("connected to " + client.peer() + " epoch " + client.epoch().str());

  auto call = [&client](av::MessageType type, const av::FieldWriter& fields) {
    auto response = client.call(type, fields);
    if (!response.ok()) return std::make_pair(false, response.status().to_string());
    return std::make_pair(true, std::string{});
  };

  av::FieldWriter create_tenant;
  create_tenant.str(av::kFieldTenantName, "control-plane-tenant");
  auto tenant = client.call(av::MessageType::CreateTenant, create_tenant);
  if (!tenant.ok()) return fail(tenant.status().to_string());
  const std::uint64_t tenant_id = tenant->u64(av::kFieldTenantId).value_or(0);
  say("tenant " + std::to_string(tenant_id) + " generation 1");

  av::ResourceContract contract;
  contract.memory_ceiling_bytes = 1u << 20;
  contract.compute_share_milli = 500;
  contract.migration_allowed = true;
  contract.allowed_migration_classes = {av::MigrationClass::RebindOnly};
  contract.normalize();
  const std::vector<av::Byte> blob = av::encode_contract_blob(contract);
  av::FieldWriter create_virtual;
  create_virtual.str(av::kFieldVirtualName, "control-plane-va");
  create_virtual.u64(av::kFieldTenantId, tenant_id);
  create_virtual.u64(av::kFieldTenantGeneration, 1);
  create_virtual.bytes(av::kFieldContractBlob, av::ByteSpan{blob.data(), blob.size()});
  auto created = client.call(av::MessageType::CreateVirtual, create_virtual);
  if (!created.ok()) return fail(created.status().to_string());
  say("virtual " + std::to_string(created->u64(av::kFieldVirtualId).value_or(0)) + " generation " +
      std::to_string(created->u64(av::kFieldVirtualGeneration).value_or(0)));

  av::FieldWriter backings;
  auto listed = client.call(av::MessageType::ListBackings, backings);
  if (!listed.ok()) return fail(listed.status().to_string());
  std::size_t available = 0;
  for (const auto& entry : listed->nested_list(av::kFieldBlobs)) {
    if (!entry.ok()) continue;
    auto record_blob = entry->bytes(av::kFieldBackingBlob);
    if (!record_blob.has_value()) continue;
    auto record = av::decode_backing_record(*record_blob);
    if (!record.ok()) continue;
    ++available;
  }
  say("backings visible: " + std::to_string(available));

  av::FieldWriter audit;
  auto report = client.call(av::MessageType::Audit, audit);
  if (!report.ok()) return fail(report.status().to_string());
  say("audit violations: " + std::to_string(report->u64(av::kFieldViolationCount).value_or(99)));
  say("state fingerprint: " + std::to_string(report->u64(av::kFieldDigest).value_or(0)));
  return report->boolean(av::kFieldClean).value_or(false) ? 0 : 1;
}
