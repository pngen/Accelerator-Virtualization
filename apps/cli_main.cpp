// Accelerator Virtualization command line interface.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "av/client.hpp"
#include "av/persistence.hpp"
#include "av/socket.hpp"
#include "proto_util.hpp"

namespace {

using av::Byte;
using av::ByteSpan;
using av::FieldReader;
using av::FieldWriter;
using av::StatusCode;
using av::Status;

struct Command {
  std::string name;
  std::vector<std::string> positional;
  std::map<std::string, std::string> flags;

  bool has(const std::string& key) const { return flags.find(key) != flags.end(); }
  std::string get(const std::string& key, const std::string& fallback = {}) const {
    const auto it = flags.find(key);
    return it == flags.end() ? fallback : it->second;
  }
  std::uint64_t number(const std::string& key, std::uint64_t fallback = 0) const {
    const auto it = flags.find(key);
    if (it == flags.end()) return fallback;
    return std::strtoull(it->second.c_str(), nullptr, 10);
  }
  bool flag(const std::string& key) const { return has(key); }
};

template <class IdT>
std::optional<IdT> parse_typed(const std::string& text) {
  return IdT::parse(text);
}

int fail_usage(const std::string& detail) {
  std::fprintf(stderr, "av_cli: %s\n", detail.c_str());
  return 2;
}

int fail_status(const Status& status) {
  std::printf("ERROR %s %s\n", std::string(av::code_name(status.code())).c_str(), status.detail().c_str());
  std::fflush(stdout);
  return 1;
}

av::Authority authority_from(const Command& command, const av::ControlClient& client) {
  av::Authority authority;
  authority.epoch = av::CoordinatorEpoch::from_value(command.number("epoch", client.epoch().value()));
  authority.policy_generation = av::PolicyGeneration::from_value(command.number("policy-generation", 0));
  if (!authority.policy_generation->valid()) authority.policy_generation.reset();
  if (command.has("tenant")) {
    if (auto id = parse_typed<av::TenantId>(command.get("tenant")); id.has_value()) authority.tenant = *id;
  }
  if (command.has("tenant-generation")) {
    authority.tenant_generation = av::TenantGeneration::from_value(command.number("tenant-generation"));
  }
  if (command.has("virtual")) {
    if (auto id = parse_typed<av::VirtualAcceleratorId>(command.get("virtual")); id.has_value()) {
      authority.virtual_id = *id;
    }
  }
  if (command.has("virtual-generation")) {
    authority.virtual_generation = av::VirtualAcceleratorGeneration::from_value(command.number("virtual-generation"));
  }
  if (command.has("lease")) {
    if (auto id = parse_typed<av::LeaseId>(command.get("lease")); id.has_value()) authority.lease = *id;
  }
  if (command.has("lease-generation")) {
    authority.lease_generation = av::LeaseGeneration::from_value(command.number("lease-generation"));
  }
  if (command.has("migration")) {
    if (auto id = parse_typed<av::MigrationId>(command.get("migration")); id.has_value()) authority.migration = *id;
  }
  if (command.has("migration-generation")) {
    authority.migration_generation = av::MigrationGeneration::from_value(command.number("migration-generation"));
  }
  return authority;
}

av::ResourceContract contract_from(const Command& command) {
  av::ResourceContract contract;
  contract.memory_ceiling_bytes = command.number("memory-bytes", 0);
  contract.compute_share_milli = static_cast<std::uint32_t>(command.number("compute-share-milli", 0));
  contract.max_streams = static_cast<std::uint32_t>(command.number("max-streams", 0));
  contract.max_concurrency = static_cast<std::uint32_t>(command.number("max-concurrency", 0));
  contract.exclusivity_required = command.flag("exclusive");
  contract.migration_allowed = !command.flag("no-migration");
  if (contract.migration_allowed) {
    contract.allowed_migration_classes.push_back(av::MigrationClass::RebindOnly);
    contract.allowed_migration_classes.push_back(av::MigrationClass::DrainAndRestart);
  }
  contract.oversubscription_allowed = command.flag("allow-oversubscription");
  contract.normalize();
  return contract;
}

int print_status_result(const Status& status) {
  if (!status.ok()) return fail_status(status);
  return 0;
}

// ---- command implementations --------------------------------------------

int cmd_version() {
  std::printf("accelerator-virtualization %s protocol=%u schema=%u\n", std::string(av::version_string()).c_str(),
              static_cast<unsigned>(av::protocol_version()), static_cast<unsigned>(av::schema_version()));
  return 0;
}

int cmd_policy_show(av::ControlClient& client) {
  FieldWriter fields;
  auto response = client.call(av::MessageType::GetPolicy, fields);
  if (!response.ok()) return fail_status(response.status());
  auto blob = response->bytes(av::kFieldPolicyBlob);
  if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "no policy was returned"));
  auto policy = av::decode_policy_blob(*blob);
  if (!policy.ok()) return fail_status(policy.status());
  std::printf("%s", policy->canonical().c_str());
  std::printf("policy_id=%s\n", policy->id.str().c_str());
  std::printf("policy_generation=%s\n", policy->generation.str().c_str());
  return 0;
}

int cmd_policy_set(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  auto current = client.call(av::MessageType::GetPolicy, fields);
  if (!current.ok()) return fail_status(current.status());
  auto blob = current->bytes(av::kFieldPolicyBlob);
  if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "no policy was returned"));
  auto decoded = av::decode_policy_blob(*blob);
  if (!decoded.ok()) return fail_status(decoded.status());
  av::VirtualizationPolicy policy = decoded.take();
  if (command.has("transparency")) {
    auto mode = av::parse_transparency(command.get("transparency"));
    if (!mode.has_value()) return fail_usage("unknown transparency mode");
    policy.transparency = *mode;
  }
  if (command.has("synthetic")) policy.synthetic_backing_allowed = command.get("synthetic") != "off";
  if (command.has("evidence-max-age-us")) policy.evidence_max_age_micros = command.number("evidence-max-age-us");
  policy.normalize();
  FieldWriter update;
  const std::vector<Byte> encoded = av::encode_policy_blob(policy);
  update.bytes(av::kFieldPolicyBlob, ByteSpan{encoded.data(), encoded.size()});
  auto response = client.call(av::MessageType::SetPolicy, update);
  if (!response.ok()) return fail_status(response.status());
  std::printf("policy_generation=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldPolicyGeneration).value_or(0)));
  return 0;
}

int cmd_tenant_create(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  fields.str(av::kFieldTenantName, command.get("name"));
  fields.str(av::kFieldExternalSubject, command.get("subject"));
  auto response = client.call(av::MessageType::CreateTenant, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("tenant=%llu tenant_generation=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldTenantId).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldTenantGeneration).value_or(0)));
  return 0;
}

int cmd_tenant_list(av::ControlClient& client) {
  FieldWriter fields;
  auto response = client.call(av::MessageType::ListTenants, fields);
  if (!response.ok()) return fail_status(response.status());
  for (const auto& entry : response->nested_list(av::kFieldBlobs)) {
    if (!entry.ok()) return fail_status(entry.status());
    auto blob = entry->bytes(av::kFieldTenantBlob);
    if (!blob.has_value()) continue;
    auto record = av::decode_tenant_record(*blob);
    if (!record.ok()) return fail_status(record.status());
    std::printf("tenant=%s generation=%s name=%s fenced=%s attachments=%u\n", record->id.str().c_str(),
                record->generation.str().c_str(), record->name.c_str(), record->fenced ? "true" : "false",
                record->active_attachments);
  }
  return 0;
}

int cmd_tenant_fence(av::ControlClient& client, const Command& command) {
  auto authority = authority_from(command, client);
  FieldWriter fields;
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  fields.str(av::kFieldReason, command.get("reason", "fenced by operator"));
  auto response = client.call(av::MessageType::FenceTenant, fields);
  return print_status_result(response.ok() ? Status{} : response.status());
}

int cmd_virtual_create(av::ControlClient& client, const Command& command) {
  av::ResourceContract contract = contract_from(command);
  FieldWriter fields;
  fields.str(av::kFieldVirtualName, command.get("name"));
  fields.u64(av::kFieldTenantId, command.number("tenant-id"));
  fields.u64(av::kFieldTenantGeneration, command.number("tenant-generation"));
  const std::vector<Byte> blob = av::encode_contract_blob(contract);
  fields.bytes(av::kFieldContractBlob, ByteSpan{blob.data(), blob.size()});
  auto response = client.call(av::MessageType::CreateVirtual, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("virtual=%llu virtual_generation=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldVirtualId).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldVirtualGeneration).value_or(0)));
  return 0;
}

int cmd_virtual_list(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  if (!command.flag("all")) fields.u64(av::kFieldTenantId, command.number("tenant-id", 0));
  auto response = client.call(av::MessageType::ListVirtual, fields);
  if (!response.ok()) return fail_status(response.status());
  std::size_t count = 0;
  for (const auto& entry : response->nested_list(av::kFieldBlobs)) {
    if (!entry.ok()) return fail_status(entry.status());
    auto blob = entry->bytes(av::kFieldViewBlob);
    if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "a view blob is missing"));
    auto view = av::decode_view(*blob);
    if (!view.ok()) return fail_status(view.status());
    std::printf("%s %s %s owner=%s attachments=%u backing_generation=%s multiplexing=%s isolation=%s\n",
                view->id.str().c_str(), view->generation.str().c_str(),
                std::string(av::lifecycle_name(view->state)).c_str(), view->owner.str().c_str(),
                view->active_attachments, view->backing_generation.str().c_str(),
                std::string(av::multiplexing_name(view->multiplexing)).c_str(),
                std::string(av::isolation_class_name(view->isolation_class)).c_str());
    ++count;
  }
  std::printf("virtual_count=%zu\n", count);
  return 0;
}

int cmd_virtual_show(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, command.number("virtual"));
  fields.u64(av::kFieldLeaseId, command.number("lease"));
  auto response = client.call(av::MessageType::Query, fields);
  if (!response.ok()) return fail_status(response.status());
  auto blob = response->bytes(av::kFieldViewBlob);
  if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "a view blob is missing"));
  auto view = av::decode_view(*blob);
  if (!view.ok()) return fail_status(view.status());
  std::printf("%s", av::render_virtual_view(*view).c_str());
  return 0;
}

int cmd_virtual_command(av::ControlClient& client, const Command& command, av::MessageType type) {
  auto authority = authority_from(command, client);
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
  fields.u64(av::kFieldVirtualGeneration,
             authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  fields.str(av::kFieldReason, command.get("reason", "operator request"));
  auto response = client.call(type, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("virtual_generation=%llu state_generation=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldVirtualGeneration).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldStateGeneration).value_or(0)));
  return 0;
}

int cmd_contract_show(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, command.number("virtual"));
  auto response = client.call(av::MessageType::ContractShow, fields);
  if (!response.ok()) return fail_status(response.status());
  auto blob = response->bytes(av::kFieldContractBlob);
  if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "a contract blob is missing"));
  auto contract = av::decode_contract_blob(*blob);
  if (!contract.ok()) return fail_status(contract.status());
  std::printf("%s", contract->canonical().c_str());
  std::printf("contract_id=%s\ncontract_generation=%s\n", contract->id.str().c_str(),
              contract->generation.str().c_str());
  return 0;
}

int cmd_contract_update(av::ControlClient& client, const Command& command) {
  av::ResourceContract contract = contract_from(command);
  contract.id = av::ResourceContractId::from_value(command.number("contract-id"));
  contract.generation = av::ResourceContractGeneration::from_value(command.number("contract-generation"));
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, command.number("virtual"));
  fields.u64(av::kFieldVirtualGeneration, command.number("virtual-generation"));
  fields.u64(av::kFieldTenantId, command.number("tenant-id"));
  fields.u64(av::kFieldTenantGeneration, command.number("tenant-generation"));
  const std::vector<Byte> blob = av::encode_contract_blob(contract);
  fields.bytes(av::kFieldContractBlob, ByteSpan{blob.data(), blob.size()});
  auto response = client.call(av::MessageType::UpdateContract, fields);
  return print_status_result(response.ok() ? Status{} : response.status());
}

int cmd_capability_show(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, command.number("virtual"));
  auto response = client.call(av::MessageType::CapabilityShow, fields);
  if (!response.ok()) return fail_status(response.status());
  auto blob = response->bytes(av::kFieldProjectionBlob);
  if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "a projection blob is missing"));
  auto projection = av::app::decode_projection_blob(*blob);
  if (!projection.ok()) return fail_status(projection.status());
  std::printf("projection=%s generation=%s fingerprint=%llu mechanism=%s\n", projection->id.str().c_str(),
              projection->generation.str().c_str(),
              static_cast<unsigned long long>(projection->fingerprint), projection->mechanism.c_str());
  std::printf("%s", projection->surface.canonical().c_str());
  for (av::CapabilityKey key : projection->hidden) {
    std::printf("hidden=%s\n", std::string(av::capability_key_name(key)).c_str());
  }
  for (av::CapabilityKey key : projection->unknown) {
    std::printf("unknown=%s\n", std::string(av::capability_key_name(key)).c_str());
  }
  return 0;
}

int cmd_backing_list(av::ControlClient& client) {
  FieldWriter fields;
  auto response = client.call(av::MessageType::ListBackings, fields);
  if (!response.ok()) return fail_status(response.status());
  std::size_t count = 0;
  for (const auto& entry : response->nested_list(av::kFieldBlobs)) {
    if (!entry.ok()) return fail_status(entry.status());
    auto blob = entry->bytes(av::kFieldBackingBlob);
    if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "a backing blob is missing"));
    auto backing = av::decode_backing_record(*blob);
    if (!backing.ok()) return fail_status(backing.status());
    std::printf(
        "backing=%s class=%s provenance=%s multiplexing=%s isolation_class=%s available=%s exclusive=%s "
        "capacity=%llu mechanism=%s\n",
        backing->id.str().c_str(), std::string(av::backing_class_name(backing->klass)).c_str(),
        std::string(av::provenance_name(backing->provenance)).c_str(),
        std::string(av::multiplexing_name(backing->multiplexing)).c_str(),
        std::string(av::isolation_class_name(backing->isolation_class)).c_str(),
        backing->available ? "true" : "false", backing->exclusive ? "true" : "false",
        static_cast<unsigned long long>(backing->capacity_bytes), backing->mechanism.c_str());
    ++count;
  }
  std::printf("backing_count=%zu\n", count);
  return 0;
}

int cmd_physical_list(av::ControlClient& client) {
  FieldWriter fields;
  auto response = client.call(av::MessageType::ListPhysical, fields);
  if (!response.ok()) return fail_status(response.status());
  std::size_t count = 0;
  for (const auto& entry : response->nested_list(av::kFieldBlobs)) {
    if (!entry.ok()) return fail_status(entry.status());
    auto blob = entry->bytes(av::kFieldPhysicalBlob);
    if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "a physical blob is missing"));
    auto record = av::decode_physical_record(*blob);
    if (!record.ok()) return fail_status(record.status());
    std::printf("physical=%s generation=%s stable_key=%s provenance=%s model=%s present=%s\n",
                record->id.str().c_str(), record->generation.str().c_str(), record->stable_key.c_str(),
                std::string(av::provenance_name(record->provenance)).c_str(), record->model.c_str(),
                record->present ? "true" : "false");
    ++count;
  }
  std::printf("physical_count=%zu\n", count);
  return 0;
}

int cmd_backing_assign(av::ControlClient& client, const Command& command, bool replacing) {
  auto authority = authority_from(command, client);
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
  fields.u64(av::kFieldVirtualGeneration,
             authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  if (auto backing = parse_typed<av::BackingId>(command.get("backing")); backing.has_value()) {
    fields.u64(av::kFieldBackingId, backing->value());
  } else {
    return fail_usage("--backing requires a backing identity such as bk-0000000000000001");
  }
  fields.str(av::kFieldReason, command.get("reason", "operator request"));
  auto response = client.call(replacing ? av::MessageType::ReplaceBacking : av::MessageType::AssignBacking, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("backing=%llu backing_generation=%llu virtual_generation=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldBackingId).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldBackingGeneration).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldVirtualGeneration).value_or(0)));
  return 0;
}

int cmd_attach(av::ControlClient& client, const Command& command) {
  auto authority = authority_from(command, client);
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
  fields.u64(av::kFieldVirtualGeneration,
             authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  auto response = client.call(av::MessageType::Attach, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("lease=%llu lease_generation=%llu virtual_generation=%llu backing_generation=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldLeaseId).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldLeaseGeneration).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldVirtualGeneration).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldBackingGeneration).value_or(0)));
  return 0;
}

int cmd_lease_command(av::ControlClient& client, const Command& command, av::MessageType type) {
  auto authority = authority_from(command, client);
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
  fields.u64(av::kFieldVirtualGeneration,
             authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  fields.u64(av::kFieldLeaseId, authority.lease.value_or(av::LeaseId{}).value());
  fields.u64(av::kFieldLeaseGeneration, authority.lease_generation.value_or(av::LeaseGeneration{}).value());
  fields.str(av::kFieldReason, command.get("reason", "operator request"));
  auto response = client.call(type, fields);
  if (!response.ok()) return fail_status(response.status());
  if (type == av::MessageType::RenewLease) {
    std::printf("lease_generation=%llu\n",
                static_cast<unsigned long long>(response->u64(av::kFieldLeaseGeneration).value_or(0)));
  } else {
    std::printf("ok\n");
  }
  return 0;
}

int cmd_isolation_explain(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, command.number("virtual"));
  auto response = client.call(av::MessageType::IsolationExplain, fields);
  if (!response.ok()) return fail_status(response.status());
  auto blob = response->bytes(av::kFieldIsolationBlob);
  if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "an isolation blob is missing"));
  auto explanation = av::decode_isolation_explanation(*blob);
  if (!explanation.ok()) return fail_status(explanation.status());
  std::printf("%s", explanation->canonical().c_str());
  return 0;
}

int cmd_migration_explain(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, command.number("virtual"));
  auto response = client.call(av::MessageType::MigrationExplain, fields);
  if (!response.ok()) return fail_status(response.status());
  auto blob = response->bytes(av::kFieldMigrationBlob);
  if (!blob.has_value()) return fail_status(Status(StatusCode::ProtocolViolation, "a migration blob is missing"));
  auto explanation = av::decode_migration_explanation(*blob);
  if (!explanation.ok()) return fail_status(explanation.status());
  std::printf("%s", explanation->canonical().c_str());
  return 0;
}

int cmd_migration_plan(av::ControlClient& client, const Command& command) {
  auto authority = authority_from(command, client);
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
  fields.u64(av::kFieldVirtualGeneration,
             authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  if (auto backing = parse_typed<av::BackingId>(command.get("backing")); backing.has_value()) {
    fields.u64(av::kFieldBackingId, backing->value());
  } else {
    return fail_usage("--backing requires a backing identity");
  }
  auto klass = av::parse_migration_class(command.get("class", "REBIND_ONLY"));
  if (!klass.has_value()) return fail_usage("unknown migration class");
  fields.u64(av::kFieldMigrationClass, static_cast<std::uint64_t>(*klass));
  auto response = client.call(av::MessageType::MigrationPlan, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("migration=%llu migration_generation=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldMigrationId).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldMigrationGeneration).value_or(0)));
  return 0;
}

int cmd_migration_phase(av::ControlClient& client, const Command& command, av::MessageType type) {
  auto authority = authority_from(command, client);
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
  fields.u64(av::kFieldVirtualGeneration,
             authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  fields.u64(av::kFieldMigrationId, authority.migration.value_or(av::MigrationId{}).value());
  fields.u64(av::kFieldMigrationGeneration,
             authority.migration_generation.value_or(av::MigrationGeneration{}).value());
  fields.str(av::kFieldReason, command.get("reason", "operator request"));
  auto response = client.call(type, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("migration=%llu migration_generation=%llu migration_state=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldMigrationId).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldMigrationGeneration).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldState).value_or(0)));
  return 0;
}

int cmd_audit(av::ControlClient& client) {
  FieldWriter fields;
  auto response = client.call(av::MessageType::Audit, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("%s", response->str(av::kFieldText).value_or(std::string{}).c_str());
  return response->boolean(av::kFieldClean).value_or(false) ? 0 : 1;
}

int cmd_snapshot(av::ControlClient& client) {
  FieldWriter fields;
  auto response = client.call(av::MessageType::Snapshot, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("%s", response->str(av::kFieldText).value_or(std::string{}).c_str());
  std::printf("state_fingerprint=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldDigest).value_or(0)));
  return 0;
}

int cmd_accounting(av::ControlClient& client) {
  FieldWriter fields;
  auto response = client.call(av::MessageType::Accounting, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("%s", response->str(av::kFieldText).value_or(std::string{}).c_str());
  return 0;
}

int cmd_decisions(av::ControlClient& client, const Command& command) {
  FieldWriter fields;
  fields.u64(av::kFieldVirtualId, command.number("virtual"));
  fields.u64(av::kFieldLimit, command.number("limit", 16));
  auto response = client.call(av::MessageType::ExplainDecisions, fields);
  if (!response.ok()) return fail_status(response.status());
  for (const auto& entry : response->nested_list(av::kFieldBlobs)) {
    if (!entry.ok()) return fail_status(entry.status());
    auto blob = entry->bytes(av::kFieldDecisionBlob);
    if (!blob.has_value()) continue;
    auto decision = av::decode_decision_record(*blob);
    if (!decision.ok()) return fail_status(decision.status());
    std::printf("decision %s operation=%s outcome=%s reason=%s\n", decision->id.str().c_str(),
                decision->operation.c_str(), std::string(av::code_name(decision->outcome)).c_str(),
                decision->reason.c_str());
    std::printf("  epoch=%s virtual=%s/%s tenant=%s/%s backing=%s/%s policy=%s migration=%s/%s\n",
                decision->epoch.str().c_str(), decision->virtual_id.str().c_str(),
                decision->virtual_generation.str().c_str(), decision->tenant.str().c_str(),
                decision->tenant_generation.str().c_str(), decision->backing.str().c_str(),
                decision->backing_generation.str().c_str(), decision->policy_generation.str().c_str(),
                decision->migration.str().c_str(), decision->migration_generation.str().c_str());
  }
  return 0;
}

int cmd_execute(av::ControlClient& client, const Command& command) {
  auto authority = authority_from(command, client);
  auto op = av::parse_execution_op(command.get("op", "info"));
  if (!op.has_value()) return fail_usage("unknown execution operation");
  FieldWriter fields;
  fields.u64(av::kFieldOp, static_cast<std::uint64_t>(*op));
  fields.u64(av::kFieldEpoch, authority.epoch.value_or(client.epoch()).value());
  fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
  fields.u64(av::kFieldVirtualGeneration,
             authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
  fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
  fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
  fields.u64(av::kFieldLeaseId, authority.lease.value_or(av::LeaseId{}).value());
  fields.u64(av::kFieldLeaseGeneration, authority.lease_generation.value_or(av::LeaseGeneration{}).value());
  fields.u64(av::kFieldBytes, command.number("bytes"));
  fields.u64(av::kFieldHandle, command.number("handle"));
  fields.u64(av::kFieldCount, command.number("count"));
  if (command.has("handles")) {
    std::vector<std::uint64_t> handles;
    std::string current;
    for (char c : command.get("handles") + ",") {
      if (c == ',') {
        if (!current.empty()) handles.push_back(std::strtoull(current.c_str(), nullptr, 10));
        current.clear();
      } else {
        current.push_back(c);
      }
    }
    fields.list_u64(av::kFieldHandles, handles);
  }
  auto response = client.call(av::MessageType::Execute, fields);
  if (!response.ok()) return fail_status(response.status());
  std::printf("handle=%llu bytes=%llu\n",
              static_cast<unsigned long long>(response->u64(av::kFieldHandle).value_or(0)),
              static_cast<unsigned long long>(response->u64(av::kFieldBytes).value_or(0)));
  if (auto total = response->u64(av::kFieldDeviceMemoryTotal); total.has_value()) {
    std::printf("device_memory_total=%llu device_memory_free=%llu\n",
                static_cast<unsigned long long>(*total),
                static_cast<unsigned long long>(response->u64(av::kFieldDeviceMemoryFree).value_or(0)));
  }
  if (auto detail = response->str(av::kFieldDetail); detail.has_value() && !detail->empty()) {
    std::printf("detail=%s\n", detail->c_str());
  }
  return 0;
}

int cmd_cuda_proof(av::ControlClient& client, const Command& command) {
  auto authority = authority_from(command, client);
  const std::uint32_t count = static_cast<std::uint32_t>(command.number("count", 4096));
  if (count == 0 || count > (1u << 26)) return fail_usage("--count is outside the supported range");
  const std::uint64_t bytes = static_cast<std::uint64_t>(count) * sizeof(float);

  auto call = [&](av::ExecutionOp op, std::uint64_t handle, std::uint64_t transfer_bytes,
                  const std::vector<std::uint64_t>& handles, const std::vector<std::uint8_t>& data)
      -> av::Result<FieldReader> {
    FieldWriter fields;
    fields.u64(av::kFieldOp, static_cast<std::uint64_t>(op));
    fields.u64(av::kFieldEpoch, authority.epoch.value_or(client.epoch()).value());
    fields.u64(av::kFieldVirtualId, authority.virtual_id.value_or(av::VirtualAcceleratorId{}).value());
    fields.u64(av::kFieldVirtualGeneration,
               authority.virtual_generation.value_or(av::VirtualAcceleratorGeneration{}).value());
    fields.u64(av::kFieldTenantId, authority.tenant.value_or(av::TenantId{}).value());
    fields.u64(av::kFieldTenantGeneration, authority.tenant_generation.value_or(av::TenantGeneration{}).value());
    fields.u64(av::kFieldLeaseId, authority.lease.value_or(av::LeaseId{}).value());
    fields.u64(av::kFieldLeaseGeneration, authority.lease_generation.value_or(av::LeaseGeneration{}).value());
    fields.u64(av::kFieldBytes, transfer_bytes);
    fields.u64(av::kFieldHandle, handle);
    fields.u64(av::kFieldCount, count);
    fields.list_u64(av::kFieldHandles, handles);
    if (!data.empty()) fields.bytes(av::kFieldData, av::byte_span(data));
    return client.call(av::MessageType::Execute, fields);
  };

  std::printf("cuda_proof begin elements=%u bytes_per_buffer=%llu\n", count,
              static_cast<unsigned long long>(bytes));
  auto info = call(av::ExecutionOp::DeviceInfo, 0, 0, {}, {});
  if (!info.ok()) return fail_status(info.status());
  std::printf("cuda_proof device_info total=%llu free=%llu\n",
              static_cast<unsigned long long>(info->u64(av::kFieldDeviceMemoryTotal).value_or(0)),
              static_cast<unsigned long long>(info->u64(av::kFieldDeviceMemoryFree).value_or(0)));

  std::vector<std::uint64_t> handle_a;
  std::vector<std::uint64_t> handle_b;
  std::vector<std::uint64_t> handle_c;
  auto allocate = [&](std::vector<std::uint64_t>& slot, const char* label) {
    auto response = call(av::ExecutionOp::Allocate, 0, bytes, {}, {});
    if (!response.ok()) {
      std::printf("cuda_proof allocate_failed buffer=%s code=%s\n", label,
                  std::string(av::code_name(response.status().code())).c_str());
      return false;
    }
    const std::uint64_t handle = response->u64(av::kFieldHandle).value_or(0);
    slot.assign(1, handle);
    std::printf("cuda_proof allocated buffer=%s handle=%llu\n", label,
                static_cast<unsigned long long>(handle));
    return true;
  };
  if (!allocate(handle_a, "a") || !allocate(handle_b, "b") || !allocate(handle_c, "c")) return 1;

  std::vector<std::uint8_t> host_a(bytes);
  std::vector<std::uint8_t> host_b(bytes);
  auto* floats_a = reinterpret_cast<float*>(host_a.data());
  auto* floats_b = reinterpret_cast<float*>(host_b.data());
  for (std::uint32_t i = 0; i < count; ++i) {
    floats_a[i] = static_cast<float>(i);
    floats_b[i] = static_cast<float>(2u * i);
  }
  std::printf("cuda_proof host_pattern a[i]=i b[i]=2i\n");

  auto upload = [&](std::uint64_t handle, const std::vector<std::uint8_t>& data, const char* label) {
    auto response = call(av::ExecutionOp::Upload, handle, 0, {}, data);
    if (!response.ok()) {
      std::printf("cuda_proof upload_failed buffer=%s code=%s\n", label,
                  std::string(av::code_name(response.status().code())).c_str());
      return false;
    }
    std::printf("cuda_proof uploaded buffer=%s bytes=%llu\n", label,
                static_cast<unsigned long long>(data.size()));
    return true;
  };
  if (!upload(handle_a[0], host_a, "a") || !upload(handle_b[0], host_b, "b")) return 1;

  std::vector<std::uint64_t> operands = {handle_a[0], handle_b[0], handle_c[0]};
  auto kernel = call(av::ExecutionOp::KernelVectorAdd, 0, 0, operands, {});
  if (!kernel.ok()) return fail_status(kernel.status());
  std::printf("cuda_proof kernel_executed vector_add elements=%u\n", count);

  std::vector<std::uint8_t> host_c(bytes);
  auto download = call(av::ExecutionOp::Download, handle_c[0], 0, {}, host_c);
  if (!download.ok()) return fail_status(download.status());
  const auto* floats_c = reinterpret_cast<const float*>(host_c.data());
  std::uint64_t mismatches = 0;
  for (std::uint32_t i = 0; i < count; ++i) {
    const float expected = static_cast<float>(i) + static_cast<float>(2u * i);
    if (floats_c[i] != expected) ++mismatches;
  }
  std::printf("cuda_proof parity mismatches=%llu of %u\n", static_cast<unsigned long long>(mismatches), count);

  for (std::uint64_t handle : {handle_a[0], handle_b[0], handle_c[0]}) {
    auto response = call(av::ExecutionOp::Free, handle, bytes, {}, {});
    if (!response.ok()) return fail_status(response.status());
    std::printf("cuda_proof released handle=%llu\n", static_cast<unsigned long long>(handle));
  }
  auto after = call(av::ExecutionOp::DeviceInfo, 0, 0, {}, {});
  if (after.ok()) {
    std::printf("cuda_proof device_info_after total=%llu free=%llu\n",
                static_cast<unsigned long long>(after->u64(av::kFieldDeviceMemoryTotal).value_or(0)),
                static_cast<unsigned long long>(after->u64(av::kFieldDeviceMemoryFree).value_or(0)));
  }
  std::printf("cuda_proof result=%s\n", mismatches == 0 ? "PASS" : "FAIL");
  return mismatches == 0 ? 0 : 1;
}

void print_usage() {
  std::fputs(
      "av_cli - Accelerator Virtualization inspection and proof\n"
      "\n"
      "Global: --coordinator HOST:PORT [--name NAME]\n"
      "\n"
      "  version\n"
      "  policy show | policy set [--transparency MODE] [--synthetic on|off]\n"
      "  tenant create --name N [--subject S]\n"
      "  tenant list\n"
      "  tenant fence --tenant ID --tenant-generation G [--reason R]\n"
      "  virtual create --name N --tenant-id ID --tenant-generation G [contract options]\n"
      "  virtual list [--all] [--tenant-id ID]\n"
      "  virtual show --virtual ID [--lease ID]\n"
      "  virtual activate|drain|suspend|resume|fence|retire|resolve-recovery \\\n"
      "        --virtual ID --virtual-generation G [--tenant/--tenant-generation] [--reason R]\n"
      "  contract show --virtual ID | contract update --virtual ID --virtual-generation G [contract options]\n"
      "  capability show --virtual ID\n"
      "  backing list | physical list\n"
      "  backing assign|replace --virtual ID --virtual-generation G --backing BK [--tenant...] [--reason R]\n"
      "  attach --virtual ID --virtual-generation G --tenant ID --tenant-generation G\n"
      "  detach|revoke|renew --virtual ID --virtual-generation G --lease ID --lease-generation G \\\n"
      "        --tenant ID --tenant-generation G\n"
      "  isolation explain --virtual ID\n"
      "  migration explain --virtual ID\n"
      "  migration plan --virtual ID --virtual-generation G --backing BK [--class CLASS]\n"
      "  migration prepare|commit|complete|abort --virtual ID --virtual-generation G \\\n"
      "        --migration ID --migration-generation G\n"
      "  execute --virtual ID --virtual-generation G --op OP [--bytes N] [--handle H] [--handles A,B,C]\n"
      "  cuda proof --virtual ID --virtual-generation G [--count N]\n"
      "  decisions --virtual ID [--limit N]\n"
      "  audit | snapshot | accounting | shutdown\n"
      "\n"
      "Contract options: --memory-bytes N --compute-share-milli N --max-streams N --max-concurrency N\n"
      "                  --exclusive --no-migration --allow-oversubscription\n",
      stderr);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage();
    return 2;
  }
  av::ClientOptions client_options;
  std::vector<std::string> words;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--coordinator" && i + 1 < argc) {
      const std::string endpoint = argv[++i];
      const std::size_t colon = endpoint.rfind(':');
      if (colon == std::string::npos) return fail_usage("--coordinator expects HOST:PORT");
      client_options.host = endpoint.substr(0, colon);
      client_options.port = static_cast<std::uint16_t>(std::strtoul(endpoint.c_str() + colon + 1, nullptr, 10));
    } else if (arg == "--client-name" && i + 1 < argc) {
      // Deliberately not --name: command subcommands use --name for their own
      // resource name.
      client_options.name = argv[++i];
    } else {
      words.push_back(arg);
    }
  }
  if (words.empty()) {
    print_usage();
    return 2;
  }
  if (words[0] == "version") return cmd_version();
  if (words[0] == "--help" || words[0] == "-h" || words[0] == "help") {
    print_usage();
    return 0;
  }
  if (client_options.port == 0) return fail_usage("--coordinator HOST:PORT is required");

  Command command;
  command.name = words[0];
  for (std::size_t i = 1; i < words.size(); ++i) {
    const std::string& token = words[i];
    if (token.size() > 2 && token[0] == '-' && token[1] == '-') {
      const std::string key = token.substr(2);
      if (i + 1 < words.size() && !(words[i + 1].size() > 2 && words[i + 1][0] == '-' && words[i + 1][1] == '-')) {
        command.flags[key] = words[++i];
      } else {
        command.flags[key] = "true";
      }
    } else {
      command.positional.push_back(token);
    }
  }

  client_options.role = av::Role::Client;
  auto client_result = av::ControlClient::connect(client_options);
  if (!client_result.ok()) {
    std::fprintf(stderr, "av_cli: %s\n", client_result.status().to_string().c_str());
    return 1;
  }
  av::ControlClient client = client_result.take();
  const std::string verb = words[0];
  const std::string noun = words.size() > 1 ? words[1] : std::string{};

  if (verb == "policy") return noun == "show" ? cmd_policy_show(client) : cmd_policy_set(client, command);
  if (verb == "tenant") {
    if (noun == "create") return cmd_tenant_create(client, command);
    if (noun == "list") return cmd_tenant_list(client);
    if (noun == "fence") return cmd_tenant_fence(client, command);
  }
  if (verb == "virtual") {
    if (noun == "create") return cmd_virtual_create(client, command);
    if (noun == "list") return cmd_virtual_list(client, command);
    if (noun == "show") return cmd_virtual_show(client, command);
    if (noun == "activate") return cmd_virtual_command(client, command, av::MessageType::ActivateVirtual);
    if (noun == "drain") return cmd_virtual_command(client, command, av::MessageType::DrainVirtual);
    if (noun == "suspend") return cmd_virtual_command(client, command, av::MessageType::SuspendVirtual);
    if (noun == "resume") return cmd_virtual_command(client, command, av::MessageType::ResumeVirtual);
    if (noun == "fence") return cmd_virtual_command(client, command, av::MessageType::FenceVirtual);
    if (noun == "retire") return cmd_virtual_command(client, command, av::MessageType::RetireVirtual);
    if (noun == "resolve-recovery") {
      return cmd_virtual_command(client, command, av::MessageType::ResolveRecovery);
    }
  }
  if (verb == "contract") {
    if (noun == "show") return cmd_contract_show(client, command);
    if (noun == "update") return cmd_contract_update(client, command);
  }
  if (verb == "capability" && noun == "show") return cmd_capability_show(client, command);
  if (verb == "backing") {
    if (noun == "list") return cmd_backing_list(client);
    if (noun == "assign") return cmd_backing_assign(client, command, false);
    if (noun == "replace") return cmd_backing_assign(client, command, true);
  }
  if (verb == "physical" && noun == "list") return cmd_physical_list(client);
  if (verb == "attach") return cmd_attach(client, command);
  if (verb == "detach") return cmd_lease_command(client, command, av::MessageType::Detach);
  if (verb == "revoke") return cmd_lease_command(client, command, av::MessageType::Revoke);
  if (verb == "renew") return cmd_lease_command(client, command, av::MessageType::RenewLease);
  if (verb == "isolation" && noun == "explain") return cmd_isolation_explain(client, command);
  if (verb == "migration") {
    if (noun == "explain") return cmd_migration_explain(client, command);
    if (noun == "plan") return cmd_migration_plan(client, command);
    if (noun == "prepare") return cmd_migration_phase(client, command, av::MessageType::MigrationPrepare);
    if (noun == "commit") return cmd_migration_phase(client, command, av::MessageType::MigrationCommit);
    if (noun == "complete") return cmd_migration_phase(client, command, av::MessageType::MigrationComplete);
    if (noun == "abort") return cmd_migration_phase(client, command, av::MessageType::MigrationAbort);
  }
  if (verb == "execute") return cmd_execute(client, command);
  if (verb == "cuda" && noun == "proof") return cmd_cuda_proof(client, command);
  if (verb == "decisions") return cmd_decisions(client, command);
  if (verb == "audit") return cmd_audit(client);
  if (verb == "snapshot") return cmd_snapshot(client);
  if (verb == "accounting") return cmd_accounting(client);
  if (verb == "shutdown") {
    FieldWriter fields;
    auto response = client.call(av::MessageType::Shutdown, fields);
    if (!response.ok()) return fail_status(response.status());
    std::printf("shutdown=accepted\n");
    return 0;
  }
  print_usage();
  return 2;
}
