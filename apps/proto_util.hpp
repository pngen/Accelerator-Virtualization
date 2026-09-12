// Accelerator Virtualization - shared control-plane helpers for the apps.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "av/backend.hpp"
#include "av/client.hpp"
#include "av/protocol.hpp"
#include "av/runtime.hpp"

namespace av {
namespace app {

inline std::optional<std::uint64_t> opt_u64(const FieldReader& reader, std::uint16_t key) {
  return reader.u64(key);
}

inline Authority read_authority(const FieldReader& reader) {
  Authority authority;
  if (auto value = reader.u64(kFieldEpoch); value.has_value()) {
    authority.epoch = CoordinatorEpoch::from_value(*value);
  }
  if (auto value = reader.u64(kFieldTenantId); value.has_value()) authority.tenant = TenantId::from_value(*value);
  if (auto value = reader.u64(kFieldTenantGeneration); value.has_value()) {
    authority.tenant_generation = TenantGeneration::from_value(*value);
  }
  if (auto value = reader.u64(kFieldVirtualId); value.has_value()) {
    authority.virtual_id = VirtualAcceleratorId::from_value(*value);
  }
  if (auto value = reader.u64(kFieldVirtualGeneration); value.has_value()) {
    authority.virtual_generation = VirtualAcceleratorGeneration::from_value(*value);
  }
  if (auto value = reader.u64(kFieldBackingId); value.has_value()) authority.backing = BackingId::from_value(*value);
  if (auto value = reader.u64(kFieldBackingGeneration); value.has_value()) {
    authority.backing_generation = BackingGeneration::from_value(*value);
  }
  if (auto value = reader.u64(kFieldPhysicalId); value.has_value()) {
    authority.physical = PhysicalDeviceId::from_value(*value);
  }
  if (auto value = reader.u64(kFieldPhysicalGeneration); value.has_value()) {
    authority.physical_generation = PhysicalDeviceGeneration::from_value(*value);
  }
  if (auto value = reader.u64(kFieldLeaseId); value.has_value()) authority.lease = LeaseId::from_value(*value);
  if (auto value = reader.u64(kFieldLeaseGeneration); value.has_value()) {
    authority.lease_generation = LeaseGeneration::from_value(*value);
  }
  if (auto value = reader.u64(kFieldPolicyGeneration); value.has_value()) {
    authority.policy_generation = PolicyGeneration::from_value(*value);
  }
  if (auto value = reader.u64(kFieldMigrationId); value.has_value()) {
    authority.migration = MigrationId::from_value(*value);
  }
  if (auto value = reader.u64(kFieldMigrationGeneration); value.has_value()) {
    authority.migration_generation = MigrationGeneration::from_value(*value);
  }
  if (auto value = reader.u64(kFieldRequest); value.has_value()) authority.request = RequestId::from_value(*value);
  return authority;
}

inline void write_authority_echo(FieldWriter& writer, const Authority& authority) {
  if (authority.epoch.has_value()) writer.u64(kFieldEpoch, authority.epoch->value());
  if (authority.tenant.has_value()) writer.u64(kFieldTenantId, authority.tenant->value());
  if (authority.tenant_generation.has_value()) {
    writer.u64(kFieldTenantGeneration, authority.tenant_generation->value());
  }
  if (authority.virtual_id.has_value()) writer.u64(kFieldVirtualId, authority.virtual_id->value());
  if (authority.virtual_generation.has_value()) {
    writer.u64(kFieldVirtualGeneration, authority.virtual_generation->value());
  }
  if (authority.lease.has_value()) writer.u64(kFieldLeaseId, authority.lease->value());
  if (authority.lease_generation.has_value()) {
    writer.u64(kFieldLeaseGeneration, authority.lease_generation->value());
  }
  if (authority.migration.has_value()) writer.u64(kFieldMigrationId, authority.migration->value());
  if (authority.migration_generation.has_value()) {
    writer.u64(kFieldMigrationGeneration, authority.migration_generation->value());
  }
}

inline void write_epoch(FieldWriter& writer, CoordinatorEpoch epoch) {
  writer.u64(kFieldEpoch, epoch.value());
}

// A response is either a payload of fields or an error carrying a stable code.
struct Response {
  std::uint32_t flags{0};
  std::vector<Byte> payload{};

  static Response ok(std::vector<Byte> payload) {
    Response response;
    response.payload = std::move(payload);
    return response;
  }
  static Response failure(StatusCode code, std::string_view detail) {
    Response response;
    response.flags = kFlagError;
    response.payload = encode_error_payload(code, detail);
    return response;
  }
  static Response failure(const Status& status) { return failure(status.code(), status.detail()); }
};

inline Response blob_response(const FieldWriter& fields) { return Response::ok(fields.take()); }

// Wraps a canonical record blob into a self-describing nested field map so a
// list response is a list of field maps rather than a list of raw blobs.
inline std::vector<Byte> wrap_blob(std::uint16_t key, const std::vector<Byte>& blob) {
  FieldWriter writer;
  writer.bytes(key, ByteSpan{blob.data(), blob.size()});
  return writer.take();
}

// ---- physical device descriptors over the wire ---------------------------

inline std::vector<Byte> encode_projection_blob(const CapabilityProjection& projection) {
  Encoder encoder;
  encode_projection(encoder, projection);
  return encoder.take();
}

inline Result<CapabilityProjection> decode_projection_blob(ByteSpan bytes) {
  Decoder decoder(bytes);
  auto projection = decode_projection(decoder);
  if (!projection.ok()) return projection.status();
  if (!decoder.at_end()) {
    return Status(StatusCode::ProtocolViolation, "the projection blob carries trailing bytes");
  }
  return projection.take();
}

inline std::vector<Byte> encode_capabilities_blob(const CapabilitySurface& surface) {
  Encoder encoder;
  encode_capability_surface(encoder, surface);
  return encoder.take();
}

inline std::vector<Byte> encode_isolation_blob(const IsolationProfile& profile) {
  Encoder encoder;
  encode_isolation_profile(encoder, profile);
  return encoder.take();
}

inline std::vector<Byte> encode_backing_descriptor(const BackingDescriptor& backing) {
  FieldWriter writer;
  writer.str(kFieldLabel, backing.label);
  writer.u64(kFieldBackingClass, static_cast<std::uint64_t>(backing.klass));
  writer.u64(kFieldMultiplexing, static_cast<std::uint64_t>(backing.multiplexing));
  writer.u64(kFieldIsolationClass, static_cast<std::uint64_t>(backing.isolation_class));
  writer.u64(kFieldCapacityBytes, backing.capacity_bytes);
  writer.u64(kFieldComputeUnits, backing.compute_units);
  writer.str(kFieldMechanism, backing.mechanism);
  writer.boolean(kFieldExclusive, backing.exclusive);
  writer.boolean(kFieldExternallyManaged, backing.externally_lifecycle_managed);
  writer.str(kFieldExternalPartitionRef, backing.external_partition_ref);
  IsolationProfile profile;
  for (const IsolationClaim& claim : backing.isolation) profile.set(claim);
  const std::vector<Byte> isolation = encode_isolation_blob(profile);
  writer.bytes(kFieldIsolationBlob, ByteSpan{isolation.data(), isolation.size()});
  const std::vector<Byte> capabilities = encode_capabilities_blob(backing.capabilities);
  writer.bytes(kFieldCapabilitiesBlob, ByteSpan{capabilities.data(), capabilities.size()});
  return writer.take();
}

inline std::vector<Byte> encode_physical_descriptor(const PhysicalDeviceDescriptor& descriptor) {
  FieldWriter writer;
  writer.str(kFieldStableKey, descriptor.stable_key);
  writer.str(kFieldVendor, descriptor.vendor);
  writer.str(kFieldModel, descriptor.model);
  writer.str(kFieldDriverVersion, descriptor.driver_version);
  writer.str(kFieldArchitecture, descriptor.architecture);
  writer.u64(kFieldProvenance, static_cast<std::uint64_t>(descriptor.provenance));
  writer.u64(kFieldDeviceMemoryTotal, descriptor.memory_total_bytes);
  writer.u64(kFieldComputeUnits, descriptor.compute_units);
  writer.u64(kFieldCcMajor, descriptor.compute_capability_major);
  writer.u64(kFieldCcMinor, descriptor.compute_capability_minor);
  writer.str(kFieldMechanism, descriptor.mechanism);
  writer.boolean(kFieldHardwarePartitionCapable, descriptor.hardware_partition_capable);
  writer.boolean(kFieldVirtualFunctionCapable, descriptor.virtual_function_capable);
  writer.boolean(kFieldMigCapable, descriptor.mig_capable);
  std::vector<std::vector<Byte>> backings;
  backings.reserve(descriptor.backings.size());
  for (const BackingDescriptor& backing : descriptor.backings) {
    backings.push_back(encode_backing_descriptor(backing));
  }
  writer.nested_list(kFieldBackings, backings);
  return writer.take();
}

inline Result<BackingDescriptor> decode_backing_descriptor(const FieldReader& reader) {
  BackingDescriptor backing;
  auto label = reader.require_str(kFieldLabel);
  if (!label.ok()) return label.status();
  backing.label = label.take();
  auto klass = reader.require_u64(kFieldBackingClass);
  if (!klass.ok()) return klass.status();
  if (*klass > static_cast<std::uint64_t>(BackingClass::SyntheticMigratable)) {
    return Status(StatusCode::ProtocolViolation, "backing class is outside its domain");
  }
  backing.klass = static_cast<BackingClass>(*klass);
  auto multiplexing = reader.require_u64(kFieldMultiplexing);
  if (!multiplexing.ok()) return multiplexing.status();
  if (*multiplexing > static_cast<std::uint64_t>(MultiplexingMode::Synthetic)) {
    return Status(StatusCode::ProtocolViolation, "multiplexing mode is outside its domain");
  }
  backing.multiplexing = static_cast<MultiplexingMode>(*multiplexing);
  auto isolation_class = reader.require_u64(kFieldIsolationClass);
  if (!isolation_class.ok()) return isolation_class.status();
  if (*isolation_class > static_cast<std::uint64_t>(IsolationClass::Synthetic)) {
    return Status(StatusCode::ProtocolViolation, "isolation class is outside its domain");
  }
  backing.isolation_class = static_cast<IsolationClass>(*isolation_class);
  if (auto value = reader.u64(kFieldCapacityBytes); value.has_value()) backing.capacity_bytes = *value;
  if (auto value = reader.u64(kFieldComputeUnits); value.has_value()) {
    backing.compute_units = static_cast<std::uint32_t>(*value);
  }
  if (auto value = reader.str(kFieldMechanism); value.has_value()) backing.mechanism = *value;
  if (auto value = reader.boolean(kFieldExclusive); value.has_value()) backing.exclusive = *value;
  if (auto value = reader.boolean(kFieldExternallyManaged); value.has_value()) {
    backing.externally_lifecycle_managed = *value;
  }
  if (auto value = reader.str(kFieldExternalPartitionRef); value.has_value()) {
    backing.external_partition_ref = *value;
  }
  auto isolation_blob = reader.bytes(kFieldIsolationBlob);
  if (!isolation_blob.has_value()) {
    return Status(StatusCode::ProtocolViolation, "a backing descriptor must carry isolation claims");
  }
  Decoder isolation_decoder(*isolation_blob);
  auto profile = decode_isolation_profile(isolation_decoder);
  if (!profile.ok()) return profile.status();
  if (!isolation_decoder.at_end()) {
    return Status(StatusCode::ProtocolViolation, "the isolation blob carries trailing bytes");
  }
  backing.isolation = profile.take().claims();
  if (auto capabilities_blob = reader.bytes(kFieldCapabilitiesBlob); capabilities_blob.has_value()) {
    Decoder capabilities_decoder(*capabilities_blob);
    auto surface = decode_capability_surface(capabilities_decoder);
    if (!surface.ok()) return surface.status();
    if (!capabilities_decoder.at_end()) {
      return Status(StatusCode::ProtocolViolation, "the capability blob carries trailing bytes");
    }
    backing.capabilities = surface.take();
  }
  return backing;
}

inline Result<PhysicalDeviceDescriptor> decode_physical_descriptor(const FieldReader& reader) {
  PhysicalDeviceDescriptor descriptor;
  auto stable_key = reader.require_str(kFieldStableKey);
  if (!stable_key.ok()) return stable_key.status();
  descriptor.stable_key = stable_key.take();
  if (auto value = reader.str(kFieldVendor); value.has_value()) descriptor.vendor = *value;
  if (auto value = reader.str(kFieldModel); value.has_value()) descriptor.model = *value;
  if (auto value = reader.str(kFieldDriverVersion); value.has_value()) descriptor.driver_version = *value;
  if (auto value = reader.str(kFieldArchitecture); value.has_value()) descriptor.architecture = *value;
  auto provenance = reader.require_u64(kFieldProvenance);
  if (!provenance.ok()) return provenance.status();
  if (*provenance > static_cast<std::uint64_t>(Provenance::Unsupported)) {
    return Status(StatusCode::ProtocolViolation, "provenance is outside its domain");
  }
  descriptor.provenance = static_cast<Provenance>(*provenance);
  if (auto value = reader.u64(kFieldDeviceMemoryTotal); value.has_value()) {
    descriptor.memory_total_bytes = *value;
  }
  if (auto value = reader.u64(kFieldComputeUnits); value.has_value()) {
    descriptor.compute_units = static_cast<std::uint32_t>(*value);
  }
  if (auto value = reader.u64(kFieldCcMajor); value.has_value()) {
    descriptor.compute_capability_major = static_cast<std::uint32_t>(*value);
  }
  if (auto value = reader.u64(kFieldCcMinor); value.has_value()) {
    descriptor.compute_capability_minor = static_cast<std::uint32_t>(*value);
  }
  if (auto value = reader.str(kFieldMechanism); value.has_value()) descriptor.mechanism = *value;
  if (auto value = reader.boolean(kFieldHardwarePartitionCapable); value.has_value()) {
    descriptor.hardware_partition_capable = *value;
  }
  if (auto value = reader.boolean(kFieldVirtualFunctionCapable); value.has_value()) {
    descriptor.virtual_function_capable = *value;
  }
  if (auto value = reader.boolean(kFieldMigCapable); value.has_value()) descriptor.mig_capable = *value;

  const auto nested = reader.nested_list(kFieldBackings);
  if (nested.size() > 64) {
    return Status(StatusCode::LimitExceeded, "a physical device may carry at most 64 backing descriptors");
  }
  for (const Result<FieldReader>& entry : nested) {
    if (!entry.ok()) return entry.status();
    auto backing = decode_backing_descriptor(entry.value());
    if (!backing.ok()) return backing.status();
    descriptor.backings.push_back(backing.take());
  }
  return descriptor;
}

}  // namespace app
}  // namespace av
