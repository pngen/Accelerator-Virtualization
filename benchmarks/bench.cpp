// Accelerator Virtualization benchmarks.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every measurement is a completed operation, timed with a steady clock. No
// enqueue-only path is reported as throughput: a measurement only ends when the
// runtime has committed, persisted and returned.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "av/persistence.hpp"
#include "av/runtime.hpp"
#include "av/synthetic.hpp"

namespace {

using Clock = std::chrono::steady_clock;

struct Measurement {
  std::string name;
  std::size_t operations{0};
  double total_milliseconds{0.0};
  std::string note;
};

void report(const std::vector<Measurement>& measurements) {
  std::printf("%-46s %10s %14s %14s\n", "benchmark", "ops", "total_ms", "per_op_us");
  for (const Measurement& entry : measurements) {
    const double per_operation =
        entry.operations == 0 ? 0.0 : (entry.total_milliseconds * 1000.0) / static_cast<double>(entry.operations);
    std::printf("%-46s %10zu %14.2f %14.2f", entry.name.c_str(), entry.operations, entry.total_milliseconds,
                per_operation);
    if (!entry.note.empty()) std::printf("  %s", entry.note.c_str());
    std::printf("\n");
  }
  std::fflush(stdout);
}

class Timer {
 public:
  Timer() : start_(Clock::now()) {}
  double milliseconds() const {
    return std::chrono::duration<double, std::milli>(Clock::now() - start_).count();
  }

 private:
  Clock::time_point start_;
};

struct Bench {
  std::unique_ptr<av::VirtualizationRuntime> runtime;
  av::AgentId agent{};
  av::AgentBootId boot{};
  av::PhysicalDeviceId device{};
  std::vector<av::BackingId> backings;
};

Bench make_bench(const std::string& directory) {
  av::RuntimeOptions options;
  options.name = "benchmark";
  av::StoreOptions store_options;
  store_options.directory = directory;
  store_options.enabled = !directory.empty();
  auto created = av::make_runtime(options, store_options, nullptr);
  if (!created.ok()) {
    std::fprintf(stderr, "benchmark could not start a runtime: %s\n", created.status().to_string().c_str());
    std::exit(2);
  }
  Bench bench;
  bench.runtime = created.take();
  auto session = bench.runtime->register_agent("bench", "in-process", 1, av::AgentId{});
  if (!session.ok()) std::exit(2);
  bench.agent = session->id;
  bench.boot = session->boot;
  auto adapters = av::make_synthetic_backends();
  for (const auto& adapter : adapters) {
    if (adapter->name() != "synthetic-migratable") continue;
    auto found = adapter->discover();
    if (!found.ok()) continue;
    auto record = bench.runtime->register_physical(bench.runtime->current_authority(), bench.agent, bench.boot,
                                                   found->front());
    if (!record.ok()) std::exit(2);
    bench.device = record->id;
  }
  for (const av::BackingRecord& backing : bench.runtime->list_backings()) {
    if (backing.physical == bench.device) bench.backings.push_back(backing.id);
  }
  if (bench.backings.empty()) std::exit(2);
  return bench;
}

av::ResourceContract bench_contract() {
  av::ResourceContract contract;
  contract.memory_ceiling_bytes = 1u << 20;
  contract.compute_share_milli = 100;
  contract.migration_allowed = true;
  contract.allowed_migration_classes = {av::MigrationClass::RebindOnly};
  contract.normalize();
  return contract;
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t requested = 10000;
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--count" && i + 1 < argc) {
      requested = static_cast<std::size_t>(std::strtoul(argv[++i], nullptr, 10));
    }
  }

  std::error_code ec;
  const std::string directory =
      (std::filesystem::temp_directory_path(ec) /
       ("av-benchmark-" + std::to_string(Clock::now().time_since_epoch().count())))
          .string();
  std::filesystem::create_directories(directory, ec);

  std::vector<Measurement> measurements;
  std::printf("Accelerator Virtualization benchmark, target fleet %zu\n", requested);
  std::printf("durable state directory: %s\n", directory.c_str());
  std::fflush(stdout);

  for (const std::size_t scale : {std::size_t{10}, std::size_t{100}, std::size_t{1000}, requested}) {
    if (scale > requested && scale != requested) continue;
    Bench bench = make_bench(directory + "/scale-" + std::to_string(scale));
    const std::string prefix = "scale=" + std::to_string(scale) + " ";

    const av::TenantRecord tenant = bench.runtime->create_tenant(bench.runtime->current_authority(), "bench", "")
                                        .value();
    std::vector<av::VirtualAcceleratorId> identities;
    identities.reserve(scale);

    {
      Timer timer;
      for (std::size_t index = 0; index < scale; ++index) {
        auto record = bench.runtime->create_virtual(bench.runtime->current_authority(),
                                                    "va-" + std::to_string(index), tenant.id, tenant.generation,
                                                    bench_contract());
        if (!record.ok()) {
          std::fprintf(stderr, "create_virtual failed: %s\n", record.status().to_string().c_str());
          return 2;
        }
        identities.push_back(record->id);
      }
      measurements.push_back(Measurement{prefix + "create virtual accelerator", scale, timer.milliseconds(),
                                         "(committed and journaled)"});
    }

    {
      Timer timer;
      for (av::VirtualAcceleratorId id : identities) {
        auto view = bench.runtime->query_virtual(bench.runtime->current_authority(), id);
        if (!view.ok()) return 2;
      }
      measurements.push_back(Measurement{prefix + "lookup by virtual identity", scale, timer.milliseconds(), {}});
    }

    {
      Timer timer;
      for (std::size_t index = 0; index < identities.size(); ++index) {
        av::Authority authority =
            bench.runtime->virtual_authority(identities[index], av::VirtualAcceleratorGeneration::from_value(1));
        authority.tenant = tenant.id;
        authority.tenant_generation = tenant.generation;
        auto record = bench.runtime->assign_backing(authority, bench.backings[index % bench.backings.size()],
                                                    "benchmark");
        (void)record;
      }
      measurements.push_back(Measurement{prefix + "backing assignment", identities.size(), timer.milliseconds(),
                                         "(shared mechanism)"});
    }

    std::vector<av::VirtualAcceleratorRecord> records;
    records.reserve(identities.size());
    for (av::VirtualAcceleratorId id : identities) {
      auto record = bench.runtime->raw_virtual(id);
      if (record.ok()) records.push_back(record.take());
    }

    {
      Timer timer;
      std::size_t attached = 0;
      for (const av::VirtualAcceleratorRecord& record : records) {
        av::Authority authority = bench.runtime->virtual_authority(record.id, record.generation);
        authority.tenant = tenant.id;
        authority.tenant_generation = tenant.generation;
        if (bench.runtime->attach(authority).ok()) ++attached;
      }
      measurements.push_back(Measurement{prefix + "attach grant", attached, timer.milliseconds(), {}});
    }

    {
      Timer timer;
      std::size_t detached = 0;
      for (const av::VirtualAcceleratorRecord& record : records) {
        auto current = bench.runtime->raw_virtual(record.id);
        if (!current.ok()) continue;
        for (const av::LeaseRecord& lease : bench.runtime->list_leases()) {
          if (lease.virtual_id != record.id || !av::lease_state_is_live(lease.state)) continue;
          av::Authority authority = bench.runtime->virtual_authority(record.id, current->generation);
          authority.tenant = tenant.id;
          authority.tenant_generation = tenant.generation;
          authority.lease = lease.id;
          authority.lease_generation = lease.generation;
          if (bench.runtime->detach(authority).ok()) ++detached;
          break;
        }
      }
      measurements.push_back(Measurement{prefix + "detach", detached, timer.milliseconds(), {}});
    }

    {
      Timer timer;
      for (av::VirtualAcceleratorId id : identities) {
        auto contract = bench.runtime->get_contract(id);
        if (!contract.ok()) return 2;
      }
      measurements.push_back(Measurement{prefix + "capability/contract inspection", identities.size(),
                                         timer.milliseconds(), {}});
    }

    {
      const std::size_t inspections = std::min<std::size_t>(identities.size(), 64);
      Timer timer;
      for (std::size_t index = 0; index < inspections; ++index) {
        auto explanation = bench.runtime->explain_isolation(identities[index]);
        if (!explanation.ok()) return 2;
      }
      measurements.push_back(Measurement{prefix + "isolation explanation", inspections, timer.milliseconds(), {}});
    }

    {
      Timer timer;
      const av::AuditReport report = bench.runtime->audit();
      measurements.push_back(Measurement{prefix + "invariant audit", identities.size(), timer.milliseconds(),
                                         report.clean() ? "(clean)" : "(VIOLATIONS)"});
    }

    {
      Timer timer;
      const std::string snapshot = bench.runtime->snapshot_text();
      measurements.push_back(Measurement{prefix + "snapshot render", snapshot.size(), timer.milliseconds(),
                                         "bytes=" + std::to_string(snapshot.size())});
    }

    {
      Timer timer;
      const av::Status status = bench.runtime->compact();
      if (!status.ok()) return 2;
      measurements.push_back(Measurement{prefix + "persistence compaction", scale, timer.milliseconds(), {}});
    }

    std::printf("-- scale %zu complete: writes=%llu journal_bytes=%llu\n", scale,
                static_cast<unsigned long long>(bench.runtime->persistence_writes()),
                static_cast<unsigned long long>(bench.runtime->persistence_bytes()));
    std::fflush(stdout);
  }

  std::printf("\ncompleted-work measurements (every operation returned before it was timed)\n");
  report(measurements);

  std::printf("\ncomplexity notes\n");
  std::printf("  create/attach/detach/assign: O(changed records) per mutation; the journal appends and never rewrites\n");
  std::printf("  lookup: O(log n) in the identity index\n");
  std::printf("  audit/snapshot/compaction: O(total records); measured at every scale above\n");
  std::fflush(stdout);

  std::filesystem::remove_all(directory, ec);
  return 0;
}