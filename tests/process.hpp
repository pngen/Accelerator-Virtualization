// Accelerator Virtualization - real OS process harness for the test suites.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The multiprocess proofs must use real operating-system processes. This
// harness spawns child processes with piped output, lets a test wait for a
// specific flushed line, and can kill a child abruptly to simulate a crash.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "av/status.hpp"

namespace avtest {

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  static av::Result<ChildProcess> spawn(const std::string& executable, const std::vector<std::string>& arguments);

  bool running() const;
  std::uint32_t id() const { return process_id_; }
  std::string drain();
  bool wait_for(const std::string& needle, int timeout_milliseconds);
  void kill();
  int wait();
  const std::string& output() const { return output_; }

 private:
  void close_handles();

  void* process_{nullptr};
  std::uintptr_t read_handle_{0};
  std::uint32_t process_id_{0};
  std::string output_{};
  bool exited_{false};
  int exit_code_{-1};
};

std::string sibling_executable(const std::string& name);

// A unique scratch directory under the system temporary directory, removed on
// destruction so no test scratch survives the run.
class ScratchDirectory {
 public:
  explicit ScratchDirectory(const std::string& label);
  ~ScratchDirectory();
  ScratchDirectory(const ScratchDirectory&) = delete;
  ScratchDirectory& operator=(const ScratchDirectory&) = delete;

  const std::string& path() const { return path_; }
  std::string file(const std::string& name) const;

 private:
  std::string path_;
};

}  // namespace avtest
