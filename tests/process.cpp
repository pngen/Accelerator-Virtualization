// Accelerator Virtualization - real OS process harness.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "process.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace avtest {
namespace {

std::string quote_argument(const std::string& value) {
  std::string out = "\"";
  for (char c : value) {
    if (c == '"') out.push_back('\\');
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}

std::string executable_directory() {
#ifdef _WIN32
  char buffer[MAX_PATH] = {};
  const DWORD length = ::GetModuleFileNameA(nullptr, buffer, MAX_PATH);
  if (length == 0) return ".";
  std::filesystem::path path(buffer);
  return path.parent_path().string();
#else
  return ".";
#endif
}

}  // namespace

std::string sibling_executable(const std::string& name) {
#ifdef _WIN32
  return (std::filesystem::path(executable_directory()) / (name + ".exe")).string();
#else
  return (std::filesystem::path(executable_directory()) / name).string();
#endif
}

ChildProcess::~ChildProcess() {
  if (running()) {
    kill();
    wait();
  }
  close_handles();
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : process_(other.process_),
      read_handle_(other.read_handle_),
      process_id_(other.process_id_),
      output_(std::move(other.output_)),
      exited_(other.exited_),
      exit_code_(other.exit_code_) {
  other.process_ = nullptr;
  other.read_handle_ = 0;
  other.process_id_ = 0;
  other.exited_ = true;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    if (running()) {
      kill();
      wait();
    }
    close_handles();
    process_ = other.process_;
    read_handle_ = other.read_handle_;
    process_id_ = other.process_id_;
    output_ = std::move(other.output_);
    exited_ = other.exited_;
    exit_code_ = other.exit_code_;
    other.process_ = nullptr;
    other.read_handle_ = 0;
    other.process_id_ = 0;
    other.exited_ = true;
  }
  return *this;
}

void ChildProcess::close_handles() {
#ifdef _WIN32
  if (read_handle_ != 0) {
    ::CloseHandle(reinterpret_cast<HANDLE>(read_handle_));
    read_handle_ = 0;
  }
  if (process_ != nullptr) {
    ::CloseHandle(reinterpret_cast<HANDLE>(process_));
    process_ = nullptr;
  }
#else
  read_handle_ = 0;
#endif
}

av::Result<ChildProcess> ChildProcess::spawn(const std::string& executable,
                                             const std::vector<std::string>& arguments) {
#ifdef _WIN32
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  attributes.lpSecurityDescriptor = nullptr;

  HANDLE read_end = nullptr;
  HANDLE write_end = nullptr;
  if (::CreatePipe(&read_end, &write_end, &attributes, 0) == 0) {
    return av::Status(av::StatusCode::IoFailure, "CreatePipe failed");
  }
  ::SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);

  std::string command = quote_argument(executable);
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command.append(quote_argument(argument));
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_end;
  startup.hStdError = write_end;
  startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION information{};
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');
  const BOOL created = ::CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                        nullptr, nullptr, &startup, &information);
  ::CloseHandle(write_end);
  if (created == 0) {
    ::CloseHandle(read_end);
    return av::Status(av::StatusCode::IoFailure, "CreateProcess failed for '" + executable +
                                                     "' with error " + std::to_string(::GetLastError()));
  }
  ::CloseHandle(information.hThread);

  ChildProcess child;
  child.process_ = information.hProcess;
  child.read_handle_ = reinterpret_cast<std::uintptr_t>(read_end);
  child.process_id_ = information.dwProcessId;
  return child;
#else
  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) return av::Status(av::StatusCode::IoFailure, "pipe failed");
  std::vector<std::string> storage;
  storage.push_back(executable);
  for (const std::string& argument : arguments) storage.push_back(argument);
  std::vector<char*> argv;
  for (std::string& value : storage) argv.push_back(value.data());
  argv.push_back(nullptr);
  pid_t pid = 0;
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
  const int spawned = posix_spawn(&pid, executable.c_str(), &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  close(pipe_fds[1]);
  if (spawned != 0) {
    close(pipe_fds[0]);
    return av::Status(av::StatusCode::IoFailure, "posix_spawn failed");
  }
  ChildProcess child;
  child.process_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(pid));
  child.read_handle_ = static_cast<std::uintptr_t>(pipe_fds[0]);
  child.process_id_ = static_cast<std::uint32_t>(pid);
  return child;
#endif
}

bool ChildProcess::running() const {
#ifdef _WIN32
  if (process_ == nullptr) return false;
  return ::WaitForSingleObject(reinterpret_cast<HANDLE>(process_), 0) == WAIT_TIMEOUT;
#else
  if (process_ == nullptr) return false;
  int status = 0;
  const pid_t pid = static_cast<pid_t>(reinterpret_cast<std::intptr_t>(process_));
  return ::waitpid(pid, &status, WNOHANG) == 0;
#endif
}

std::string ChildProcess::drain() {
  if (read_handle_ == 0) return {};
  std::string collected;
#ifdef _WIN32
  HANDLE handle = reinterpret_cast<HANDLE>(read_handle_);
  DWORD available = 0;
  while (::PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr) != 0 && available > 0) {
    char buffer[4096];
    DWORD read = 0;
    const DWORD want = available < sizeof(buffer) ? available : static_cast<DWORD>(sizeof(buffer));
    if (::ReadFile(handle, buffer, want, &read, nullptr) == 0 || read == 0) break;
    collected.append(buffer, read);
  }
#else
  char buffer[4096];
  const ssize_t read = ::read(static_cast<int>(read_handle_), buffer, sizeof(buffer));
  if (read > 0) collected.append(buffer, static_cast<std::size_t>(read));
#endif
  output_.append(collected);
  return collected;
}

bool ChildProcess::wait_for(const std::string& needle, int timeout_milliseconds) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_milliseconds);
  for (;;) {
    drain();
    if (output_.find(needle) != std::string::npos) return true;
    if (!running()) {
      drain();
      return output_.find(needle) != std::string::npos;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      drain();
      return output_.find(needle) != std::string::npos;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

void ChildProcess::kill() {
#ifdef _WIN32
  if (process_ != nullptr) ::TerminateProcess(reinterpret_cast<HANDLE>(process_), 137);
#else
  if (process_ != nullptr) {
    ::kill(static_cast<pid_t>(reinterpret_cast<std::intptr_t>(process_)), SIGKILL);
  }
#endif
}

int ChildProcess::wait() {
  if (exited_) return exit_code_;
#ifdef _WIN32
  if (process_ == nullptr) {
    exited_ = true;
    exit_code_ = -1;
    return exit_code_;
  }
  ::WaitForSingleObject(reinterpret_cast<HANDLE>(process_), INFINITE);
  DWORD code = 0;
  ::GetExitCodeProcess(reinterpret_cast<HANDLE>(process_), &code);
  exit_code_ = static_cast<int>(code);
#else
  int status = 0;
  const pid_t pid = static_cast<pid_t>(reinterpret_cast<std::intptr_t>(process_));
  ::waitpid(pid, &status, 0);
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
  drain();
  exited_ = true;
  return exit_code_;
}

ScratchDirectory::ScratchDirectory(const std::string& label) {
  std::error_code ec;
  const auto base = std::filesystem::temp_directory_path(ec);
  const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
  path_ = (base / ("av-test-" + label + "-" + std::to_string(unique))).string();
  std::filesystem::remove_all(path_, ec);
  std::filesystem::create_directories(path_, ec);
}

ScratchDirectory::~ScratchDirectory() {
  std::error_code ec;
  std::filesystem::remove_all(path_, ec);
}

std::string ScratchDirectory::file(const std::string& name) const { return path_ + "/" + name; }

}  // namespace avtest
