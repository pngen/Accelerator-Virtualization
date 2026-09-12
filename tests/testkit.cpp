// Accelerator Virtualization - test framework.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "testkit.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace avtest {
namespace {

bool g_in_case = false;

}  // namespace

Registry& Registry::instance() {
  static Registry registry;
  return registry;
}

void Registry::add(std::string suite, std::string name, CaseFn fn) {
  cases_.push_back(Case{std::move(suite), std::move(name), std::move(fn)});
}

void report_failure(const char* file, int line, const std::string& message) {
  throw Failure(std::string(file) + ":" + std::to_string(line) + ": " + message);
}

bool soft_check(const char* file, int line, bool condition, const std::string& message) {
  if (condition) return true;
  std::printf("CHECK-FAIL %s:%d %s\n", file, line, message.c_str());
  std::fflush(stdout);
  return false;
}

void phase(std::string_view name) {
  if (!g_in_case) return;
  std::printf("PHASE %.*s\n", static_cast<int>(name.size()), name.data());
  std::fflush(stdout);
}

void note(std::string_view text) {
  if (!g_in_case) return;
  std::printf("NOTE %.*s\n", static_cast<int>(text.size()), text.data());
  std::fflush(stdout);
}

int run_all(int argc, char** argv) {
  std::string only;
  std::string suite_filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--case" && i + 1 < argc) {
      only = argv[++i];
    } else if (arg == "--suite" && i + 1 < argc) {
      suite_filter = argv[++i];
    } else if (arg == "--list") {
      list_only = true;
    } else {
      std::fprintf(stderr, "unknown argument '%s' (use --case NAME, --suite NAME, --list)\n", arg.c_str());
      return 2;
    }
  }

  const std::vector<Case>& cases = Registry::instance().cases();
  if (list_only) {
    for (const Case& entry : cases) {
      std::printf("%s.%s\n", entry.suite.c_str(), entry.name.c_str());
    }
    std::fflush(stdout);
    return 0;
  }

  std::size_t selected = 0;
  std::size_t passed = 0;
  std::size_t failed = 0;
  std::size_t skipped = 0;
  for (const Case& entry : cases) {
    const std::string full = entry.suite + "." + entry.name;
    if (!only.empty() && full != only && entry.name != only) continue;
    if (!suite_filter.empty() && entry.suite != suite_filter) continue;
    ++selected;
    std::printf("BEGIN %s\n", full.c_str());
    std::fflush(stdout);
    g_in_case = true;
    try {
      entry.fn();
      g_in_case = false;
      ++passed;
      std::printf("PASS %s\n", full.c_str());
    } catch (const Skip& skip) {
      g_in_case = false;
      ++skipped;
      std::printf("SKIP %s %s\n", full.c_str(), skip.reason().c_str());
    } catch (const Failure& failure) {
      g_in_case = false;
      ++failed;
      std::printf("FAIL %s %s\n", full.c_str(), failure.message().c_str());
    } catch (const std::exception& error) {
      g_in_case = false;
      ++failed;
      std::printf("FAIL %s unexpected exception: %s\n", full.c_str(), error.what());
    } catch (...) {
      g_in_case = false;
      ++failed;
      std::printf("FAIL %s unexpected non-standard exception\n", full.c_str());
    }
    std::fflush(stdout);
  }

  std::printf("SUITE-TOTAL selected=%zu passed=%zu failed=%zu skipped=%zu\n", selected, passed, failed, skipped);
  std::fflush(stdout);
  if (selected == 0) {
    std::printf("SUITE-EMPTY no case matched the selection\n");
    std::fflush(stdout);
    return 2;
  }
  return failed == 0 ? 0 : 1;
}

}  // namespace avtest

int main(int argc, char** argv) { return ::avtest::run_all(argc, argv); }
