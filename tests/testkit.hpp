// Accelerator Virtualization - test framework.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// A deliberately small, self-contained harness. Every case has a stable name,
// prints a flushed BEGIN line, flushed phase markers and a flushed PASS/FAIL
// line, and can be run on its own with --case NAME so a hang or a failure can
// be localised to an exact case and phase without rerunning an opaque suite.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "av/status.hpp"

namespace avtest {

using CaseFn = std::function<void()>;

struct Case {
  std::string suite;
  std::string name;
  CaseFn fn;
};

class Registry {
 public:
  static Registry& instance();
  void add(std::string suite, std::string name, CaseFn fn);
  const std::vector<Case>& cases() const { return cases_; }

 private:
  std::vector<Case> cases_;
};

struct Registrar {
  Registrar(std::string suite, std::string name, CaseFn fn) {
    Registry::instance().add(std::move(suite), std::move(name), std::move(fn));
  }
};

// Reported failures. The first failure ends the case so the report names the
// exact assertion that broke.
class Failure {
 public:
  explicit Failure(std::string message) : message_(std::move(message)) {}
  const std::string& message() const { return message_; }

 private:
  std::string message_;
};

// A case may report that a required capability is genuinely absent (for
// example no CUDA device on this host). A skip is never a pass: it is reported
// separately and the case name and reason are printed.
class Skip {
 public:
  explicit Skip(std::string reason) : reason_(std::move(reason)) {}
  const std::string& reason() const { return reason_; }

 private:
  std::string reason_;
};

// Uniform extraction of the outcome from either a Status or a Result<T>, so
// the assertion macros work for both shapes.
inline ::av::Status to_status(const ::av::Status& status) { return status; }
template <class T>
inline ::av::Status to_status(const ::av::Result<T>& result) {
  return result.status();
}

void report_failure(const char* file, int line, const std::string& message);
void phase(std::string_view name);
void note(std::string_view text);

int run_all(int argc, char** argv);

bool soft_check(const char* file, int line, bool condition, const std::string& message);

}  // namespace avtest

#define AV_TEST(suite_name, case_name)                                      \
  static void av_test_##suite_name##_##case_name();                         \
  static const ::avtest::Registrar av_registrar_##suite_name##_##case_name( \
      #suite_name, #case_name, av_test_##suite_name##_##case_name);         \
  static void av_test_##suite_name##_##case_name()

#define AV_SKIP(reason) throw ::avtest::Skip(reason)

#define AV_PHASE(name) ::avtest::phase(name)

#define AV_NOTE(text) ::avtest::note(text)

#define AV_REQUIRE(condition)                                                         \
  do {                                                                                \
    if (!(condition)) {                                                               \
      ::avtest::report_failure(__FILE__, __LINE__, "requirement failed: " #condition); \
    }                                                                                 \
  } while (false)

#define AV_REQUIRE_MSG(condition, message)                                                    \
  do {                                                                                        \
    if (!(condition)) {                                                                       \
      ::avtest::report_failure(__FILE__, __LINE__,                                            \
                               std::string("requirement failed: " #condition " - ") + (message)); \
    }                                                                                         \
  } while (false)

#define AV_EQUAL(actual, expected)                                          \
  do {                                                                      \
    const auto av_a = (actual);                                             \
    const auto av_b = (expected);                                           \
    if (!(av_a == av_b)) {                                                  \
      ::avtest::report_failure(__FILE__, __LINE__,                          \
                               std::string("expected " #actual " == " #expected)); \
    }                                                                       \
  } while (false)

#define AV_OK(expr)                                                                     \
  do {                                                                                  \
    const ::av::Status av_status = ::avtest::to_status(expr);                           \
    if (!av_status.ok()) {                                                              \
      ::avtest::report_failure(__FILE__, __LINE__,                                      \
                               std::string("expected success from " #expr " but got ") + \
                                   av_status.to_string());                          \
    }                                                                                   \
  } while (false)

#define AV_CODE(expr, expected_code)                                                     \
  do {                                                                                   \
    const ::av::Status av_status = ::avtest::to_status(expr);                            \
    if (av_status.ok()) {                                                                \
      ::avtest::report_failure(__FILE__, __LINE__,                                       \
                               std::string("expected " #expr " to fail with " #expected_code \
                                           " but it succeeded"));                        \
    } else if (av_status.code() != (expected_code)) {                                    \
      ::avtest::report_failure(__FILE__, __LINE__,                                       \
                               std::string("expected " #expr " to fail with " #expected_code \
                                           " but it failed with ") +                     \
                                   av_status.to_string());                               \
    }                                                                                    \
  } while (false)

#define AV_RESULT(result)                                                                 \
  do {                                                                                  \
    if (!(result).ok()) {                                                               \
      ::avtest::report_failure(__FILE__, __LINE__,                                      \
                               std::string("expected a value from " #result " but got ") + \
                                   (result).status().to_string());                      \
    }                                                                                   \
  } while (false)
