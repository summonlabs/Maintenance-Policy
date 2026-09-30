#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "maintpol/error.hpp"

namespace maintpol::test {

// ---------------------------------------------------------------------------
// Minimal test harness. Tests are registered statically and run by group so
// that a single executable covers unit, integration and end-to-end cases.
// ---------------------------------------------------------------------------
struct Failure {
    std::string message;
};

struct TestCase {
    std::string group;
    std::string name;
    std::function<void()> body;
};

std::vector<TestCase>& registry();

struct Registrar {
    Registrar(const char* group, const char* name, std::function<void()> body);
};

[[noreturn]] void fail(const char* file, int line, const std::string& message);

int run_all(const std::string& group_filter);

// Unwraps a Result, failing the test when it holds an error.
inline void require_value(Result<void> result, const char* file, int line) {
    if (!result) {
        fail(file, line, std::string("unexpected error: ") + std::string(to_string(result.error().code)) +
                            " - " + result.error().detail);
    }
}

template <typename T>
T require_value(Result<T> result, const char* file, int line) {
    if (!result) {
        fail(file, line, std::string("unexpected error: ") + std::string(to_string(result.error().code)) +
                            " - " + result.error().detail);
    }
    return std::move(result).value();
}

// Deterministic pseudo random generator (splitmix64) used by the property and
// state machine tests. Every generated seed is printed so that a failure can
// be reproduced exactly.
class Rng {
public:
    explicit Rng(std::uint64_t seed) : state_(seed), seed_(seed) {}

    std::uint64_t next() {
        state_ += 0x9E3779B97F4A7C15ull;
        std::uint64_t value = state_;
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
        return value ^ (value >> 31);
    }

    std::uint32_t below(std::uint32_t bound) {
        if (bound == 0) {
            return 0;
        }
        return static_cast<std::uint32_t>(next() % bound);
    }

    bool chance(std::uint32_t percent) { return below(100) < percent; }

    std::uint64_t seed() const { return seed_; }

private:
    std::uint64_t state_;
    std::uint64_t seed_;
};

// Environment supplied paths for end to end tests.
std::string cli_path();
std::string helper_path();
std::uint64_t process_identifier();
std::string make_temp_directory(const std::string& label);
void remove_temp_directory(const std::string& path);
std::string write_temp_file(const std::string& directory, const std::string& name, const std::string& content);
std::string read_text_file(const std::string& path);
// Runs a command line and returns its exit code; stdout and stderr are
// captured when an output string is supplied.
int run_process(const std::vector<std::string>& arguments, std::string* output = nullptr);

// A child process whose output can be read incrementally, so that a test can
// interact with it and terminate it while it is still running.
class ChildProcess {
public:
    ChildProcess() = default;
    ~ChildProcess();
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ChildProcess(ChildProcess&& other) noexcept;
    ChildProcess& operator=(ChildProcess&& other) noexcept;

    bool valid() const { return process_ != nullptr; }
    // Reads one line, without its terminator. Returns false at end of output;
    // an empty line is delivered as an empty string with a true result.
    bool read_line(std::string& line);
    int wait();
    // Terminates the process abruptly, as a crash would.
    void terminate();

private:
    friend ChildProcess start_process(const std::vector<std::string>& arguments);

    void* process_ = nullptr;
    void* pipe_ = nullptr;
    std::string pending_;
    bool eof_ = false;
};

ChildProcess start_process(const std::vector<std::string>& arguments);

}  // namespace maintpol::test

#define MP_TEST(group, name)                                                  \
    static void mp_test_##group##_##name();                                   \
    static ::maintpol::test::Registrar mp_registrar_##group##_##name(         \
        #group, #name, mp_test_##group##_##name);                             \
    static void mp_test_##group##_##name()

#define MP_FAIL(message) ::maintpol::test::fail(__FILE__, __LINE__, (message))

#define MP_CHECK(expr)                                                         \
    do {                                                                       \
        if (!(expr)) {                                                         \
            ::maintpol::test::fail(__FILE__, __LINE__, "check failed: " #expr); \
        }                                                                      \
    } while (false)

#define MP_CHECK_EQ(left, right)                                                                 \
    do {                                                                                         \
        if (!((left) == (right))) {                                                              \
            ::maintpol::test::fail(__FILE__, __LINE__, "expected equality: " #left " == " #right); \
        }                                                                                        \
    } while (false)

#define MP_CHECK_CODE(result, expected)                                                             \
    do {                                                                                            \
        const auto& mp_result_value = (result);                                                     \
        if (mp_result_value.has_value()) {                                                          \
            ::maintpol::test::fail(__FILE__, __LINE__, #result " unexpectedly succeeded");           \
        } else if (mp_result_value.error().code != (expected)) {                                    \
            ::maintpol::test::fail(                                                                 \
                __FILE__, __LINE__,                                                                 \
                std::string("expected code ") + std::string(::maintpol::to_string(expected)) +       \
                    " but got " + std::string(::maintpol::to_string(mp_result_value.error().code))); \
        }                                                                                           \
    } while (false)

#define MP_REQUIRE(result) ::maintpol::test::require_value((result), __FILE__, __LINE__)

// Asserts that a Result holds a value, reporting the error when it does not.
#define MP_CHECK_OK(result)                                                                               do {                                                                                                      const auto& mp_checked = (result);                                                                    if (!mp_checked) {                                                                                        ::maintpol::test::fail(__FILE__, __LINE__,                                                                                   std::string("unexpected error: ") +                                                                       std::string(::maintpol::to_string(mp_checked.error().code)) +                                         " - " + mp_checked.error().detail);                                    }                                                                                                 } while (false)
