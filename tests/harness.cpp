#include "harness.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "maintpol/fileio.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <process.h>
#else
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace maintpol::test {

std::vector<TestCase>& registry() {
    static std::vector<TestCase> cases;
    return cases;
}

Registrar::Registrar(const char* group, const char* name, std::function<void()> body) {
    TestCase test;
    test.group = group;
    test.name = name;
    test.body = std::move(body);
    registry().push_back(std::move(test));
}

void fail(const char* file, int line, const std::string& message) {
    std::ostringstream stream;
    stream << file << ":" << line << ": " << message;
    throw Failure{stream.str()};
}

namespace {

std::string environment_value(const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string();
}

std::string preferred_path(std::string value) {
    for (char& character : value) {
        if (character == '/') {
            character = '\\';
        }
    }
    return value;
}

#if defined(_WIN32)

std::wstring to_wide(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) {
        return std::wstring();
    }
    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
    return wide;
}

// Builds a CreateProcess command line with the standard Windows quoting rules.
std::wstring build_command_line(const std::vector<std::string>& arguments) {
    std::wstring line;
    for (const std::string& argument : arguments) {
        if (!line.empty()) {
            line.push_back(L' ');
        }
        line.push_back(L'"');
        std::size_t backslashes = 0;
        for (char character : argument) {
            if (character == '\\') {
                ++backslashes;
                continue;
            }
            if (character == '"') {
                line.append(backslashes * 2u + 1u, L'\\');
                line.push_back(L'"');
                backslashes = 0;
                continue;
            }
            line.append(backslashes, L'\\');
            backslashes = 0;
            line.push_back(static_cast<wchar_t>(static_cast<unsigned char>(character)));
        }
        line.append(backslashes * 2u, L'\\');
        line.push_back(L'"');
    }
    return line;
}

#endif

}  // namespace

std::uint64_t process_identifier() {
#if defined(_WIN32)
    return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
    return static_cast<std::uint64_t>(::getpid());
#endif
}

std::string cli_path() { return preferred_path(environment_value("MAINTPOL_CLI")); }
std::string helper_path() { return preferred_path(environment_value("MAINTPOL_HELPER")); }

std::string make_temp_directory(const std::string& label) {
    static std::uint64_t counter = 0;
    ++counter;
    std::string base = environment_value("TEMP");
    if (base.empty()) {
        base = environment_value("TMP");
    }
    if (base.empty()) {
        base = ".";
    }
    std::ostringstream stream;
    stream << base << "\\maintpol-test-" << label << "-" << counter << "-" << process_identifier();
    const std::string path = stream.str();
    auto created = create_directory(path, false);
    if (!created) {
        MP_FAIL("cannot create temporary directory: " + created.error().detail);
    }
    return path;
}

void remove_temp_directory(const std::string& path) {
    auto removed = remove_tree(path);
    if (!removed) {
        MP_FAIL("cannot remove temporary directory: " + removed.error().detail);
    }
}

std::string write_temp_file(const std::string& directory, const std::string& name, const std::string& content) {
    const std::string path = directory + "\\" + name;
    auto written = write_file_durable(path, content);
    if (!written) {
        MP_FAIL("cannot write temporary file: " + written.error().detail);
    }
    return path;
}

std::string read_text_file(const std::string& path) {
    auto content = read_file_bounded(path, 64u * 1024u * 1024u);
    if (!content) {
        MP_FAIL("cannot read file: " + content.error().detail);
    }
    return content.value();
}

// ---------------------------------------------------------------------------
// Child processes are created directly by the operating system. No shell is
// involved, so an argument that contains spaces or quotes can never be
// reinterpreted as shell syntax.
// ---------------------------------------------------------------------------
#if defined(_WIN32)

ChildProcess start_process(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        MP_FAIL("start_process requires a program");
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE read_end = nullptr;
    HANDLE write_end = nullptr;
    if (!CreatePipe(&read_end, &write_end, &attributes, 0)) {
        MP_FAIL("cannot create output pipe");
    }
    SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_end;
    startup.hStdError = write_end;
    startup.hStdInput = nullptr;

    PROCESS_INFORMATION information{};
    std::wstring command_line = build_command_line(arguments);
    const BOOL created = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information);
    CloseHandle(write_end);
    if (!created) {
        CloseHandle(read_end);
        MP_FAIL("cannot start process: " + arguments.front());
    }
    CloseHandle(information.hThread);
    ChildProcess process;
    process.process_ = information.hProcess;
    process.pipe_ = read_end;
    return process;
}

bool ChildProcess::read_line(std::string& line) {
    line.clear();
    if (pipe_ == nullptr) {
        return false;
    }
    HANDLE pipe = static_cast<HANDLE>(pipe_);
    while (true) {
        const std::size_t newline = pending_.find('\n');
        if (newline != std::string::npos) {
            line = pending_.substr(0, newline);
            pending_.erase(0, newline + 1u);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return true;
        }
        if (eof_) {
            line = pending_;
            pending_.clear();
            return !line.empty();
        }
        char buffer[512];
        DWORD read = 0;
        if (!ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) || read == 0) {
            eof_ = true;
            continue;
        }
        pending_.append(buffer, read);
    }
}

int ChildProcess::wait() {
    if (process_ == nullptr) {
        return -1;
    }
    HANDLE process = static_cast<HANDLE>(process_);
    DWORD exit_code = 0;
    WaitForSingleObject(process, INFINITE);
    GetExitCodeProcess(process, &exit_code);
    CloseHandle(process);
    if (pipe_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(pipe_));
        pipe_ = nullptr;
    }
    process_ = nullptr;
    return static_cast<int>(exit_code);
}

void ChildProcess::terminate() {
    if (process_ == nullptr) {
        return;
    }
    TerminateProcess(static_cast<HANDLE>(process_), 7);
}

#else

ChildProcess start_process(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        MP_FAIL("start_process requires a program");
    }
    int descriptors[2] = {-1, -1};
    if (::pipe(descriptors) != 0) {
        MP_FAIL("cannot create output pipe");
    }
    const pid_t child = ::fork();
    if (child < 0) {
        MP_FAIL("cannot fork");
    }
    if (child == 0) {
        ::close(descriptors[0]);
        ::dup2(descriptors[1], STDOUT_FILENO);
        ::dup2(descriptors[1], STDERR_FILENO);
        ::close(descriptors[1]);
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1u);
        for (const std::string& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }
    ::close(descriptors[1]);
    ChildProcess process;
    process.process_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(child));
    process.pipe_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(descriptors[0]));
    return process;
}

bool ChildProcess::read_line(std::string& line) {
    line.clear();
    if (pipe_ == nullptr) {
        return false;
    }
    const int descriptor = static_cast<int>(reinterpret_cast<std::intptr_t>(pipe_));
    while (true) {
        const std::size_t newline = pending_.find('\n');
        if (newline != std::string::npos) {
            line = pending_.substr(0, newline);
            pending_.erase(0, newline + 1u);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return true;
        }
        if (eof_) {
            line = pending_;
            pending_.clear();
            return !line.empty();
        }
        char buffer[512];
        const ssize_t read = ::read(descriptor, buffer, sizeof(buffer));
        if (read <= 0) {
            eof_ = true;
            continue;
        }
        pending_.append(buffer, static_cast<std::size_t>(read));
    }
}

int ChildProcess::wait() {
    if (process_ == nullptr) {
        return -1;
    }
    const pid_t child = static_cast<pid_t>(reinterpret_cast<std::intptr_t>(process_));
    if (pipe_ != nullptr) {
        ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(pipe_)));
        pipe_ = nullptr;
    }
    int status = 0;
    ::waitpid(child, &status, 0);
    process_ = nullptr;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void ChildProcess::terminate() {
    if (process_ == nullptr) {
        return;
    }
    ::kill(static_cast<pid_t>(reinterpret_cast<std::intptr_t>(process_)), SIGKILL);
}

#endif

ChildProcess::~ChildProcess() {
    if (process_ != nullptr) {
        wait();
    }
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : process_(other.process_), pipe_(other.pipe_), pending_(std::move(other.pending_)), eof_(other.eof_) {
    other.process_ = nullptr;
    other.pipe_ = nullptr;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
        if (process_ != nullptr) {
            wait();
        }
        process_ = other.process_;
        pipe_ = other.pipe_;
        pending_ = std::move(other.pending_);
        eof_ = other.eof_;
        other.process_ = nullptr;
        other.pipe_ = nullptr;
    }
    return *this;
}

int run_process(const std::vector<std::string>& arguments, std::string* output) {
    ChildProcess process = start_process(arguments);
    if (!process.valid()) {
        MP_FAIL("process did not start");
    }
    std::string captured;
    std::string line;
    while (process.read_line(line)) {
        captured.append(line);
        captured.push_back('\n');
    }
    const int exit_code = process.wait();
    if (output != nullptr) {
        *output = captured;
    }
    return exit_code;
}

int run_all(const std::string& group_filter) {
    std::vector<TestCase> cases = registry();
    std::sort(cases.begin(), cases.end(), [](const TestCase& left, const TestCase& right) {
        if (left.group != right.group) {
            return left.group < right.group;
        }
        return left.name < right.name;
    });
    std::size_t passed = 0;
    std::size_t failed = 0;
    std::size_t skipped = 0;
    for (const TestCase& test : cases) {
        if (!group_filter.empty() && test.group != group_filter) {
            ++skipped;
            continue;
        }
        try {
            test.body();
            ++passed;
        } catch (const Failure& failure) {
            ++failed;
            std::cout << "FAIL " << test.group << "." << test.name << "\n  " << failure.message << "\n";
        } catch (const std::exception& error) {
            ++failed;
            std::cout << "FAIL " << test.group << "." << test.name << "\n  unexpected exception: " << error.what()
                      << "\n";
        } catch (...) {
            ++failed;
            std::cout << "FAIL " << test.group << "." << test.name << "\n  unexpected non standard exception\n";
        }
    }
    std::cout << "tests passed: " << passed << ", failed: " << failed;
    if (skipped != 0) {
        std::cout << ", skipped: " << skipped;
    }
    std::cout << "\n";
    return failed == 0 ? 0 : 1;
}

}  // namespace maintpol::test
