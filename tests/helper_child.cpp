// ---------------------------------------------------------------------------
// Child process helper used by the multi-process and crash consistency tests.
//
//   hold-exclusive <store> <milliseconds>   open read-write, hold the lock, sleep
//   hold-shared <store> <milliseconds>      open read-only, hold the lock, sleep
//   crash <store> <fault-point>             commit the bundle read from stdin
//   eval-store <store> <request-file>       evaluate against a store and print
// ---------------------------------------------------------------------------
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include "maintpol/engine.hpp"
#include "maintpol/fault.hpp"
#include "maintpol/fileio.hpp"
#include "maintpol/store.hpp"
#include "maintpol/text.hpp"

namespace {

int usage() {
    std::cerr << "helper: unknown invocation\n";
    return 2;
}

std::string read_stream() {
    std::string content;
    std::string line;
    while (std::getline(std::cin, line)) {
        content.append(line);
        content.push_back('\n');
    }
    return content;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        return usage();
    }
    const std::string command = argv[1];
    if (command == "hold-exclusive" || command == "hold-shared") {
        if (argc < 4) {
            return usage();
        }
        const bool read_only = command == "hold-shared";
        auto store = maintpol::PolicyStore::open(argv[2], read_only);
        if (!store) {
            std::cout << "open-failed " << maintpol::to_string(store.error().code) << "\n";
            return 1;
        }
#if defined(_WIN32)
        std::cout << "pid " << GetCurrentProcessId() << "\n";
#else
        std::cout << "pid " << ::getpid() << "\n";
#endif
        std::cout << "locked\n";
        std::cout.flush();
        const auto milliseconds = std::stoll(argv[3]);
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
        return 0;
    }
    if (command == "crash") {
        if (argc < 4) {
            return usage();
        }
        maintpol::FaultPlan plan;
        if (!maintpol::fault_point_from_name(argv[3], plan.crash_at)) {
            return usage();
        }
        const std::string document = read_stream();
        auto bundle = maintpol::parse_bundle_document(document);
        if (!bundle) {
            std::cout << "parse-failed " << maintpol::to_string(bundle.error().code) << "\n";
            return 1;
        }
        auto store = maintpol::PolicyStore::open(argv[2], false);
        if (!store) {
            std::cout << "open-failed " << maintpol::to_string(store.error().code) << "\n";
            return 1;
        }
        auto committed = store.value().commit(bundle.value(), plan);
        if (!committed) {
            std::cout << "commit-failed " << maintpol::to_string(committed.error().code) << "\n";
            return 1;
        }
        std::cout << "committed\n";
        return 0;
    }
    if (command == "eval-store") {
        if (argc < 4) {
            return usage();
        }
        auto store = maintpol::PolicyStore::open(argv[2], true);
        if (!store) {
            std::cout << "open-failed " << maintpol::to_string(store.error().code) << "\n";
            return 1;
        }
        auto bundle = store.value().load_bundle();
        if (!bundle) {
            std::cout << "load-failed " << maintpol::to_string(bundle.error().code) << "\n";
            return 1;
        }
        auto request_text = maintpol::read_file_bounded(argv[3], maintpol::kMaxTextDocumentBytes);
        if (!request_text) {
            return 1;
        }
        auto request = maintpol::parse_request_document(request_text.value());
        if (!request) {
            std::cout << "request-failed " << maintpol::to_string(request.error().code) << "\n";
            return 1;
        }
        maintpol::KeySet keys;
        auto decision = maintpol::evaluate(bundle.value(), keys, request.value());
        if (!decision) {
            std::cout << "eval-failed " << maintpol::to_string(decision.error().code) << "\n";
            return 1;
        }
        std::cout << maintpol::to_string(decision.value().outcome) << " "
                  << decision.value().digest().hex() << "\n";
        return 0;
    }
    return usage();
}
