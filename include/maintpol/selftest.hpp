#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace maintpol {

// ---------------------------------------------------------------------------
// Built-in known-answer self test.
//
// Every primitive whose correctness cannot be inferred from the rest of the
// system is checked here against published vectors: SHA-256 against FIPS
// 180-4 examples, HMAC-SHA256 against RFC 4231, CRC-32/ISO-HDLC against the
// standard check value, and the calendar conversions against known civil
// dates including leap days and pre-epoch instants.
// ---------------------------------------------------------------------------
struct SelfTestResult {
    std::string name;
    bool passed = false;
    std::string detail;

    friend bool operator==(const SelfTestResult&, const SelfTestResult&) = default;
};

struct SelfTestReport {
    std::vector<SelfTestResult> results;

    bool all_passed() const;
    std::size_t passed_count() const;
    std::size_t failed_count() const;
};

SelfTestReport run_self_tests();

}  // namespace maintpol
