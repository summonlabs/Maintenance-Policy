#include "maintpol/selftest.hpp"

#include <string>
#include <vector>

#include "maintpol/canonical.hpp"
#include "maintpol/digest.hpp"
#include "maintpol/policy.hpp"
#include "maintpol/text.hpp"
#include "maintpol/time.hpp"
#include "maintpol/types.hpp"

namespace maintpol {
namespace {

struct Collector {
    SelfTestReport report;

    void check(std::string name, bool passed, std::string detail) {
        SelfTestResult result;
        result.name = std::move(name);
        result.passed = passed;
        result.detail = std::move(detail);
        report.results.push_back(std::move(result));
    }

    void expect_digest(std::string name, const Digest256& actual, std::string_view expected) {
        const bool ok = actual.hex() == expected;
        check(std::move(name), ok, ok ? std::string("matches vector") : "expected " + std::string(expected) +
                                                                             " but computed " + actual.hex());
    }
};

std::string repeat(char character, std::size_t count) { return std::string(count, character); }

void check_digests(Collector& collector) {
    collector.expect_digest("sha256 empty",
                            sha256(std::string_view()),
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    collector.expect_digest("sha256 abc",
                            sha256("abc"),
                            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    collector.expect_digest("sha256 56 byte message",
                            sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    collector.expect_digest("sha256 one million a",
                            sha256(repeat('a', 1000000u)),
                            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    const bool crc_ok = crc32("123456789") == 0xCBF43926u;
    collector.check("crc32 check value", crc_ok,
                    crc_ok ? "matches 0xCBF43926" : "unexpected CRC-32 value");
}

void check_hmac(Collector& collector) {
    // RFC 4231 test cases.
    {
        const std::string key(20u, static_cast<char>(0x0b));
        collector.expect_digest("hmac-sha256 rfc4231 case 1", hmac_sha256(key, "Hi There"),
                                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
    collector.expect_digest("hmac-sha256 rfc4231 case 2", hmac_sha256("Jefe", "what do ya want for nothing?"),
                            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    {
        const std::string key(20u, static_cast<char>(0xaa));
        const std::string data(50u, static_cast<char>(0xdd));
        collector.expect_digest("hmac-sha256 rfc4231 case 3", hmac_sha256(key, data),
                                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }
    {
        std::string key;
        for (int value = 1; value <= 25; ++value) {
            key.push_back(static_cast<char>(value));
        }
        const std::string data(50u, static_cast<char>(0xcd));
        collector.expect_digest("hmac-sha256 rfc4231 case 4", hmac_sha256(key, data),
                                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    }
    {
        const std::string key(131u, static_cast<char>(0xaa));
        collector.expect_digest("hmac-sha256 rfc4231 case 6",
                                hmac_sha256(key, "Test Using Larger Than Block-Size Key - Hash Key First"),
                                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }
    {
        const std::string key(131u, static_cast<char>(0xaa));
        collector.expect_digest(
            "hmac-sha256 rfc4231 case 7",
            hmac_sha256(key, "This is a test using a larger than block-size key and a larger than block-size data. "
                             "The key needs to be hashed before being used by the HMAC algorithm."),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
    }
}

void check_calendar(Collector& collector) {
    collector.check("leap year 2000", is_leap_year(2000), "2000 is divisible by 400");
    collector.check("leap year 1900", !is_leap_year(1900), "1900 is divisible by 100 but not 400");
    collector.check("leap year 2024", is_leap_year(2024), "2024 is divisible by 4");
    collector.check("leap year 2100", !is_leap_year(2100), "2100 is divisible by 100 but not 400");
    collector.check("february 2024 length", days_in_month(2024, 2) == 29u, "2024-02 has 29 days");

    const bool epoch_ok = days_from_civil(1970, 1, 1) == 0;
    collector.check("days_from_civil epoch", epoch_ok, epoch_ok ? "1970-01-01 is day 0" : "unexpected day number");
    const bool pre_epoch_ok = days_from_civil(1969, 12, 31) == -1;
    collector.check("days_from_civil pre epoch", pre_epoch_ok,
                    pre_epoch_ok ? "1969-12-31 is day -1" : "unexpected day number");
    {
        const CivilTime civil = civil_from_days(days_from_civil(2000, 2, 29));
        const bool ok = civil.year == 2000 && civil.month == 2 && civil.day == 29;
        collector.check("civil round trip leap day", ok, "2000-02-29 round trips");
    }
    {
        auto instant = Instant::parse("1677-09-21T00:12:43.145224192Z");
        const bool ok = instant.has_value() && instant.value().unix_nanos() == INT64_MIN;
        collector.check("min instant boundary", ok,
                        ok ? "int64 minimum nanosecond instant parses"
                           : "expected int64 minimum, got " + (instant ? instant.value().format() : "error"));
    }
    {
        auto instant = Instant::parse("2262-04-11T23:47:16.854775807Z");
        const bool ok = instant.has_value() && instant.value().unix_nanos() == INT64_MAX;
        collector.check("max instant boundary", ok, ok ? "int64 maximum nanosecond instant parses" : "out of range");
    }
    {
        auto instant = Instant::parse("1969-12-31T23:59:59.999999999Z");
        const bool ok = instant.has_value() && instant.value().format() == "1969-12-31T23:59:59.999999999Z";
        collector.check("pre epoch round trip", ok, ok ? "one nanosecond before the epoch round trips" : "mismatch");
    }
    {
        auto instant = Instant::parse("2026-01-01T05:30:00+05:30");
        const bool ok = instant.has_value() && instant.value().format() == "2026-01-01T00:00:00.000000000Z";
        collector.check("offset normalisation", ok, ok ? "explicit offset normalised to UTC" : "mismatch");
    }
    collector.check("reject 2023-02-29", !Instant::parse("2023-02-29T00:00:00Z").has_value(),
                    "a non-leap 29 February is rejected");
    collector.check("reject month 13", !Instant::parse("2023-13-01T00:00:00Z").has_value(), "month 13 is rejected");
    collector.check("reject year 0000", !Instant::parse("0000-01-01T00:00:00Z").has_value(), "year 0000 is rejected");
    {
        auto instant = Instant::parse("2023-01-01T00:00:60Z");
        const bool ok = !instant.has_value() && instant.error().code == Code::LeapSecondUnsupported;
        collector.check("reject leap second", ok, "second 60 is refused explicitly");
    }
    {
        auto instant = Instant::parse("2023-01-01T00:00:00");
        const bool ok = !instant.has_value() && instant.error().code == Code::TimestampMalformed;
        collector.check("reject missing designator", ok, "a timestamp without a UTC designator is refused");
    }
    {
        auto duration = Duration::parse("P1DT2H3M4.5S");
        const bool ok = duration.has_value() && duration.value().format() == "P1DT2H3M4.500000000S";
        collector.check("duration round trip", ok, ok ? duration.value().format() : "mismatch");
    }
}

void check_canonical(Collector& collector) {
    const std::vector<std::string> samples = {
        "simple",          "with space",      "quote\"inside",   "back\\slash",
        "tab\there",       "line\nbreak",     "[",               "=",
        "unicode-\xC3\xA9", std::string("\x01") + "control"};
    bool all_ok = true;
    std::string failing;
    for (const std::string& sample : samples) {
        const std::string encoded = canonical_escape(sample);
        auto decoded = canonical_unescape(encoded);
        if (!decoded || !(decoded.value() == sample)) {
            all_ok = false;
            failing = sample;
            break;
        }
    }
    collector.check("canonical escape round trip", all_ok,
                    all_ok ? "all samples round trip" : "sample failed: " + failing);
    collector.check("bare value rule", canonical_value_is_bare("abc-123") && !canonical_value_is_bare("a b"),
                    "bare values exclude whitespace");
    collector.check("identifier validation",
                    validate_identifier("fac-1.pod_a", IdKind::Identifier).has_value() &&
                        !validate_identifier("-leading", IdKind::Identifier).has_value(),
                    "identifiers must start alphanumeric");
    collector.check("scope selector validation",
                    ScopePath::parse_selector("*/*").has_value() && !ScopePath::parse("FAC/*").has_value(),
                    "selectors allow wildcards, concrete scopes do not");
}

Policy sample_policy() {
    std::vector<Rule> rules;
    {
        BlackoutRule blackout;
        blackout.header.id = RuleId::parse("blackout-a").value();
        blackout.header.priority = 10;
        blackout.header.scope = ScopePath::parse_selector("FAC-1/*").value();
        blackout.header.classes.all = true;
        blackout.windows.push_back(make_interval(Instant::parse("2026-03-01T00:00:00Z").value(),
                                                 Instant::parse("2026-03-01T06:00:00Z").value())
                                      .value());
        blackout.waivable = true;
        rules.emplace_back(std::move(blackout));
    }
    {
        RedundancyRule redundancy;
        redundancy.header.id = RuleId::parse("redundancy-a").value();
        redundancy.header.priority = 20;
        redundancy.header.scope = ScopePath::parse_selector("FAC-1/fabric").value();
        redundancy.header.classes.classes.push_back(ObligationClassId::parse("power").value());
        redundancy.minimum_survivors = 2;
        rules.emplace_back(std::move(redundancy));
    }
    PolicySettings settings;
    settings.evidence_max_age = Duration::parse("PT24H").value();
    settings.max_window = Duration::parse("PT8H").value();
    settings.min_waiver_level = AuthorityLevel::from_value(4).value();
    return Policy::create(PolicyId::parse("policy-a").value(), PolicyGeneration::from_value(1).value(),
                          Revision::from_value(1).value(), PolicyLifecycle::Published,
                          Instant::parse("2026-01-01T00:00:00Z").value(), settings, std::move(rules))
        .value();
}

void check_roundtrip(Collector& collector) {
    const Policy policy = sample_policy();
    const std::string canonical = canonical_policy(policy);
    auto reparsed = parse_policy_document(canonical);
    const bool parse_ok = reparsed.has_value();
    collector.check("policy document parse", parse_ok,
                    parse_ok ? "canonical policy parses" : reparsed.error().detail);
    if (parse_ok) {
        const bool stable = canonical_policy(reparsed.value()) == canonical;
        collector.check("policy canonical stability", stable, "canonical form is byte stable");
        const bool digest_equal = reparsed.value().digest() == policy.digest();
        collector.check("policy digest stability", digest_equal, "digest is unchanged by a round trip");
    }

    Decision decision;
    decision.outcome = Outcome::Deny;
    decision.replay = ReplayDisposition::Fresh;
    decision.bindings.policy_id = policy.id();
    decision.bindings.policy_generation = policy.generation();
    decision.bindings.policy_digest = policy.digest();
    decision.bindings.control_epoch = ControlEpoch::from_value(1).value();
    decision.bindings.registry_revision = Revision::from_value(1).value();
    decision.bindings.context_id = ContextId::parse("ctx-1").value();
    decision.bindings.request_id = RequestId::parse("req-1").value();
    decision.bindings.request_digest = sha256("request");
    decision.bindings.evaluated_at = Instant::parse("2026-01-02T00:00:00Z").value();
    Finding finding;
    finding.code = Code::BlackoutConflict;
    finding.rule = RuleId::parse("blackout-a").value();
    decision.findings.push_back(finding);
    const Digest256 fresh_digest = decision.digest();
    Decision replayed = decision;
    replayed.replay = ReplayDisposition::Replayed;
    const bool digest_stable = replayed.digest() == fresh_digest;
    collector.check("replay disposition excluded from digest", digest_stable,
                    "the digest answers the request, not the transport");
    const std::string document = decision_document(decision);
    auto parsed = parse_decision_document(document);
    const bool ok = parsed.has_value() && parsed.value().digest() == fresh_digest;
    collector.check("decision document round trip", ok,
                    ok ? "decision document verifies its own digest" : "decision document did not verify");
}

}  // namespace

bool SelfTestReport::all_passed() const { return failed_count() == 0; }

std::size_t SelfTestReport::passed_count() const {
    std::size_t count = 0;
    for (const SelfTestResult& result : results) {
        if (result.passed) {
            ++count;
        }
    }
    return count;
}

std::size_t SelfTestReport::failed_count() const {
    std::size_t count = 0;
    for (const SelfTestResult& result : results) {
        if (!result.passed) {
            ++count;
        }
    }
    return count;
}

SelfTestReport run_self_tests() {
    Collector collector;
    check_digests(collector);
    check_hmac(collector);
    check_calendar(collector);
    check_canonical(collector);
    check_roundtrip(collector);
    return collector.report;
}

}  // namespace maintpol
