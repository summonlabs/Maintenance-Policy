#include <algorithm>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"
#include "maintpol/version.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

std::string valid_bundle_document() {
    const Policy policy = make_policy(
        {Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z", "2026-03-01T06:00:00Z")},
         Rule{redundancy_rule("redundancy-a", "FAC-1/*", "power", 2)}});
    std::vector<AuthorityRecord> authorities;
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(6));
    authority.description = "facility change authority";
    authorities.push_back(authority);
    return canonical_bundle(make_bundle(policy, authorities));
}

}  // namespace

MP_TEST(adversarial, truncation_sweep_never_crashes) {
    const std::string document = valid_bundle_document();
    MP_CHECK(document.size() > 200u);
    for (std::size_t length = 0; length < document.size(); ++length) {
        auto parsed = parse_bundle_document(document.substr(0, length));
        if (parsed.has_value()) {
            // A prefix that parses must round trip like any other document.
            MP_CHECK_EQ(canonical_bundle(parsed.value()).size() > 0u, true);
        }
    }
    MP_CHECK(parse_bundle_document(document).has_value());
}

MP_TEST(adversarial, byte_mutation_sweep_never_crashes) {
    const std::string document = valid_bundle_document();
    const std::vector<char> replacements = {'\x00', '\xff', '=', '"', '\\', '\n', '[', '9', 'x', ' ', ':'};
    for (std::size_t offset = 0; offset < document.size(); offset += 3u) {
        for (char replacement : replacements) {
            std::string mutated = document;
            mutated[offset] = replacement;
            auto parsed = parse_bundle_document(mutated);
            if (parsed.has_value()) {
                MP_CHECK(!canonical_bundle(parsed.value()).empty());
            }
        }
    }
}

MP_TEST(adversarial, duplicate_identities_are_rejected) {
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z")}});
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(6));
    MP_CHECK_CODE(PolicyBundle::create(policy, {authority, authority}, {}, {}, MP_REQUIRE(ControlEpoch::from_value(1)),
                                       MP_REQUIRE(Revision::from_value(1))),
                  Code::DuplicateIdentifier);

    RequestSpec duplicate_scopes;
    duplicate_scopes.scopes = {"FAC-1/fabric", "FAC-1/fabric"};
    MP_CHECK_CODE(build_request_result(duplicate_scopes), Code::DuplicateIdentifier);

    RequestSpec duplicate_classes;
    duplicate_classes.classes = {"power", "power"};
    MP_CHECK_CODE(build_request_result(duplicate_classes), Code::DuplicateIdentifier);

    RequestSpec duplicate_evidence;
    duplicate_evidence.evidence_classes = {EvidenceSpec{}, EvidenceSpec{}};
    MP_CHECK_CODE(build_request_result(duplicate_evidence), Code::EvidenceDuplicateClass);

    RequestSpec duplicate_interlocks;
    duplicate_interlocks.interlocks = {{"bus-a", true}, {"bus-a", false}};
    MP_CHECK_CODE(build_request_result(duplicate_interlocks), Code::DuplicateIdentifier);
}

MP_TEST(adversarial, hostile_identifiers_and_text) {
    MP_CHECK_CODE(RuleId::parse(""), Code::ValueMalformed);
    MP_CHECK_CODE(RuleId::parse(std::string(65u, 'a')), Code::TextTooLong);
    MP_CHECK_CODE(RuleId::parse("-leading"), Code::ValueMalformed);
    MP_CHECK_CODE(RuleId::parse("has space"), Code::ValueMalformed);
    MP_CHECK_CODE(RuleId::parse(std::string("bad\xC3\x28utf8")), Code::ValueMalformed);
    MP_CHECK_CODE(ObligationClassId::parse("../../etc/passwd"), Code::ValueMalformed);
    MP_CHECK_CODE(ScopePath::parse("FAC-1/../other"), Code::ScopeInvalid);
    MP_CHECK_CODE(ScopePath::parse("FAC-1//other"), Code::ScopeInvalid);
    MP_CHECK_CODE(ScopePath::parse("/FAC-1"), Code::ScopeInvalid);
    MP_CHECK_CODE(ScopePath::parse("FAC-1/"), Code::ScopeInvalid);
    MP_CHECK_CODE(ScopePath::parse("FAC-1/*"), Code::ScopeInvalid);
    MP_CHECK_CODE(ScopePath::parse(std::string(300u, 'a')), Code::ScopeInvalid);
    MP_CHECK(ScopePath::parse_selector("*/*").has_value());
    MP_CHECK(ScopePath::parse_selector("FAC-1/*/pod").has_value());
    MP_CHECK_CODE(validate_description(std::string("has\nnewline")), Code::ValueMalformed);
    MP_CHECK_CODE(validate_description(std::string(300u, 'a')), Code::TextTooLong);
    MP_CHECK_CODE(validate_description(std::string("bad\xC3\x28utf8")), Code::InvalidUtf8);
    MP_CHECK(validate_description("plain text with unicode-\xC3\xA9").has_value());
}

MP_TEST(adversarial, numeric_and_structural_bounds) {
    RequestSpec zero_generation;
    zero_generation.expected_generation = 0;
    MP_CHECK_CODE(build_request_result(zero_generation), Code::ValueOutOfRange);

    RequestSpec reversed;
    reversed.window_start = "2026-03-01T02:00:00Z";
    reversed.window_end = "2026-03-01T01:00:00Z";
    MP_CHECK_CODE(build_request_result(reversed), Code::IntervalReversed);

    RequestSpec impossible_evidence;
    impossible_evidence.evidence_classes.front().surviving_units = 9;
    impossible_evidence.evidence_classes.front().total_units = 4;
    MP_CHECK_CODE(build_request_result(impossible_evidence), Code::ValueOutOfRange);

    RequestSpec zero_epoch;
    zero_epoch.evidence_epoch = 0;
    MP_CHECK_CODE(build_request_result(zero_epoch), Code::ValueOutOfRange);

    RequestSpec many_scopes;
    for (int index = 0; index < 33; ++index) {
        many_scopes.scopes.push_back("FAC-1/pod-" + std::to_string(index));
    }
    MP_CHECK_CODE(build_request_result(many_scopes), Code::TooManyItems);

    RequestSpec wildcard_scope;
    wildcard_scope.scopes = {"FAC-1/*"};
    MP_CHECK_CODE(build_request_result(wildcard_scope), Code::ScopeInvalid);

    MP_CHECK_CODE(PolicyGeneration::from_value(0), Code::ValueOutOfRange);
    MP_CHECK_CODE(PolicyGeneration::parse("0"), Code::ValueOutOfRange);
    MP_CHECK_CODE(PolicyGeneration::parse("00"), Code::NumberMalformed);
    MP_CHECK_CODE(PolicyGeneration::parse("18446744073709551616"), Code::IntegerOverflow);
    MP_CHECK_CODE(AuthorityLevel::from_value(9), Code::ValueOutOfRange);
    MP_CHECK_CODE(AuthorityLevel::parse("0"), Code::ValueOutOfRange);
    const PolicyGeneration maximum = MP_REQUIRE(PolicyGeneration::from_value(UINT64_MAX));
    MP_CHECK_CODE(maximum.next(), Code::IntegerOverflow);
}

MP_TEST(adversarial, hostile_documents_are_rejected_with_a_code) {
    const std::vector<std::string> documents = {
        "",
        "\n\n\n",
        "[document]\nformat = maintpol/1\n",
        "[document]\nformat = maintpol/1\nkind = bundle\n",
        "[document]\nformat = maintpol/1\nkind = bundle\n[policy]\npolicy_id = p\n",
        "[unknown]\nk = 1\n",
        "[document]\nformat = maintpol/1\nkind = bundle\n[policy]\npolicy_id = p\ngeneration = 1\n"
        "revision = 1\nlifecycle = published\npublished_at = 2026-01-01T00:00:00Z\nevidence_max_age = PT0S\n"
        "max_window = PT8H\nmin_waiver_level = 4\nrequire_evidence_for_classes = true\nmax_recurrence_count = 512\n"
        "[registry]\ncontrol_epoch = 1\nregistry_revision = 1\n",
        "[document]\nformat = maintpol/1\nkind = request\n[request]\ncontext_id = c\n"};
    for (const std::string& document : documents) {
        auto parsed = parse_bundle_document(document);
        MP_CHECK(!parsed.has_value());
        MP_CHECK(parsed.error().code != Code::Ok);
        MP_CHECK(!to_string(parsed.error().code).empty());
    }

    // A decision document whose declared digest does not match its body.
    Decision decision;
    decision.outcome = Outcome::Allow;
    decision.bindings.policy_id = MP_REQUIRE(PolicyId::parse("policy-a"));
    decision.bindings.policy_generation = MP_REQUIRE(PolicyGeneration::from_value(1));
    decision.bindings.policy_digest = sha256("policy");
    decision.bindings.control_epoch = MP_REQUIRE(ControlEpoch::from_value(1));
    decision.bindings.registry_revision = MP_REQUIRE(Revision::from_value(1));
    decision.bindings.context_id = MP_REQUIRE(ContextId::parse("ctx-1"));
    decision.bindings.request_id = MP_REQUIRE(RequestId::parse("req-1"));
    decision.bindings.request_digest = sha256("request");
    decision.bindings.evaluated_at = instant("2026-03-01T00:30:00Z");
    decision.bindings.semantics_version = semantics_version;
    decision.bindings.digest_format_version = digest_format_version;
    const std::string document = decision_document(decision);
    MP_CHECK_OK(parse_decision_document(document));
    std::string tampered = document;
    const std::size_t position = tampered.find("outcome = allow");
    MP_CHECK(position != std::string::npos);
    tampered.replace(position, std::string("outcome = allow").size(), "outcome = deny");
    auto broken = parse_decision_document(tampered);
    if (broken) {
        MP_FAIL("a decision document with a mismatched digest parsed successfully");
    }
    if (broken.error().code != Code::StoreCorrupt) {
        const std::size_t line_start = tampered.rfind('\n', position) + 1u;
        const std::size_t line_end = tampered.find('\n', position);
        MP_FAIL("expected StoreCorrupt but got " + std::string(to_string(broken.error().code)) + " - " +
                broken.error().detail + " [line: " + tampered.substr(line_start, line_end - line_start) + "]");
    }
}

MP_TEST(adversarial, impossible_enum_values_and_digests) {
    const std::string document = valid_bundle_document();

    std::string impossible_lifecycle = document;
    const std::size_t lifecycle = impossible_lifecycle.find("lifecycle = published");
    MP_CHECK(lifecycle != std::string::npos);
    impossible_lifecycle.replace(lifecycle, std::string("lifecycle = published").size(), "lifecycle = 7");
    MP_CHECK_CODE(parse_bundle_document(impossible_lifecycle), Code::UnknownEnumValue);

    std::string unknown_rule_kind = document;
    const std::size_t kind = unknown_rule_kind.find("kind = blackout");
    MP_CHECK(kind != std::string::npos);
    unknown_rule_kind.replace(kind, std::string("kind = blackout").size(), "kind = nonsense");
    MP_CHECK_CODE(parse_bundle_document(unknown_rule_kind), Code::UnknownEnumValue);

    // An exception record binds a policy digest; a malformed or upper case
    // digest is rejected before the record is considered.
    const AuthorityKey key = make_key("key-1");
    const Policy signed_policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                                 "2026-03-01T06:00:00Z")}});
    std::vector<AuthorityRecord> authorities;
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(6));
    authorities.push_back(authority);
    const PolicyBundle base = make_bundle(signed_policy, authorities);
    const ExceptionRecord exception = make_exception("exception-a", base, key, {"blackout-a"});
    const std::string with_exception = canonical_bundle(make_bundle(signed_policy, authorities, {exception}));
    const std::size_t policy_digest = with_exception.find("policy_digest");
    MP_CHECK(policy_digest != std::string::npos);
    const std::size_t value_start = with_exception.find('=', policy_digest) + 2u;

    std::string malformed_digest = with_exception;
    malformed_digest.replace(value_start, 64u, std::string(63u, 'a'));
    MP_CHECK_CODE(parse_bundle_document(malformed_digest), Code::DigestMalformed);

    std::string uppercase_digest = with_exception;
    for (std::size_t index = value_start; index < value_start + 64u; ++index) {
        const char character = uppercase_digest[index];
        if (character >= 'a' && character <= 'f') {
            uppercase_digest[index] = static_cast<char>(character - 'a' + 'A');
        }
    }
    MP_CHECK_CODE(parse_bundle_document(uppercase_digest), Code::DigestMalformed);

    // A request document with an unknown measurement state.
    std::string request = request_document(RequestSpec{});
    const std::size_t state = request.find("state = measured");
    MP_CHECK(state != std::string::npos);
    request.replace(state, std::string("state = measured").size(), "state = maybe");
    MP_CHECK_CODE(parse_request_document(request), Code::UnknownEnumValue);
}

MP_TEST(adversarial, absurd_declared_sizes) {
    // A framed record may not declare a payload larger than the bound.
    MP_CHECK_CODE(unframe_record("MPS-TEST-1\n99999999999999999999\n00000000\nx", "MPS-TEST-1"),
                  Code::StoreRecordTooLarge);
    MP_CHECK_CODE(unframe_record("MPS-TEST-1\n18446744073709551616\n00000000\nx", "MPS-TEST-1"),
                  Code::StoreRecordTooLarge);
    // A declared length that does not match the payload is a length error.
    MP_CHECK_CODE(unframe_record("MPS-TEST-1\n4\n00000000\nx", "MPS-TEST-1"), Code::LengthMismatch);
    // A document larger than the bound is refused before parsing.
    std::string huge;
    huge.resize(kMaxTextDocumentBytes + 1u, 'a');
    MP_CHECK_CODE(parse_text_document(huge, TextLimits{}), Code::DocumentTooLarge);

    // A bundle whose policy generation is the maximum representable value
    // cannot be advanced any further, and the store refuses to guess.
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z")}},
                                      MP_REQUIRE(PolicyGeneration::from_value(UINT64_MAX)));
    const std::string document = canonical_bundle(make_bundle(policy));
    MP_CHECK_OK(parse_bundle_document(document));
}
