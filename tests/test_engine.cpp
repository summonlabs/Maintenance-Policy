#include <algorithm>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"
#include "maintpol/version.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

std::vector<AuthorityRecord> default_authorities() {
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(6));
    authority.description = "facility change authority";
    return {authority};
}

KeySet key_set(const std::vector<AuthorityKey>& keys) { return MP_REQUIRE(KeySet::create(keys)); }

bool has_finding(const Decision& decision, Code code) {
    for (const Finding& finding : decision.findings) {
        if (finding.code == code) {
            return true;
        }
    }
    return false;
}

const Finding* first_finding(const Decision& decision, Code code) {
    for (const Finding& finding : decision.findings) {
        if (finding.code == code) {
            return &finding;
        }
    }
    return nullptr;
}

}  // namespace

MP_TEST(engine, allow_when_no_rule_applies) {
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-04-01T00:00:00Z",
                                                          "2026-04-01T06:00:00Z")}});
    const PolicyBundle bundle = make_bundle(policy);
    const Decision decision = evaluate_spec(bundle, KeySet{}, RequestSpec{});
    MP_CHECK_OUTCOME(decision, Outcome::Allow);
    MP_CHECK(has_finding(decision, Code::NoApplicableRules));
    MP_CHECK(decision.applied_rules.empty());
    MP_CHECK_EQ(decision.bindings.policy_digest.hex(), policy.digest().hex());
    MP_CHECK_EQ(decision.bindings.semantics_version, semantics_version);
    MP_CHECK(!decision.bindings.request_digest.is_zero());
    MP_CHECK(decision.bindings.evaluated_at == instant("2026-03-01T00:30:00Z"));
}

MP_TEST(engine, blackout_conflict_denies) {
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z")}});
    const PolicyBundle bundle = make_bundle(policy);
    const Decision decision = evaluate_spec(bundle, KeySet{}, RequestSpec{});
    MP_CHECK_OUTCOME(decision, Outcome::Deny);
    const Finding* finding = first_finding(decision, Code::BlackoutConflict);
    MP_CHECK(finding != nullptr);
    if (finding != nullptr) {
        MP_CHECK(finding->rule.has_value());
        MP_CHECK_EQ(finding->severity(), Severity::Denial);
    }
    MP_CHECK_EQ(decision.applied_rules.size(), std::size_t(1));
}

MP_TEST(engine, non_waivable_blackout_denies_even_with_exception) {
    const AuthorityKey key = make_key("key-1");
    const std::vector<AuthorityRecord> authorities = default_authorities();
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z", false)}});
    const PolicyBundle base = make_bundle(policy, authorities);
    const ExceptionRecord exception = make_exception("exception-a", base, key, {"blackout-a"});
    const PolicyBundle bundle = make_bundle(policy, authorities, {exception});
    RequestSpec spec;
    spec.exceptions = {"exception-a"};
    const Decision decision = evaluate_spec(bundle, key_set({key}), spec);
    MP_CHECK_OUTCOME(decision, Outcome::Deny);
    MP_CHECK(has_finding(decision, Code::BlackoutConflict));
    MP_CHECK(decision.honored_exceptions.empty());
}

MP_TEST(engine, waivable_blackout_is_relaxed_by_a_valid_exception) {
    const AuthorityKey key = make_key("key-1");
    const std::vector<AuthorityRecord> authorities = default_authorities();
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z", true)}});
    const PolicyBundle base = make_bundle(policy, authorities);
    const ExceptionRecord exception = make_exception("exception-a", base, key, {"blackout-a"});
    const PolicyBundle bundle = make_bundle(policy, authorities, {exception});
    RequestSpec spec;
    spec.exceptions = {"exception-a"};
    const Decision decision = evaluate_spec(bundle, key_set({key}), spec);
    MP_CHECK_OUTCOME(decision, Outcome::Allow);
    MP_CHECK(has_finding(decision, Code::ExceptionWaiverApplied));
    MP_CHECK_EQ(decision.honored_exceptions.size(), std::size_t(1));
    MP_CHECK_EQ(decision.bindings.exception_digests.size(), std::size_t(1));
}

MP_TEST(engine, exception_defects_are_attributed_and_do_not_waive) {
    const AuthorityKey key = make_key("key-1");
    const AuthorityKey other = make_key("key-2", 0x77);
    const std::vector<AuthorityRecord> authorities = default_authorities();
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z", true)}});
    const PolicyBundle base = make_bundle(policy, authorities);

    const auto evaluate_with = [&](const ExceptionRecord& exception, const KeySet& keys) {
        const PolicyBundle bundle = make_bundle(policy, authorities, {exception});
        RequestSpec spec;
        spec.exceptions = {exception.id.value()};
        return evaluate_spec(bundle, keys, spec);
    };

    {
        ExceptionRecord expired = make_exception("exception-expired", base, key, {"blackout-a"});
        set_exception_validity(expired, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", key);
        const Decision decision = evaluate_with(expired, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionExpired));
    }
    {
        ExceptionRecord revoked = make_exception("exception-revoked", base, key, {"blackout-a"});
        revoked.revoked_at = instant("2026-02-15T00:00:00Z");
        const Decision decision = evaluate_with(revoked, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionRevoked));
    }
    {
        ExceptionRecord not_yet = make_exception("exception-future", base, key, {"blackout-a"});
        set_exception_validity(not_yet, "2026-02-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-05-01T00:00:00Z", key);
        const Decision decision = evaluate_with(not_yet, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionNotYetValid));
    }
    {
        const ExceptionRecord scoped = make_exception("exception-scope", base, key, {"blackout-a"}, "OTHER-1/*");
        const Decision decision = evaluate_with(scoped, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionScopeMismatch));
    }
    {
        ExceptionRecord class_mismatch = make_exception("exception-class", base, key, {"blackout-a"}, "FAC-1/*", false);
        class_mismatch.classes.classes.push_back(MP_REQUIRE(ObligationClassId::parse("cooling")));
        sign_exception(class_mismatch, key);
        const Decision decision = evaluate_with(class_mismatch, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionClassMismatch));
    }
    {
        ExceptionRecord wrong_generation = make_exception("exception-generation", base, key, {"blackout-a"});
        wrong_generation.generation = MP_REQUIRE(PolicyGeneration::from_value(9));
        sign_exception(wrong_generation, key);
        const Decision decision = evaluate_with(wrong_generation, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionGenerationMismatch));
    }
    {
        ExceptionRecord tampered = make_exception("exception-mac", base, key, {"blackout-a"});
        tampered.reason = "tampered after signing";
        const Decision decision = evaluate_with(tampered, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::MacInvalid));
    }
    {
        const ExceptionRecord unknown_key = make_exception("exception-unknown-key", base, key, {"blackout-a"});
        const Decision decision = evaluate_with(unknown_key, key_set({other}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::KeyUnknown));
    }
    {
        ExceptionRecord unknown_issuer = make_exception("exception-issuer", base, key, {"blackout-a"});
        unknown_issuer.issued_by = MP_REQUIRE(AuthorityId::parse("authority-9"));
        sign_exception(unknown_issuer, key);
        const Decision decision = evaluate_with(unknown_issuer, key_set({key}));
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::AuthorityUnknown));
    }
    {
        ExceptionRecord weak = make_exception("exception-weak", base, key, {"blackout-a"});
        weak.issued_by = MP_REQUIRE(AuthorityId::parse("authority-weak"));
        sign_exception(weak, key);
        AuthorityRecord weak_authority;
        weak_authority.id = MP_REQUIRE(AuthorityId::parse("authority-weak"));
        weak_authority.level = MP_REQUIRE(AuthorityLevel::from_value(1));
        std::vector<AuthorityRecord> weak_authorities = authorities;
        weak_authorities.push_back(weak_authority);
        const PolicyBundle bundle = make_bundle(policy, weak_authorities, {weak});
        RequestSpec spec;
        spec.exceptions = {weak.id.value()};
        const Decision decision = evaluate_spec(bundle, key_set({key}), spec);
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionAuthorityInsufficient));
    }
    {
        RequestSpec spec;
        spec.exceptions = {"exception-missing"};
        const Decision decision = evaluate_spec(base, key_set({key}), spec);
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ExceptionNotInRegistry));
    }
}

MP_TEST(engine, exception_cannot_relax_a_hard_interlock) {
    const AuthorityKey key = make_key("key-1");
    const std::vector<AuthorityRecord> authorities = default_authorities();
    const Policy policy = make_policy({Rule{hard_interlock_rule("interlock-a", "FAC-1/*", "power-bus-a")}});
    const PolicyBundle base = make_bundle(policy, authorities);
    const ExceptionRecord exception = make_exception("exception-a", base, key, {"interlock-a"});
    const PolicyBundle bundle = make_bundle(policy, authorities, {exception});
    RequestSpec spec;
    spec.exceptions = {"exception-a"};
    spec.interlocks = {{"power-bus-a", false}};
    const Decision decision = evaluate_spec(bundle, key_set({key}), spec);
    MP_CHECK_OUTCOME(decision, Outcome::Deny);
    MP_CHECK(has_finding(decision, Code::ExceptionWaivesHardInterlock));
}

MP_TEST(engine, hard_interlock_states) {
    const Policy policy = make_policy({Rule{hard_interlock_rule("interlock-a", "FAC-1/*", "power-bus-a")}});
    const PolicyBundle bundle = make_bundle(policy);
    {
        RequestSpec spec;
        spec.interlocks = {{"power-bus-a", true}};
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::HardInterlockViolation));
    }
    {
        RequestSpec spec;
        spec.interlocks = {{"power-bus-a", false}};
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Allow);
    }
    {
        RequestSpec spec;
        spec.interlocks = {{"other-interlock", false}};
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::InterlockUnknown));
    }
    {
        RequestSpec spec;
        spec.include_interlocks = false;
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::InterlockUnknown));
    }
}

MP_TEST(engine, protected_classes_cannot_be_bypassed) {
    const Policy policy = make_policy({Rule{protected_class_rule("protected-a", "FAC-1/*", "power", true,
                                                                    "2026-03-01T00:00:00Z", "2026-03-01T06:00:00Z")}});
    const PolicyBundle bundle = make_bundle(policy);
    {
        const Decision decision = evaluate_spec(bundle, KeySet{}, RequestSpec{});
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ProtectedClassViolation));
    }
    {
        RequestSpec spec;
        spec.window_start = "2026-03-01T07:00:00Z";
        spec.window_end = "2026-03-01T08:00:00Z";
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Allow);
    }
    {
        // Omitting the class list must not bypass a class scoped rule.
        RequestSpec spec;
        spec.classes.clear();
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::ProtectedClassViolation));
    }
    {
        RequestSpec spec;
        spec.classes = {"cooling"};
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Allow);
    }
}

MP_TEST(engine, evidence_defects_refuse) {
    PolicySettings settings = default_settings();
    const Policy policy = make_policy(
        {Rule{redundancy_rule("redundancy-a", "FAC-1/*", "power", 2)}}, MP_REQUIRE(PolicyGeneration::from_value(1)),
        settings);
    const PolicyBundle bundle = make_bundle(policy);
    {
        RequestSpec spec;
        spec.evidence_classes.front().surviving_units = 1;
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::RedundancyShortfall));
    }
    {
        RequestSpec spec;
        spec.include_evidence = false;
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceMissing));
    }
    {
        RequestSpec spec;
        spec.evidence_classes.front().state = "unmeasured";
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceUnmeasured));
    }
    {
        RequestSpec spec;
        spec.evidence_observed_at = "2026-02-20T00:00:00Z";
        spec.evidence_classes.front().observed_at = "2026-02-20T00:00:00Z";
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceStale));
    }
    {
        RequestSpec spec;
        spec.evidence_observed_at = "2026-03-01T01:00:00Z";
        spec.evidence_classes.front().observed_at = "2026-03-01T01:00:00Z";
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceFromFuture));
    }
    {
        RequestSpec spec;
        spec.evidence_classes.clear();
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceMissing));
    }
    {
        RequestSpec spec;
        spec.classes.clear();
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceMissing));
    }
}

MP_TEST(engine, evidence_epoch_fence_and_source_trust) {
    PolicySettings settings = default_settings();
    settings.min_evidence_epoch = MP_REQUIRE(EvidenceEpoch::from_value(50));
    settings.evidence_sources.push_back(MP_REQUIRE(EvidenceSourceId::parse("telemetry-1")));
    const Policy policy = make_policy({Rule{redundancy_rule("redundancy-a", "FAC-1/*", "power", 2)}},
                                      MP_REQUIRE(PolicyGeneration::from_value(1)), settings);
    const PolicyBundle bundle = make_bundle(policy);
    {
        RequestSpec spec;
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceEpochFenced));
    }
    {
        RequestSpec spec;
        spec.evidence_epoch = 60;
        spec.interlock_epoch = 60;
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Allow);
    }
    {
        RequestSpec spec;
        spec.evidence_epoch = 60;
        spec.interlock_epoch = 60;
        spec.evidence_source = "telemetry-rogue";
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::EvidenceAuthorityUnknown));
    }
}

MP_TEST(engine, redundancy_waiver_and_escalation_trigger) {
    const AuthorityKey key = make_key("key-1");
    const std::vector<AuthorityRecord> authorities = default_authorities();
    const std::vector<Rule> rules = {
        Rule{redundancy_rule("redundancy-a", "FAC-1/*", "power", 4, true)},
        Rule{escalation_rule("escalation-a", "FAC-1/*", 5, false, true)}};
    const Policy policy = make_policy(rules);
    const PolicyBundle base = make_bundle(policy, authorities);
    const ExceptionRecord exception = make_exception("exception-a", base, key, {"redundancy-a"});
    const PolicyBundle bundle = make_bundle(policy, authorities, {exception});
    RequestSpec spec;
    spec.exceptions = {"exception-a"};
    const Decision decision = evaluate_spec(bundle, key_set({key}), spec);
    MP_CHECK_OUTCOME(decision, Outcome::RequireEscalation);
    MP_CHECK(has_finding(decision, Code::ExceptionWaiverApplied));
    MP_CHECK(has_finding(decision, Code::EscalationRequired));
    MP_CHECK(decision.required_level.has_value());
    if (decision.required_level.has_value()) {
        MP_CHECK_EQ(decision.required_level.value().value(), std::uint64_t(5));
    }
}

MP_TEST(engine, escalation_is_satisfied_by_an_exact_approval) {
    const AuthorityKey key = make_key("key-1");
    const std::vector<AuthorityRecord> authorities = default_authorities();
    const std::vector<Rule> rules = {Rule{soft_constraint_rule("soft-a", "FAC-1/*", 1)},
                                     Rule{escalation_rule("escalation-a", "FAC-1/*", 5)}};
    const Policy policy = make_policy(rules);
    const PolicyBundle base = make_bundle(policy, authorities);
    RequestSpec spec;
    spec.concurrent_maintenance = 3;
    spec.approvals = {"approval-a"};
    const Digest256 request_digest = build_request(spec).digest();
    const ApprovalRecord approval = make_approval("approval-a", base, key, request_digest.hex(), 5);
    const PolicyBundle bundle = make_bundle(policy, authorities, {}, {approval});
    RequestSpec unapproved = spec;
    unapproved.approvals.clear();

    const Decision unsatisfied = evaluate_spec(base, key_set({key}), unapproved);
    MP_CHECK_OUTCOME(unsatisfied, Outcome::RequireEscalation);
    MP_CHECK(has_finding(unsatisfied, Code::SoftConstraintViolation));
    MP_CHECK(has_finding(unsatisfied, Code::EscalationRequired));

    const Decision decision = evaluate_spec(bundle, key_set({key}), spec);
    MP_CHECK_OUTCOME(decision, Outcome::Allow);
    MP_CHECK(has_finding(decision, Code::SoftConstraintApproved));
    MP_CHECK(!has_finding(decision, Code::SoftConstraintViolation));
    MP_CHECK(!has_finding(decision, Code::EscalationRequired));
    MP_CHECK_EQ(decision.bindings.approval_digests.size(), std::size_t(1));
}

MP_TEST(engine, approval_defects_keep_the_escalation_open) {
    const AuthorityKey key = make_key("key-1");
    const AuthorityKey other = make_key("key-2", 0x77);
    const std::vector<AuthorityRecord> authorities = default_authorities();
    const std::vector<Rule> rules = {Rule{soft_constraint_rule("soft-a", "FAC-1/*", 1)},
                                     Rule{escalation_rule("escalation-a", "FAC-1/*", 5)}};
    const Policy policy = make_policy(rules);
    const PolicyBundle base = make_bundle(policy, authorities);
    RequestSpec spec;
    spec.concurrent_maintenance = 3;

    // Every case approves the exact request digest it is evaluated with, so
    // the only defect present is the one each case is testing.
    const auto evaluate_with = [&](const ApprovalRecord& approval, const KeySet& keys, bool bind_exact) {
        RequestSpec approved = spec;
        approved.approvals = {approval.id.value()};
        ApprovalRecord bound = approval;
        if (bind_exact) {
            bound.bound_request_digest = build_request(approved).digest();
        }
        sign_approval(bound, key);
        return evaluate_spec(make_bundle(policy, authorities, {}, {bound}), keys, approved);
    };
    // Each case supplies the exact request digest before signing; this value
    // only has to be a well formed digest until the case binds the real one.
    const std::string unbound_digest = sha256("unbound-approval-binding").hex();
    {
        ApprovalRecord expired = make_approval("approval-expired", base, key, unbound_digest, 5);
        set_approval_validity(expired, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", key);
        const Decision decision = evaluate_with(expired, key_set({key}), true);
        MP_CHECK_OUTCOME(decision, Outcome::RequireEscalation);
        MP_CHECK(has_finding(decision, Code::ApprovalExpired));
        MP_CHECK(has_finding(decision, Code::EscalationRequired));
    }
    {
        ApprovalRecord level = make_approval("approval-level", base, key, unbound_digest, 3);
        const Decision decision = evaluate_with(level, key_set({key}), true);
        MP_CHECK_OUTCOME(decision, Outcome::RequireEscalation);
        MP_CHECK(has_finding(decision, Code::ApprovalAuthorityInsufficient));
    }
    {
        ApprovalRecord other_request = make_approval("approval-other", base, key, sha256("different").hex(), 5);
        // A deliberate mismatch: the approval authorises a different request.
        const Decision decision = evaluate_with(other_request, key_set({key}), false);
        MP_CHECK_OUTCOME(decision, Outcome::RequireEscalation);
        MP_CHECK(has_finding(decision, Code::ApprovalContextMismatch));
    }
    {
        ApprovalRecord fenced = make_approval("approval-fenced", base, key, unbound_digest, 5);
        fenced.generation = MP_REQUIRE(PolicyGeneration::from_value(9));
        const Decision decision = evaluate_with(fenced, key_set({key}), true);
        MP_CHECK_OUTCOME(decision, Outcome::RequireEscalation);
        MP_CHECK(has_finding(decision, Code::ApprovalFenced));
    }
    {
        ApprovalRecord revoked_record = make_approval("approval-revoked", base, key, unbound_digest, 5);
        revoked_record.revoked_at = instant("2026-02-15T00:00:00Z");
        const Decision decision = evaluate_with(revoked_record, key_set({key}), true);
        MP_CHECK_OUTCOME(decision, Outcome::RequireEscalation);
        MP_CHECK(has_finding(decision, Code::ApprovalRevoked));
    }
    {
        // The escalation level is raised after signing, so the MAC no longer
        // covers the record that is presented.
        RequestSpec approved = spec;
        approved.approvals = {"approval-tampered"};
        ApprovalRecord tampered_record = make_approval("approval-tampered", base, key, unbound_digest, 5);
        tampered_record.bound_request_digest = build_request(approved).digest();
        sign_approval(tampered_record, key);
        tampered_record.level = MP_REQUIRE(AuthorityLevel::from_value(8));
        const Decision decision = evaluate_spec(make_bundle(policy, authorities, {}, {tampered_record}),
                                                key_set({key}), approved);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::MacInvalid));
    }
    {
        const ApprovalRecord unknown_key = make_approval("approval-key", base, key, unbound_digest, 5);
        const Decision decision = evaluate_with(unknown_key, key_set({other}), true);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::KeyUnknown));
    }
    {
        RequestSpec missing = spec;
        missing.approvals = {"approval-absent"};
        const Decision decision = evaluate_spec(base, key_set({key}), missing);
        MP_CHECK_OUTCOME(decision, Outcome::RequireEscalation);
        MP_CHECK(has_finding(decision, Code::ApprovalNotInRegistry));
    }
}

MP_TEST(engine, policy_state_and_generation_fence) {
    const std::vector<Rule> rules = {Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                        "2026-03-01T06:00:00Z")}};
    RequestSpec clear;
    clear.window_start = "2026-03-02T01:00:00Z";
    clear.window_end = "2026-03-02T02:00:00Z";
    clear.evaluated_at = "2026-03-02T00:30:00Z";
    {
        const Policy draft = make_policy(rules, MP_REQUIRE(PolicyGeneration::from_value(1)), default_settings(),
                                         PolicyLifecycle::Draft);
        const Decision decision = evaluate_spec(make_bundle(draft), KeySet{}, clear);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::PolicyNotPublished));
    }
    {
        const Policy revoked = make_policy(rules, MP_REQUIRE(PolicyGeneration::from_value(1)), default_settings(),
                                           PolicyLifecycle::Revoked);
        const Decision decision = evaluate_spec(make_bundle(revoked), KeySet{}, clear);
        MP_CHECK_OUTCOME(decision, Outcome::Deny);
        MP_CHECK(has_finding(decision, Code::PolicyRevoked));
    }
    {
        const Policy superseded = make_policy(rules, MP_REQUIRE(PolicyGeneration::from_value(1)), default_settings(),
                                              PolicyLifecycle::Superseded);
        const Decision decision = evaluate_spec(make_bundle(superseded), KeySet{}, clear);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::PolicySuperseded));
    }
    {
        const Policy policy = make_policy(rules, MP_REQUIRE(PolicyGeneration::from_value(2)));
        RequestSpec spec;
        spec.expected_generation = 1;
        spec.window_start = "2026-04-01T00:00:00Z";
        spec.window_end = "2026-04-01T01:00:00Z";
        const Decision decision = evaluate_spec(make_bundle(policy), KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::PolicyGenerationStale));
        MP_CHECK_EQ(decision.bindings.policy_generation.value(), std::uint64_t(2));
    }
    {
        const Policy policy = make_policy(rules);
        RequestSpec spec = clear;
        spec.expected_policy_digest = sha256("not-the-policy").hex();
        const Decision decision = evaluate_spec(make_bundle(policy), KeySet{}, spec);
        MP_CHECK_OUTCOME(decision, Outcome::Unknown);
        MP_CHECK(has_finding(decision, Code::PolicyDigestMismatch));
    }
}

MP_TEST(engine, policy_window_limit_is_not_waivable) {
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-04-01T00:00:00Z",
                                                          "2026-04-01T06:00:00Z")}});
    RequestSpec spec;
    spec.window_start = "2026-03-01T00:00:00Z";
    spec.window_end = "2026-03-02T00:00:00Z";
    const Decision decision = evaluate_spec(make_bundle(policy), KeySet{}, spec);
    MP_CHECK_OUTCOME(decision, Outcome::Deny);
    MP_CHECK(has_finding(decision, Code::WindowTooLong));
}

MP_TEST(engine, replay_resolution_precedes_staleness) {
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-04-01T00:00:00Z",
                                                          "2026-04-01T06:00:00Z")}});
    const PolicyBundle bundle = make_bundle(policy);
    RequestSpec spec;
    const EvaluationRequest request = build_request(spec);
    const Decision original = evaluate_spec(bundle, KeySet{}, spec);

    PriorDecisionRecord prior;
    prior.context_id = request.context_id();
    prior.request_id = request.request_id();
    prior.request_digest = request.digest();
    prior.decision_digest = original.digest();
    prior.decision = original;

    const Decision replayed = evaluate_spec(bundle, KeySet{}, spec, {prior});
    MP_CHECK(replayed.replay == ReplayDisposition::Replayed);
    MP_CHECK(replayed.outcome == original.outcome);
    MP_CHECK_EQ(replayed.digest().hex(), original.digest().hex());

    // The same request repeated against a later policy generation is refused
    // rather than silently re-authorised.
    const Policy later = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-04-01T00:00:00Z",
                                                         "2026-04-01T06:00:00Z")}},
                                     MP_REQUIRE(PolicyGeneration::from_value(2)));
    Decision superseded = evaluate_spec(make_bundle(later), KeySet{}, spec, {prior});
    MP_CHECK(superseded.replay == ReplayDisposition::ReplaySuperseded);
    MP_CHECK_OUTCOME(superseded, Outcome::Unknown);
    MP_CHECK(has_finding(superseded, Code::ReplaySuperseded));
}

MP_TEST(engine, decisions_are_deterministic_and_order_independent) {
    const AuthorityKey key = make_key("key-1");
    const std::vector<AuthorityRecord> authorities = default_authorities();
    std::vector<Rule> rules;
    rules.emplace_back(blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z", "2026-03-01T06:00:00Z"));
    rules.emplace_back(redundancy_rule("redundancy-a", "FAC-1/fabric", "power", 4));
    rules.emplace_back(protected_class_rule("protected-a", "FAC-1/*", "cooling", false));
    const Policy policy = make_policy(rules);
    const PolicyBundle base = make_bundle(policy, authorities);
    const ExceptionRecord exception = make_exception("exception-a", base, key, {"blackout-a"});
    const PolicyBundle bundle = make_bundle(policy, authorities, {exception});
    RequestSpec spec;
    spec.exceptions = {"exception-a"};

    const Decision first = evaluate_spec(bundle, key_set({key}), spec);
    const Decision second = evaluate_spec(bundle, key_set({key}), spec);
    MP_CHECK_EQ(first.digest().hex(), second.digest().hex());

    std::vector<Rule> reversed(rules.rbegin(), rules.rend());
    const Policy other = make_policy(reversed);
    const PolicyBundle other_base = make_bundle(other, authorities);
    const ExceptionRecord other_exception = make_exception("exception-a", other_base, key, {"blackout-a"});
    const PolicyBundle other_bundle = make_bundle(other, authorities, {other_exception});
    const Decision third = evaluate_spec(other_bundle, key_set({key}), spec);
    MP_CHECK_EQ(first.digest().hex(), third.digest().hex());
}

MP_TEST(engine, findings_are_sorted_by_precedence) {
    const Policy policy = make_policy(
        {Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z", "2026-03-01T06:00:00Z")},
         Rule{redundancy_rule("redundancy-a", "FAC-1/*", "power", 4)},
         Rule{soft_constraint_rule("soft-a", "FAC-1/*", 1)}});
    RequestSpec spec;
    spec.concurrent_maintenance = 5;
    spec.evidence_classes.front().surviving_units = 1;
    const Decision decision = evaluate_spec(make_bundle(policy), KeySet{}, spec);
    MP_CHECK_OUTCOME(decision, Outcome::Deny);
    for (std::size_t index = 1; index < decision.findings.size(); ++index) {
        MP_CHECK(!finding_less(decision.findings[index], decision.findings[index - 1]));
    }
    MP_CHECK(has_finding(decision, Code::BlackoutConflict));
    MP_CHECK(has_finding(decision, Code::RedundancyShortfall));
    MP_CHECK(has_finding(decision, Code::SoftConstraintViolation));
}
