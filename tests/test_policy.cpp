#include <algorithm>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

}  // namespace

MP_TEST(policy, rule_validation_rejects_inconsistent_rules) {
    // A blackout rule with neither an explicit window nor a recurrence.
    BlackoutRule empty;
    empty.header = make_header("blackout-empty", "FAC-1/*");
    MP_CHECK_CODE(Policy::create(MP_REQUIRE(PolicyId::parse("p")), MP_REQUIRE(PolicyGeneration::from_value(1)),
                                 MP_REQUIRE(Revision::from_value(1)), PolicyLifecycle::Published,
                                 instant("2026-01-01T00:00:00Z"), default_settings(), {Rule{empty}}),
                  Code::RuleInvalid);

    // Two rules that share an identifier.
    MP_CHECK_CODE(Policy::create(MP_REQUIRE(PolicyId::parse("p")), MP_REQUIRE(PolicyGeneration::from_value(1)),
                                 MP_REQUIRE(Revision::from_value(1)), PolicyLifecycle::Published,
                                 instant("2026-01-01T00:00:00Z"), default_settings(),
                                 {Rule{blackout_rule("dup", "FAC-1/*", "2026-03-01T00:00:00Z", "2026-03-01T01:00:00Z")},
                                  Rule{blackout_rule("dup", "FAC-1/*", "2026-04-01T00:00:00Z", "2026-04-01T01:00:00Z")}}),
                  Code::RuleIdConflict);

    // A policy without rules.
    MP_CHECK_CODE(Policy::create(MP_REQUIRE(PolicyId::parse("p")), MP_REQUIRE(PolicyGeneration::from_value(1)),
                                 MP_REQUIRE(Revision::from_value(1)), PolicyLifecycle::Published,
                                 instant("2026-01-01T00:00:00Z"), default_settings(), {}),
                  Code::PolicyEmpty);

    // A zero evidence maximum age would make every measurement stale.
    PolicySettings bad_settings = default_settings();
    bad_settings.evidence_max_age = Duration{};
    MP_CHECK_CODE(Policy::create(MP_REQUIRE(PolicyId::parse("p")), MP_REQUIRE(PolicyGeneration::from_value(1)),
                                 MP_REQUIRE(Revision::from_value(1)), PolicyLifecycle::Published,
                                 instant("2026-01-01T00:00:00Z"), bad_settings,
                                 {Rule{blackout_rule("b", "FAC-1/*", "2026-03-01T00:00:00Z", "2026-03-01T01:00:00Z")}}),
                  Code::PolicyEmpty);

    // An escalation rule without a required level.
    EscalationRule escalation;
    escalation.header = make_header("escalation", "FAC-1/*");
    MP_CHECK_CODE(Policy::create(MP_REQUIRE(PolicyId::parse("p")), MP_REQUIRE(PolicyGeneration::from_value(1)),
                                 MP_REQUIRE(Revision::from_value(1)), PolicyLifecycle::Published,
                                 instant("2026-01-01T00:00:00Z"), default_settings(), {Rule{escalation}}),
                  Code::RuleInvalid);

    // A redundancy floor of zero would require nothing.
    RedundancyRule zero_floor = redundancy_rule("redundancy", "FAC-1/*", "power", 0);
    MP_CHECK_CODE(Policy::create(MP_REQUIRE(PolicyId::parse("p")), MP_REQUIRE(PolicyGeneration::from_value(1)),
                                 MP_REQUIRE(Revision::from_value(1)), PolicyLifecycle::Published,
                                 instant("2026-01-01T00:00:00Z"), default_settings(), {Rule{zero_floor}}),
                  Code::ThresholdInvalid);
}

MP_TEST(policy, windows_are_normalised_and_merged) {
    BlackoutRule rule;
    rule.header = make_header("blackout", "FAC-1/*");
    rule.windows.push_back(MP_REQUIRE(make_interval(instant("2026-03-01T02:00:00Z"), instant("2026-03-01T03:00:00Z"))));
    rule.windows.push_back(MP_REQUIRE(make_interval(instant("2026-03-01T00:00:00Z"), instant("2026-03-01T01:00:00Z"))));
    rule.windows.push_back(MP_REQUIRE(make_interval(instant("2026-03-01T00:30:00Z"), instant("2026-03-01T02:30:00Z"))));
    rule.windows.push_back(MP_REQUIRE(make_interval(instant("2026-03-01T03:00:00Z"), instant("2026-03-01T04:00:00Z"))));
    const Policy policy = make_policy({Rule{rule}});
    const auto& windows = std::get<BlackoutRule>(policy.rules().front()).windows;
    MP_CHECK_EQ(windows.size(), std::size_t(1));
    MP_CHECK_EQ(windows.front().start.format(), std::string("2026-03-01T00:00:00.000000000Z"));
    MP_CHECK_EQ(windows.front().end.format(), std::string("2026-03-01T04:00:00.000000000Z"));
}

MP_TEST(policy, recurrence_expansion_is_bounded_and_deterministic) {
    {
        const BlackoutRule rule = recurring_blackout_rule("daily", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          RecurrenceKind::Daily, 3, "PT1H", "PT30M");
        auto windows = expand_recurrence(rule.recurrence.value());
        MP_CHECK(windows.has_value());
        MP_CHECK_EQ(windows.value().size(), std::size_t(3));
        MP_CHECK_EQ(windows.value().front().start.format(), std::string("2026-03-01T01:00:00.000000000Z"));
        MP_CHECK_EQ(windows.value().back().start.format(), std::string("2026-03-03T01:00:00.000000000Z"));
    }
    {
        Recurrence weekly;
        weekly.kind = RecurrenceKind::Weekly;
        weekly.origin = instant("2026-03-04T00:00:00Z");  // a Wednesday
        weekly.weekday = 0;                               // Monday
        weekly.start_offset = duration("PT2H");
        weekly.duration = duration("PT1H");
        weekly.count = 2;
        auto windows = expand_recurrence(weekly);
        MP_CHECK(windows.has_value());
        MP_CHECK_EQ(windows.value().front().start.format(), std::string("2026-03-02T02:00:00.000000000Z"));
        MP_CHECK_EQ(windows.value().back().start.format(), std::string("2026-03-09T02:00:00.000000000Z"));
    }
    {
        Recurrence monthly;
        monthly.kind = RecurrenceKind::Monthly;
        monthly.origin = instant("2026-01-31T00:00:00Z");
        monthly.day_of_month = 31;
        monthly.duration = duration("PT1H");
        monthly.count = 4;  // February and April have no 31st, so two periods yield nothing
        auto windows = expand_recurrence(monthly);
        MP_CHECK(windows.has_value());
        MP_CHECK_EQ(windows.value().size(), std::size_t(2));
        MP_CHECK_EQ(windows.value().front().start.format(), std::string("2026-01-31T00:00:00.000000000Z"));
        MP_CHECK_EQ(windows.value().back().start.format(), std::string("2026-03-31T00:00:00.000000000Z"));
    }
    {
        Recurrence monthly;
        monthly.kind = RecurrenceKind::Monthly;
        monthly.origin = instant("2024-01-29T00:00:00Z");
        monthly.day_of_month = 29;
        monthly.duration = duration("PT1H");
        monthly.count = 2;
        auto windows = expand_recurrence(monthly);
        MP_CHECK(windows.has_value());
        MP_CHECK_EQ(windows.value().size(), std::size_t(2));
        MP_CHECK_EQ(windows.value().back().start.format(), std::string("2024-02-29T00:00:00.000000000Z"));
    }
    {
        Recurrence unbounded;
        unbounded.kind = RecurrenceKind::Daily;
        unbounded.origin = instant("2026-01-01T00:00:00Z");
        unbounded.duration = duration("PT1H");
        unbounded.count = 100000;
        MP_CHECK_CODE(expand_recurrence(unbounded), Code::RecurrenceUnbounded);
    }
    {
        Recurrence zero_length;
        zero_length.kind = RecurrenceKind::Daily;
        zero_length.origin = instant("2026-01-01T00:00:00Z");
        zero_length.count = 1;
        MP_CHECK_CODE(expand_recurrence(zero_length), Code::RecurrenceInvalid);
    }
    {
        Recurrence weekly_bad_day;
        weekly_bad_day.kind = RecurrenceKind::Weekly;
        weekly_bad_day.origin = instant("2026-01-01T00:00:00Z");
        weekly_bad_day.weekday = 9;
        weekly_bad_day.duration = duration("PT1H");
        weekly_bad_day.count = 1;
        MP_CHECK_CODE(expand_recurrence(weekly_bad_day), Code::RecurrenceInvalid);
    }
}

MP_TEST(policy, canonical_round_trip_covers_every_rule_kind) {
    std::vector<Rule> rules;
    rules.emplace_back(blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z", "2026-03-01T06:00:00Z"));
    rules.emplace_back(recurring_blackout_rule("blackout-recurring", "FAC-1/pod/*", "2026-03-01T00:00:00Z",
                                               RecurrenceKind::Daily, 5, "PT1H", "PT2H"));
    rules.emplace_back(redundancy_rule("redundancy-a", "FAC-1/fabric", "power", 2, true));
    rules.emplace_back(protected_class_rule("protected-a", "FAC-1/*", "control-plane", true));
    rules.emplace_back(escalation_rule("escalation-a", "FAC-1/*", 5, true, true));
    rules.emplace_back(hard_interlock_rule("interlock-a", "FAC-1/*", "power-bus-a"));
    rules.emplace_back(soft_constraint_rule("soft-a", "FAC-1/*", 2));
    PolicySettings settings = default_settings();
    settings.evidence_sources.push_back(MP_REQUIRE(EvidenceSourceId::parse("telemetry-1")));
    settings.min_evidence_epoch = MP_REQUIRE(EvidenceEpoch::from_value(5));
    const Policy policy = make_policy(std::move(rules), MP_REQUIRE(PolicyGeneration::from_value(3)), settings);

    const std::string canonical = canonical_policy(policy);
    auto reparsed = parse_policy_document(canonical);
    MP_CHECK(reparsed.has_value());
    MP_CHECK_EQ(canonical_policy(reparsed.value()), canonical);
    MP_CHECK(reparsed.value().digest() == policy.digest());
    MP_CHECK_EQ(reparsed.value().rules().size(), policy.rules().size());
    MP_CHECK_EQ(reparsed.value().settings().evidence_sources.size(), std::size_t(1));
    MP_CHECK(reparsed.value().settings().min_evidence_epoch.is_set());
}

MP_TEST(policy, digests_are_independent_of_declaration_order) {
    std::vector<Rule> forward;
    forward.emplace_back(blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z", "2026-03-01T06:00:00Z"));
    forward.emplace_back(redundancy_rule("redundancy-a", "FAC-1/fabric", "power", 2));
    forward.emplace_back(protected_class_rule("protected-a", "FAC-1/*", "control-plane", false));
    std::vector<Rule> reversed(forward.rbegin(), forward.rend());
    std::vector<Rule> shuffled = forward;
    std::rotate(shuffled.begin(), shuffled.begin() + 1, shuffled.end());

    const Policy first = make_policy(forward);
    const Policy second = make_policy(reversed);
    const Policy third = make_policy(shuffled);
    MP_CHECK(first.digest() == second.digest());
    MP_CHECK(first.digest() == third.digest());
    MP_CHECK_EQ(canonical_policy(first), canonical_policy(second));
}

MP_TEST(policy, document_rejects_waivable_hard_interlock) {
    const std::string document =
        "[document]\n"
        "format = maintpol/1\n"
        "kind = policy\n"
        "[policy]\n"
        "policy_id = p\n"
        "generation = 1\n"
        "revision = 1\n"
        "lifecycle = published\n"
        "published_at = 2026-01-01T00:00:00Z\n"
        "evidence_max_age = PT24H\n"
        "max_window = PT8H\n"
        "min_waiver_level = 4\n"
        "require_evidence_for_classes = true\n"
        "max_recurrence_count = 512\n"
        "[rule interlock-a]\n"
        "kind = hard-interlock\n"
        "priority = 100\n"
        "scope = FAC-1/*\n"
        "classes = \"*\"\n"
        "enabled = true\n"
        "waivable = true\n"
        "interlock = power-bus-a\n";
    MP_CHECK_CODE(parse_policy_document(document), Code::HardInterlockWaivable);

    const std::string protected_document =
        "[document]\n"
        "format = maintpol/1\n"
        "kind = policy\n"
        "[policy]\n"
        "policy_id = p\n"
        "generation = 1\n"
        "revision = 1\n"
        "lifecycle = published\n"
        "published_at = 2026-01-01T00:00:00Z\n"
        "evidence_max_age = PT24H\n"
        "max_window = PT8H\n"
        "min_waiver_level = 4\n"
        "require_evidence_for_classes = true\n"
        "max_recurrence_count = 512\n"
        "[rule protected-a]\n"
        "kind = protected-class\n"
        "priority = 100\n"
        "scope = FAC-1/*\n"
        "classes = control-plane\n"
        "enabled = true\n"
        "waivable = true\n";
    MP_CHECK_CODE(parse_policy_document(protected_document), Code::HardInterlockWaivable);
}

MP_TEST(policy, document_parsing_is_strict) {
    const std::string good =
        "[document]\n"
        "format = maintpol/1\n"
        "kind = policy\n"
        "[policy]\n"
        "policy_id = p\n"
        "generation = 1\n"
        "revision = 1\n"
        "lifecycle = published\n"
        "published_at = 2026-01-01T00:00:00Z\n"
        "evidence_max_age = PT24H\n"
        "max_window = PT8H\n"
        "min_waiver_level = 4\n"
        "require_evidence_for_classes = true\n"
        "max_recurrence_count = 512\n"
        "[rule blackout-a]\n"
        "kind = blackout\n"
        "priority = 100\n"
        "scope = FAC-1/*\n"
        "classes = \"*\"\n"
        "enabled = true\n"
        "waivable = true\n"
        "window = \"2026-03-01T00:00:00Z 2026-03-01T06:00:00Z\"\n";
    MP_CHECK(parse_policy_document(good).has_value());

    std::string unknown_field = good;
    unknown_field.append("unexpected = 1\n");
    MP_CHECK_CODE(parse_policy_document(unknown_field), Code::UnknownKey);

    std::string duplicate_field = good;
    duplicate_field.append("waivable = false\n");
    MP_CHECK_CODE(parse_policy_document(duplicate_field), Code::DuplicateKey);

    std::string missing_field = good;
    const std::size_t position = missing_field.find("min_waiver_level = 4\n");
    missing_field.erase(position, std::string("min_waiver_level = 4\n").size());
    MP_CHECK_CODE(parse_policy_document(missing_field), Code::MissingKey);

    std::string wrong_format = good;
    wrong_format.replace(wrong_format.find("maintpol/1"), std::string("maintpol/9").size(), "maintpol/9");
    MP_CHECK_CODE(parse_policy_document(wrong_format), Code::UnsupportedFormatVersion);

    std::string wrong_kind = good;
    wrong_kind.replace(wrong_kind.find("kind = policy"), std::string("kind = policy").size(), "kind = bundle");
    MP_CHECK_CODE(parse_policy_document(wrong_kind), Code::UnexpectedSection);

    std::string bad_enum = good;
    bad_enum.replace(bad_enum.find("lifecycle = published"), std::string("lifecycle = published").size(),
                     "lifecycle = nonsense");
    MP_CHECK_CODE(parse_policy_document(bad_enum), Code::UnknownEnumValue);

    std::string bad_number = good;
    bad_number.replace(bad_number.find("generation = 1"), std::string("generation = 1").size(),
                       "generation = 007");
    MP_CHECK_CODE(parse_policy_document(bad_number), Code::NumberMalformed);

    std::string extra_section = good;
    extra_section.append("[registry]\ncontrol_epoch = 1\n");
    MP_CHECK_CODE(parse_policy_document(extra_section), Code::UnexpectedSection);
}

MP_TEST(policy, lifecycle_transitions) {
    MP_CHECK(policy_lifecycle_transition_allowed(PolicyLifecycle::Draft, PolicyLifecycle::Published));
    MP_CHECK(policy_lifecycle_transition_allowed(PolicyLifecycle::Published, PolicyLifecycle::Superseded));
    MP_CHECK(policy_lifecycle_transition_allowed(PolicyLifecycle::Superseded, PolicyLifecycle::Revoked));
    MP_CHECK(!policy_lifecycle_transition_allowed(PolicyLifecycle::Revoked, PolicyLifecycle::Published));
    MP_CHECK(!policy_lifecycle_transition_allowed(PolicyLifecycle::Published, PolicyLifecycle::Draft));
    MP_CHECK(!policy_lifecycle_transition_allowed(PolicyLifecycle::Revoked, PolicyLifecycle::Superseded));
}
