#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"
#include "maintpol/store.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

std::string random_identifier(Rng& rng, const std::string& prefix) {
    return prefix + "-" + std::to_string(rng.below(100000));
}

Instant random_instant(Rng& rng) {
    // Instants between 2026-01-01 and 2026-12-31.
    const std::int64_t base = instant("2026-01-01T00:00:00Z").unix_nanos();
    const std::int64_t span = static_cast<std::int64_t>(365ull * 86400ull * 1000000000ull);
    return MP_REQUIRE(Instant::from_unix_nanos(base + static_cast<std::int64_t>(rng.next() % static_cast<std::uint64_t>(span))));
}

Rule random_rule(Rng& rng, std::size_t index) {
    const std::string id = "rule-" + std::to_string(index);
    const std::string scope = rng.chance(50) ? "FAC-1/*" : "FAC-1/pod-" + std::to_string(rng.below(4));
    switch (rng.below(5)) {
        case 0: {
            const Instant start = random_instant(rng);
            const Instant end = MP_REQUIRE(start.add(MP_REQUIRE(Duration::from_minutes(1 + rng.below(600)))));
            return Rule{blackout_rule(id, scope, start.format(), end.format(), rng.chance(50))};
        }
        case 1:
            return Rule{redundancy_rule(id, scope, "power", 1 + rng.below(4), rng.chance(50))};
        case 2:
            return Rule{protected_class_rule(id, scope, "power", rng.chance(50))};
        case 3:
            return Rule{escalation_rule(id, scope, 1 + rng.below(8))};
        default:
            return Rule{soft_constraint_rule(id, scope, 1 + rng.below(4), rng.chance(50))};
    }
}

RequestSpec random_request(Rng& rng) {
    RequestSpec spec;
    const Instant start = random_instant(rng);
    spec.window_start = start.format();
    spec.window_end = MP_REQUIRE(start.add(MP_REQUIRE(Duration::from_minutes(1 + rng.below(240))))).format();
    spec.evaluated_at = MP_REQUIRE(start.add(MP_REQUIRE(Duration::from_minutes(1 + rng.below(60))))).format();
    spec.evidence_observed_at = spec.evaluated_at;
    spec.evidence_classes.front().observed_at = spec.evaluated_at;
    spec.evidence_classes.front().surviving_units = rng.below(6);
    spec.evidence_classes.front().total_units = 6;
    spec.evidence_classes.front().state = rng.chance(80) ? "measured" : "unmeasured";
    if (rng.chance(30)) {
        spec.include_evidence = false;
    }
    if (rng.chance(20)) {
        spec.classes.clear();
    }
    spec.concurrent_maintenance = rng.below(5);
    spec.context_id = random_identifier(rng, "ctx");
    spec.request_id = random_identifier(rng, "req");
    return spec;
}

}  // namespace

MP_TEST(property, canonical_round_trip_is_stable_for_random_policies) {
    for (std::uint64_t seed = 1; seed <= 60u; ++seed) {
        Rng rng(seed);
        std::vector<Rule> rules;
        const std::size_t count = 1u + rng.below(6);
        for (std::size_t index = 0; index < count; ++index) {
            rules.push_back(random_rule(rng, index));
        }
        const Policy policy = make_policy(std::move(rules));
        const std::string canonical = canonical_policy(policy);
        auto reparsed = parse_policy_document(canonical);
        if (!reparsed.has_value()) {
            MP_FAIL("seed " + std::to_string(seed) + ": canonical policy did not parse: " +
                    reparsed.error().detail);
        }
        const std::string second = canonical_policy(reparsed.value());
        if (second != canonical) {
            std::size_t offset = 0;
            while (offset < second.size() && offset < canonical.size() && second[offset] == canonical[offset]) {
                ++offset;
            }
            MP_FAIL("seed " + std::to_string(seed) + ": canonical form is not stable at offset " +
                    std::to_string(offset) + " first=[" + canonical.substr(offset, 80) + "] second=[" +
                    second.substr(offset, 80) + "]");
        }
        if (!(reparsed.value().digest() == policy.digest())) {
            MP_FAIL("seed " + std::to_string(seed) + ": digest changed across a round trip");
        }
    }
}

MP_TEST(property, evaluation_is_deterministic_and_order_independent) {
    const AuthorityKey key = make_key("key-1");
    std::vector<AuthorityRecord> authorities;
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(8));
    authorities.push_back(authority);
    const KeySet keys = MP_REQUIRE(KeySet::create({key}));

    for (std::uint64_t seed = 100; seed <= 140u; ++seed) {
        Rng rng(seed);
        std::vector<Rule> rules;
        const std::size_t count = 1u + rng.below(5);
        for (std::size_t index = 0; index < count; ++index) {
            rules.push_back(random_rule(rng, index));
        }
        const Policy policy = make_policy(rules);
        std::vector<Rule> reversed(rules.rbegin(), rules.rend());
        const Policy other = make_policy(reversed);
        const PolicyBundle bundle = make_bundle(policy, authorities);
        const PolicyBundle other_bundle = make_bundle(other, authorities);
        const RequestSpec spec = random_request(rng);

        const Decision first = evaluate_spec(bundle, keys, spec);
        const Decision second = evaluate_spec(bundle, keys, spec);
        if (!(first.digest() == second.digest())) {
            MP_FAIL("seed " + std::to_string(seed) + ": repeated evaluation differs");
        }
        const Decision third = evaluate_spec(other_bundle, keys, spec);
        if (!(first.digest() == third.digest())) {
            MP_FAIL("seed " + std::to_string(seed) + ": rule declaration order changed the decision");
        }
        // The outcome is never more permissive than the highest severity found.
        Severity highest = Severity::None;
        for (const Finding& finding : first.findings) {
            if (static_cast<unsigned>(finding.severity()) > static_cast<unsigned>(highest)) {
                highest = finding.severity();
            }
        }
        if (first.outcome != outcome_for_severity(highest)) {
            MP_FAIL("seed " + std::to_string(seed) + ": outcome does not match the highest severity");
        }
    }
}

MP_TEST(property, interval_semantics_are_consistent) {
    for (std::uint64_t seed = 500; seed <= 900u; ++seed) {
        Rng rng(seed);
        const Instant start = random_instant(rng);
        const Duration length = MP_REQUIRE(Duration::from_minutes(1 + rng.below(1000)));
        const Interval interval = MP_REQUIRE(make_interval(start, MP_REQUIRE(start.add(length))));
        const Instant inside = MP_REQUIRE(start.add(MP_REQUIRE(Duration::from_nanos(rng.next() % length.nanos()))));
        if (!interval.contains(inside)) {
            MP_FAIL("seed " + std::to_string(seed) + ": an instant inside the interval is not contained");
        }
        const Instant end = MP_REQUIRE(start.add(length));
        if (interval.contains(end)) {
            MP_FAIL("seed " + std::to_string(seed) + ": the end instant must be excluded");
        }
        if (!interval.contains(start)) {
            MP_FAIL("seed " + std::to_string(seed) + ": the start instant must be included");
        }
        const Instant before = MP_REQUIRE(start.subtract(MP_REQUIRE(Duration::from_nanos(1))));
        const Interval touching = MP_REQUIRE(make_interval(before, start));
        if (interval.intersects(touching)) {
            MP_FAIL("seed " + std::to_string(seed) + ": intervals that only touch must not intersect");
        }
        const Interval overlapping = MP_REQUIRE(make_interval(inside, MP_REQUIRE(end.add(length))));
        if (!interval.intersects(overlapping)) {
            MP_FAIL("seed " + std::to_string(seed) + ": overlapping intervals must intersect");
        }
    }
}

MP_TEST(property, store_state_machine_keeps_its_invariants) {
    const std::string root = make_temp_directory("store-machine");
    const std::uint64_t generations = 6;
    {
        auto store = PolicyStore::create(root, bundle_for_generation(1, 1, 1));
        MP_CHECK(store.has_value());
        Rng rng(2026);
        std::uint64_t expected_generation = 1;
        std::uint64_t expected_epoch = 1;
        std::uint64_t decisions = 0;
        for (std::uint64_t step = 0; step < generations; ++step) {
            const std::uint64_t action = rng.below(3);
            if (action == 0) {
                // Publish the next generation.
                auto committed = store.value().commit(bundle_for_generation(expected_generation + 1,
                                                                            expected_epoch + 1, 1));
                MP_CHECK(committed.has_value());
                expected_generation += 1;
                expected_epoch += 1;
            } else if (action == 1) {
                const PolicyBundle bundle = MP_REQUIRE(store.value().load_bundle());
                RequestSpec spec = random_request(rng);
                spec.expected_generation = expected_generation;
                const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
                auto recorded = store.value().record_decision(decision);
                if (recorded.has_value() && recorded.value() == DecisionWriteResult::Appended) {
                    decisions += 1;
                }
            } else {
                MP_CHECK(store.value().compact().has_value());
            }
            // Invariants after every action.
            MP_CHECK_EQ(store.value().info().generation.value(), expected_generation);
            MP_CHECK_EQ(store.value().info().control_epoch.value(), expected_epoch);
            MP_CHECK_OK(store.value().verify());
            auto listing = store.value().list_decisions(1000);
            MP_CHECK(listing.has_value());
            MP_CHECK_EQ(listing.value().size(), std::size_t(decisions));
        }
    }
    {
        auto reopened = PolicyStore::open(root, false);
        MP_CHECK(reopened.has_value());
        MP_CHECK(reopened.value().verify().has_value());
    }
    remove_temp_directory(root);
}
