// ---------------------------------------------------------------------------
// Independent downstream consumer.
//
// It exercises the public API the way an adjacent DCCP repository would: build
// a policy, publish a generation into a store, evaluate a request, record the
// decision, replay it, and check that a stale authority is fenced.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <string>
#include <vector>

#include "maintpol/engine.hpp"
#include "maintpol/fileio.hpp"
#include "maintpol/store.hpp"
#include "maintpol/text.hpp"

namespace {

using namespace maintpol;

int fail(const char* step, const Error& error) {
    std::printf("downstream: %s failed: %s - %s\n", step, std::string(to_string(error.code)).c_str(),
                error.detail.c_str());
    return 1;
}

struct Fixture {
    PolicyBundle bundle;
    EvaluationRequest request;
};

Result<Fixture> build_fixture() {
    PolicySettings settings;
    settings.evidence_max_age = Duration::parse("PT24H").value();
    settings.max_window = Duration::parse("PT8H").value();
    settings.min_waiver_level = AuthorityLevel::from_value(4).value();

    RuleHeader header;
    header.id = RuleId::parse("blackout-a").value();
    header.priority = 100;
    header.scope = ScopePath::parse_selector("FAC-1/*").value();
    header.classes.all = true;
    BlackoutRule blackout;
    blackout.header = header;
    blackout.windows.push_back(
        make_interval(Instant::parse("2026-03-01T00:00:00Z").value(),
                      Instant::parse("2026-03-01T06:00:00Z").value())
            .value());
    blackout.waivable = true;

    std::vector<Rule> rules;
    rules.emplace_back(std::move(blackout));

    auto policy = Policy::create(PolicyId::parse("policy-a").value(), PolicyGeneration::from_value(1).value(),
                                 Revision::from_value(1).value(), PolicyLifecycle::Published,
                                 Instant::parse("2026-01-01T00:00:00Z").value(), settings, std::move(rules));
    if (!policy) {
        return policy.error();
    }
    auto bundle = PolicyBundle::create(policy.value(), {}, {}, {}, ControlEpoch::from_value(1).value(),
                                       Revision::from_value(1).value());
    if (!bundle) {
        return bundle.error();
    }

    std::vector<ScopePath> scopes;
    scopes.push_back(ScopePath::parse("FAC-1/fabric").value());
    std::vector<ObligationClassId> classes;
    classes.push_back(ObligationClassId::parse("power").value());
    EvidenceBundle evidence;
    evidence.source = EvidenceSourceId::parse("telemetry-1").value();
    evidence.epoch = EvidenceEpoch::from_value(10).value();
    evidence.observed_at = Instant::parse("2026-03-01T00:30:00Z").value();
    ClassEvidence entry;
    entry.obligation_class = classes.front();
    entry.state = MeasurementState::Measured;
    entry.surviving_units = 3;
    entry.total_units = 4;
    entry.observed_at = evidence.observed_at;
    entry.source = evidence.source;
    entry.epoch = evidence.epoch;
    evidence.classes.push_back(std::move(entry));

    auto request = EvaluationRequest::create(
        ContextId::parse("ctx-1").value(), RequestId::parse("req-1").value(), std::move(scopes), std::move(classes),
        make_interval(Instant::parse("2026-03-01T01:00:00Z").value(),
                      Instant::parse("2026-03-01T02:00:00Z").value())
            .value(),
        PrincipalId::parse("operator-1").value(), PolicyGeneration::from_value(1).value(), std::nullopt, {}, {},
        evidence, std::nullopt, 0, Instant::parse("2026-03-01T00:45:00Z").value());
    if (!request) {
        return request.error();
    }
    Fixture fixture;
    fixture.bundle = bundle.value();
    fixture.request = request.value();
    return fixture;
}

}  // namespace

int main(int argc, char** argv) {
    // The store root is the first argument, or a directory in the working
    // directory when the consumer is run without arguments.
    const std::string root = argc > 1 ? std::string(argv[1]) : std::string("maintpol-downstream-store");
    auto fixture = build_fixture();
    if (!fixture) {
        return fail("fixture", fixture.error());
    }
    const PolicyBundle& bundle = fixture.value().bundle;
    const EvaluationRequest& request = fixture.value().request;
    const KeySet keys;

    // 1. A request inside a blackout window must be denied with attribution.
    auto decision = evaluate(bundle, keys, request);
    if (!decision) {
        return fail("evaluate", decision.error());
    }
    if (decision.value().outcome != Outcome::Deny) {
        std::printf("downstream: expected deny, got %s\n", std::string(to_string(decision.value().outcome)).c_str());
        return 1;
    }
    std::printf("downstream: deny with %zu finding(s), decision digest %s\n", decision.value().findings.size(),
                decision.value().digest().hex().c_str());

    // 2. A request outside the window must be permitted.
    auto clear_request = EvaluationRequest::create(
        request.context_id(), RequestId::parse("req-2").value(), request.scopes(), request.classes(),
        make_interval(Instant::parse("2026-03-02T01:00:00Z").value(),
                      Instant::parse("2026-03-02T02:00:00Z").value())
            .value(),
        request.requested_by(), request.expected_generation(), std::nullopt, {}, {}, request.evidence(),
        std::nullopt, 0, Instant::parse("2026-03-02T00:30:00Z").value());
    if (!clear_request) {
        return fail("request", clear_request.error());
    }
    auto permitted = evaluate(bundle, keys, clear_request.value());
    if (!permitted) {
        return fail("evaluate", permitted.error());
    }
    if (permitted.value().outcome != Outcome::Allow) {
        std::printf("downstream: expected allow, got %s\n",
                    std::string(to_string(permitted.value().outcome)).c_str());
        return 1;
    }
    std::printf("downstream: allow, decision digest %s\n", permitted.value().digest().hex().c_str());

    // 3. A store round trip: publish, load, record the decision, replay it.
    (void)remove_tree(root);
    auto store = PolicyStore::create(root, bundle);
    if (!store) {
        return fail("store create", store.error());
    }
    auto loaded = store.value().load_bundle();
    if (!loaded) {
        return fail("store load", loaded.error());
    }
    if (!(loaded.value().digest() == bundle.digest())) {
        std::printf("downstream: the stored bundle digest does not match\n");
        return 1;
    }
    auto recorded = store.value().record_decision(permitted.value());
    if (!recorded) {
        return fail("record decision", recorded.error());
    }
    auto prior = store.value().prior_decisions(clear_request.value().context_id());
    if (!prior) {
        return fail("prior decisions", prior.error());
    }
    auto replayed = evaluate(loaded.value(), keys, clear_request.value(), prior.value(), EvaluationLimits{});
    if (!replayed) {
        return fail("replay", replayed.error());
    }
    if (replayed.value().replay != ReplayDisposition::Replayed ||
        !(replayed.value().digest() == permitted.value().digest())) {
        std::printf("downstream: replay did not return the recorded decision\n");
        return 1;
    }
    std::printf("downstream: replay returned the identical decision digest\n");

    // 4. A generation fence: the same request against a later generation is a
    //    refusal, never an inherited permission.
    auto later_policy = Policy::create(bundle.policy().id(), PolicyGeneration::from_value(2).value(),
                                       Revision::from_value(1).value(), PolicyLifecycle::Published,
                                       bundle.policy().published_at(), bundle.policy().settings(),
                                       bundle.policy().rules());
    if (!later_policy) {
        return fail("later policy", later_policy.error());
    }
    auto later_bundle = PolicyBundle::create(later_policy.value(), {}, {}, {},
                                             ControlEpoch::from_value(2).value(), Revision::from_value(1).value());
    if (!later_bundle) {
        return fail("later bundle", later_bundle.error());
    }
    auto fenced = evaluate(later_bundle.value(), keys, clear_request.value());
    if (!fenced) {
        return fail("fence", fenced.error());
    }
    if (fenced.value().outcome == Outcome::Allow) {
        std::printf("downstream: a stale generation was permitted\n");
        return 1;
    }
    std::printf("downstream: stale generation refused (%s)\n",
                std::string(to_string(fenced.value().outcome)).c_str());

    auto notes = store.value().verify();
    if (!notes) {
        return fail("verify", notes.error());
    }
    std::printf("downstream: store verified with %zu note(s)\n", notes.value().size());
    std::printf("downstream: ok\n");
    return 0;
}
