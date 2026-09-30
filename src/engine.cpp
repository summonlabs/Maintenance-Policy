#include "maintpol/engine.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "maintpol/text.hpp"
#include "maintpol/version.hpp"

namespace maintpol {
namespace {

// ---------------------------------------------------------------------------
// Evaluation state. Every finding is attributed to the smallest set of inputs
// that produced it; the outcome is derived from the highest severity present.
// ---------------------------------------------------------------------------
struct ExceptionStatus {
    ExceptionId id;
    const ExceptionRecord* record = nullptr;
    bool present = false;
    std::vector<Finding> problems;
    Digest256 digest;
};

struct EvaluationState {
    const PolicyBundle& bundle;
    const KeySet& keys;
    const EvaluationRequest& request;
    const EvaluationLimits& limits;
    const Policy& policy;
    Digest256 policy_digest;
    Digest256 request_digest;
    Duration window_length;
    bool budget_exceeded = false;
    bool exception_used = false;
    bool redundancy_waived = false;
    bool escalation_satisfied = false;
    std::vector<Finding> findings;
    std::vector<RuleId> applied_rules;
    std::vector<ExceptionId> honored_exceptions;
    std::vector<Digest256> exception_digests;
    std::vector<Digest256> approval_digests;
    std::vector<ExceptionStatus> exceptions;
    std::optional<AuthorityLevel> required_level;
};

void add_finding(EvaluationState& state, Finding finding) {
    if (state.findings.size() + 1u >= state.limits.max_findings) {
        if (!state.budget_exceeded) {
            state.budget_exceeded = true;
            Finding budget;
            budget.code = Code::TooManyItems;
            budget.detail = "evaluation exceeded the bounded finding budget of " +
                            std::to_string(state.limits.max_findings) + " entries";
            state.findings.push_back(std::move(budget));
        }
        return;
    }
    state.findings.push_back(std::move(finding));
}

void note_rule(EvaluationState& state, const RuleId& rule) { state.applied_rules.push_back(rule); }

bool selector_covers_any_request_scope(const EvaluationState& state, const ScopePath& selector) {
    for (const ScopePath& scope : state.request.scopes()) {
        if (selector.matches(scope)) {
            return true;
        }
    }
    return false;
}

// A request that declares no affected classes is treated as potentially
// affecting every class: a class-scoped rule can never be bypassed by
// omitting the class list.
bool selector_covers_request_classes(const EvaluationState& state, const ClassSelector& selector) {
    if (state.request.classes().empty()) {
        return true;
    }
    for (const ObligationClassId& obligation_class : state.request.classes()) {
        if (selector.matches(obligation_class)) {
            return true;
        }
    }
    return false;
}

bool rule_applicable(const EvaluationState& state, const RuleHeader& header) {
    if (!header.enabled) {
        return false;
    }
    if (!selector_covers_any_request_scope(state, header.scope)) {
        return false;
    }
    return selector_covers_request_classes(state, header.classes);
}

const Rule* find_rule(const EvaluationState& state, const RuleId& id) {
    for (const Rule& rule : state.policy.rules()) {
        if (rule_header_of(rule).id == id) {
            return &rule;
        }
    }
    return nullptr;
}

void check_freshness(EvaluationState& state, const Instant& observed, std::string_view subject, Finding finding) {
    if (observed > state.request.evaluated_at()) {
        finding.code = Code::EvidenceFromFuture;
        finding.detail = std::string(subject) + " observation is after the evaluation instant";
        add_finding(state, std::move(finding));
        return;
    }
    auto age = state.request.evaluated_at().difference(observed);
    if (!age) {
        finding.code = Code::IntegerOverflow;
        finding.detail = std::string(subject) + " age is not representable";
        add_finding(state, std::move(finding));
        return;
    }
    if (age.value().is_negative() ||
        static_cast<std::uint64_t>(age.value().nanos()) > state.policy.settings().evidence_max_age.nanos()) {
        finding.code = Code::EvidenceStale;
        finding.detail = std::string(subject) + " is older than the policy evidence maximum age";
        add_finding(state, std::move(finding));
    }
}

bool source_is_trusted(const EvaluationState& state, const EvidenceSourceId& source) {
    const std::vector<EvidenceSourceId>& trusted = state.policy.settings().evidence_sources;
    if (trusted.empty()) {
        return true;
    }
    return std::find(trusted.begin(), trusted.end(), source) != trusted.end();
}

// ---------------------------------------------------------------------------
// Exception evaluation. Problems are computed without side effects so that a
// referenced exception is only reported when it was actually needed, while a
// hard-interlock bypass attempt is always reported.
// ---------------------------------------------------------------------------
std::vector<Finding> exception_problems(const EvaluationState& state, const ExceptionRecord& record, bool check_mac) {
    std::vector<Finding> problems;
    Finding finding;
    finding.exception = record.id;

    if (check_mac) {
        auto verified = verify_exception_mac(state.keys, record);
        if (!verified) {
            finding.code = verified.error().code;
            finding.detail = verified.error().detail;
            problems.push_back(finding);
        }
    }
    if (record.generation != state.policy.generation() || !(record.policy_digest == state.policy_digest)) {
        finding.code = Code::ExceptionGenerationMismatch;
        finding.detail = "exception binds policy generation " + record.generation.format() +
                         " and a different policy digest";
        problems.push_back(finding);
    }
    if (record.revoked_at.has_value()) {
        finding.code = Code::ExceptionRevoked;
        finding.detail = "exception was revoked at " + record.revoked_at.value().format();
        problems.push_back(finding);
    }
    if (state.request.evaluated_at() < record.not_before) {
        finding.code = Code::ExceptionNotYetValid;
        finding.detail = "exception becomes valid at " + record.not_before.format();
        problems.push_back(finding);
    }
    if (!(state.request.evaluated_at() < record.expires_at)) {
        finding.code = Code::ExceptionExpired;
        finding.detail = "exception expired at " + record.expires_at.format();
        problems.push_back(finding);
    }
    for (const ScopePath& scope : state.request.scopes()) {
        if (!record.scope.matches(scope)) {
            finding.code = Code::ExceptionScopeMismatch;
            finding.detail = "exception scope '" + record.scope.format() + "' does not cover '" + scope.format() + "'";
            problems.push_back(finding);
            break;
        }
    }
    if (state.request.classes().empty()) {
        if (!record.classes.all) {
            finding.code = Code::ExceptionClassMismatch;
            finding.detail = "request declares no affected classes, so the exception must cover all classes";
            problems.push_back(finding);
        }
    } else {
        for (const ObligationClassId& obligation_class : state.request.classes()) {
            if (!record.classes.matches(obligation_class)) {
                finding.code = Code::ExceptionClassMismatch;
                finding.detail = "exception does not cover obligation class '" + obligation_class.value() + "'";
                problems.push_back(finding);
                break;
            }
        }
    }
    const AuthorityRecord* issuer = state.bundle.find_authority(record.issued_by);
    if (issuer == nullptr) {
        finding.code = Code::AuthorityUnknown;
        finding.detail = "exception issuer '" + record.issued_by.value() + "' is not declared by this policy";
        problems.push_back(finding);
    } else if (issuer->level < state.policy.settings().min_waiver_level) {
        finding.code = Code::ExceptionAuthorityInsufficient;
        finding.detail = "exception issuer holds level " + issuer->level.format() + " but the policy requires " +
                         state.policy.settings().min_waiver_level.format();
        problems.push_back(finding);
    }
    for (const RuleId& relaxed : record.relaxed_rules) {
        if (find_rule(state, relaxed) == nullptr) {
            finding.code = Code::ExceptionNotInRegistry;
            finding.detail = "exception relaxes rule '" + relaxed.value() + "' which this policy does not define";
            problems.push_back(finding);
        }
    }
    return problems;
}

void validate_referenced_exceptions(EvaluationState& state) {
    for (const ExceptionId& id : state.request.exceptions()) {
        ExceptionStatus status;
        status.id = id;
        status.record = state.bundle.find_exception(id);
        status.present = status.record != nullptr;
        if (status.present) {
            status.digest = sha256(canonical_exception_record(*status.record));
            state.exception_digests.push_back(status.digest);
            status.problems = exception_problems(state, *status.record, true);
            // Hard interlock and protected class rules can never be relaxed.
            for (const RuleId& relaxed : status.record->relaxed_rules) {
                const Rule* rule = find_rule(state, relaxed);
                if (rule == nullptr) {
                    continue;
                }
                if (rule_kind_is_never_waivable(rule_kind_of(*rule)) && rule_applicable(state, rule_header_of(*rule))) {
                    Finding bypass;
                    bypass.code = Code::ExceptionWaivesHardInterlock;
                    bypass.exception = id;
                    bypass.rule = relaxed;
                    bypass.detail = "exception attempts to relax '" + relaxed.value() +
                                    "', which is never waivable";
                    add_finding(state, std::move(bypass));
                    note_rule(state, relaxed);
                }
            }
        }
        state.exceptions.push_back(std::move(status));
    }
}

const ExceptionStatus* find_exception_status(const EvaluationState& state, const ExceptionId& id) {
    for (const ExceptionStatus& status : state.exceptions) {
        if (status.id == id) {
            return &status;
        }
    }
    return nullptr;
}

// True when a valid referenced exception relaxes the rule. When the exception
// was needed but unusable, its problems are reported exactly once.
bool rule_is_waived(EvaluationState& state, const RuleId& rule) {
    bool needed = false;
    bool waived = false;
    ExceptionId honored;
    for (const ExceptionId& id : state.request.exceptions()) {
        const ExceptionStatus* status = find_exception_status(state, id);
        if (status == nullptr) {
            continue;
        }
        if (!status->present) {
            needed = true;
            continue;
        }
        const std::vector<RuleId>& relaxed = status->record->relaxed_rules;
        if (std::find(relaxed.begin(), relaxed.end(), rule) == relaxed.end()) {
            continue;
        }
        needed = true;
        if (status->problems.empty()) {
            waived = true;
            honored = status->id;
        }
    }
    if (waived) {
        state.honored_exceptions.push_back(honored);
        return true;
    }
    if (!needed) {
        return false;
    }
    // Report the problems of the exceptions that targeted this rule, once each.
    for (const ExceptionId& id : state.request.exceptions()) {
        const ExceptionStatus* status = find_exception_status(state, id);
        if (status == nullptr) {
            continue;
        }
        if (!status->present) {
            Finding finding;
            finding.code = Code::ExceptionNotInRegistry;
            finding.exception = id;
            finding.rule = rule;
            finding.detail = "request references exception '" + id.value() +
                             "' which the authoritative registry does not contain";
            add_finding(state, std::move(finding));
            continue;
        }
        const std::vector<RuleId>& relaxed = status->record->relaxed_rules;
        if (std::find(relaxed.begin(), relaxed.end(), rule) == relaxed.end()) {
            continue;
        }
        if (status->problems.empty()) {
            continue;
        }
        for (const Finding& problem : status->problems) {
            Finding copy = problem;
            copy.rule = rule;
            add_finding(state, std::move(copy));
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Stage 5: evidence availability, freshness, epoch fence and source trust.
// ---------------------------------------------------------------------------
void check_evidence(EvaluationState& state) {
    const PolicySettings& settings = state.policy.settings();
    const EvidenceBundle* evidence = state.request.evidence().has_value() ? &state.request.evidence().value() : nullptr;

    if (evidence == nullptr) {
        // Missing evidence is reported by the redundancy stage, attributed to
        // the rule that required it.
        return;
    }

    Finding report_finding;
    if (!source_is_trusted(state, evidence->source)) {
        report_finding.code = Code::EvidenceAuthorityUnknown;
        report_finding.detail = "evidence source '" + evidence->source.value() + "' is not trusted by this policy";
        add_finding(state, report_finding);
    }
    if (settings.min_evidence_epoch.is_set() && evidence->epoch < settings.min_evidence_epoch) {
        report_finding.code = Code::EvidenceEpochFenced;
        report_finding.detail = "evidence epoch " + evidence->epoch.format() + " is behind the policy fence " +
                                settings.min_evidence_epoch.format();
        add_finding(state, report_finding);
    }
    check_freshness(state, evidence->observed_at, "evidence report", Finding{});

    for (const ObligationClassId& obligation_class : state.request.classes()) {
        const ClassEvidence* entry = nullptr;
        for (const ClassEvidence& candidate : evidence->classes) {
            if (candidate.obligation_class == obligation_class) {
                entry = &candidate;
                break;
            }
        }
        if (entry == nullptr) {
            continue;  // Reported by the redundancy stage, attributed to the rule.
        }
        Finding finding;
        finding.obligation_class = obligation_class;
        if (!source_is_trusted(state, entry->source)) {
            finding.code = Code::EvidenceAuthorityUnknown;
            finding.detail = "evidence for '" + obligation_class.value() + "' comes from untrusted source '" +
                             entry->source.value() + "'";
            add_finding(state, finding);
        }
        if (settings.min_evidence_epoch.is_set() && entry->epoch < settings.min_evidence_epoch) {
            finding.code = Code::EvidenceEpochFenced;
            finding.detail = "evidence epoch " + entry->epoch.format() + " for '" + obligation_class.value() +
                             "' is behind the policy fence " + settings.min_evidence_epoch.format();
            add_finding(state, finding);
        }
        Finding freshness;
        freshness.obligation_class = obligation_class;
        check_freshness(state, entry->observed_at, "evidence for '" + obligation_class.value() + "'",
                        std::move(freshness));
    }
}

// ---------------------------------------------------------------------------
// Stage 6: hard interlocks. An interlock that the report does not cover is
// unknown, never inactive.
// ---------------------------------------------------------------------------
void check_interlocks(EvaluationState& state) {
    const InterlockReport* report = state.request.interlocks().has_value() ? &state.request.interlocks().value() : nullptr;
    if (report != nullptr) {
        Finding finding;
        if (!source_is_trusted(state, report->source)) {
            finding.code = Code::EvidenceAuthorityUnknown;
            finding.detail = "interlock report source '" + report->source.value() + "' is not trusted by this policy";
            add_finding(state, finding);
        }
        if (state.policy.settings().min_evidence_epoch.is_set() &&
            report->epoch < state.policy.settings().min_evidence_epoch) {
            finding.code = Code::EvidenceEpochFenced;
            finding.detail = "interlock report epoch is behind the policy evidence fence";
            add_finding(state, finding);
        }
        check_freshness(state, report->observed_at, "interlock report", Finding{});
    }

    for (const Rule& rule : state.policy.rules()) {
        if (rule_kind_of(rule) != RuleKind::HardInterlock) {
            continue;
        }
        const RuleHeader& header = rule_header_of(rule);
        if (!rule_applicable(state, header)) {
            continue;
        }
        const HardInterlockRule& concrete = std::get<HardInterlockRule>(rule);
        note_rule(state, header.id);
        Finding finding;
        finding.rule = header.id;
        if (report == nullptr) {
            finding.code = Code::InterlockUnknown;
            finding.detail = "no interlock report was supplied, so interlock '" + concrete.interlock.value() +
                             "' is unknown";
            add_finding(state, std::move(finding));
            continue;
        }
        const InterlockAssertion* assertion = nullptr;
        for (const InterlockAssertion& candidate : report->assertions) {
            if (candidate.interlock == concrete.interlock) {
                assertion = &candidate;
                break;
            }
        }
        if (assertion == nullptr) {
            finding.code = Code::InterlockUnknown;
            finding.detail = "interlock report does not cover '" + concrete.interlock.value() + "'";
            add_finding(state, std::move(finding));
            continue;
        }
        if (assertion->active) {
            finding.code = Code::HardInterlockViolation;
            finding.detail = "interlock '" + concrete.interlock.value() + "' is asserted active";
            add_finding(state, std::move(finding));
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 7: protected classes. Never waivable.
// ---------------------------------------------------------------------------
void check_protected_classes(EvaluationState& state) {
    for (const Rule& rule : state.policy.rules()) {
        if (rule_kind_of(rule) != RuleKind::ProtectedClass) {
            continue;
        }
        const RuleHeader& header = rule_header_of(rule);
        if (!rule_applicable(state, header)) {
            continue;
        }
        const ProtectedClassRule& concrete = std::get<ProtectedClassRule>(rule);
        bool violated = true;
        if (concrete.window.has_value()) {
            violated = concrete.window->intersects(state.request.window());
        }
        if (!violated) {
            continue;
        }
        note_rule(state, header.id);
        std::vector<ObligationClassId> classes;
        if (state.request.classes().empty()) {
            for (const ObligationClassId& declared : header.classes.classes) {
                classes.push_back(declared);
            }
        } else {
            for (const ObligationClassId& candidate : state.request.classes()) {
                if (header.classes.matches(candidate)) {
                    classes.push_back(candidate);
                }
            }
        }
        for (const ObligationClassId& obligation_class : classes) {
            Finding finding;
            finding.code = Code::ProtectedClassViolation;
            finding.rule = header.id;
            finding.obligation_class = obligation_class;
            if (concrete.window.has_value()) {
                finding.detail = "protected class '" + obligation_class.value() + "' may not be maintained in window [" +
                                 concrete.window->start.format() + ", " + concrete.window->end.format() + ")";
            } else {
                finding.detail = "protected class '" + obligation_class.value() + "' may not be maintained at all";
            }
            add_finding(state, std::move(finding));
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 8: blackout windows (waivable).
// ---------------------------------------------------------------------------
void check_blackouts(EvaluationState& state) {
    for (const Rule& rule : state.policy.rules()) {
        if (rule_kind_of(rule) != RuleKind::Blackout) {
            continue;
        }
        const RuleHeader& header = rule_header_of(rule);
        if (!rule_applicable(state, header)) {
            continue;
        }
        const BlackoutRule& concrete = std::get<BlackoutRule>(rule);
        auto effective = blackout_windows(concrete);
        if (!effective) {
            Finding finding;
            finding.code = effective.error().code;
            finding.rule = header.id;
            finding.detail = effective.error().detail;
            add_finding(state, std::move(finding));
            continue;
        }
        const Interval* hit = nullptr;
        for (const Interval& window : effective.value()) {
            if (window.intersects(state.request.window())) {
                hit = &window;
                break;
            }
        }
        if (hit == nullptr) {
            continue;
        }
        note_rule(state, header.id);
        if (concrete.waivable && rule_is_waived(state, header.id)) {
            Finding finding;
            finding.code = Code::ExceptionWaiverApplied;
            finding.rule = header.id;
            finding.detail = "blackout window was relaxed by an authoritative exception";
            add_finding(state, std::move(finding));
            state.exception_used = true;
            continue;
        }
        Finding finding;
        finding.code = Code::BlackoutConflict;
        finding.rule = header.id;
        finding.detail = "requested window intersects [" + hit->start.format() + ", " + hit->end.format() + ")";
        add_finding(state, std::move(finding));
    }
}

// ---------------------------------------------------------------------------
// Stage 9: redundancy floors (waivable only when the rule says so).
// ---------------------------------------------------------------------------
void check_redundancy(EvaluationState& state) {
    const EvidenceBundle* evidence = state.request.evidence().has_value() ? &state.request.evidence().value() : nullptr;

    for (const Rule& rule : state.policy.rules()) {
        if (rule_kind_of(rule) != RuleKind::Redundancy) {
            continue;
        }
        const RuleHeader& header = rule_header_of(rule);
        if (!rule_applicable(state, header)) {
            continue;
        }
        const RedundancyRule& concrete = std::get<RedundancyRule>(rule);
        note_rule(state, header.id);

        if (state.request.classes().empty()) {
            // The rule's own class list is a requirement, not an observation:
            // a request that omits its affected classes cannot satisfy it.
            Finding finding;
            finding.rule = header.id;
            finding.code = Code::EvidenceMissing;
            finding.detail = "request declares no affected classes, so this redundancy floor cannot be evaluated";
            add_finding(state, std::move(finding));
            continue;
        }

        std::vector<ObligationClassId> classes;
        {
            for (const ObligationClassId& candidate : state.request.classes()) {
                if (header.classes.matches(candidate)) {
                    classes.push_back(candidate);
                }
            }
        }
        if (classes.empty()) {
            // A request that declares no affected classes cannot satisfy a
            // redundancy floor, so the omission is a refusal rather than a
            // silent pass.
            Finding finding;
            finding.rule = header.id;
            finding.code = Code::EvidenceMissing;
            finding.detail = "request declares no affected classes, so this redundancy floor cannot be evaluated";
            add_finding(state, std::move(finding));
            continue;
        }

        for (const ObligationClassId& obligation_class : classes) {
            const ClassEvidence* entry = nullptr;
            if (evidence != nullptr) {
                for (const ClassEvidence& candidate : evidence->classes) {
                    if (candidate.obligation_class == obligation_class) {
                        entry = &candidate;
                        break;
                    }
                }
            }
            Finding finding;
            finding.rule = header.id;
            finding.obligation_class = obligation_class;
            if (entry == nullptr) {
                finding.code = Code::EvidenceMissing;
                finding.detail = "no evidence was supplied for obligation class '" + obligation_class.value() + "'";
                add_finding(state, std::move(finding));
                continue;
            }
            if (entry->state != MeasurementState::Measured) {
                finding.code = Code::EvidenceUnmeasured;
                finding.detail = "evidence reports obligation class '" + obligation_class.value() + "' as " +
                                 std::string(to_string(entry->state));
                add_finding(state, std::move(finding));
                continue;
            }
            if (entry->surviving_units >= concrete.minimum_survivors) {
                continue;
            }
            if (concrete.waivable && rule_is_waived(state, header.id)) {
                Finding waived;
                waived.code = Code::ExceptionWaiverApplied;
                waived.rule = header.id;
                waived.obligation_class = obligation_class;
                waived.detail = "redundancy floor was relaxed by an authoritative exception";
                add_finding(state, std::move(waived));
                state.exception_used = true;
                state.redundancy_waived = true;
                continue;
            }
            finding.code = Code::RedundancyShortfall;
            finding.detail = "obligation class '" + obligation_class.value() + "' reports " +
                             std::to_string(entry->surviving_units) + " surviving units but the floor requires " +
                             std::to_string(concrete.minimum_survivors);
            add_finding(state, std::move(finding));
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 10: soft constraints (waivable) and the policy window limit.
// ---------------------------------------------------------------------------
void check_soft_constraints(EvaluationState& state) {
    if (state.window_length > state.policy.settings().max_window) {
        Finding finding;
        finding.code = Code::WindowTooLong;
        finding.detail = "requested window length " + state.window_length.format() +
                         " exceeds the policy maximum " + state.policy.settings().max_window.format();
        add_finding(state, std::move(finding));
    }

    for (const Rule& rule : state.policy.rules()) {
        if (rule_kind_of(rule) != RuleKind::SoftConstraint) {
            continue;
        }
        const RuleHeader& header = rule_header_of(rule);
        if (!rule_applicable(state, header)) {
            continue;
        }
        const SoftConstraintRule& concrete = std::get<SoftConstraintRule>(rule);
        std::vector<std::string> breaches;
        if (concrete.max_concurrent != 0 && state.request.concurrent_maintenance() > concrete.max_concurrent) {
            breaches.push_back("concurrent maintenance " + std::to_string(state.request.concurrent_maintenance()) +
                               " exceeds the limit of " + std::to_string(concrete.max_concurrent));
        }
        if (concrete.max_window.has_value() && state.window_length > concrete.max_window.value()) {
            breaches.push_back("window length " + state.window_length.format() + " exceeds the limit of " +
                               concrete.max_window.value().format());
        }
        if (breaches.empty()) {
            continue;
        }
        note_rule(state, header.id);
        bool waived = concrete.waivable && rule_is_waived(state, header.id);
        for (const std::string& breach : breaches) {
            Finding finding;
            finding.rule = header.id;
            if (waived) {
                finding.code = Code::ExceptionWaiverApplied;
                finding.detail = "soft constraint was relaxed by an authoritative exception: " + breach;
                state.exception_used = true;
            } else {
                finding.code = Code::SoftConstraintViolation;
                finding.detail = breach;
            }
            add_finding(state, std::move(finding));
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 11: escalation requirement and approval verification.
// ---------------------------------------------------------------------------
std::vector<Finding> approval_problems(const EvaluationState& state, const ApprovalRecord& record,
                                       const AuthorityLevel& required) {
    std::vector<Finding> problems;
    Finding finding;
    finding.approval = record.id;

    auto verified = verify_approval_mac(state.keys, record);
    if (!verified) {
        finding.code = verified.error().code;
        finding.detail = verified.error().detail;
        problems.push_back(finding);
    }
    if (record.generation != state.policy.generation() || !(record.policy_digest == state.policy_digest)) {
        finding.code = Code::ApprovalFenced;
        finding.detail = "approval binds policy generation " + record.generation.format() +
                         " and a different policy digest";
        problems.push_back(finding);
    }
    if (record.revoked_at.has_value()) {
        finding.code = Code::ApprovalRevoked;
        finding.detail = "approval was revoked at " + record.revoked_at.value().format();
        problems.push_back(finding);
    }
    if (state.request.evaluated_at() < record.not_before) {
        finding.code = Code::ApprovalNotYetValid;
        finding.detail = "approval becomes valid at " + record.not_before.format();
        problems.push_back(finding);
    }
    if (!(state.request.evaluated_at() < record.expires_at)) {
        finding.code = Code::ApprovalExpired;
        finding.detail = "approval expired at " + record.expires_at.format();
        problems.push_back(finding);
    }
    if (!(record.bound_request_digest == state.request_digest)) {
        finding.code = Code::ApprovalContextMismatch;
        finding.detail = "approval authorises a different request digest";
        problems.push_back(finding);
    }
    for (const ScopePath& scope : state.request.scopes()) {
        if (!record.scope.matches(scope)) {
            finding.code = Code::ApprovalScopeMismatch;
            finding.detail = "approval scope '" + record.scope.format() + "' does not cover '" + scope.format() + "'";
            problems.push_back(finding);
            break;
        }
    }
    if (state.request.classes().empty()) {
        if (!record.classes.all) {
            finding.code = Code::ApprovalClassMismatch;
            finding.detail = "request declares no affected classes, so the approval must cover all classes";
            problems.push_back(finding);
        }
    } else {
        for (const ObligationClassId& obligation_class : state.request.classes()) {
            if (!record.classes.matches(obligation_class)) {
                finding.code = Code::ApprovalClassMismatch;
                finding.detail = "approval does not cover obligation class '" + obligation_class.value() + "'";
                problems.push_back(finding);
                break;
            }
        }
    }
    const AuthorityRecord* issuer = state.bundle.find_authority(record.issued_by);
    if (issuer == nullptr) {
        finding.code = Code::AuthorityUnknown;
        finding.detail = "approval issuer '" + record.issued_by.value() + "' is not declared by this policy";
        problems.push_back(finding);
    } else if (record.level < required || issuer->level < required) {
        finding.code = Code::ApprovalAuthorityInsufficient;
        finding.detail = "approval holds level " + record.level.format() + " from an issuer of level " +
                         issuer->level.format() + " but level " + required.format() + " is required";
        problems.push_back(finding);
    }
    return problems;
}

void check_escalation(EvaluationState& state) {
    std::optional<AuthorityLevel> required;
    for (const Rule& rule : state.policy.rules()) {
        if (rule_kind_of(rule) != RuleKind::Escalation) {
            continue;
        }
        const RuleHeader& header = rule_header_of(rule);
        if (!rule_applicable(state, header)) {
            continue;
        }
        const EscalationRule& concrete = std::get<EscalationRule>(rule);
        const bool unconditional = !concrete.min_window.has_value() && !concrete.on_exception_used &&
                                   !concrete.on_redundancy_waiver;
        bool triggers = unconditional;
        if (concrete.min_window.has_value() && state.window_length >= concrete.min_window.value()) {
            triggers = true;
        }
        if (concrete.on_exception_used && state.exception_used) {
            triggers = true;
        }
        if (concrete.on_redundancy_waiver && state.redundancy_waived) {
            triggers = true;
        }
        if (!triggers) {
            continue;
        }
        note_rule(state, header.id);
        if (!required.has_value() || required.value() < concrete.required_level) {
            required = concrete.required_level;
        }
    }

    bool satisfied = false;
    for (const ApprovalId& id : state.request.approvals()) {
        const ApprovalRecord* record = state.bundle.find_approval(id);
        if (record == nullptr) {
            if (required.has_value()) {
                Finding finding;
                finding.code = Code::ApprovalNotInRegistry;
                finding.approval = id;
                finding.detail = "request references approval '" + id.value() +
                                 "' which the authoritative registry does not contain";
                add_finding(state, std::move(finding));
            }
            continue;
        }
        state.approval_digests.push_back(sha256(canonical_approval_record(*record)));
        if (!required.has_value()) {
            continue;
        }
        std::vector<Finding> problems = approval_problems(state, *record, required.value());
        if (problems.empty()) {
            satisfied = true;
            continue;
        }
        for (Finding& problem : problems) {
            add_finding(state, std::move(problem));
        }
    }

    if (required.has_value()) {
        state.required_level = required;
        state.escalation_satisfied = satisfied;
        if (!satisfied) {
            Finding finding;
            finding.code = Code::EscalationRequired;
            finding.detail = "authority level " + required.value().format() +
                             " must approve this exact request before it may proceed";
            add_finding(state, std::move(finding));
        }
    }
}

// ---------------------------------------------------------------------------
// Replay resolution runs before ordinary staleness rejection so that a lost
// response can be retried safely. A replay that binds a policy generation
// other than the current one is reported as superseded and can never restore
// the authority it once carried.
// ---------------------------------------------------------------------------
std::optional<Decision> resolve_replay(const PolicyBundle& bundle, const EvaluationRequest& request,
                                    const Digest256& request_digest,
                                    const std::vector<PriorDecisionRecord>& prior_decisions) {
    for (const PriorDecisionRecord& record : prior_decisions) {
        if (!(record.context_id == request.context_id()) || !(record.request_digest == request_digest)) {
            continue;
        }
        Decision decision = record.decision;
        const bool same_policy = record.decision.bindings.policy_generation == bundle.policy().generation() &&
                                 record.decision.bindings.policy_digest == bundle.policy().digest();
        if (same_policy) {
            decision.replay = ReplayDisposition::Replayed;
            return decision;
        }
        decision.replay = ReplayDisposition::ReplaySuperseded;
        Finding finding;
        finding.code = Code::ReplaySuperseded;
        finding.detail = "the recorded decision binds policy generation " +
                         record.decision.bindings.policy_generation.format() +
                         " which is not the current generation; its authority is not inherited";
        decision.findings.push_back(finding);
        sort_findings(decision.findings);
        const Outcome outcome = outcome_for_severity(finding.severity());
        if (static_cast<unsigned>(outcome) > static_cast<unsigned>(decision.outcome)) {
            decision.outcome = outcome;
        }
        return decision;
    }
    return std::nullopt;
}

}  // namespace

Result<Decision> evaluate(const PolicyBundle& bundle, const KeySet& keys, const EvaluationRequest& request,
                          const std::vector<PriorDecisionRecord>& prior_decisions,
                          const EvaluationLimits& limits) {
    EvaluationState state{bundle,
                          keys,
                          request,
                          limits,
                          bundle.policy(),
                          bundle.policy().digest(),
                          request.digest(),
                          Duration{},
                          false,
                          false,
                          false,
                          false,
                          {},
                          {},
                          {},
                          {},
                          {},
                          {},
                          std::nullopt};

    auto length = request.window().length();
    if (!length) {
        return length.error();
    }
    state.window_length = length.value();

    std::optional<Decision> replay = resolve_replay(bundle, request, state.request_digest, prior_decisions);
    if (replay.has_value()) {
        return replay.value();
    }

    // Stage 3: policy lifecycle.
    switch (state.policy.lifecycle()) {
        case PolicyLifecycle::Draft: {
            Finding finding;
            finding.code = Code::PolicyNotPublished;
            finding.detail = "policy generation " + state.policy.generation().format() + " is not published";
            add_finding(state, std::move(finding));
            break;
        }
        case PolicyLifecycle::Superseded: {
            Finding finding;
            finding.code = Code::PolicySuperseded;
            finding.detail = "policy generation " + state.policy.generation().format() + " was superseded";
            add_finding(state, std::move(finding));
            break;
        }
        case PolicyLifecycle::Revoked: {
            Finding finding;
            finding.code = Code::PolicyRevoked;
            finding.detail = "policy generation " + state.policy.generation().format() + " is revoked";
            add_finding(state, std::move(finding));
            break;
        }
        case PolicyLifecycle::Published:
            break;
    }

    // Stage 4: generation and digest fence.
    if (request.expected_generation() != state.policy.generation()) {
        Finding finding;
        finding.code = Code::PolicyGenerationStale;
        finding.detail = "request binds policy generation " + request.expected_generation().format() +
                         " but the authoritative generation is " + state.policy.generation().format();
        add_finding(state, std::move(finding));
    }
    if (request.expected_policy_digest().has_value() &&
        !(request.expected_policy_digest().value() == state.policy_digest)) {
        Finding finding;
        finding.code = Code::PolicyDigestMismatch;
        finding.detail = "request binds a policy digest that is not the authoritative policy digest";
        add_finding(state, std::move(finding));
    }

    validate_referenced_exceptions(state);
    check_evidence(state);
    check_interlocks(state);
    check_protected_classes(state);
    check_blackouts(state);
    check_redundancy(state);
    check_soft_constraints(state);
    check_escalation(state);

    Decision decision;
    decision.replay = ReplayDisposition::Fresh;
    decision.findings = state.findings;
    // A soft constraint violation that the required authority has approved is
    // recorded as an advisory: it stays visible without blocking the request.
    if (state.escalation_satisfied) {
        for (Finding& finding : decision.findings) {
            if (finding.code == Code::SoftConstraintViolation) {
                finding.code = Code::SoftConstraintApproved;
            }
        }
    }
    sort_findings(decision.findings);

    Severity highest = Severity::None;
    for (const Finding& finding : decision.findings) {
        if (static_cast<unsigned>(finding.severity()) > static_cast<unsigned>(highest)) {
            highest = finding.severity();
        }
    }
    if (decision.findings.empty()) {
        Finding finding;
        finding.code = Code::NoApplicableRules;
        finding.detail = "no rule applies to this request, so nothing constrains it";
        decision.findings.push_back(finding);
        highest = Severity::Info;
    }
    decision.outcome = outcome_for_severity(highest);
    decision.required_level = state.required_level;

    decision.applied_rules = state.applied_rules;
    std::sort(decision.applied_rules.begin(), decision.applied_rules.end());
    decision.applied_rules.erase(std::unique(decision.applied_rules.begin(), decision.applied_rules.end()),
                                 decision.applied_rules.end());

    decision.honored_exceptions = state.honored_exceptions;
    std::sort(decision.honored_exceptions.begin(), decision.honored_exceptions.end());
    decision.honored_exceptions.erase(
        std::unique(decision.honored_exceptions.begin(), decision.honored_exceptions.end()),
        decision.honored_exceptions.end());

    DecisionBindings bindings;
    bindings.policy_id = state.policy.id();
    bindings.policy_generation = state.policy.generation();
    bindings.policy_digest = state.policy_digest;
    bindings.control_epoch = bundle.control_epoch();
    bindings.registry_revision = bundle.registry_revision();
    bindings.context_id = request.context_id();
    bindings.request_id = request.request_id();
    bindings.request_digest = state.request_digest;
    if (request.evidence().has_value()) {
        bindings.evidence_digest = sha256(canonical_evidence(request.evidence().value()));
        bindings.evidence_epoch = request.evidence().value().epoch;
    }
    if (request.interlocks().has_value()) {
        bindings.interlock_digest = sha256(canonical_interlock_report(request.interlocks().value()));
    }
    std::sort(state.exception_digests.begin(), state.exception_digests.end());
    state.exception_digests.erase(std::unique(state.exception_digests.begin(), state.exception_digests.end()),
                                  state.exception_digests.end());
    std::sort(state.approval_digests.begin(), state.approval_digests.end());
    state.approval_digests.erase(std::unique(state.approval_digests.begin(), state.approval_digests.end()),
                                 state.approval_digests.end());
    bindings.exception_digests = state.exception_digests;
    bindings.approval_digests = state.approval_digests;
    bindings.evaluated_at = request.evaluated_at();
    bindings.semantics_version = semantics_version;
    bindings.digest_format_version = digest_format_version;
    decision.bindings = bindings;
    return decision;
}

Result<Decision> evaluate(const PolicyBundle& bundle, const KeySet& keys, const EvaluationRequest& request) {
    const std::vector<PriorDecisionRecord> no_prior;
    EvaluationLimits limits;
    return evaluate(bundle, keys, request, no_prior, limits);
}

}  // namespace maintpol
