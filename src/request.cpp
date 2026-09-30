#include "maintpol/request.hpp"

#include <algorithm>

namespace maintpol {

std::string_view to_string(MeasurementState state) {
    switch (state) {
        case MeasurementState::Measured: return "measured";
        case MeasurementState::Unmeasured: return "unmeasured";
        case MeasurementState::Unavailable: return "unavailable";
    }
    return "unknown";
}

bool measurement_state_from_name(std::string_view name, MeasurementState& out) {
    if (name == "measured") { out = MeasurementState::Measured; return true; }
    if (name == "unmeasured") { out = MeasurementState::Unmeasured; return true; }
    if (name == "unavailable") { out = MeasurementState::Unavailable; return true; }
    return false;
}

namespace {

template <typename T>
Result<void> require_unique_sorted(std::vector<T> values, std::string_view what) {
    std::sort(values.begin(), values.end());
    if (std::adjacent_find(values.begin(), values.end()) != values.end()) {
        return make_error(Code::DuplicateIdentifier, std::string(what) + " repeats an identity");
    }
    return {};
}

}  // namespace

Result<EvaluationRequest> EvaluationRequest::create(
    ContextId context_id, RequestId request_id, std::vector<ScopePath> scopes,
    std::vector<ObligationClassId> classes, Interval window, PrincipalId requested_by,
    PolicyGeneration expected_generation, std::optional<Digest256> expected_policy_digest,
    std::vector<ExceptionId> exceptions, std::vector<ApprovalId> approvals,
    std::optional<EvidenceBundle> evidence, std::optional<InterlockReport> interlocks,
    std::uint32_t concurrent_maintenance, Instant evaluated_at) {
    if (!context_id.is_set()) {
        return make_error(Code::ValueMalformed, "request context identity is unset");
    }
    if (!request_id.is_set()) {
        return make_error(Code::ValueMalformed, "request identity is unset");
    }
    if (!requested_by.is_set()) {
        return make_error(Code::ValueMalformed, "requesting principal is unset");
    }
    if (!expected_generation.is_set()) {
        return make_error(Code::ValueOutOfRange, "expected policy generation is unset");
    }
    if (scopes.empty()) {
        return make_error(Code::ScopeInvalid, "request must name at least one scope");
    }
    if (scopes.size() > kMaxRequestScopes) {
        return make_error(Code::TooManyItems, "request exceeds 32 scopes");
    }
    for (const ScopePath& scope : scopes) {
        if (!scope.is_set()) {
            return make_error(Code::ScopeInvalid, "request scope is unset");
        }
        if (scope.has_wildcard()) {
            return make_error(Code::ScopeInvalid, "request scopes must be concrete and must not contain '*'");
        }
    }
    auto unique_scopes = require_unique_sorted(scopes, "request scope list");
    if (!unique_scopes) {
        return unique_scopes.error();
    }
    if (classes.size() > kMaxRequestClasses) {
        return make_error(Code::TooManyItems, "request exceeds 64 obligation classes");
    }
    for (const ObligationClassId& obligation_class : classes) {
        if (!obligation_class.is_set()) {
            return make_error(Code::ValueMalformed, "request names an unset obligation class");
        }
    }
    auto unique_classes = require_unique_sorted(classes, "request class list");
    if (!unique_classes) {
        return unique_classes.error();
    }
    if (window.end <= window.start) {
        return make_error(Code::IntervalReversed, "requested window end must be strictly after its start");
    }
    if (exceptions.size() > kMaxReferenceListLength) {
        return make_error(Code::TooManyItems, "request exceeds 256 exception references");
    }
    for (const ExceptionId& id : exceptions) {
        if (!id.is_set()) {
            return make_error(Code::ValueMalformed, "request references an unset exception");
        }
    }
    auto unique_exceptions = require_unique_sorted(exceptions, "request exception list");
    if (!unique_exceptions) {
        return unique_exceptions.error();
    }
    if (approvals.size() > kMaxReferenceListLength) {
        return make_error(Code::TooManyItems, "request exceeds 256 approval references");
    }
    for (const ApprovalId& id : approvals) {
        if (!id.is_set()) {
            return make_error(Code::ValueMalformed, "request references an unset approval");
        }
    }
    auto unique_approvals = require_unique_sorted(approvals, "request approval list");
    if (!unique_approvals) {
        return unique_approvals.error();
    }

    if (evidence.has_value()) {
        const EvidenceBundle& bundle = evidence.value();
        if (!bundle.source.is_set()) {
            return make_error(Code::ValueMalformed, "evidence source is unset");
        }
        if (!bundle.epoch.is_set()) {
            return make_error(Code::ValueOutOfRange, "evidence epoch is unset");
        }
        if (bundle.classes.size() > kMaxEvidenceClasses) {
            return make_error(Code::TooManyItems, "evidence exceeds 256 obligation classes");
        }
        std::vector<ObligationClassId> reported;
        reported.reserve(bundle.classes.size());
        for (const ClassEvidence& entry : bundle.classes) {
            if (!entry.obligation_class.is_set()) {
                return make_error(Code::ValueMalformed, "evidence names an unset obligation class");
            }
            if (!entry.source.is_set()) {
                return make_error(Code::ValueMalformed, "evidence entry source is unset");
            }
            if (!entry.epoch.is_set()) {
                return make_error(Code::ValueOutOfRange, "evidence entry epoch is unset");
            }
            if (entry.state == MeasurementState::Measured && entry.surviving_units > entry.total_units) {
                return make_error(Code::ValueOutOfRange,
                                  "evidence reports more surviving units than total units");
            }
            reported.push_back(entry.obligation_class);
        }
        std::sort(reported.begin(), reported.end());
        if (std::adjacent_find(reported.begin(), reported.end()) != reported.end()) {
            return make_error(Code::EvidenceDuplicateClass, "evidence reports the same class twice");
        }
    }

    if (interlocks.has_value()) {
        const InterlockReport& report = interlocks.value();
        if (!report.source.is_set()) {
            return make_error(Code::ValueMalformed, "interlock report source is unset");
        }
        if (!report.epoch.is_set()) {
            return make_error(Code::ValueOutOfRange, "interlock report epoch is unset");
        }
        if (report.assertions.size() > kMaxReferenceListLength) {
            return make_error(Code::TooManyItems, "interlock report exceeds 256 assertions");
        }
        std::vector<InterlockId> reported;
        reported.reserve(report.assertions.size());
        for (const InterlockAssertion& assertion : report.assertions) {
            if (!assertion.interlock.is_set()) {
                return make_error(Code::ValueMalformed, "interlock report names an unset interlock");
            }
            reported.push_back(assertion.interlock);
        }
        std::sort(reported.begin(), reported.end());
        if (std::adjacent_find(reported.begin(), reported.end()) != reported.end()) {
            return make_error(Code::DuplicateIdentifier, "interlock report repeats an interlock");
        }
    }

    EvaluationRequest request;
    request.context_id_ = std::move(context_id);
    request.request_id_ = std::move(request_id);
    request.scopes_ = std::move(scopes);
    request.classes_ = std::move(classes);
    request.window_ = window;
    request.requested_by_ = std::move(requested_by);
    request.expected_generation_ = expected_generation;
    request.expected_policy_digest_ = expected_policy_digest;
    request.exceptions_ = std::move(exceptions);
    request.approvals_ = std::move(approvals);
    request.evidence_ = std::move(evidence);
    request.interlocks_ = std::move(interlocks);
    request.concurrent_maintenance_ = concurrent_maintenance;
    request.evaluated_at_ = evaluated_at;
    return request;
}

}  // namespace maintpol
