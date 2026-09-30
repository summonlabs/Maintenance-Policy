#include "maintpol/decision.hpp"

#include <algorithm>
#include <tuple>

namespace maintpol {
namespace {

template <typename T>
int compare_optional(const std::optional<T>& left, const std::optional<T>& right) {
    if (left.has_value() != right.has_value()) {
        return left.has_value() ? 1 : -1;
    }
    if (!left.has_value()) {
        return 0;
    }
    if (left.value() == right.value()) {
        return 0;
    }
    return left.value() < right.value() ? -1 : 1;
}

}  // namespace

std::string_view to_string(Outcome outcome) {
    switch (outcome) {
        case Outcome::Allow: return "allow";
        case Outcome::RequireEscalation: return "require-escalation";
        case Outcome::Unknown: return "unknown";
        case Outcome::Deny: return "deny";
    }
    return "unknown";
}

bool outcome_from_name(std::string_view name, Outcome& out) {
    if (name == "allow") { out = Outcome::Allow; return true; }
    if (name == "require-escalation") { out = Outcome::RequireEscalation; return true; }
    if (name == "unknown") { out = Outcome::Unknown; return true; }
    if (name == "deny") { out = Outcome::Deny; return true; }
    return false;
}

Outcome outcome_for_severity(Severity severity) {
    switch (severity) {
        case Severity::Denial:
        case Severity::Error:
            return Outcome::Deny;
        case Severity::Refusal:
            return Outcome::Unknown;
        case Severity::Escalation:
            return Outcome::RequireEscalation;
        case Severity::None:
        case Severity::Info:
        case Severity::Advisory:
            return Outcome::Allow;
    }
    return Outcome::Unknown;
}

std::string_view to_string(ReplayDisposition disposition) {
    switch (disposition) {
        case ReplayDisposition::Fresh: return "fresh";
        case ReplayDisposition::Replayed: return "replayed";
        case ReplayDisposition::ReplaySuperseded: return "replay-superseded";
    }
    return "fresh";
}

bool replay_disposition_from_name(std::string_view name, ReplayDisposition& out) {
    if (name == "fresh") { out = ReplayDisposition::Fresh; return true; }
    if (name == "replayed") { out = ReplayDisposition::Replayed; return true; }
    if (name == "replay-superseded") { out = ReplayDisposition::ReplaySuperseded; return true; }
    return false;
}

bool finding_less(const Finding& left, const Finding& right) {
    const auto left_severity = static_cast<unsigned>(left.severity());
    const auto right_severity = static_cast<unsigned>(right.severity());
    if (left_severity != right_severity) {
        return left_severity > right_severity;
    }
    if (left.code != right.code) {
        return static_cast<std::uint16_t>(left.code) < static_cast<std::uint16_t>(right.code);
    }
    int comparison = compare_optional(left.rule, right.rule);
    if (comparison != 0) {
        return comparison < 0;
    }
    comparison = compare_optional(left.exception, right.exception);
    if (comparison != 0) {
        return comparison < 0;
    }
    comparison = compare_optional(left.approval, right.approval);
    if (comparison != 0) {
        return comparison < 0;
    }
    comparison = compare_optional(left.obligation_class, right.obligation_class);
    if (comparison != 0) {
        return comparison < 0;
    }
    return left.detail < right.detail;
}

void sort_findings(std::vector<Finding>& findings) {
    std::sort(findings.begin(), findings.end(), finding_less);
}

}  // namespace maintpol
