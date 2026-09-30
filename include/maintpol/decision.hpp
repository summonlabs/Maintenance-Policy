#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "maintpol/digest.hpp"
#include "maintpol/error.hpp"
#include "maintpol/time.hpp"
#include "maintpol/types.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Outcome ladder. The outcome of a decision is the highest severity among its
// findings:
//
//   Denial      -> Deny
//   Refusal     -> Unknown   (the request cannot be resolved)
//   Escalation  -> RequireEscalation
//   Advisory/Info -> Allow
//
// Unknown is never a permissive state and never means "healthy".
// ---------------------------------------------------------------------------
enum class Outcome : std::uint8_t { Allow = 1, RequireEscalation = 2, Unknown = 3, Deny = 4 };

MAINTPOL_API std::string_view to_string(Outcome outcome);
MAINTPOL_API bool outcome_from_name(std::string_view name, Outcome& out);
MAINTPOL_API Outcome outcome_for_severity(Severity severity);

// How a decision relates to an earlier decision for the same request.
enum class ReplayDisposition : std::uint8_t { Fresh = 1, Replayed = 2, ReplaySuperseded = 3 };

MAINTPOL_API std::string_view to_string(ReplayDisposition disposition);
MAINTPOL_API bool replay_disposition_from_name(std::string_view name, ReplayDisposition& out);

// ---------------------------------------------------------------------------
// A finding attributes one evaluation fact to the smallest set of inputs that
// produced it. Findings never carry free-form-only information: the code is
// the contract, the detail is an explanation.
// ---------------------------------------------------------------------------
struct Finding {
    Code code = Code::Ok;
    std::optional<RuleId> rule;
    std::optional<ExceptionId> exception;
    std::optional<ApprovalId> approval;
    std::optional<ObligationClassId> obligation_class;
    std::string detail;

    Severity severity() const { return severity_of(code); }

    friend bool operator==(const Finding&, const Finding&) = default;
};

// Deterministic finding order: severity descending, then code, then the
// attributed identities, then the detail text.
MAINTPOL_API bool finding_less(const Finding& left, const Finding& right);
MAINTPOL_API void sort_findings(std::vector<Finding>& findings);

// ---------------------------------------------------------------------------
// Bindings: the exact identities, generations, revisions and digests the
// decision was computed against. Nothing that can invalidate the decision may
// be missing here.
// ---------------------------------------------------------------------------
struct DecisionBindings {
    PolicyId policy_id;
    PolicyGeneration policy_generation;
    Digest256 policy_digest;
    ControlEpoch control_epoch;
    Revision registry_revision;
    ContextId context_id;
    RequestId request_id;
    Digest256 request_digest;
    std::optional<Digest256> evidence_digest;
    std::optional<EvidenceEpoch> evidence_epoch;
    std::optional<Digest256> interlock_digest;
    std::vector<Digest256> exception_digests;
    std::vector<Digest256> approval_digests;
    Instant evaluated_at;
    std::uint32_t semantics_version = 0;
    std::uint32_t digest_format_version = 0;

    friend bool operator==(const DecisionBindings&, const DecisionBindings&) = default;
};

struct Decision {
    Outcome outcome = Outcome::Unknown;
    ReplayDisposition replay = ReplayDisposition::Fresh;
    std::vector<Finding> findings;
    std::vector<RuleId> applied_rules;
    std::vector<ExceptionId> honored_exceptions;
    std::optional<AuthorityLevel> required_level;
    DecisionBindings bindings;

    // SHA-256 over the canonical serialisation of the decision content. The
    // digest excludes the digest field itself and excludes journal sequence
    // numbers, which are transport metadata.
    Digest256 digest() const;

    friend bool operator==(const Decision&, const Decision&) = default;
};

}  // namespace maintpol
