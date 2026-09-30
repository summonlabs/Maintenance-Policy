#pragma once

#include <cstddef>
#include <vector>

#include "maintpol/decision.hpp"
#include "maintpol/error.hpp"
#include "maintpol/policy.hpp"
#include "maintpol/request.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// A previously issued decision, as recorded by the decision journal. Replay
// resolution uses it to answer a repeated request before ordinary staleness
// rejection, which is what makes a lost response safe to retry.
// ---------------------------------------------------------------------------
struct PriorDecisionRecord {
    ContextId context_id;
    RequestId request_id;
    Digest256 request_digest;
    Digest256 decision_digest;
    Decision decision;

    friend bool operator==(const PriorDecisionRecord&, const PriorDecisionRecord&) = default;
};

struct EvaluationLimits {
    // Bounds the number of findings a single evaluation may produce.
    std::size_t max_findings = 512;
};

// ---------------------------------------------------------------------------
// Deterministic evaluation of one request against one authoritative bundle.
//
// The engine is a pure function of (bundle, keys, request, prior decisions):
// it never reads a clock, never touches the filesystem and never mutates its
// inputs. Callers supply the authoritative evaluation instant.
//
// Deterministic precedence (a decision reports every condition it found; the
// highest severity present decides the outcome):
//
//   1. request shape errors are returned as an Error, not as a decision
//   2. replay resolution (before ordinary staleness rejection)
//   3. policy lifecycle state
//   4. policy generation and digest fence
//   5. evidence availability, freshness, epoch fence and source authority
//   6. hard interlocks
//   7. protected classes
//   8. blackout windows (waivable)
//   9. redundancy floors (waivable when the rule says so)
//  10. soft constraints (waivable)
//  11. escalation requirement and approval verification
// ---------------------------------------------------------------------------
MAINTPOL_API Result<Decision> evaluate(const PolicyBundle& bundle, const KeySet& keys,
                                       const EvaluationRequest& request,
                                       const std::vector<PriorDecisionRecord>& prior_decisions,
                                       const EvaluationLimits& limits);

MAINTPOL_API Result<Decision> evaluate(const PolicyBundle& bundle, const KeySet& keys,
                                       const EvaluationRequest& request);

}  // namespace maintpol
