#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "maintpol/digest.hpp"
#include "maintpol/error.hpp"
#include "maintpol/policy.hpp"
#include "maintpol/time.hpp"
#include "maintpol/types.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Evidence supplied by the systems that own measurement. This runtime never
// measures redundancy; it consumes bounded, attributed evidence and refuses
// when evidence is absent, unmeasured, stale or fenced.
// ---------------------------------------------------------------------------
enum class MeasurementState : std::uint8_t {
    Measured = 1,
    Unmeasured = 2,
    Unavailable = 3,
};

MAINTPOL_API std::string_view to_string(MeasurementState state);
MAINTPOL_API bool measurement_state_from_name(std::string_view name, MeasurementState& out);

struct ClassEvidence {
    ObligationClassId obligation_class;
    MeasurementState state = MeasurementState::Unmeasured;
    std::uint32_t surviving_units = 0;
    std::uint32_t total_units = 0;
    Instant observed_at;
    EvidenceSourceId source;
    EvidenceEpoch epoch;

    friend bool operator==(const ClassEvidence&, const ClassEvidence&) = default;
};

struct EvidenceBundle {
    EvidenceSourceId source;
    EvidenceEpoch epoch;
    Instant observed_at;
    std::vector<ClassEvidence> classes;

    friend bool operator==(const EvidenceBundle&, const EvidenceBundle&) = default;
};

struct InterlockAssertion {
    InterlockId interlock;
    bool active = false;

    friend bool operator==(const InterlockAssertion&, const InterlockAssertion&) = default;
};

// A report is complete for the interlocks it lists: an interlock that is
// absent from the report is unknown, not inactive.
struct InterlockReport {
    EvidenceSourceId source;
    EvidenceEpoch epoch;
    Instant observed_at;
    std::vector<InterlockAssertion> assertions;

    friend bool operator==(const InterlockReport&, const InterlockReport&) = default;
};

// ---------------------------------------------------------------------------
// A maintenance request. The request references authority records by identity
// only; waivers and approvals are always resolved against the authoritative
// registry, so a request can never carry its own grant.
// ---------------------------------------------------------------------------
class EvaluationRequest {
public:
    EvaluationRequest() = default;

    static Result<EvaluationRequest> create(ContextId context_id, RequestId request_id,
                                            std::vector<ScopePath> scopes,
                                            std::vector<ObligationClassId> classes, Interval window,
                                            PrincipalId requested_by, PolicyGeneration expected_generation,
                                            std::optional<Digest256> expected_policy_digest,
                                            std::vector<ExceptionId> exceptions,
                                            std::vector<ApprovalId> approvals,
                                            std::optional<EvidenceBundle> evidence,
                                            std::optional<InterlockReport> interlocks,
                                            std::uint32_t concurrent_maintenance, Instant evaluated_at);

    const ContextId& context_id() const { return context_id_; }
    const RequestId& request_id() const { return request_id_; }
    const std::vector<ScopePath>& scopes() const { return scopes_; }
    const std::vector<ObligationClassId>& classes() const { return classes_; }
    const Interval& window() const { return window_; }
    const PrincipalId& requested_by() const { return requested_by_; }
    PolicyGeneration expected_generation() const { return expected_generation_; }
    const std::optional<Digest256>& expected_policy_digest() const { return expected_policy_digest_; }
    const std::vector<ExceptionId>& exceptions() const { return exceptions_; }
    const std::vector<ApprovalId>& approvals() const { return approvals_; }
    const std::optional<EvidenceBundle>& evidence() const { return evidence_; }
    const std::optional<InterlockReport>& interlocks() const { return interlocks_; }
    std::uint32_t concurrent_maintenance() const { return concurrent_maintenance_; }
    const Instant& evaluated_at() const { return evaluated_at_; }

    // SHA-256 over the canonical serialisation of the request content. The
    // digest is stable across replays: it excludes nothing that identifies the
    // request and includes nothing that changes between attempts.
    Digest256 digest() const;

private:
    ContextId context_id_;
    RequestId request_id_;
    std::vector<ScopePath> scopes_;
    std::vector<ObligationClassId> classes_;
    Interval window_;
    PrincipalId requested_by_;
    PolicyGeneration expected_generation_;
    std::optional<Digest256> expected_policy_digest_;
    std::vector<ExceptionId> exceptions_;
    std::vector<ApprovalId> approvals_;
    std::optional<EvidenceBundle> evidence_;
    std::optional<InterlockReport> interlocks_;
    std::uint32_t concurrent_maintenance_ = 0;
    Instant evaluated_at_;
};

}  // namespace maintpol
