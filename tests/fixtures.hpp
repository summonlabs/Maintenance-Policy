#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "harness.hpp"
#include "maintpol/engine.hpp"
#include "maintpol/policy.hpp"
#include "maintpol/request.hpp"
#include "maintpol/store.hpp"
#include "maintpol/text.hpp"

#define MP_CHECK_OUTCOME(decision, expected)                                                     \
    do {                                                                                         \
        const ::maintpol::Decision& mp_outcome = (decision);                                     \
        if (mp_outcome.outcome != (expected)) {                                                  \
            ::maintpol::test::fail(__FILE__, __LINE__,                                           \
                                   std::string("expected outcome ") +                            \
                                       std::string(::maintpol::to_string(expected)) + " but got " + \
                                       ::maintpol::test::describe_decision(mp_outcome));         \
        }                                                                                        \
    } while (false)

namespace maintpol::test {

// ---------------------------------------------------------------------------
// Shared fixture builders. Every test composes the smallest policy, bundle and
// request it needs so that failures stay attributable.
// ---------------------------------------------------------------------------
Instant instant(const std::string& text);
Duration duration(const std::string& text);
Digest256 digest_of(const std::string& text);

AuthorityKey make_key(const std::string& id, std::uint8_t fill = 0x42);
void sign_exception(ExceptionRecord& record, const AuthorityKey& key);
void sign_approval(ApprovalRecord& record, const AuthorityKey& key);
// Sets the validity window of a signed record and re-signs it, so that the
// issue time, the validity start and the expiry stay consistent.
void set_exception_validity(ExceptionRecord& record, const std::string& issued_at, const std::string& not_before,
                            const std::string& expires_at, const AuthorityKey& key);
void set_approval_validity(ApprovalRecord& record, const std::string& issued_at, const std::string& not_before,
                           const std::string& expires_at, const AuthorityKey& key);

PolicySettings default_settings();
RuleHeader make_header(const std::string& id, const std::string& scope, std::uint32_t priority = 100);
RuleHeader make_class_header(const std::string& id, const std::string& scope, const std::string& obligation_class,
                             std::uint32_t priority = 100);

BlackoutRule blackout_rule(const std::string& id, const std::string& scope, const std::string& start,
                           const std::string& end, bool waivable = true, bool all_classes = true);
BlackoutRule recurring_blackout_rule(const std::string& id, const std::string& scope, const std::string& origin,
                                     RecurrenceKind kind, std::uint32_t count, const std::string& start_offset,
                                     const std::string& window_length);
RedundancyRule redundancy_rule(const std::string& id, const std::string& scope, const std::string& obligation_class,
                               std::uint32_t minimum_survivors, bool waivable = false);
ProtectedClassRule protected_class_rule(const std::string& id, const std::string& scope,
                                        const std::string& obligation_class, bool with_window,
                                        const std::string& start = "2026-03-01T00:00:00Z",
                                        const std::string& end = "2026-03-01T06:00:00Z");
EscalationRule escalation_rule(const std::string& id, const std::string& scope, std::uint32_t required_level,
                               bool on_exception_used = false, bool on_redundancy_waiver = false);
EscalationRule escalation_rule_with_window(const std::string& id, const std::string& scope,
                                           std::uint32_t required_level, const std::string& min_window);
HardInterlockRule hard_interlock_rule(const std::string& id, const std::string& scope, const std::string& interlock);
SoftConstraintRule soft_constraint_rule(const std::string& id, const std::string& scope, std::uint32_t max_concurrent,
                                         bool waivable = true);

Policy make_policy(std::vector<Rule> rules, PolicyGeneration generation = PolicyGeneration::from_value(1).value(),
                   PolicySettings settings = default_settings(),
                   PolicyLifecycle lifecycle = PolicyLifecycle::Published);
PolicyBundle bundle_for_generation(std::uint64_t generation, std::uint64_t control_epoch,
                                  std::uint64_t registry_revision);

PolicyBundle make_bundle(Policy policy, std::vector<AuthorityRecord> authorities = {},
                         std::vector<ExceptionRecord> exceptions = {}, std::vector<ApprovalRecord> approvals = {},
                         ControlEpoch control_epoch = ControlEpoch::from_value(1).value(),
                         Revision registry_revision = Revision::from_value(1).value());

ExceptionRecord make_exception(const std::string& id, const PolicyBundle& bundle, const AuthorityKey& key,
                               std::vector<std::string> relaxed_rules, const std::string& scope = "FAC-1/*",
                               bool all_classes = true, const std::string& not_before = "2026-02-01T00:00:00Z",
                               const std::string& expires_at = "2026-04-01T00:00:00Z");

ApprovalRecord make_approval(const std::string& id, const PolicyBundle& bundle, const AuthorityKey& key,
                             const std::string& request_digest, std::uint32_t level,
                             const std::string& scope = "FAC-1/*", bool all_classes = true,
                             const std::string& not_before = "2026-02-01T00:00:00Z",
                             const std::string& expires_at = "2026-04-01T00:00:00Z");

struct EvidenceSpec {
    std::string obligation_class = "power";
    std::string state = "measured";
    std::uint32_t surviving_units = 3;
    std::uint32_t total_units = 4;
    std::string observed_at = "2026-03-01T00:00:00Z";
};

struct RequestSpec {
    std::string context_id = "ctx-1";
    std::string request_id = "req-1";
    std::vector<std::string> scopes = {"FAC-1/fabric"};
    std::vector<std::string> classes = {"power"};
    std::string window_start = "2026-03-01T01:00:00Z";
    std::string window_end = "2026-03-01T02:00:00Z";
    std::string requested_by = "operator-1";
    std::uint64_t expected_generation = 1;
    std::string expected_policy_digest;
    std::vector<std::string> exceptions;
    std::vector<std::string> approvals;
    bool include_evidence = true;
    std::string evidence_source = "telemetry-1";
    std::uint64_t evidence_epoch = 10;
    std::string evidence_observed_at = "2026-03-01T00:00:00Z";
    std::vector<EvidenceSpec> evidence_classes = {EvidenceSpec{}};
    bool include_interlocks = true;
    std::string interlock_source = "telemetry-1";
    std::uint64_t interlock_epoch = 10;
    std::string interlock_observed_at = "2026-03-01T00:00:00Z";
    std::vector<std::pair<std::string, bool>> interlocks;
    std::uint32_t concurrent_maintenance = 0;
    std::string evaluated_at = "2026-03-01T00:30:00Z";
};

// Builds the request, returning the first validation error instead of failing.
Result<EvaluationRequest> build_request_result(const RequestSpec& spec);
EvaluationRequest build_request(const RequestSpec& spec);
std::string request_document(const RequestSpec& spec);

// Human readable summary of a decision, used in test failure messages.
std::string describe_decision(const Decision& decision);

// Runs one evaluation over the fixture pair and returns the decision.
Decision evaluate_spec(const PolicyBundle& bundle, const KeySet& keys, const RequestSpec& spec,
                       const std::vector<PriorDecisionRecord>& prior = {});

}  // namespace maintpol::test
