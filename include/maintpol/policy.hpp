#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "maintpol/digest.hpp"
#include "maintpol/error.hpp"
#include "maintpol/time.hpp"
#include "maintpol/types.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Half-open time interval [start, end). A zero length interval is invalid:
// start must be strictly before end.
// ---------------------------------------------------------------------------
struct Interval {
    Instant start;
    Instant end;

    bool contains(const Instant& instant) const { return instant >= start && instant < end; }
    // True when the half-open intervals share at least one instant.
    bool intersects(const Interval& other) const { return start < other.end && other.start < end; }
    Result<Duration> length() const;

    friend bool operator==(const Interval&, const Interval&) = default;
};

MAINTPOL_API Result<Interval> make_interval(const Instant& start, const Instant& end);

// ---------------------------------------------------------------------------
// Bounded deterministic recurrence. A recurrence names a first period, a
// fixed UTC offset used to interpret local civil time, a per-period window
// start offset and window length, and a period count bounded by
// kMaxRecurrenceOccurrences. There is no unbounded calendar language:
// the expansion is a bounded list computed by expand_recurrence().
//
//   Daily    period i starts at civil date(origin) + i days
//   Weekly   period i starts at the Monday of the origin week + i weeks,
//            and the occurrence falls on 'weekday' of that week
//   Monthly  period i is calendar month(origin) + i months, and the
//            occurrence falls on 'day_of_month'; a month that does not
//            contain that day yields no window for that period
//
// In every case the window starts at period_date + start_offset (local civil
// time interpreted with offset_minutes) and lasts 'duration'.
// ---------------------------------------------------------------------------
enum class RecurrenceKind : std::uint8_t { None = 0, Daily = 1, Weekly = 2, Monthly = 3 };

MAINTPOL_API std::string_view to_string(RecurrenceKind kind);
MAINTPOL_API bool recurrence_kind_from_name(std::string_view name, RecurrenceKind& out);

struct Recurrence {
    RecurrenceKind kind = RecurrenceKind::None;
    Instant origin;
    std::int32_t offset_minutes = 0;
    unsigned weekday = 0;
    unsigned day_of_month = 0;
    Duration start_offset;
    Duration duration;
    std::uint32_t count = 0;

    friend bool operator==(const Recurrence&, const Recurrence&) = default;
};

MAINTPOL_API Result<void> validate_recurrence(const Recurrence& recurrence);
// Expands a validated recurrence into its bounded occurrence list.
MAINTPOL_API Result<std::vector<Interval>> expand_recurrence(const Recurrence& recurrence);
// Sorts and merges intervals so that overlapping blackout periods collapse into
// a minimal canonical set. Merging is idempotent, which is what makes the
// canonical form of a policy stable across a serialisation round trip.
MAINTPOL_API void normalise_intervals(std::vector<Interval>& windows);

// ---------------------------------------------------------------------------
// Rules.
// ---------------------------------------------------------------------------
enum class RuleKind : std::uint8_t {
    Blackout = 1,
    Redundancy = 2,
    ProtectedClass = 3,
    Escalation = 4,
    HardInterlock = 5,
    SoftConstraint = 6,
};

MAINTPOL_API std::string_view to_string(RuleKind kind);
MAINTPOL_API bool rule_kind_from_name(std::string_view name, RuleKind& out);
// Hard interlocks and protected-class rules can never be relaxed by an
// exception, whatever a document claims.
MAINTPOL_API bool rule_kind_is_never_waivable(RuleKind kind);

inline constexpr std::uint32_t kMaxRulePriority = 1000000;

struct RuleHeader {
    RuleId id;
    std::uint32_t priority = 1000;
    ScopePath scope;
    ClassSelector classes;
    bool enabled = true;
    std::string description;

    friend bool operator==(const RuleHeader&, const RuleHeader&) = default;
};

struct BlackoutRule {
    RuleHeader header;
    std::vector<Interval> windows;
    std::optional<Recurrence> recurrence;
    bool waivable = true;

    friend bool operator==(const BlackoutRule&, const BlackoutRule&) = default;
};

struct RedundancyRule {
    RuleHeader header;
    std::uint32_t minimum_survivors = 1;
    bool waivable = false;

    friend bool operator==(const RedundancyRule&, const RedundancyRule&) = default;
};

struct ProtectedClassRule {
    RuleHeader header;
    std::optional<Interval> window;

    friend bool operator==(const ProtectedClassRule&, const ProtectedClassRule&) = default;
};

struct EscalationRule {
    RuleHeader header;
    AuthorityLevel required_level;
    std::optional<Duration> min_window;
    bool on_exception_used = false;
    bool on_redundancy_waiver = false;

    friend bool operator==(const EscalationRule&, const EscalationRule&) = default;
};

struct HardInterlockRule {
    RuleHeader header;
    InterlockId interlock;

    friend bool operator==(const HardInterlockRule&, const HardInterlockRule&) = default;
};

struct SoftConstraintRule {
    RuleHeader header;
    std::uint32_t max_concurrent = 0;
    std::optional<Duration> max_window;
    bool waivable = true;

    friend bool operator==(const SoftConstraintRule&, const SoftConstraintRule&) = default;
};

using Rule = std::variant<BlackoutRule, RedundancyRule, ProtectedClassRule, EscalationRule, HardInterlockRule, SoftConstraintRule>;

// The effective windows of a blackout rule: its explicit windows plus the
// bounded expansion of its recurrence, sorted and merged.
MAINTPOL_API Result<std::vector<Interval>> blackout_windows(const BlackoutRule& rule);

MAINTPOL_API RuleKind rule_kind_of(const Rule& rule);
MAINTPOL_API const RuleHeader& rule_header_of(const Rule& rule);
MAINTPOL_API bool rule_is_waivable(const Rule& rule);
// Canonical order key: (priority, kind ordinal, rule id). Evaluation order and
// every serialised list use this key, so results never depend on the order in
// which rules were declared or inserted.
MAINTPOL_API std::string rule_order_key(const Rule& rule);
MAINTPOL_API bool rule_order_less(const Rule& left, const Rule& right);

// ---------------------------------------------------------------------------
// Policy lifecycle. Only Published authorises decisions; every other state is
// a refusal, and Revoked is a denial.
// ---------------------------------------------------------------------------
enum class PolicyLifecycle : std::uint8_t { Draft = 1, Published = 2, Superseded = 3, Revoked = 4 };

MAINTPOL_API std::string_view to_string(PolicyLifecycle lifecycle);
MAINTPOL_API bool policy_lifecycle_from_name(std::string_view name, PolicyLifecycle& out);
MAINTPOL_API bool policy_lifecycle_transition_allowed(PolicyLifecycle from, PolicyLifecycle to);

struct PolicySettings {
    Duration evidence_max_age;
    Duration max_window;
    AuthorityLevel min_waiver_level;
    EvidenceEpoch min_evidence_epoch;
    // Measurement sources this policy trusts. Empty means the policy does not
    // restrict evidence sources; a non-empty list makes any other source a
    // refusal.
    std::vector<EvidenceSourceId> evidence_sources;
    bool require_evidence_for_classes = true;
    std::uint32_t max_recurrence_count = static_cast<std::uint32_t>(kMaxRecurrenceOccurrences);

    friend bool operator==(const PolicySettings&, const PolicySettings&) = default;
};

inline constexpr std::uint32_t kPolicyFormatVersion = 1;

class Policy {
public:
    Policy() = default;

    static Result<Policy> create(PolicyId id, PolicyGeneration generation, Revision revision,
                                 PolicyLifecycle lifecycle, Instant published_at, PolicySettings settings,
                                 std::vector<Rule> rules);

    const PolicyId& id() const { return id_; }
    PolicyGeneration generation() const { return generation_; }
    Revision revision() const { return revision_; }
    PolicyLifecycle lifecycle() const { return lifecycle_; }
    const Instant& published_at() const { return published_at_; }
    const PolicySettings& settings() const { return settings_; }
    const std::vector<Rule>& rules() const { return rules_; }

    // SHA-256 over the canonical serialisation of this policy. The digest
    // covers exactly the fields that are serialised, including the format and
    // semantics versions.
    Digest256 digest() const;

    bool is_authoritative() const { return lifecycle_ == PolicyLifecycle::Published; }

private:
    PolicyId id_;
    PolicyGeneration generation_;
    Revision revision_;
    PolicyLifecycle lifecycle_ = PolicyLifecycle::Draft;
    Instant published_at_;
    PolicySettings settings_;
    std::vector<Rule> rules_;
};

// ---------------------------------------------------------------------------
// Authority registry: the policy declares which issuers exist and how much
// authority each one holds. An identity that is not declared here cannot grant
// a waiver or an approval.
// ---------------------------------------------------------------------------
struct AuthorityRecord {
    AuthorityId id;
    AuthorityLevel level;
    std::string description;

    friend bool operator==(const AuthorityRecord&, const AuthorityRecord&) = default;
};

// ---------------------------------------------------------------------------
// Exceptions (waivers). An exception relaxes named waivable rules only. It
// binds the policy generation and digest it was issued against, the scope and
// classes it covers, its issuer, its validity window and its revocation
// state. The MAC binds the issuer-signed body; 'use_count' and 'revoked_at'
// are registry state and are excluded from the MAC payload.
// ---------------------------------------------------------------------------
struct ExceptionRecord {
    ExceptionId id;
    PolicyGeneration generation;
    Digest256 policy_digest;
    std::vector<RuleId> relaxed_rules;
    ScopePath scope;
    ClassSelector classes;
    AuthorityId issued_by;
    Instant issued_at;
    Instant not_before;
    Instant expires_at;
    std::string reason;
    std::optional<Instant> revoked_at;
    KeyId key_id;
    Digest256 mac;

    friend bool operator==(const ExceptionRecord&, const ExceptionRecord&) = default;
};

// ---------------------------------------------------------------------------
// Approvals. An approval is bound to the exact request digest it authorises,
// to the policy generation and digest in force when it was issued, and to the
// authority level the escalation requires. A policy change therefore fences
// every outstanding approval.
// ---------------------------------------------------------------------------
struct ApprovalRecord {
    ApprovalId id;
    PolicyGeneration generation;
    Digest256 policy_digest;
    Digest256 bound_request_digest;
    ScopePath scope;
    ClassSelector classes;
    AuthorityId issued_by;
    AuthorityLevel level;
    Instant issued_at;
    Instant not_before;
    Instant expires_at;
    std::string reason;
    std::optional<Instant> revoked_at;
    KeyId key_id;
    Digest256 mac;

    friend bool operator==(const ApprovalRecord&, const ApprovalRecord&) = default;
};

// ---------------------------------------------------------------------------
// Policy bundle: the complete authoritative state used by one evaluation.
// Exceptions and approvals are consumed from this registry, never from the
// request, so a caller cannot grant itself a waiver.
// ---------------------------------------------------------------------------
class PolicyBundle {
public:
    PolicyBundle() = default;

    static Result<PolicyBundle> create(Policy policy, std::vector<AuthorityRecord> authorities,
                                       std::vector<ExceptionRecord> exceptions,
                                       std::vector<ApprovalRecord> approvals, ControlEpoch control_epoch,
                                       Revision registry_revision);

    const Policy& policy() const { return policy_; }
    const std::vector<AuthorityRecord>& authorities() const { return authorities_; }
    const std::vector<ExceptionRecord>& exceptions() const { return exceptions_; }
    const std::vector<ApprovalRecord>& approvals() const { return approvals_; }
    ControlEpoch control_epoch() const { return control_epoch_; }
    Revision registry_revision() const { return registry_revision_; }

    const AuthorityRecord* find_authority(const AuthorityId& id) const;
    const ExceptionRecord* find_exception(const ExceptionId& id) const;
    const ApprovalRecord* find_approval(const ApprovalId& id) const;

    // Rebuilds the same content under a new control epoch and registry
    // revision. The store uses this to advance authority explicitly rather
    // than mutating a bundle in place.
    Result<PolicyBundle> with_epochs(ControlEpoch control_epoch, Revision registry_revision) const;

    // SHA-256 over the canonical serialisation of the whole bundle.
    Digest256 digest() const;

private:
    Policy policy_;
    std::vector<AuthorityRecord> authorities_;
    std::vector<ExceptionRecord> exceptions_;
    std::vector<ApprovalRecord> approvals_;
    ControlEpoch control_epoch_;
    Revision registry_revision_;
};

// ---------------------------------------------------------------------------
// Authority key material. Keys are supplied out of band and are never
// persisted by this runtime. Key material is raw bytes; a secret shorter than
// 16 bytes or longer than 64 bytes is rejected.
// ---------------------------------------------------------------------------
inline constexpr std::size_t kMinKeyBytes = 16;
inline constexpr std::size_t kMaxKeyBytes = 64;

struct AuthorityKey {
    KeyId id;
    std::vector<std::uint8_t> secret;
};

class KeySet {
public:
    KeySet() = default;

    static Result<KeySet> create(std::vector<AuthorityKey> keys);

    const AuthorityKey* find(const KeyId& id) const;
    const std::vector<AuthorityKey>& keys() const { return keys_; }
    bool empty() const { return keys_.empty(); }
    std::size_t size() const { return keys_.size(); }

private:
    std::vector<AuthorityKey> keys_;
};

}  // namespace maintpol
