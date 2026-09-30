#include "maintpol/policy.hpp"

#include <algorithm>

#include "maintpol/text.hpp"

namespace maintpol {
namespace {

constexpr std::int64_t kNanosPerDay = 86400000000000LL;

Result<void> validate_rule_header(const RuleHeader& header) {
    if (!header.id.is_set()) {
        return make_error(Code::RuleInvalid, "rule identifier is unset");
    }
    if (header.priority > kMaxRulePriority) {
        return make_error(Code::PriorityOutOfRange, "rule priority exceeds 1000000");
    }
    if (!header.scope.is_set()) {
        return make_error(Code::ScopeInvalid, "rule scope selector is unset");
    }
    if (!header.classes.all) {
        if (header.classes.classes.empty()) {
            return make_error(Code::SelectorInvalid, "class selector must be '*' or a non-empty class list");
        }
        if (header.classes.classes.size() > kMaxClassesPerSelector) {
            return make_error(Code::TooManyItems, "class selector exceeds 64 classes");
        }
        std::vector<ObligationClassId> sorted = header.classes.classes;
        std::sort(sorted.begin(), sorted.end());
        if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
            return make_error(Code::DuplicateIdentifier, "class selector repeats an obligation class");
        }
    }
    if (header.description.size() > kMaxDescriptionLength) {
        return make_error(Code::TextTooLong, "rule description exceeds 256 bytes");
    }
    auto description = validate_description(header.description);
    if (!description) {
        return description.error();
    }
    return {};
}

Result<void> validate_windows(const std::vector<Interval>& windows) {
    if (windows.size() > kMaxRulesPerPolicy) {
        return make_error(Code::TooManyItems, "blackout rule declares too many windows");
    }
    for (const Interval& window : windows) {
        if (window.end <= window.start) {
            return make_error(Code::IntervalReversed, "blackout window end must be after its start");
        }
    }
    return {};
}

// Validates a rule and normalises its stored windows in place.
Result<void> validate_rule(Rule& rule) {
    const RuleHeader& header = rule_header_of(rule);
    auto header_result = validate_rule_header(header);
    if (!header_result) {
        return header_result.error();
    }
    if (auto* blackout = std::get_if<BlackoutRule>(&rule)) {
        auto windows_result = validate_windows(blackout->windows);
        if (!windows_result) {
            return windows_result.error();
        }
        if (blackout->recurrence.has_value()) {
            auto recurrence_result = validate_recurrence(blackout->recurrence.value());
            if (!recurrence_result) {
                return recurrence_result.error();
            }
            auto expanded = expand_recurrence(blackout->recurrence.value());
            if (!expanded) {
                return expanded.error();
            }
            std::vector<Interval> all = blackout->windows;
            all.insert(all.end(), expanded.value().begin(), expanded.value().end());
            auto all_result = validate_windows(all);
            if (!all_result) {
                return all_result.error();
            }
            if (all.empty()) {
                return make_error(Code::RecurrenceInvalid, "blackout rule declares no window");
            }
        } else if (blackout->windows.empty()) {
            return make_error(Code::RuleInvalid, "blackout rule declares neither a window nor a recurrence");
        }
        normalise_intervals(blackout->windows);
        return {};
    }
    if (const auto* redundancy = std::get_if<RedundancyRule>(&rule)) {
        if (redundancy->minimum_survivors == 0) {
            return make_error(Code::ThresholdInvalid, "redundancy floor must be at least one surviving unit");
        }
        if (redundancy->minimum_survivors > 1000000u) {
            return make_error(Code::ThresholdInvalid, "redundancy floor exceeds 1000000 units");
        }
        return {};
    }
    if (const auto* protected_class = std::get_if<ProtectedClassRule>(&rule)) {
        if (protected_class->header.classes.all) {
            return make_error(Code::SelectorInvalid, "a protected-class rule must name explicit classes");
        }
        if (protected_class->window.has_value() && protected_class->window->end <= protected_class->window->start) {
            return make_error(Code::IntervalReversed, "protected-class window end must be after its start");
        }
        return {};
    }
    if (const auto* escalation = std::get_if<EscalationRule>(&rule)) {
        if (!escalation->required_level.is_set()) {
            return make_error(Code::RuleInvalid, "escalation rule declares no required authority level");
        }
        return {};
    }
    if (const auto* interlock = std::get_if<HardInterlockRule>(&rule)) {
        if (!interlock->interlock.is_set()) {
            return make_error(Code::RuleInvalid, "hard interlock rule declares no interlock identity");
        }
        return {};
    }
    if (const auto* soft = std::get_if<SoftConstraintRule>(&rule)) {
        if (soft->max_concurrent == 0 && !soft->max_window.has_value()) {
            return make_error(Code::RuleInvalid, "soft constraint rule declares no constraint");
        }
        if (soft->max_window.has_value() && soft->max_window->is_zero()) {
            return make_error(Code::ThresholdInvalid, "soft constraint window must be greater than zero");
        }
        return {};
    }
    return make_error(Code::RuleInvalid, "rule kind is not recognised");
}

}  // namespace

std::string_view to_string(RecurrenceKind kind) {
    switch (kind) {
        case RecurrenceKind::None: return "none";
        case RecurrenceKind::Daily: return "daily";
        case RecurrenceKind::Weekly: return "weekly";
        case RecurrenceKind::Monthly: return "monthly";
    }
    return "unknown";
}

bool recurrence_kind_from_name(std::string_view name, RecurrenceKind& out) {
    if (name == "none") { out = RecurrenceKind::None; return true; }
    if (name == "daily") { out = RecurrenceKind::Daily; return true; }
    if (name == "weekly") { out = RecurrenceKind::Weekly; return true; }
    if (name == "monthly") { out = RecurrenceKind::Monthly; return true; }
    return false;
}

Result<void> validate_recurrence(const Recurrence& recurrence) {
    if (recurrence.kind == RecurrenceKind::None) {
        return make_error(Code::RecurrenceInvalid, "recurrence kind is 'none'");
    }
    if (recurrence.count == 0 || recurrence.count > kMaxRecurrenceOccurrences) {
        return make_error(Code::RecurrenceUnbounded, "recurrence count must be between 1 and 512");
    }
    if (recurrence.duration.is_zero()) {
        return make_error(Code::RecurrenceInvalid, "recurrence window duration must be greater than zero");
    }
    if (recurrence.offset_minutes < -ZoneOffset::kMaxMinutes || recurrence.offset_minutes > ZoneOffset::kMaxMinutes) {
        return make_error(Code::OffsetOutOfRange, "recurrence offset must be within -18:00..+18:00");
    }
    if (recurrence.kind == RecurrenceKind::Weekly && recurrence.weekday > 6) {
        return make_error(Code::RecurrenceInvalid, "weekly recurrence weekday must be between 0 and 6");
    }
    if (recurrence.kind == RecurrenceKind::Monthly &&
        (recurrence.day_of_month < 1 || recurrence.day_of_month > 31)) {
        return make_error(Code::RecurrenceInvalid, "monthly recurrence day must be between 1 and 31");
    }
    auto total = recurrence.start_offset.add(recurrence.duration);
    if (!total) {
        return total.error();
    }
    if (total.value().nanos() > static_cast<std::uint64_t>(3650LL * kNanosPerDay)) {
        return make_error(Code::DurationTooLong, "recurrence window exceeds ten years");
    }
    return {};
}

Result<std::vector<Interval>> expand_recurrence(const Recurrence& recurrence) {
    auto valid = validate_recurrence(recurrence);
    if (!valid) {
        return valid.error();
    }
    auto offset = ZoneOffset::from_minutes(static_cast<int>(recurrence.offset_minutes));
    if (!offset) {
        return offset.error();
    }
    auto origin_civil = recurrence.origin.to_civil();
    if (!origin_civil) {
        return origin_civil.error();
    }

    const std::int64_t origin_days = days_from_civil(origin_civil.value().year, origin_civil.value().month,
                                                     origin_civil.value().day);
    unsigned origin_weekday = 0;
    {
        // 1970-01-01 was a Thursday (index 3 with Monday == 0).
        std::int64_t shifted = (origin_days + 3) % 7;
        if (shifted < 0) {
            shifted += 7;
        }
        origin_weekday = static_cast<unsigned>(shifted);
    }

    std::vector<Interval> windows;
    windows.reserve(recurrence.count);
    for (std::uint32_t index = 0; index < recurrence.count; ++index) {
        std::int64_t period_days = 0;
        if (recurrence.kind == RecurrenceKind::Daily) {
            period_days = origin_days + static_cast<std::int64_t>(index);
        } else if (recurrence.kind == RecurrenceKind::Weekly) {
            const std::int64_t week_start = origin_days - static_cast<std::int64_t>(origin_weekday);
            period_days = week_start + (static_cast<std::int64_t>(index) * 7) +
                          static_cast<std::int64_t>(recurrence.weekday);
        } else {
            const std::int64_t month_index = static_cast<std::int64_t>(origin_civil.value().month) - 1 +
                                             static_cast<std::int64_t>(index);
            const std::int64_t year = static_cast<std::int64_t>(origin_civil.value().year) + (month_index / 12);
            const std::int64_t month = (month_index % 12) + 1;
            if (year < 1 || year > 9999) {
                return make_error(Code::TimestampOutOfRange, "recurrence expands beyond the civil year range");
            }
            const unsigned limit = days_in_month(static_cast<int>(year), static_cast<unsigned>(month));
            if (recurrence.day_of_month > limit) {
                continue;  // This period has no such day; the period yields no window.
            }
            period_days = days_from_civil(static_cast<int>(year), static_cast<unsigned>(month),
                                          recurrence.day_of_month);
        }

        CivilTime window_start_civil = civil_from_days(period_days);
        window_start_civil.hour = 0;
        window_start_civil.minute = 0;
        window_start_civil.second = 0;
        window_start_civil.nanosecond = 0;
        auto period_start = Instant::from_civil_with_offset(window_start_civil, offset.value());
        if (!period_start) {
            return period_start.error();
        }
        auto start = period_start.value().add(recurrence.start_offset);
        if (!start) {
            return start.error();
        }
        auto end = start.value().add(recurrence.duration);
        if (!end) {
            return end.error();
        }
        windows.push_back(Interval{start.value(), end.value()});
    }
    return windows;
}

void normalise_intervals(std::vector<Interval>& windows) {
    std::sort(windows.begin(), windows.end(), [](const Interval& left, const Interval& right) {
        if (left.start != right.start) {
            return left.start < right.start;
        }
        return left.end < right.end;
    });
    std::vector<Interval> merged;
    merged.reserve(windows.size());
    for (const Interval& window : windows) {
        if (!merged.empty() && window.start <= merged.back().end) {
            if (window.end > merged.back().end) {
                merged.back().end = window.end;
            }
            continue;
        }
        merged.push_back(window);
    }
    windows = std::move(merged);
}

Result<Interval> make_interval(const Instant& start, const Instant& end) {
    if (end <= start) {
        return make_error(Code::IntervalReversed, "interval end must be strictly after its start");
    }
    return Interval{start, end};
}

Result<std::vector<Interval>> blackout_windows(const BlackoutRule& rule) {
    std::vector<Interval> windows = rule.windows;
    if (rule.recurrence.has_value()) {
        auto expanded = expand_recurrence(rule.recurrence.value());
        if (!expanded) {
            return expanded.error();
        }
        windows.insert(windows.end(), expanded.value().begin(), expanded.value().end());
    }
    normalise_intervals(windows);
    return windows;
}

Result<Duration> Interval::length() const {
    auto delta = end.difference(start);
    if (!delta) {
        return delta.error();
    }
    if (delta.value().is_negative()) {
        return make_error(Code::IntervalReversed, "interval end must be strictly after its start");
    }
    return Duration::from_nanos(static_cast<std::uint64_t>(delta.value().nanos()));
}

std::string_view to_string(RuleKind kind) {
    switch (kind) {
        case RuleKind::Blackout: return "blackout";
        case RuleKind::Redundancy: return "redundancy";
        case RuleKind::ProtectedClass: return "protected-class";
        case RuleKind::Escalation: return "escalation";
        case RuleKind::HardInterlock: return "hard-interlock";
        case RuleKind::SoftConstraint: return "soft-constraint";
    }
    return "unknown";
}

bool rule_kind_from_name(std::string_view name, RuleKind& out) {
    if (name == "blackout") { out = RuleKind::Blackout; return true; }
    if (name == "redundancy") { out = RuleKind::Redundancy; return true; }
    if (name == "protected-class") { out = RuleKind::ProtectedClass; return true; }
    if (name == "escalation") { out = RuleKind::Escalation; return true; }
    if (name == "hard-interlock") { out = RuleKind::HardInterlock; return true; }
    if (name == "soft-constraint") { out = RuleKind::SoftConstraint; return true; }
    return false;
}

bool rule_kind_is_never_waivable(RuleKind kind) {
    return kind == RuleKind::HardInterlock || kind == RuleKind::ProtectedClass;
}

RuleKind rule_kind_of(const Rule& rule) {
    switch (rule.index()) {
        case 0: return RuleKind::Blackout;
        case 1: return RuleKind::Redundancy;
        case 2: return RuleKind::ProtectedClass;
        case 3: return RuleKind::Escalation;
        case 4: return RuleKind::HardInterlock;
        case 5: return RuleKind::SoftConstraint;
        default: return RuleKind::Blackout;
    }
}

const RuleHeader& rule_header_of(const Rule& rule) {
    return std::visit([](const auto& concrete) -> const RuleHeader& { return concrete.header; }, rule);
}

bool rule_is_waivable(const Rule& rule) {
    const RuleKind kind = rule_kind_of(rule);
    if (rule_kind_is_never_waivable(kind)) {
        return false;
    }
    switch (kind) {
        case RuleKind::Blackout: return std::get<BlackoutRule>(rule).waivable;
        case RuleKind::Redundancy: return std::get<RedundancyRule>(rule).waivable;
        case RuleKind::SoftConstraint: return std::get<SoftConstraintRule>(rule).waivable;
        default: return false;
    }
}

std::string rule_order_key(const Rule& rule) {
    const RuleHeader& header = rule_header_of(rule);
    std::string key;
    key.reserve(32);
    key.append(std::to_string(header.priority));
    key.push_back('|');
    key.append(std::to_string(static_cast<unsigned>(rule_kind_of(rule))));
    key.push_back('|');
    key.append(header.id.value());
    return key;
}

bool rule_order_less(const Rule& left, const Rule& right) {
    const RuleHeader& left_header = rule_header_of(left);
    const RuleHeader& right_header = rule_header_of(right);
    if (left_header.priority != right_header.priority) {
        return left_header.priority < right_header.priority;
    }
    const auto left_kind = static_cast<unsigned>(rule_kind_of(left));
    const auto right_kind = static_cast<unsigned>(rule_kind_of(right));
    if (left_kind != right_kind) {
        return left_kind < right_kind;
    }
    return left_header.id < right_header.id;
}

std::string_view to_string(PolicyLifecycle lifecycle) {
    switch (lifecycle) {
        case PolicyLifecycle::Draft: return "draft";
        case PolicyLifecycle::Published: return "published";
        case PolicyLifecycle::Superseded: return "superseded";
        case PolicyLifecycle::Revoked: return "revoked";
    }
    return "unknown";
}

bool policy_lifecycle_from_name(std::string_view name, PolicyLifecycle& out) {
    if (name == "draft") { out = PolicyLifecycle::Draft; return true; }
    if (name == "published") { out = PolicyLifecycle::Published; return true; }
    if (name == "superseded") { out = PolicyLifecycle::Superseded; return true; }
    if (name == "revoked") { out = PolicyLifecycle::Revoked; return true; }
    return false;
}

bool policy_lifecycle_transition_allowed(PolicyLifecycle from, PolicyLifecycle to) {
    switch (from) {
        case PolicyLifecycle::Draft:
            return to == PolicyLifecycle::Published || to == PolicyLifecycle::Revoked;
        case PolicyLifecycle::Published:
            return to == PolicyLifecycle::Superseded || to == PolicyLifecycle::Revoked;
        case PolicyLifecycle::Superseded:
            return to == PolicyLifecycle::Revoked;
        case PolicyLifecycle::Revoked:
            return false;
    }
    return false;
}

Result<Policy> Policy::create(PolicyId id, PolicyGeneration generation, Revision revision,
                              PolicyLifecycle lifecycle, Instant published_at, PolicySettings settings,
                              std::vector<Rule> rules) {
    if (!id.is_set()) {
        return make_error(Code::PolicyEmpty, "policy identifier is unset");
    }
    if (!generation.is_set()) {
        return make_error(Code::PolicyEmpty, "policy generation is unset");
    }
    if (!revision.is_set()) {
        return make_error(Code::PolicyEmpty, "policy revision is unset");
    }
    if (rules.empty()) {
        return make_error(Code::PolicyEmpty, "policy declares no rules");
    }
    if (rules.size() > kMaxRulesPerPolicy) {
        return make_error(Code::TooManyItems, "policy exceeds 4096 rules");
    }
    if (!settings.evidence_max_age.nanos()) {
        return make_error(Code::PolicyEmpty, "policy must declare a non-zero evidence maximum age");
    }
    if (settings.evidence_max_age.nanos() > static_cast<std::uint64_t>(3650LL * kNanosPerDay)) {
        return make_error(Code::DurationTooLong, "evidence maximum age exceeds ten years");
    }
    if (settings.max_window.is_zero()) {
        return make_error(Code::PolicyEmpty, "policy must declare a non-zero maximum maintenance window");
    }
    if (!settings.min_waiver_level.is_set()) {
        return make_error(Code::PolicyEmpty, "policy must declare the minimum waiver authority level");
    }
    if (settings.max_recurrence_count == 0 || settings.max_recurrence_count > kMaxRecurrenceOccurrences) {
        return make_error(Code::RecurrenceUnbounded, "policy maximum recurrence count must be between 1 and 512");
    }
    if (settings.evidence_sources.size() > kMaxEvidenceSources) {
        return make_error(Code::TooManyItems, "policy declares more than 32 trusted evidence sources");
    }
    {
        std::vector<EvidenceSourceId> sources = settings.evidence_sources;
        std::sort(sources.begin(), sources.end());
        if (std::adjacent_find(sources.begin(), sources.end()) != sources.end()) {
            return make_error(Code::DuplicateIdentifier, "policy repeats a trusted evidence source");
        }
        for (const EvidenceSourceId& source : settings.evidence_sources) {
            if (!source.is_set()) {
                return make_error(Code::ValueMalformed, "policy declares an unset evidence source");
            }
        }
    }

    std::vector<Rule> normalised = rules;
    for (Rule& rule : normalised) {
        auto rule_result = validate_rule(rule);
        if (!rule_result) {
            return rule_result.error();
        }
    }

    std::vector<Rule> sorted = std::move(normalised);
    std::sort(sorted.begin(), sorted.end(), rule_order_less);
    for (std::size_t index = 1; index < sorted.size(); ++index) {
        if (rule_header_of(sorted[index - 1]).id == rule_header_of(sorted[index]).id) {
            return make_error(Code::RuleIdConflict, "two rules share the identifier '" +
                                                        rule_header_of(sorted[index]).id.value() + "'");
        }
    }

    Policy policy;
    policy.id_ = std::move(id);
    policy.generation_ = generation;
    policy.revision_ = revision;
    policy.lifecycle_ = lifecycle;
    policy.published_at_ = published_at;
    policy.settings_ = settings;
    policy.rules_ = std::move(sorted);
    return policy;
}

const AuthorityRecord* PolicyBundle::find_authority(const AuthorityId& id) const {
    for (const AuthorityRecord& record : authorities_) {
        if (record.id == id) {
            return &record;
        }
    }
    return nullptr;
}

const ExceptionRecord* PolicyBundle::find_exception(const ExceptionId& id) const {
    for (const ExceptionRecord& record : exceptions_) {
        if (record.id == id) {
            return &record;
        }
    }
    return nullptr;
}

const ApprovalRecord* PolicyBundle::find_approval(const ApprovalId& id) const {
    for (const ApprovalRecord& record : approvals_) {
        if (record.id == id) {
            return &record;
        }
    }
    return nullptr;
}

Result<PolicyBundle> PolicyBundle::create(Policy policy, std::vector<AuthorityRecord> authorities,
                                          std::vector<ExceptionRecord> exceptions,
                                          std::vector<ApprovalRecord> approvals, ControlEpoch control_epoch,
                                          Revision registry_revision) {
    if (!control_epoch.is_set()) {
        return make_error(Code::ValueOutOfRange, "bundle control epoch is unset");
    }
    if (!registry_revision.is_set()) {
        return make_error(Code::ValueOutOfRange, "bundle registry revision is unset");
    }
    if (authorities.size() > kMaxAuthoritiesPerPolicy) {
        return make_error(Code::TooManyItems, "bundle exceeds 64 authorities");
    }
    if (exceptions.size() > kMaxExceptionsPerBundle) {
        return make_error(Code::TooManyItems, "bundle exceeds 1024 exceptions");
    }
    if (approvals.size() > kMaxApprovalsPerBundle) {
        return make_error(Code::TooManyItems, "bundle exceeds 4096 approvals");
    }

    std::vector<AuthorityId> authority_ids;
    authority_ids.reserve(authorities.size());
    for (const AuthorityRecord& record : authorities) {
        if (!record.id.is_set()) {
            return make_error(Code::ValueMalformed, "authority identifier is unset");
        }
        if (!record.level.is_set()) {
            return make_error(Code::ValueOutOfRange, "authority level is unset");
        }
        auto description = validate_description(record.description);
        if (!description) {
            return description.error();
        }
        authority_ids.push_back(record.id);
    }
    std::sort(authority_ids.begin(), authority_ids.end());
    if (std::adjacent_find(authority_ids.begin(), authority_ids.end()) != authority_ids.end()) {
        return make_error(Code::DuplicateIdentifier, "bundle declares the same authority twice");
    }

    std::vector<ExceptionId> exception_ids;
    exception_ids.reserve(exceptions.size());
    for (const ExceptionRecord& record : exceptions) {
        if (!record.id.is_set() || !record.issued_by.is_set() || !record.key_id.is_set()) {
            return make_error(Code::ValueMalformed, "exception identity, issuer and key must all be set");
        }
        if (!record.generation.is_set()) {
            return make_error(Code::ValueOutOfRange, "exception policy generation is unset");
        }
        if (record.policy_digest.is_zero()) {
            return make_error(Code::ValueMalformed, "exception policy digest is unset");
        }
        if (record.relaxed_rules.empty()) {
            return make_error(Code::SelectorInvalid, "exception must name at least one relaxed rule");
        }
        if (record.relaxed_rules.size() > kMaxReferenceListLength) {
            return make_error(Code::TooManyItems, "exception names too many relaxed rules");
        }
        std::vector<RuleId> sorted_rules = record.relaxed_rules;
        std::sort(sorted_rules.begin(), sorted_rules.end());
        if (std::adjacent_find(sorted_rules.begin(), sorted_rules.end()) != sorted_rules.end()) {
            return make_error(Code::DuplicateIdentifier, "exception repeats a relaxed rule");
        }
        if (!record.scope.is_set() || record.scope.facility().empty()) {
            return make_error(Code::ScopeInvalid, "exception scope is unset");
        }
        if (record.expires_at <= record.not_before) {
            return make_error(Code::IntervalReversed, "exception expiry must be after its validity start");
        }
        if (record.issued_at > record.not_before) {
            return make_error(Code::IntervalReversed, "exception issue time must not be after its validity start");
        }
        if (record.revoked_at.has_value() && record.revoked_at.value() < record.issued_at) {
            return make_error(Code::IntervalReversed, "exception revocation must not precede its issue time");
        }
        if (!record.classes.all && record.classes.classes.empty()) {
            return make_error(Code::SelectorInvalid, "exception class selector must be '*' or a non-empty list");
        }
        auto reason = validate_description(record.reason);
        if (!reason) {
            return reason.error();
        }
        exception_ids.push_back(record.id);
    }
    std::sort(exception_ids.begin(), exception_ids.end());
    if (std::adjacent_find(exception_ids.begin(), exception_ids.end()) != exception_ids.end()) {
        return make_error(Code::DuplicateIdentifier, "bundle declares the same exception twice");
    }

    std::vector<ApprovalId> approval_ids;
    approval_ids.reserve(approvals.size());
    for (const ApprovalRecord& record : approvals) {
        if (!record.id.is_set() || !record.issued_by.is_set() || !record.key_id.is_set()) {
            return make_error(Code::ValueMalformed, "approval identity, issuer and key must all be set");
        }
        if (!record.generation.is_set() || !record.level.is_set()) {
            return make_error(Code::ValueOutOfRange, "approval generation and level must be set");
        }
        if (record.policy_digest.is_zero() || record.bound_request_digest.is_zero()) {
            return make_error(Code::ValueMalformed, "approval digests must be set");
        }
        if (!record.scope.is_set()) {
            return make_error(Code::ScopeInvalid, "approval scope is unset");
        }
        if (record.expires_at <= record.not_before) {
            return make_error(Code::IntervalReversed, "approval expiry must be after its validity start");
        }
        if (record.issued_at > record.not_before) {
            return make_error(Code::IntervalReversed, "approval issue time must not be after its validity start");
        }
        if (record.revoked_at.has_value() && record.revoked_at.value() < record.issued_at) {
            return make_error(Code::IntervalReversed, "approval revocation must not precede its issue time");
        }
        if (!record.classes.all && record.classes.classes.empty()) {
            return make_error(Code::SelectorInvalid, "approval class selector must be '*' or a non-empty list");
        }
        approval_ids.push_back(record.id);
    }
    std::sort(approval_ids.begin(), approval_ids.end());
    if (std::adjacent_find(approval_ids.begin(), approval_ids.end()) != approval_ids.end()) {
        return make_error(Code::DuplicateIdentifier, "bundle declares the same approval twice");
    }

    PolicyBundle bundle;
    bundle.policy_ = std::move(policy);
    bundle.authorities_ = std::move(authorities);
    bundle.exceptions_ = std::move(exceptions);
    bundle.approvals_ = std::move(approvals);
    bundle.control_epoch_ = control_epoch;
    bundle.registry_revision_ = registry_revision;
    return bundle;
}

Result<PolicyBundle> PolicyBundle::with_epochs(ControlEpoch control_epoch, Revision registry_revision) const {
    return PolicyBundle::create(policy_, authorities_, exceptions_, approvals_, control_epoch, registry_revision);
}

Result<KeySet> KeySet::create(std::vector<AuthorityKey> keys) {
    if (keys.size() > 64) {
        return make_error(Code::TooManyItems, "key set exceeds 64 keys");
    }
    std::vector<KeyId> ids;
    ids.reserve(keys.size());
    for (const AuthorityKey& key : keys) {
        if (!key.id.is_set()) {
            return make_error(Code::KeyMalformed, "key identifier is unset");
        }
        if (key.secret.size() < kMinKeyBytes || key.secret.size() > kMaxKeyBytes) {
            return make_error(Code::KeyMalformed, "key material must be between 16 and 64 bytes");
        }
        ids.push_back(key.id);
    }
    std::sort(ids.begin(), ids.end());
    if (std::adjacent_find(ids.begin(), ids.end()) != ids.end()) {
        return make_error(Code::DuplicateIdentifier, "key set declares the same key twice");
    }
    KeySet set;
    set.keys_ = std::move(keys);
    return set;
}

const AuthorityKey* KeySet::find(const KeyId& id) const {
    for (const AuthorityKey& key : keys_) {
        if (key.id == id) {
            return &key;
        }
    }
    return nullptr;
}

}  // namespace maintpol
