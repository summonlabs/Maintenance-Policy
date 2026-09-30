#include "fixtures.hpp"

#include <algorithm>
#include <string>

namespace maintpol::test {

Instant instant(const std::string& text) { return MP_REQUIRE(Instant::parse(text)); }

Duration duration(const std::string& text) { return MP_REQUIRE(Duration::parse(text)); }

Digest256 digest_of(const std::string& text) { return sha256(text); }

AuthorityKey make_key(const std::string& id, std::uint8_t fill) {
    AuthorityKey key;
    key.id = MP_REQUIRE(KeyId::parse(id));
    key.secret.assign(32u, fill);
    return key;
}

void sign_exception(ExceptionRecord& record, const AuthorityKey& key) {
    record.key_id = key.id;
    const std::string payload = exception_mac_payload(record);
    const std::string_view secret(reinterpret_cast<const char*>(key.secret.data()), key.secret.size());
    record.mac = hmac_sha256(secret, payload);
}

void sign_approval(ApprovalRecord& record, const AuthorityKey& key) {
    record.key_id = key.id;
    const std::string payload = approval_mac_payload(record);
    const std::string_view secret(reinterpret_cast<const char*>(key.secret.data()), key.secret.size());
    record.mac = hmac_sha256(secret, payload);
}

void set_exception_validity(ExceptionRecord& record, const std::string& issued_at, const std::string& not_before,
                            const std::string& expires_at, const AuthorityKey& key) {
    record.issued_at = instant(issued_at);
    record.not_before = instant(not_before);
    record.expires_at = instant(expires_at);
    sign_exception(record, key);
}

void set_approval_validity(ApprovalRecord& record, const std::string& issued_at, const std::string& not_before,
                           const std::string& expires_at, const AuthorityKey& key) {
    record.issued_at = instant(issued_at);
    record.not_before = instant(not_before);
    record.expires_at = instant(expires_at);
    sign_approval(record, key);
}

PolicySettings default_settings() {
    PolicySettings settings;
    settings.evidence_max_age = duration("PT24H");
    settings.max_window = duration("PT8H");
    settings.min_waiver_level = MP_REQUIRE(AuthorityLevel::from_value(4));
    settings.require_evidence_for_classes = true;
    settings.max_recurrence_count = static_cast<std::uint32_t>(kMaxRecurrenceOccurrences);
    return settings;
}

RuleHeader make_header(const std::string& id, const std::string& scope, std::uint32_t priority) {
    RuleHeader header;
    header.id = MP_REQUIRE(RuleId::parse(id));
    header.priority = priority;
    header.scope = MP_REQUIRE(ScopePath::parse_selector(scope));
    header.classes.all = true;
    header.enabled = true;
    return header;
}

RuleHeader make_class_header(const std::string& id, const std::string& scope, const std::string& obligation_class,
                             std::uint32_t priority) {
    RuleHeader header = make_header(id, scope, priority);
    header.classes.all = false;
    header.classes.classes.push_back(MP_REQUIRE(ObligationClassId::parse(obligation_class)));
    return header;
}

BlackoutRule blackout_rule(const std::string& id, const std::string& scope, const std::string& start,
                           const std::string& end, bool waivable, bool all_classes) {
    BlackoutRule rule;
    rule.header = make_header(id, scope);
    rule.header.classes.all = all_classes;
    rule.windows.push_back(MP_REQUIRE(make_interval(instant(start), instant(end))));
    rule.waivable = waivable;
    return rule;
}

BlackoutRule recurring_blackout_rule(const std::string& id, const std::string& scope, const std::string& origin,
                                     RecurrenceKind kind, std::uint32_t count, const std::string& start_offset,
                                     const std::string& window_length) {
    BlackoutRule rule;
    rule.header = make_header(id, scope);
    Recurrence recurrence;
    recurrence.kind = kind;
    recurrence.origin = instant(origin);
    recurrence.offset_minutes = 0;
    recurrence.weekday = 0;
    recurrence.day_of_month = 1;
    recurrence.start_offset = duration(start_offset);
    recurrence.duration = duration(window_length);
    recurrence.count = count;
    rule.recurrence = recurrence;
    rule.waivable = true;
    return rule;
}

RedundancyRule redundancy_rule(const std::string& id, const std::string& scope, const std::string& obligation_class,
                               std::uint32_t minimum_survivors, bool waivable) {
    RedundancyRule rule;
    rule.header = make_class_header(id, scope, obligation_class);
    rule.minimum_survivors = minimum_survivors;
    rule.waivable = waivable;
    return rule;
}

ProtectedClassRule protected_class_rule(const std::string& id, const std::string& scope,
                                        const std::string& obligation_class, bool with_window, const std::string& start,
                                        const std::string& end) {
    ProtectedClassRule rule;
    rule.header = make_class_header(id, scope, obligation_class);
    if (with_window) {
        rule.window = MP_REQUIRE(make_interval(instant(start), instant(end)));
    }
    return rule;
}

EscalationRule escalation_rule(const std::string& id, const std::string& scope, std::uint32_t required_level,
                               bool on_exception_used, bool on_redundancy_waiver) {
    EscalationRule rule;
    rule.header = make_header(id, scope);
    rule.required_level = MP_REQUIRE(AuthorityLevel::from_value(required_level));
    rule.on_exception_used = on_exception_used;
    rule.on_redundancy_waiver = on_redundancy_waiver;
    return rule;
}

EscalationRule escalation_rule_with_window(const std::string& id, const std::string& scope,
                                           std::uint32_t required_level, const std::string& min_window) {
    EscalationRule rule = escalation_rule(id, scope, required_level);
    rule.min_window = duration(min_window);
    return rule;
}

HardInterlockRule hard_interlock_rule(const std::string& id, const std::string& scope, const std::string& interlock) {
    HardInterlockRule rule;
    rule.header = make_header(id, scope);
    rule.interlock = MP_REQUIRE(InterlockId::parse(interlock));
    return rule;
}

SoftConstraintRule soft_constraint_rule(const std::string& id, const std::string& scope, std::uint32_t max_concurrent,
                                         bool waivable) {
    SoftConstraintRule rule;
    rule.header = make_header(id, scope);
    rule.max_concurrent = max_concurrent;
    rule.waivable = waivable;
    return rule;
}

Policy make_policy(std::vector<Rule> rules, PolicyGeneration generation, PolicySettings settings,
                   PolicyLifecycle lifecycle) {
    return MP_REQUIRE(Policy::create(MP_REQUIRE(PolicyId::parse("policy-a")), generation,
                                     MP_REQUIRE(Revision::from_value(1)), lifecycle,
                                     instant("2026-01-01T00:00:00Z"), settings, std::move(rules)));
}

PolicyBundle make_bundle(Policy policy, std::vector<AuthorityRecord> authorities,
                         std::vector<ExceptionRecord> exceptions, std::vector<ApprovalRecord> approvals,
                         ControlEpoch control_epoch, Revision registry_revision) {
    return MP_REQUIRE(PolicyBundle::create(std::move(policy), std::move(authorities), std::move(exceptions),
                                           std::move(approvals), control_epoch, registry_revision));
}

PolicyBundle bundle_for_generation(std::uint64_t generation, std::uint64_t control_epoch,
                                  std::uint64_t registry_revision) {
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z")}},
                                      MP_REQUIRE(PolicyGeneration::from_value(generation)));
    std::vector<AuthorityRecord> authorities;
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(6));
    authority.description = "facility change authority";
    authorities.push_back(authority);
    return make_bundle(policy, authorities, {}, {}, MP_REQUIRE(ControlEpoch::from_value(control_epoch)),
                       MP_REQUIRE(Revision::from_value(registry_revision)));
}

ExceptionRecord make_exception(const std::string& id, const PolicyBundle& bundle, const AuthorityKey& key,
                               std::vector<std::string> relaxed_rules, const std::string& scope, bool all_classes,
                               const std::string& not_before, const std::string& expires_at) {
    ExceptionRecord record;
    record.id = MP_REQUIRE(ExceptionId::parse(id));
    record.generation = bundle.policy().generation();
    record.policy_digest = bundle.policy().digest();
    for (const std::string& rule : relaxed_rules) {
        record.relaxed_rules.push_back(MP_REQUIRE(RuleId::parse(rule)));
    }
    record.scope = MP_REQUIRE(ScopePath::parse_selector(scope));
    record.classes.all = all_classes;
    record.issued_by = MP_REQUIRE(AuthorityId::parse("authority-1"));
    record.not_before = instant(not_before);
    record.issued_at = record.not_before;
    record.expires_at = instant(expires_at);
    record.reason = "planned maintenance waiver";
    sign_exception(record, key);
    return record;
}

ApprovalRecord make_approval(const std::string& id, const PolicyBundle& bundle, const AuthorityKey& key,
                             const std::string& request_digest, std::uint32_t level, const std::string& scope,
                             bool all_classes, const std::string& not_before, const std::string& expires_at) {
    ApprovalRecord record;
    record.id = MP_REQUIRE(ApprovalId::parse(id));
    record.generation = bundle.policy().generation();
    record.policy_digest = bundle.policy().digest();
    record.bound_request_digest = MP_REQUIRE(Digest256::from_hex(request_digest));
    record.scope = MP_REQUIRE(ScopePath::parse_selector(scope));
    record.classes.all = all_classes;
    record.issued_by = MP_REQUIRE(AuthorityId::parse("authority-1"));
    record.level = MP_REQUIRE(AuthorityLevel::from_value(level));
    record.not_before = instant(not_before);
    record.issued_at = record.not_before;
    record.expires_at = instant(expires_at);
    record.reason = "change advisory board approval";
    sign_approval(record, key);
    return record;
}

Result<Instant> parse_instant(const std::string& text) { return Instant::parse(text); }

Result<EvaluationRequest> build_request_result(const RequestSpec& spec) {
    std::vector<ScopePath> scopes;
    for (const std::string& scope : spec.scopes) {
        auto parsed = ScopePath::parse(scope);
        if (!parsed) {
            return parsed.error();
        }
        scopes.push_back(parsed.value());
    }
    std::vector<ObligationClassId> classes;
    for (const std::string& obligation_class : spec.classes) {
        auto parsed = ObligationClassId::parse(obligation_class);
        if (!parsed) {
            return parsed.error();
        }
        classes.push_back(parsed.value());
    }
    std::vector<ExceptionId> exceptions;
    for (const std::string& id : spec.exceptions) {
        auto parsed = ExceptionId::parse(id);
        if (!parsed) {
            return parsed.error();
        }
        exceptions.push_back(parsed.value());
    }
    std::vector<ApprovalId> approvals;
    for (const std::string& id : spec.approvals) {
        auto parsed = ApprovalId::parse(id);
        if (!parsed) {
            return parsed.error();
        }
        approvals.push_back(parsed.value());
    }

    auto window_start = parse_instant(spec.window_start);
    if (!window_start) {
        return window_start.error();
    }
    auto window_end = parse_instant(spec.window_end);
    if (!window_end) {
        return window_end.error();
    }
    auto window = make_interval(window_start.value(), window_end.value());
    if (!window) {
        return window.error();
    }
    auto evaluated_at = parse_instant(spec.evaluated_at);
    if (!evaluated_at) {
        return evaluated_at.error();
    }

    std::optional<EvidenceBundle> evidence;
    if (spec.include_evidence) {
        EvidenceBundle bundle;
        auto source = EvidenceSourceId::parse(spec.evidence_source);
        if (!source) {
            return source.error();
        }
        bundle.source = source.value();
        auto epoch = EvidenceEpoch::from_value(spec.evidence_epoch);
        if (!epoch) {
            return epoch.error();
        }
        bundle.epoch = epoch.value();
        auto observed = parse_instant(spec.evidence_observed_at);
        if (!observed) {
            return observed.error();
        }
        bundle.observed_at = observed.value();
        for (const EvidenceSpec& entry : spec.evidence_classes) {
            ClassEvidence class_evidence;
            auto obligation_class = ObligationClassId::parse(entry.obligation_class);
            if (!obligation_class) {
                return obligation_class.error();
            }
            class_evidence.obligation_class = obligation_class.value();
            MeasurementState state = MeasurementState::Measured;
            if (!measurement_state_from_name(entry.state, state)) {
                return make_error(Code::UnknownEnumValue, "measurement state '" + entry.state + "' is not known");
            }
            class_evidence.state = state;
            class_evidence.surviving_units = entry.surviving_units;
            class_evidence.total_units = entry.total_units;
            auto entry_observed = parse_instant(entry.observed_at);
            if (!entry_observed) {
                return entry_observed.error();
            }
            class_evidence.observed_at = entry_observed.value();
            class_evidence.source = bundle.source;
            class_evidence.epoch = bundle.epoch;
            bundle.classes.push_back(std::move(class_evidence));
        }
        evidence = std::move(bundle);
    }

    std::optional<InterlockReport> interlocks;
    if (spec.include_interlocks) {
        InterlockReport report;
        auto source = EvidenceSourceId::parse(spec.interlock_source);
        if (!source) {
            return source.error();
        }
        report.source = source.value();
        auto epoch = EvidenceEpoch::from_value(spec.interlock_epoch);
        if (!epoch) {
            return epoch.error();
        }
        report.epoch = epoch.value();
        auto observed = parse_instant(spec.interlock_observed_at);
        if (!observed) {
            return observed.error();
        }
        report.observed_at = observed.value();
        for (const std::pair<std::string, bool>& entry : spec.interlocks) {
            InterlockAssertion assertion;
            auto interlock = InterlockId::parse(entry.first);
            if (!interlock) {
                return interlock.error();
            }
            assertion.interlock = interlock.value();
            assertion.active = entry.second;
            report.assertions.push_back(std::move(assertion));
        }
        interlocks = std::move(report);
    }

    std::optional<Digest256> expected_digest;
    if (!spec.expected_policy_digest.empty()) {
        auto parsed = Digest256::from_hex(spec.expected_policy_digest);
        if (!parsed) {
            return parsed.error();
        }
        expected_digest = parsed.value();
    }

    auto context_id = ContextId::parse(spec.context_id);
    if (!context_id) {
        return context_id.error();
    }
    auto request_id = RequestId::parse(spec.request_id);
    if (!request_id) {
        return request_id.error();
    }
    auto requested_by = PrincipalId::parse(spec.requested_by);
    if (!requested_by) {
        return requested_by.error();
    }
    auto expected_generation = PolicyGeneration::from_value(spec.expected_generation);
    if (!expected_generation) {
        return expected_generation.error();
    }

    return EvaluationRequest::create(context_id.value(), request_id.value(), std::move(scopes), std::move(classes),
                                     window.value(), requested_by.value(), expected_generation.value(),
                                     expected_digest, std::move(exceptions), std::move(approvals),
                                     std::move(evidence), std::move(interlocks), spec.concurrent_maintenance,
                                     evaluated_at.value());
}

EvaluationRequest build_request(const RequestSpec& spec) { return MP_REQUIRE(build_request_result(spec)); }

std::string request_document(const RequestSpec& spec) { return canonical_request(build_request(spec)); }

std::string describe_decision(const Decision& decision) {
    std::string text = "outcome=";
    text.append(to_string(decision.outcome));
    text.append(" replay=");
    text.append(to_string(decision.replay));
    text.append(" findings=[");
    for (std::size_t index = 0; index < decision.findings.size(); ++index) {
        if (index > 0) {
            text.push_back(',');
        }
        text.append(to_string(decision.findings[index].code));
        if (decision.findings[index].rule.has_value()) {
            text.push_back('/');
            text.append(decision.findings[index].rule.value().value());
        }
    }
    text.push_back(']');
    return text;
}

Decision evaluate_spec(const PolicyBundle& bundle, const KeySet& keys, const RequestSpec& spec,
                       const std::vector<PriorDecisionRecord>& prior) {
    const EvaluationRequest request = build_request(spec);
    EvaluationLimits limits;
    return MP_REQUIRE(evaluate(bundle, keys, request, prior, limits));
}

}  // namespace maintpol::test
