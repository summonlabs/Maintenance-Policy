#include "maintpol/text.hpp"

#include <algorithm>
#include <cstring>
#include <optional>
#include <utility>

#include "maintpol/version.hpp"

namespace maintpol {
namespace {

const TextLimits kLimits{};

#define MP_TRY(expr)                       \
    do {                                   \
        auto mp_result = (expr);           \
        if (!mp_result) {                  \
            return mp_result.error();      \
        }                                  \
    } while (false)

#define MP_ASSIGN(name, expr)                                     \
    auto name##_result = (expr);                                  \
    if (!name##_result) {                                         \
        return name##_result.error();                             \
    }                                                             \
    auto name = name##_result.value()

std::string interval_text(const Interval& interval) {
    return interval.start.format() + " " + interval.end.format();
}

std::string recurrence_text(const Recurrence& recurrence) {
    std::string out;
    out.append(to_string(recurrence.kind));
    out.push_back(' ');
    out.append(recurrence.origin.format());
    out.push_back(' ');
    out.append(std::to_string(recurrence.offset_minutes));
    out.push_back(' ');
    out.append(std::to_string(recurrence.weekday));
    out.push_back(' ');
    out.append(std::to_string(recurrence.day_of_month));
    out.push_back(' ');
    out.append(recurrence.start_offset.format());
    out.push_back(' ');
    out.append(recurrence.duration.format());
    out.push_back(' ');
    out.append(std::to_string(recurrence.count));
    return out;
}

Result<Interval> parse_interval_value(const std::string& text) {
    const std::size_t space = text.find(' ');
    if (space == std::string::npos) {
        return make_error(Code::SyntaxInvalid, "interval must be '<start> <end>'");
    }
    if (text.find(' ', space + 1u) != std::string::npos) {
        return make_error(Code::SyntaxInvalid, "interval must contain exactly one space");
    }
    auto start = Instant::parse(std::string_view(text).substr(0, space));
    if (!start) {
        return start.error();
    }
    auto end = Instant::parse(std::string_view(text).substr(space + 1u));
    if (!end) {
        return end.error();
    }
    return make_interval(start.value(), end.value());
}

Result<ClassSelector> parse_class_selector_value(const std::string& text) {
    ClassSelector selector;
    if (text == "*") {
        selector.all = true;
        return selector;
    }
    if (text.empty()) {
        return make_error(Code::SelectorInvalid, "class selector must not be empty");
    }
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t comma = text.find(',', start);
        const std::size_t end = comma == std::string::npos ? text.size() : comma;
        const std::string_view token = std::string_view(text).substr(start, end - start);
        if (token.empty()) {
            return make_error(Code::SelectorInvalid, "class selector contains an empty entry");
        }
        auto id = ObligationClassId::parse(token);
        if (!id) {
            return id.error();
        }
        selector.classes.push_back(id.value());
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1u;
    }
    if (selector.classes.size() > kMaxClassesPerSelector) {
        return make_error(Code::TooManyItems, "class selector exceeds 64 classes");
    }
    std::vector<ObligationClassId> sorted = selector.classes;
    std::sort(sorted.begin(), sorted.end());
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
        return make_error(Code::DuplicateIdentifier, "class selector repeats a class");
    }
    selector.classes = std::move(sorted);
    return selector;
}

Result<Recurrence> parse_recurrence_value(const std::string& text) {
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t space = text.find(' ', start);
        const std::size_t end = space == std::string::npos ? text.size() : space;
        parts.push_back(std::string_view(text).substr(start, end - start));
        if (space == std::string::npos) {
            break;
        }
        start = space + 1u;
    }
    if (parts.size() != 8u) {
        return make_error(Code::RecurrenceInvalid, "recurrence must declare exactly eight fields");
    }
    Recurrence recurrence;
    if (!recurrence_kind_from_name(parts[0], recurrence.kind)) {
        return make_error(Code::UnknownEnumValue, "recurrence kind is not recognised");
    }
    auto origin = Instant::parse(parts[1]);
    if (!origin) {
        return origin.error();
    }
    recurrence.origin = origin.value();
    auto parse_int = [](std::string_view value, std::int64_t& out) -> Result<void> {
        if (value.empty() || value.size() > 12) {
            return make_error(Code::NumberMalformed, "recurrence field is not an integer");
        }
        std::size_t index = 0;
        bool negative = false;
        if (value[0] == '-') {
            negative = true;
            index = 1;
            if (value.size() == 1u) {
                return make_error(Code::NumberMalformed, "recurrence field is not an integer");
            }
        }
        std::int64_t result = 0;
        for (; index < value.size(); ++index) {
            if (value[index] < '0' || value[index] > '9') {
                return make_error(Code::NumberMalformed, "recurrence field is not an integer");
            }
            result = (result * 10) + (value[index] - '0');
        }
        out = negative ? -result : result;
        return {};
    };
    std::int64_t offset = 0;
    std::int64_t weekday = 0;
    std::int64_t day_of_month = 0;
    std::int64_t count = 0;
    MP_TRY(parse_int(parts[2], offset));
    MP_TRY(parse_int(parts[3], weekday));
    MP_TRY(parse_int(parts[4], day_of_month));
    MP_TRY(parse_int(parts[7], count));
    if (offset < -100000 || offset > 100000) {
        return make_error(Code::OffsetOutOfRange, "recurrence offset is out of range");
    }
    if (weekday < 0 || weekday > 6) {
        return make_error(Code::RecurrenceInvalid, "recurrence weekday is out of range");
    }
    if (day_of_month < 0 || day_of_month > 31) {
        return make_error(Code::RecurrenceInvalid, "recurrence day is out of range");
    }
    if (count < 0 || count > static_cast<std::int64_t>(kMaxRecurrenceOccurrences)) {
        return make_error(Code::RecurrenceUnbounded, "recurrence count is out of range");
    }
    auto start_offset = Duration::parse(parts[5]);
    if (!start_offset) {
        return start_offset.error();
    }
    auto duration = Duration::parse(parts[6]);
    if (!duration) {
        return duration.error();
    }
    recurrence.offset_minutes = static_cast<std::int32_t>(offset);
    recurrence.weekday = static_cast<unsigned>(weekday);
    recurrence.day_of_month = static_cast<unsigned>(day_of_month);
    recurrence.start_offset = start_offset.value();
    recurrence.duration = duration.value();
    recurrence.count = static_cast<std::uint32_t>(count);
    return recurrence;
}

Result<AuthorityLevel> parse_level_value(const std::string& text) { return AuthorityLevel::parse(text); }

// ---------------------------------------------------------------------------
// Writers.
// ---------------------------------------------------------------------------
void write_rule(CanonicalWriter& writer, const Rule& rule) {
    const RuleHeader& header = rule_header_of(rule);
    const RuleKind kind = rule_kind_of(rule);
    writer.section("rule " + header.id.value());
    writer.field("kind", to_string(kind));
    writer.field("priority", header.priority);
    writer.field("scope", header.scope.format());
    writer.field("classes", header.classes.format());
    writer.field("enabled", header.enabled);
    if (!header.description.empty()) {
        writer.field("description", header.description);
    }
    switch (kind) {
        case RuleKind::Blackout: {
            const BlackoutRule& concrete = std::get<BlackoutRule>(rule);
            writer.field("waivable", concrete.waivable);
            for (const Interval& window : concrete.windows) {
                writer.field("window", interval_text(window));
            }
            if (concrete.recurrence.has_value()) {
                writer.field("recurrence", recurrence_text(concrete.recurrence.value()));
            }
            break;
        }
        case RuleKind::Redundancy: {
            const RedundancyRule& concrete = std::get<RedundancyRule>(rule);
            writer.field("minimum_survivors", concrete.minimum_survivors);
            writer.field("waivable", concrete.waivable);
            break;
        }
        case RuleKind::ProtectedClass: {
            const ProtectedClassRule& concrete = std::get<ProtectedClassRule>(rule);
            writer.field("waivable", false);
            if (concrete.window.has_value()) {
                writer.field("window", interval_text(concrete.window.value()));
            }
            break;
        }
        case RuleKind::Escalation: {
            const EscalationRule& concrete = std::get<EscalationRule>(rule);
            writer.field("required_level", concrete.required_level.value());
            if (concrete.min_window.has_value()) {
                writer.field("min_window", concrete.min_window.value().format());
            }
            writer.field("on_exception_used", concrete.on_exception_used);
            writer.field("on_redundancy_waiver", concrete.on_redundancy_waiver);
            break;
        }
        case RuleKind::HardInterlock: {
            const HardInterlockRule& concrete = std::get<HardInterlockRule>(rule);
            writer.field("waivable", false);
            writer.field("interlock", concrete.interlock.value());
            break;
        }
        case RuleKind::SoftConstraint: {
            const SoftConstraintRule& concrete = std::get<SoftConstraintRule>(rule);
            if (concrete.max_concurrent != 0) {
                writer.field("max_concurrent", concrete.max_concurrent);
            }
            if (concrete.max_window.has_value()) {
                writer.field("max_window", concrete.max_window.value().format());
            }
            writer.field("waivable", concrete.waivable);
            break;
        }
    }
}

void write_policy_body(CanonicalWriter& writer, const Policy& policy) {
    writer.section("policy");
    writer.field("policy_id", policy.id().value());
    writer.field("generation", policy.generation().value());
    writer.field("revision", policy.revision().value());
    writer.field("lifecycle", to_string(policy.lifecycle()));
    writer.field("published_at", policy.published_at().format());
    writer.field("evidence_max_age", policy.settings().evidence_max_age.format());
    writer.field("max_window", policy.settings().max_window.format());
    writer.field("min_waiver_level", policy.settings().min_waiver_level.value());
    std::vector<std::string> sources;
    sources.reserve(policy.settings().evidence_sources.size());
    for (const EvidenceSourceId& source : policy.settings().evidence_sources) {
        sources.push_back(source.value());
    }
    std::sort(sources.begin(), sources.end());
    for (const std::string& source : sources) {
        writer.field("evidence_source", source);
    }
    if (policy.settings().min_evidence_epoch.is_set()) {
        writer.field("min_evidence_epoch", policy.settings().min_evidence_epoch.value());
    }
    writer.field("require_evidence_for_classes", policy.settings().require_evidence_for_classes);
    writer.field("max_recurrence_count", policy.settings().max_recurrence_count);
    for (const Rule& rule : policy.rules()) {
        write_rule(writer, rule);
    }
}

void write_exception_body(CanonicalWriter& writer, const ExceptionRecord& record, bool include_registry_state) {
    writer.section("exception " + record.id.value());
    writer.field("generation", record.generation.value());
    writer.field("policy_digest", record.policy_digest);
    const std::vector<RuleId> relaxed = [&record] {
        std::vector<RuleId> sorted = record.relaxed_rules;
        std::sort(sorted.begin(), sorted.end());
        return sorted;
    }();
    for (const RuleId& rule : relaxed) {
        writer.field("relaxed_rule", rule.value());
    }
    writer.field("scope", record.scope.format());
    writer.field("classes", record.classes.format());
    writer.field("issued_by", record.issued_by.value());
    writer.field("issued_at", record.issued_at.format());
    writer.field("not_before", record.not_before.format());
    writer.field("expires_at", record.expires_at.format());
    if (!record.reason.empty()) {
        writer.field("reason", record.reason);
    }
    writer.field("key_id", record.key_id.value());
    if (include_registry_state) {
        if (record.revoked_at.has_value()) {
            writer.field("revoked_at", record.revoked_at.value().format());
        }
        writer.field("mac", record.mac);
    }
}

void write_approval_body(CanonicalWriter& writer, const ApprovalRecord& record, bool include_registry_state) {
    writer.section("approval " + record.id.value());
    writer.field("generation", record.generation.value());
    writer.field("policy_digest", record.policy_digest);
    writer.field("bound_request_digest", record.bound_request_digest);
    writer.field("scope", record.scope.format());
    writer.field("classes", record.classes.format());
    writer.field("issued_by", record.issued_by.value());
    writer.field("level", record.level.value());
    writer.field("issued_at", record.issued_at.format());
    writer.field("not_before", record.not_before.format());
    writer.field("expires_at", record.expires_at.format());
    if (!record.reason.empty()) {
        writer.field("reason", record.reason);
    }
    writer.field("key_id", record.key_id.value());
    if (include_registry_state) {
        if (record.revoked_at.has_value()) {
            writer.field("revoked_at", record.revoked_at.value().format());
        }
        writer.field("mac", record.mac);
    }
}

void write_request_body(CanonicalWriter& writer, const EvaluationRequest& request) {
    writer.section("request");
    writer.field("context_id", request.context_id().value());
    writer.field("request_id", request.request_id().value());
    writer.field("requested_by", request.requested_by().value());
    writer.field("expected_generation", request.expected_generation().value());
    if (request.expected_policy_digest().has_value()) {
        writer.field("expected_policy_digest", request.expected_policy_digest().value());
    }
    writer.field("window", interval_text(request.window()));
    writer.field("concurrent_maintenance", request.concurrent_maintenance());
    writer.field("evaluated_at", request.evaluated_at().format());
    std::vector<std::string> scopes;
    scopes.reserve(request.scopes().size());
    for (const ScopePath& scope : request.scopes()) {
        scopes.push_back(scope.format());
    }
    std::sort(scopes.begin(), scopes.end());
    for (const std::string& scope : scopes) {
        writer.field("scope", scope);
    }
    std::vector<std::string> classes;
    classes.reserve(request.classes().size());
    for (const ObligationClassId& obligation_class : request.classes()) {
        classes.push_back(obligation_class.value());
    }
    std::sort(classes.begin(), classes.end());
    for (const std::string& obligation_class : classes) {
        writer.field("class", obligation_class);
    }
    std::vector<std::string> exceptions;
    exceptions.reserve(request.exceptions().size());
    for (const ExceptionId& id : request.exceptions()) {
        exceptions.push_back(id.value());
    }
    std::sort(exceptions.begin(), exceptions.end());
    for (const std::string& id : exceptions) {
        writer.field("exception_ref", id);
    }
    std::vector<std::string> approvals;
    approvals.reserve(request.approvals().size());
    for (const ApprovalId& id : request.approvals()) {
        approvals.push_back(id.value());
    }
    std::sort(approvals.begin(), approvals.end());
    for (const std::string& id : approvals) {
        writer.field("approval_ref", id);
    }
    if (request.evidence().has_value()) {
        const EvidenceBundle& evidence = request.evidence().value();
        writer.section("evidence");
        writer.field("source", evidence.source.value());
        writer.field("epoch", evidence.epoch.value());
        writer.field("observed_at", evidence.observed_at.format());
        std::vector<const ClassEvidence*> sorted;
        sorted.reserve(evidence.classes.size());
        for (const ClassEvidence& entry : evidence.classes) {
            sorted.push_back(&entry);
        }
        std::sort(sorted.begin(), sorted.end(), [](const ClassEvidence* left, const ClassEvidence* right) {
            return left->obligation_class < right->obligation_class;
        });
        for (const ClassEvidence* entry : sorted) {
            writer.section("evidence-class " + entry->obligation_class.value());
            writer.field("state", to_string(entry->state));
            writer.field("surviving_units", entry->surviving_units);
            writer.field("total_units", entry->total_units);
            writer.field("observed_at", entry->observed_at.format());
            writer.field("source", entry->source.value());
            writer.field("epoch", entry->epoch.value());
        }
    }
    if (request.interlocks().has_value()) {
        const InterlockReport& report = request.interlocks().value();
        writer.section("interlock-report");
        writer.field("source", report.source.value());
        writer.field("epoch", report.epoch.value());
        writer.field("observed_at", report.observed_at.format());
        std::vector<const InterlockAssertion*> sorted;
        sorted.reserve(report.assertions.size());
        for (const InterlockAssertion& assertion : report.assertions) {
            sorted.push_back(&assertion);
        }
        std::sort(sorted.begin(), sorted.end(), [](const InterlockAssertion* left, const InterlockAssertion* right) {
            return left->interlock < right->interlock;
        });
        for (const InterlockAssertion* assertion : sorted) {
            writer.section("interlock " + assertion->interlock.value());
            writer.field("active", assertion->active);
        }
    }
}

void write_decision_body(CanonicalWriter& writer, const Decision& decision, bool include_metadata) {
    writer.section("document");
    writer.field("format", document_format_id);
    writer.field("kind", kDocumentKindDecision);
    writer.section("decision");
    writer.field("outcome", to_string(decision.outcome));
    // The replay disposition describes how this answer was delivered, not what
    // was decided, so it is excluded from the decision digest. A replayed
    // decision therefore carries the digest of the decision it replays.
    if (include_metadata) {
        writer.field("replay", to_string(decision.replay));
    }
    if (decision.required_level.has_value()) {
        writer.field("required_level", decision.required_level.value().value());
    }
    if (include_metadata) {
        writer.field("digest", decision.digest());
    }

    writer.section("bindings");
    const DecisionBindings& bindings = decision.bindings;
    writer.field("policy_id", bindings.policy_id.value());
    writer.field("policy_generation", bindings.policy_generation.value());
    writer.field("policy_digest", bindings.policy_digest);
    writer.field("control_epoch", bindings.control_epoch.value());
    writer.field("registry_revision", bindings.registry_revision.value());
    writer.field("context_id", bindings.context_id.value());
    writer.field("request_id", bindings.request_id.value());
    writer.field("request_digest", bindings.request_digest);
    if (bindings.evidence_digest.has_value()) {
        writer.field("evidence_digest", bindings.evidence_digest.value());
    }
    if (bindings.evidence_epoch.has_value()) {
        writer.field("evidence_epoch", bindings.evidence_epoch.value().value());
    }
    if (bindings.interlock_digest.has_value()) {
        writer.field("interlock_digest", bindings.interlock_digest.value());
    }
    writer.field("evaluated_at", bindings.evaluated_at.format());
    writer.field("semantics_version", bindings.semantics_version);
    writer.field("digest_format_version", bindings.digest_format_version);

    writer.section("applied-rules");
    std::vector<RuleId> rules = decision.applied_rules;
    std::sort(rules.begin(), rules.end());
    for (const RuleId& rule : rules) {
        writer.field("rule", rule.value());
    }

    writer.section("honored-exceptions");
    std::vector<ExceptionId> exceptions = decision.honored_exceptions;
    std::sort(exceptions.begin(), exceptions.end());
    for (const ExceptionId& id : exceptions) {
        writer.field("exception", id.value());
    }

    writer.section("exception-bindings");
    std::vector<Digest256> exception_digests = bindings.exception_digests;
    std::sort(exception_digests.begin(), exception_digests.end());
    for (const Digest256& digest : exception_digests) {
        writer.field("digest", digest);
    }

    writer.section("approval-bindings");
    std::vector<Digest256> approval_digests = bindings.approval_digests;
    std::sort(approval_digests.begin(), approval_digests.end());
    for (const Digest256& digest : approval_digests) {
        writer.field("digest", digest);
    }

    std::vector<Finding> findings = decision.findings;
    sort_findings(findings);
    for (std::size_t index = 0; index < findings.size(); ++index) {
        const Finding& finding = findings[index];
        writer.section("finding " + std::to_string(index));
        writer.field("code", to_string(finding.code));
        if (finding.rule.has_value()) {
            writer.field("rule", finding.rule.value().value());
        }
        if (finding.exception.has_value()) {
            writer.field("exception", finding.exception.value().value());
        }
        if (finding.approval.has_value()) {
            writer.field("approval", finding.approval.value().value());
        }
        if (finding.obligation_class.has_value()) {
            writer.field("class", finding.obligation_class.value().value());
        }
        if (!finding.detail.empty()) {
            writer.field("detail", finding.detail);
        }
    }
}

// ---------------------------------------------------------------------------
// Section bookkeeping helpers.
// ---------------------------------------------------------------------------
Result<void> require_single_section(const TextDocument& document, std::string_view name) {
    std::size_t count = 0;
    for (const TextEntry& entry : document.entries) {
        if (entry.is_section && entry.section == name) {
            ++count;
        }
    }
    if (count == 0) {
        return make_error(Code::MissingKey, "document has no '" + std::string(name) + "' section");
    }
    if (count > 1) {
        return make_error(Code::DuplicateKey, "document has more than one '" + std::string(name) + "' section");
    }
    return {};
}

bool section_is_one_of(const std::string& section, std::string_view name) { return section == name; }

bool section_has_prefix(const std::string& section, std::string_view prefix) {
    return section.size() > prefix.size() && section.compare(0, prefix.size(), prefix) == 0;
}

Result<void> check_allowed_sections(const TextDocument& document, const std::vector<std::string>& fixed,
                                    const std::vector<std::string>& prefixes) {
    for (const TextEntry& entry : document.entries) {
        if (!entry.is_section) {
            continue;
        }
        bool allowed = false;
        for (const std::string& name : fixed) {
            if (section_is_one_of(entry.section, name)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            for (const std::string& prefix : prefixes) {
                if (section_has_prefix(entry.section, prefix)) {
                    allowed = true;
                    break;
                }
            }
        }
        if (!allowed) {
            return make_error(Code::UnexpectedSection, "section '" + entry.section + "' is not permitted here");
        }
    }
    return {};
}

std::vector<std::string> collect_sections(const TextDocument& document, std::string_view prefix) {
    std::vector<std::string> sections;
    for (const TextEntry& entry : document.entries) {
        if (entry.is_section && section_has_prefix(entry.section, prefix)) {
            bool known = false;
            for (const std::string& existing : sections) {
                if (existing == entry.section) {
                    known = true;
                    break;
                }
            }
            if (!known) {
                sections.push_back(entry.section);
            }
        }
    }
    std::sort(sections.begin(), sections.end());
    return sections;
}

Result<void> read_document_header(const TextDocument& document, std::string_view expected_kind) {
    MP_TRY(require_single_section(document, "document"));
    SectionReader reader(document, "document");
    auto format = reader.take_string("format");
    if (!format) {
        return format.error();
    }
    if (format.value() != document_format_id) {
        return make_error(Code::UnsupportedFormatVersion, "document format is not '" +
                                                              std::string(document_format_id) + "'");
    }
    auto kind = reader.take_string("kind");
    if (!kind) {
        return kind.error();
    }
    if (kind.value() != expected_kind) {
        return make_error(Code::UnexpectedSection, "document kind is not '" + std::string(expected_kind) + "'");
    }
    return reader.finish();
}

// ---------------------------------------------------------------------------
// Parsers.
// ---------------------------------------------------------------------------
Result<Rule> parse_rule_section(const TextDocument& document, const std::string& section) {
    SectionReader reader(document, section);
    const std::string_view id_text = std::string_view(section).substr(5u);
    auto id = RuleId::parse(id_text);
    if (!id) {
        return id.error();
    }
    auto kind_text = reader.take_string("kind");
    if (!kind_text) {
        return kind_text.error();
    }
    RuleKind kind = RuleKind::Blackout;
    if (!rule_kind_from_name(kind_text.value(), kind)) {
        return make_error(Code::UnknownEnumValue, "rule kind '" + kind_text.value() + "' is not recognised");
    }

    RuleHeader header;
    header.id = id.value();
    auto priority = reader.take_u64("priority");
    if (!priority) {
        return priority.error();
    }
    if (priority.value() > kMaxRulePriority) {
        return make_error(Code::PriorityOutOfRange, "rule priority exceeds 1000000");
    }
    header.priority = static_cast<std::uint32_t>(priority.value());

    auto scope_text = reader.take_string("scope");
    if (!scope_text) {
        return scope_text.error();
    }
    auto scope = ScopePath::parse_selector(scope_text.value());
    if (!scope) {
        return scope.error();
    }
    header.scope = scope.value();

    auto classes_text = reader.take_string("classes");
    if (!classes_text) {
        return classes_text.error();
    }
    auto classes = parse_class_selector_value(classes_text.value());
    if (!classes) {
        return classes.error();
    }
    header.classes = classes.value();

    auto enabled = reader.take_bool("enabled");
    if (!enabled) {
        return enabled.error();
    }
    header.enabled = enabled.value();

    auto description = reader.take_optional_string("description", std::string());
    if (!description) {
        return description.error();
    }
    header.description = description.value();

    if (kind == RuleKind::Blackout) {
        BlackoutRule rule;
        rule.header = header;
        auto waivable = reader.take_bool("waivable");
        if (!waivable) {
            return waivable.error();
        }
        rule.waivable = waivable.value();
        auto windows = reader.take_all("window");
        if (!windows) {
            return windows.error();
        }
        for (const std::string& text : windows.value()) {
            auto window = parse_interval_value(text);
            if (!window) {
                return window.error();
            }
            rule.windows.push_back(window.value());
        }
        if (reader.has("recurrence")) {
            auto recurrence_text_value = reader.take_string("recurrence");
            if (!recurrence_text_value) {
                return recurrence_text_value.error();
            }
            auto recurrence = parse_recurrence_value(recurrence_text_value.value());
            if (!recurrence) {
                return recurrence.error();
            }
            rule.recurrence = recurrence.value();
        }
        MP_TRY(reader.finish());
        return Rule{std::move(rule)};
    }
    if (kind == RuleKind::Redundancy) {
        RedundancyRule rule;
        rule.header = header;
        auto minimum = reader.take_u64("minimum_survivors");
        if (!minimum) {
            return minimum.error();
        }
        if (minimum.value() == 0 || minimum.value() > 1000000u) {
            return make_error(Code::ThresholdInvalid, "redundancy floor must be between 1 and 1000000");
        }
        rule.minimum_survivors = static_cast<std::uint32_t>(minimum.value());
        auto waivable = reader.take_bool("waivable");
        if (!waivable) {
            return waivable.error();
        }
        rule.waivable = waivable.value();
        MP_TRY(reader.finish());
        return Rule{std::move(rule)};
    }
    if (kind == RuleKind::ProtectedClass) {
        ProtectedClassRule rule;
        rule.header = header;
        if (reader.has("waivable")) {
            MP_ASSIGN(waivable, reader.take_bool("waivable"));
            if (waivable) {
                return make_error(Code::HardInterlockWaivable,
                                  "a protected-class rule can never be waived, so it must not declare 'waivable'");
            }
        }
        if (reader.has("window")) {
            auto window_text = reader.take_string("window");
            if (!window_text) {
                return window_text.error();
            }
            auto window = parse_interval_value(window_text.value());
            if (!window) {
                return window.error();
            }
            rule.window = window.value();
        }
        MP_TRY(reader.finish());
        return Rule{std::move(rule)};
    }
    if (kind == RuleKind::Escalation) {
        EscalationRule rule;
        rule.header = header;
        auto level_text = reader.take_string("required_level");
        if (!level_text) {
            return level_text.error();
        }
        auto level = parse_level_value(level_text.value());
        if (!level) {
            return level.error();
        }
        rule.required_level = level.value();
        if (reader.has("min_window")) {
            auto min_window_text = reader.take_string("min_window");
            if (!min_window_text) {
                return min_window_text.error();
            }
            auto min_window = Duration::parse(min_window_text.value());
            if (!min_window) {
                return min_window.error();
            }
            rule.min_window = min_window.value();
        }
        auto on_exception = reader.take_bool("on_exception_used");
        if (!on_exception) {
            return on_exception.error();
        }
        rule.on_exception_used = on_exception.value();
        auto on_waiver = reader.take_bool("on_redundancy_waiver");
        if (!on_waiver) {
            return on_waiver.error();
        }
        rule.on_redundancy_waiver = on_waiver.value();
        MP_TRY(reader.finish());
        return Rule{std::move(rule)};
    }
    if (kind == RuleKind::HardInterlock) {
        HardInterlockRule rule;
        rule.header = header;
        if (reader.has("waivable")) {
            MP_ASSIGN(waivable, reader.take_bool("waivable"));
            if (waivable) {
                return make_error(Code::HardInterlockWaivable,
                                  "a hard interlock can never be waived, so it must not declare 'waivable'");
            }
        }
        auto interlock_text = reader.take_string("interlock");
        if (!interlock_text) {
            return interlock_text.error();
        }
        auto interlock = InterlockId::parse(interlock_text.value());
        if (!interlock) {
            return interlock.error();
        }
        rule.interlock = interlock.value();
        MP_TRY(reader.finish());
        return Rule{std::move(rule)};
    }

    SoftConstraintRule rule;
    rule.header = header;
    if (reader.has("max_concurrent")) {
        auto max_concurrent = reader.take_u64("max_concurrent");
        if (!max_concurrent) {
            return max_concurrent.error();
        }
        if (max_concurrent.value() == 0 || max_concurrent.value() > 1000000u) {
            return make_error(Code::ThresholdInvalid, "concurrent maintenance limit must be between 1 and 1000000");
        }
        rule.max_concurrent = static_cast<std::uint32_t>(max_concurrent.value());
    }
    if (reader.has("max_window")) {
        auto max_window_text = reader.take_string("max_window");
        if (!max_window_text) {
            return max_window_text.error();
        }
        auto max_window = Duration::parse(max_window_text.value());
        if (!max_window) {
            return max_window.error();
        }
        rule.max_window = max_window.value();
    }
    auto waivable = reader.take_bool("waivable");
    if (!waivable) {
        return waivable.error();
    }
    rule.waivable = waivable.value();
    MP_TRY(reader.finish());
    return Rule{std::move(rule)};
}

Result<Policy> parse_policy_sections(const TextDocument& document) {
    MP_TRY(require_single_section(document, "policy"));
    SectionReader reader(document, "policy");

    auto policy_id_text = reader.take_string("policy_id");
    if (!policy_id_text) {
        return policy_id_text.error();
    }
    auto policy_id = PolicyId::parse(policy_id_text.value());
    if (!policy_id) {
        return policy_id.error();
    }
    auto generation_text = reader.take_string("generation");
    if (!generation_text) {
        return generation_text.error();
    }
    auto generation = PolicyGeneration::parse(generation_text.value());
    if (!generation) {
        return generation.error();
    }
    auto revision_text = reader.take_string("revision");
    if (!revision_text) {
        return revision_text.error();
    }
    auto revision = Revision::parse(revision_text.value());
    if (!revision) {
        return revision.error();
    }
    auto lifecycle_text = reader.take_string("lifecycle");
    if (!lifecycle_text) {
        return lifecycle_text.error();
    }
    PolicyLifecycle lifecycle = PolicyLifecycle::Draft;
    if (!policy_lifecycle_from_name(lifecycle_text.value(), lifecycle)) {
        return make_error(Code::UnknownEnumValue, "policy lifecycle is not recognised");
    }
    auto published_text = reader.take_string("published_at");
    if (!published_text) {
        return published_text.error();
    }
    auto published_at = Instant::parse(published_text.value());
    if (!published_at) {
        return published_at.error();
    }

    PolicySettings settings;
    auto evidence_age_text = reader.take_string("evidence_max_age");
    if (!evidence_age_text) {
        return evidence_age_text.error();
    }
    auto evidence_age = Duration::parse(evidence_age_text.value());
    if (!evidence_age) {
        return evidence_age.error();
    }
    settings.evidence_max_age = evidence_age.value();

    auto max_window_text = reader.take_string("max_window");
    if (!max_window_text) {
        return max_window_text.error();
    }
    auto max_window = Duration::parse(max_window_text.value());
    if (!max_window) {
        return max_window.error();
    }
    settings.max_window = max_window.value();

    auto min_waiver_text = reader.take_string("min_waiver_level");
    if (!min_waiver_text) {
        return min_waiver_text.error();
    }
    auto min_waiver = parse_level_value(min_waiver_text.value());
    if (!min_waiver) {
        return min_waiver.error();
    }
    settings.min_waiver_level = min_waiver.value();

    MP_ASSIGN(source_values, reader.take_all("evidence_source"));
    for (const std::string& source_text : source_values) {
        auto source = EvidenceSourceId::parse(source_text);
        if (!source) {
            return source.error();
        }
        settings.evidence_sources.push_back(source.value());
    }
    if (reader.has("min_evidence_epoch")) {
        auto epoch_text = reader.take_string("min_evidence_epoch");
        if (!epoch_text) {
            return epoch_text.error();
        }
        auto epoch = EvidenceEpoch::parse(epoch_text.value());
        if (!epoch) {
            return epoch.error();
        }
        settings.min_evidence_epoch = epoch.value();
    }

    auto require_evidence = reader.take_bool("require_evidence_for_classes");
    if (!require_evidence) {
        return require_evidence.error();
    }
    settings.require_evidence_for_classes = require_evidence.value();

    auto max_recurrence = reader.take_u64("max_recurrence_count");
    if (!max_recurrence) {
        return max_recurrence.error();
    }
    if (max_recurrence.value() == 0 || max_recurrence.value() > kMaxRecurrenceOccurrences) {
        return make_error(Code::RecurrenceUnbounded, "policy maximum recurrence count is out of range");
    }
    settings.max_recurrence_count = static_cast<std::uint32_t>(max_recurrence.value());

    MP_TRY(reader.finish());

    std::vector<Rule> rules;
    for (const std::string& section : collect_sections(document, "rule ")) {
        auto rule = parse_rule_section(document, section);
        if (!rule) {
            return rule.error();
        }
        rules.push_back(std::move(rule.value()));
    }
    if (rules.empty()) {
        return make_error(Code::PolicyEmpty, "document declares no rules");
    }
    return Policy::create(policy_id.value(), generation.value(), revision.value(), lifecycle,
                          published_at.value(), settings, std::move(rules));
}

Result<ExceptionRecord> parse_exception_section(const TextDocument& document, const std::string& section) {
    SectionReader reader(document, section);
    const std::string_view id_text = std::string_view(section).substr(11u);
    auto id = ExceptionId::parse(id_text);
    if (!id) {
        return id.error();
    }
    ExceptionRecord record;
    record.id = id.value();
    auto generation_text = reader.take_string("generation");
    if (!generation_text) {
        return generation_text.error();
    }
    auto generation = PolicyGeneration::parse(generation_text.value());
    if (!generation) {
        return generation.error();
    }
    record.generation = generation.value();
    auto policy_digest = reader.take_digest("policy_digest");
    if (!policy_digest) {
        return policy_digest.error();
    }
    record.policy_digest = policy_digest.value();
    auto relaxed = reader.take_all("relaxed_rule");
    if (!relaxed) {
        return relaxed.error();
    }
    for (const std::string& text : relaxed.value()) {
        auto rule_id = RuleId::parse(text);
        if (!rule_id) {
            return rule_id.error();
        }
        record.relaxed_rules.push_back(rule_id.value());
    }
    auto scope_text = reader.take_string("scope");
    if (!scope_text) {
        return scope_text.error();
    }
    auto scope = ScopePath::parse_selector(scope_text.value());
    if (!scope) {
        return scope.error();
    }
    record.scope = scope.value();
    auto classes_text = reader.take_string("classes");
    if (!classes_text) {
        return classes_text.error();
    }
    auto classes = parse_class_selector_value(classes_text.value());
    if (!classes) {
        return classes.error();
    }
    record.classes = classes.value();
    auto issued_by_text = reader.take_string("issued_by");
    if (!issued_by_text) {
        return issued_by_text.error();
    }
    auto issued_by = AuthorityId::parse(issued_by_text.value());
    if (!issued_by) {
        return issued_by.error();
    }
    record.issued_by = issued_by.value();
    auto issued_at_text = reader.take_string("issued_at");
    if (!issued_at_text) {
        return issued_at_text.error();
    }
    auto issued_at = Instant::parse(issued_at_text.value());
    if (!issued_at) {
        return issued_at.error();
    }
    record.issued_at = issued_at.value();
    auto not_before_text = reader.take_string("not_before");
    if (!not_before_text) {
        return not_before_text.error();
    }
    auto not_before = Instant::parse(not_before_text.value());
    if (!not_before) {
        return not_before.error();
    }
    record.not_before = not_before.value();
    auto expires_text = reader.take_string("expires_at");
    if (!expires_text) {
        return expires_text.error();
    }
    auto expires_at = Instant::parse(expires_text.value());
    if (!expires_at) {
        return expires_at.error();
    }
    record.expires_at = expires_at.value();
    auto reason = reader.take_optional_string("reason", std::string());
    if (!reason) {
        return reason.error();
    }
    record.reason = reason.value();
    auto key_id_text = reader.take_string("key_id");
    if (!key_id_text) {
        return key_id_text.error();
    }
    auto key_id = KeyId::parse(key_id_text.value());
    if (!key_id) {
        return key_id.error();
    }
    record.key_id = key_id.value();
    if (reader.has("revoked_at")) {
        auto revoked_text = reader.take_string("revoked_at");
        if (!revoked_text) {
            return revoked_text.error();
        }
        auto revoked_at = Instant::parse(revoked_text.value());
        if (!revoked_at) {
            return revoked_at.error();
        }
        record.revoked_at = revoked_at.value();
    }
    auto mac = reader.take_digest("mac");
    if (!mac) {
        return mac.error();
    }
    record.mac = mac.value();
    MP_TRY(reader.finish());
    return record;
}

Result<ApprovalRecord> parse_approval_section(const TextDocument& document, const std::string& section) {
    SectionReader reader(document, section);
    const std::string_view id_text = std::string_view(section).substr(9u);
    auto id = ApprovalId::parse(id_text);
    if (!id) {
        return id.error();
    }
    ApprovalRecord record;
    record.id = id.value();
    auto generation_text = reader.take_string("generation");
    if (!generation_text) {
        return generation_text.error();
    }
    auto generation = PolicyGeneration::parse(generation_text.value());
    if (!generation) {
        return generation.error();
    }
    record.generation = generation.value();
    auto policy_digest = reader.take_digest("policy_digest");
    if (!policy_digest) {
        return policy_digest.error();
    }
    record.policy_digest = policy_digest.value();
    auto bound_digest = reader.take_digest("bound_request_digest");
    if (!bound_digest) {
        return bound_digest.error();
    }
    record.bound_request_digest = bound_digest.value();
    auto scope_text = reader.take_string("scope");
    if (!scope_text) {
        return scope_text.error();
    }
    auto scope = ScopePath::parse_selector(scope_text.value());
    if (!scope) {
        return scope.error();
    }
    record.scope = scope.value();
    auto classes_text = reader.take_string("classes");
    if (!classes_text) {
        return classes_text.error();
    }
    auto classes = parse_class_selector_value(classes_text.value());
    if (!classes) {
        return classes.error();
    }
    record.classes = classes.value();
    auto issued_by_text = reader.take_string("issued_by");
    if (!issued_by_text) {
        return issued_by_text.error();
    }
    auto issued_by = AuthorityId::parse(issued_by_text.value());
    if (!issued_by) {
        return issued_by.error();
    }
    record.issued_by = issued_by.value();
    auto level_text = reader.take_string("level");
    if (!level_text) {
        return level_text.error();
    }
    auto level = parse_level_value(level_text.value());
    if (!level) {
        return level.error();
    }
    record.level = level.value();
    auto issued_at_text = reader.take_string("issued_at");
    if (!issued_at_text) {
        return issued_at_text.error();
    }
    auto issued_at = Instant::parse(issued_at_text.value());
    if (!issued_at) {
        return issued_at.error();
    }
    record.issued_at = issued_at.value();
    auto not_before_text = reader.take_string("not_before");
    if (!not_before_text) {
        return not_before_text.error();
    }
    auto not_before = Instant::parse(not_before_text.value());
    if (!not_before) {
        return not_before.error();
    }
    record.not_before = not_before.value();
    auto expires_text = reader.take_string("expires_at");
    if (!expires_text) {
        return expires_text.error();
    }
    auto expires_at = Instant::parse(expires_text.value());
    if (!expires_at) {
        return expires_at.error();
    }
    record.expires_at = expires_at.value();
    auto reason = reader.take_optional_string("reason", std::string());
    if (!reason) {
        return reason.error();
    }
    record.reason = reason.value();
    auto key_id_text = reader.take_string("key_id");
    if (!key_id_text) {
        return key_id_text.error();
    }
    auto key_id = KeyId::parse(key_id_text.value());
    if (!key_id) {
        return key_id.error();
    }
    record.key_id = key_id.value();
    if (reader.has("revoked_at")) {
        auto revoked_text = reader.take_string("revoked_at");
        if (!revoked_text) {
            return revoked_text.error();
        }
        auto revoked_at = Instant::parse(revoked_text.value());
        if (!revoked_at) {
            return revoked_at.error();
        }
        record.revoked_at = revoked_at.value();
    }
    auto mac = reader.take_digest("mac");
    if (!mac) {
        return mac.error();
    }
    record.mac = mac.value();
    MP_TRY(reader.finish());
    return record;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public canonical serialisation.
// ---------------------------------------------------------------------------
std::string canonical_policy(const Policy& policy) {
    CanonicalWriter writer;
    writer.section("document");
    writer.field("format", document_format_id);
    writer.field("kind", kDocumentKindPolicy);
    write_policy_body(writer, policy);
    return writer.take();
}

std::string canonical_bundle(const PolicyBundle& bundle) {
    CanonicalWriter writer;
    writer.section("document");
    writer.field("format", document_format_id);
    writer.field("kind", kDocumentKindBundle);
    write_policy_body(writer, bundle.policy());

    std::vector<const AuthorityRecord*> authorities;
    authorities.reserve(bundle.authorities().size());
    for (const AuthorityRecord& record : bundle.authorities()) {
        authorities.push_back(&record);
    }
    std::sort(authorities.begin(), authorities.end(),
              [](const AuthorityRecord* left, const AuthorityRecord* right) { return left->id < right->id; });
    for (const AuthorityRecord* record : authorities) {
        writer.section("authority " + record->id.value());
        writer.field("level", record->level.value());
        if (!record->description.empty()) {
            writer.field("description", record->description);
        }
    }

    std::vector<const ExceptionRecord*> exceptions;
    exceptions.reserve(bundle.exceptions().size());
    for (const ExceptionRecord& record : bundle.exceptions()) {
        exceptions.push_back(&record);
    }
    std::sort(exceptions.begin(), exceptions.end(),
              [](const ExceptionRecord* left, const ExceptionRecord* right) { return left->id < right->id; });
    for (const ExceptionRecord* record : exceptions) {
        write_exception_body(writer, *record, true);
    }

    std::vector<const ApprovalRecord*> approvals;
    approvals.reserve(bundle.approvals().size());
    for (const ApprovalRecord& record : bundle.approvals()) {
        approvals.push_back(&record);
    }
    std::sort(approvals.begin(), approvals.end(),
              [](const ApprovalRecord* left, const ApprovalRecord* right) { return left->id < right->id; });
    for (const ApprovalRecord* record : approvals) {
        write_approval_body(writer, *record, true);
    }

    writer.section("registry");
    writer.field("control_epoch", bundle.control_epoch().value());
    writer.field("registry_revision", bundle.registry_revision().value());
    return writer.take();
}

std::string canonical_request(const EvaluationRequest& request) {
    CanonicalWriter writer;
    writer.section("document");
    writer.field("format", document_format_id);
    writer.field("kind", kDocumentKindRequest);
    write_request_body(writer, request);
    return writer.take();
}

std::string canonical_evidence(const EvidenceBundle& evidence) {
    CanonicalWriter writer;
    writer.section("evidence");
    writer.field("source", evidence.source.value());
    writer.field("epoch", evidence.epoch.value());
    writer.field("observed_at", evidence.observed_at.format());
    std::vector<const ClassEvidence*> sorted;
    sorted.reserve(evidence.classes.size());
    for (const ClassEvidence& entry : evidence.classes) {
        sorted.push_back(&entry);
    }
    std::sort(sorted.begin(), sorted.end(), [](const ClassEvidence* left, const ClassEvidence* right) {
        return left->obligation_class < right->obligation_class;
    });
    for (const ClassEvidence* entry : sorted) {
        writer.section("evidence-class " + entry->obligation_class.value());
        writer.field("state", to_string(entry->state));
        writer.field("surviving_units", entry->surviving_units);
        writer.field("total_units", entry->total_units);
        writer.field("observed_at", entry->observed_at.format());
        writer.field("source", entry->source.value());
        writer.field("epoch", entry->epoch.value());
    }
    return writer.take();
}

std::string canonical_interlock_report(const InterlockReport& report) {
    CanonicalWriter writer;
    writer.section("interlock-report");
    writer.field("source", report.source.value());
    writer.field("epoch", report.epoch.value());
    writer.field("observed_at", report.observed_at.format());
    std::vector<const InterlockAssertion*> sorted;
    sorted.reserve(report.assertions.size());
    for (const InterlockAssertion& assertion : report.assertions) {
        sorted.push_back(&assertion);
    }
    std::sort(sorted.begin(), sorted.end(), [](const InterlockAssertion* left, const InterlockAssertion* right) {
        return left->interlock < right->interlock;
    });
    for (const InterlockAssertion* assertion : sorted) {
        writer.section("interlock " + assertion->interlock.value());
        writer.field("active", assertion->active);
    }
    return writer.take();
}

std::string canonical_decision(const Decision& decision) {
    CanonicalWriter writer;
    write_decision_body(writer, decision, false);
    return writer.take();
}

std::string decision_document(const Decision& decision) {
    CanonicalWriter writer;
    write_decision_body(writer, decision, true);
    return writer.take();
}

std::string key_document(const KeySet& keys) {
    CanonicalWriter writer;
    writer.section("document");
    writer.field("format", document_format_id);
    writer.field("kind", kDocumentKindKeys);
    std::vector<const AuthorityKey*> sorted;
    sorted.reserve(keys.keys().size());
    for (const AuthorityKey& key : keys.keys()) {
        sorted.push_back(&key);
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const AuthorityKey* left, const AuthorityKey* right) { return left->id < right->id; });
    for (const AuthorityKey* key : sorted) {
        writer.section("key " + key->id.value());
        writer.field("secret", to_hex(key->secret.data(), key->secret.size()));
    }
    return writer.take();
}

std::string canonical_exception_record(const ExceptionRecord& record) {
    CanonicalWriter writer;
    write_exception_body(writer, record, true);
    return writer.take();
}

std::string canonical_approval_record(const ApprovalRecord& record) {
    CanonicalWriter writer;
    write_approval_body(writer, record, true);
    return writer.take();
}

std::string exception_mac_payload(const ExceptionRecord& record) {
    CanonicalWriter writer;
    write_exception_body(writer, record, false);
    return writer.take();
}

std::string approval_mac_payload(const ApprovalRecord& record) {
    CanonicalWriter writer;
    write_approval_body(writer, record, false);
    return writer.take();
}

Result<bool> verify_exception_mac(const KeySet& keys, const ExceptionRecord& record) {
    if (!record.key_id.is_set()) {
        return make_error(Code::KeyUnknown, "exception declares no key identifier");
    }
    const AuthorityKey* key = keys.find(record.key_id);
    if (key == nullptr) {
        return make_error(Code::KeyUnknown, "no key material is available for key '" + record.key_id.value() + "'");
    }
    if (record.mac.is_zero()) {
        return make_error(Code::MacMissing, "exception MAC is absent");
    }
    const std::string payload = exception_mac_payload(record);
    const std::string_view key_bytes(reinterpret_cast<const char*>(key->secret.data()), key->secret.size());
    const Digest256 expected = hmac_sha256(key_bytes, payload);
    if (!constant_time_equal(expected.bytes().data(), record.mac.bytes().data(), Digest256::kBytes)) {
        return make_error(Code::MacInvalid, "exception MAC does not verify");
    }
    return true;
}

Result<bool> verify_approval_mac(const KeySet& keys, const ApprovalRecord& record) {
    if (!record.key_id.is_set()) {
        return make_error(Code::KeyUnknown, "approval declares no key identifier");
    }
    const AuthorityKey* key = keys.find(record.key_id);
    if (key == nullptr) {
        return make_error(Code::KeyUnknown, "no key material is available for key '" + record.key_id.value() + "'");
    }
    if (record.mac.is_zero()) {
        return make_error(Code::MacMissing, "approval MAC is absent");
    }
    const std::string payload = approval_mac_payload(record);
    const std::string_view key_bytes(reinterpret_cast<const char*>(key->secret.data()), key->secret.size());
    const Digest256 expected = hmac_sha256(key_bytes, payload);
    if (!constant_time_equal(expected.bytes().data(), record.mac.bytes().data(), Digest256::kBytes)) {
        return make_error(Code::MacInvalid, "approval MAC does not verify");
    }
    return true;
}

// ---------------------------------------------------------------------------
// Digests.
// ---------------------------------------------------------------------------
Digest256 Policy::digest() const { return sha256(canonical_policy(*this)); }
Digest256 PolicyBundle::digest() const { return sha256(canonical_bundle(*this)); }
Digest256 EvaluationRequest::digest() const { return sha256(canonical_request(*this)); }
Digest256 Decision::digest() const { return sha256(canonical_decision(*this)); }

// ---------------------------------------------------------------------------
// Public parsers.
// ---------------------------------------------------------------------------
Result<Policy> parse_policy_document(std::string_view text) {
    auto document = parse_text_document(text, kLimits);
    if (!document) {
        return document.error();
    }
    auto header = read_document_header(document.value(), kDocumentKindPolicy);
    if (!header) {
        return header.error();
    }
    auto allowed = check_allowed_sections(document.value(), {"document", "policy"}, {"rule "});
    if (!allowed) {
        return allowed.error();
    }
    return parse_policy_sections(document.value());
}

Result<AuthorityRecord> parse_authority_section(const TextDocument& document, const std::string& section) {
    SectionReader reader(document, section);
    auto id = AuthorityId::parse(std::string_view(section).substr(10u));
    if (!id) {
        return id.error();
    }
    AuthorityRecord record;
    record.id = id.value();
    MP_ASSIGN(level_text, reader.take_string("level"));
    auto level = parse_level_value(level_text);
    if (!level) {
        return level.error();
    }
    record.level = level.value();
    MP_ASSIGN(description, reader.take_optional_string("description", std::string()));
    record.description = description;
    MP_TRY(reader.finish());
    return record;
}

Result<PolicyBundle> parse_bundle_document(std::string_view text) {
    auto document = parse_text_document(text, kLimits);
    if (!document) {
        return document.error();
    }
    auto header = read_document_header(document.value(), kDocumentKindBundle);
    if (!header) {
        return header.error();
    }
    auto allowed = check_allowed_sections(document.value(), {"document", "policy", "registry"},
                                           {"rule ", "authority ", "exception ", "approval "});
    if (!allowed) {
        return allowed.error();
    }
    MP_TRY(require_single_section(document.value(), "registry"));

    auto policy = parse_policy_sections(document.value());
    if (!policy) {
        return policy.error();
    }

    SectionReader registry(document.value(), "registry");
    MP_ASSIGN(control_epoch_text, registry.take_string("control_epoch"));
    auto control_epoch = ControlEpoch::parse(control_epoch_text);
    if (!control_epoch) {
        return control_epoch.error();
    }
    MP_ASSIGN(registry_revision_text, registry.take_string("registry_revision"));
    auto registry_revision = Revision::parse(registry_revision_text);
    if (!registry_revision) {
        return registry_revision.error();
    }
    MP_TRY(registry.finish());

    std::vector<AuthorityRecord> authorities;
    for (const std::string& section : collect_sections(document.value(), "authority ")) {
        auto record = parse_authority_section(document.value(), section);
        if (!record) {
            return record.error();
        }
        authorities.push_back(std::move(record.value()));
    }
    std::vector<ExceptionRecord> exceptions;
    for (const std::string& section : collect_sections(document.value(), "exception ")) {
        auto record = parse_exception_section(document.value(), section);
        if (!record) {
            return record.error();
        }
        exceptions.push_back(std::move(record.value()));
    }
    std::vector<ApprovalRecord> approvals;
    for (const std::string& section : collect_sections(document.value(), "approval ")) {
        auto record = parse_approval_section(document.value(), section);
        if (!record) {
            return record.error();
        }
        approvals.push_back(std::move(record.value()));
    }
    return PolicyBundle::create(std::move(policy.value()), std::move(authorities), std::move(exceptions),
                                std::move(approvals), control_epoch.value(), registry_revision.value());
}

Result<EvaluationRequest> parse_request_document(std::string_view text) {
    auto document = parse_text_document(text, kLimits);
    if (!document) {
        return document.error();
    }
    auto header = read_document_header(document.value(), kDocumentKindRequest);
    if (!header) {
        return header.error();
    }
    auto allowed = check_allowed_sections(document.value(), {"document", "request", "evidence", "interlock-report"},
                                           {"evidence-class ", "interlock "});
    if (!allowed) {
        return allowed.error();
    }
    MP_TRY(require_single_section(document.value(), "request"));
    SectionReader reader(document.value(), "request");

    MP_ASSIGN(context_text, reader.take_string("context_id"));
    auto context_id = ContextId::parse(context_text);
    if (!context_id) {
        return context_id.error();
    }
    MP_ASSIGN(request_text, reader.take_string("request_id"));
    auto request_id = RequestId::parse(request_text);
    if (!request_id) {
        return request_id.error();
    }
    MP_ASSIGN(principal_text, reader.take_string("requested_by"));
    auto requested_by = PrincipalId::parse(principal_text);
    if (!requested_by) {
        return requested_by.error();
    }
    MP_ASSIGN(generation_text, reader.take_string("expected_generation"));
    auto expected_generation = PolicyGeneration::parse(generation_text);
    if (!expected_generation) {
        return expected_generation.error();
    }
    std::optional<Digest256> expected_digest;
    if (reader.has("expected_policy_digest")) {
        auto digest = reader.take_digest("expected_policy_digest");
        if (!digest) {
            return digest.error();
        }
        expected_digest = digest.value();
    }
    MP_ASSIGN(window_text, reader.take_string("window"));
    auto window = parse_interval_value(window_text);
    if (!window) {
        return window.error();
    }
    MP_ASSIGN(concurrent, reader.take_u64("concurrent_maintenance"));
    if (concurrent > 1000000u) {
        return make_error(Code::ValueOutOfRange, "concurrent maintenance count exceeds 1000000");
    }
    MP_ASSIGN(evaluated_text, reader.take_string("evaluated_at"));
    auto evaluated_at = Instant::parse(evaluated_text);
    if (!evaluated_at) {
        return evaluated_at.error();
    }

    std::vector<ScopePath> scopes;
    MP_ASSIGN(scope_values, reader.take_all("scope"));
    for (const std::string& scope_text : scope_values) {
        auto scope = ScopePath::parse(scope_text);
        if (!scope) {
            return scope.error();
        }
        scopes.push_back(scope.value());
    }
    std::vector<ObligationClassId> classes;
    MP_ASSIGN(class_values, reader.take_all("class"));
    for (const std::string& class_text : class_values) {
        auto id = ObligationClassId::parse(class_text);
        if (!id) {
            return id.error();
        }
        classes.push_back(id.value());
    }
    std::vector<ExceptionId> exceptions;
    MP_ASSIGN(exception_values, reader.take_all("exception_ref"));
    for (const std::string& exception_text : exception_values) {
        auto id = ExceptionId::parse(exception_text);
        if (!id) {
            return id.error();
        }
        exceptions.push_back(id.value());
    }
    std::vector<ApprovalId> approvals;
    MP_ASSIGN(approval_values, reader.take_all("approval_ref"));
    for (const std::string& approval_text : approval_values) {
        auto id = ApprovalId::parse(approval_text);
        if (!id) {
            return id.error();
        }
        approvals.push_back(id.value());
    }
    MP_TRY(reader.finish());

    std::optional<EvidenceBundle> evidence;
    if (document.value().has_section("evidence")) {
        SectionReader evidence_reader(document.value(), "evidence");
        EvidenceBundle bundle;
        MP_ASSIGN(source_text, evidence_reader.take_string("source"));
        auto source = EvidenceSourceId::parse(source_text);
        if (!source) {
            return source.error();
        }
        bundle.source = source.value();
        MP_ASSIGN(epoch_text, evidence_reader.take_string("epoch"));
        auto epoch = EvidenceEpoch::parse(epoch_text);
        if (!epoch) {
            return epoch.error();
        }
        bundle.epoch = epoch.value();
        MP_ASSIGN(observed_text, evidence_reader.take_string("observed_at"));
        auto observed_at = Instant::parse(observed_text);
        if (!observed_at) {
            return observed_at.error();
        }
        bundle.observed_at = observed_at.value();
        MP_TRY(evidence_reader.finish());

        for (const std::string& section : collect_sections(document.value(), "evidence-class ")) {
            SectionReader class_reader(document.value(), section);
            auto class_id = ObligationClassId::parse(std::string_view(section).substr(15u));
            if (!class_id) {
                return class_id.error();
            }
            ClassEvidence entry;
            entry.obligation_class = class_id.value();
            MP_ASSIGN(state_text, class_reader.take_string("state"));
            if (!measurement_state_from_name(state_text, entry.state)) {
                return make_error(Code::UnknownEnumValue, "measurement state is not recognised");
            }
            MP_ASSIGN(surviving, class_reader.take_u64("surviving_units"));
            if (surviving > 1000000000ull) {
                return make_error(Code::ValueOutOfRange, "surviving unit count is out of range");
            }
            entry.surviving_units = static_cast<std::uint32_t>(surviving);
            MP_ASSIGN(total, class_reader.take_u64("total_units"));
            if (total > 1000000000ull) {
                return make_error(Code::ValueOutOfRange, "total unit count is out of range");
            }
            entry.total_units = static_cast<std::uint32_t>(total);
            MP_ASSIGN(class_observed_text, class_reader.take_string("observed_at"));
            auto class_observed = Instant::parse(class_observed_text);
            if (!class_observed) {
                return class_observed.error();
            }
            entry.observed_at = class_observed.value();
            MP_ASSIGN(class_source_text, class_reader.take_string("source"));
            auto class_source = EvidenceSourceId::parse(class_source_text);
            if (!class_source) {
                return class_source.error();
            }
            entry.source = class_source.value();
            MP_ASSIGN(class_epoch_text, class_reader.take_string("epoch"));
            auto class_epoch = EvidenceEpoch::parse(class_epoch_text);
            if (!class_epoch) {
                return class_epoch.error();
            }
            entry.epoch = class_epoch.value();
            MP_TRY(class_reader.finish());
            bundle.classes.push_back(std::move(entry));
        }
        evidence = std::move(bundle);
    }

    std::optional<InterlockReport> interlocks;
    if (document.value().has_section("interlock-report")) {
        SectionReader report_reader(document.value(), "interlock-report");
        InterlockReport report;
        MP_ASSIGN(report_source_text, report_reader.take_string("source"));
        auto report_source = EvidenceSourceId::parse(report_source_text);
        if (!report_source) {
            return report_source.error();
        }
        report.source = report_source.value();
        MP_ASSIGN(report_epoch_text, report_reader.take_string("epoch"));
        auto report_epoch = EvidenceEpoch::parse(report_epoch_text);
        if (!report_epoch) {
            return report_epoch.error();
        }
        report.epoch = report_epoch.value();
        MP_ASSIGN(report_observed_text, report_reader.take_string("observed_at"));
        auto report_observed = Instant::parse(report_observed_text);
        if (!report_observed) {
            return report_observed.error();
        }
        report.observed_at = report_observed.value();
        MP_TRY(report_reader.finish());
        for (const std::string& section : collect_sections(document.value(), "interlock ")) {
            SectionReader interlock_reader(document.value(), section);
            auto interlock_id = InterlockId::parse(std::string_view(section).substr(10u));
            if (!interlock_id) {
                return interlock_id.error();
            }
            InterlockAssertion assertion;
            assertion.interlock = interlock_id.value();
            MP_ASSIGN(active, interlock_reader.take_bool("active"));
            assertion.active = active;
            MP_TRY(interlock_reader.finish());
            report.assertions.push_back(std::move(assertion));
        }
        interlocks = std::move(report);
    }

    return EvaluationRequest::create(context_id.value(), request_id.value(), std::move(scopes), std::move(classes),
                                     window.value(), requested_by.value(), expected_generation.value(),
                                     expected_digest, std::move(exceptions), std::move(approvals),
                                     std::move(evidence), std::move(interlocks),
                                     static_cast<std::uint32_t>(concurrent), evaluated_at.value());
}

Result<Decision> parse_decision_document(std::string_view text) {
    auto document = parse_text_document(text, kLimits);
    if (!document) {
        return document.error();
    }
    auto header = read_document_header(document.value(), kDocumentKindDecision);
    if (!header) {
        return header.error();
    }
    auto allowed = check_allowed_sections(document.value(),
                                           {"document", "decision", "bindings", "applied-rules",
                                            "honored-exceptions", "exception-bindings", "approval-bindings"},
                                           {"finding "});
    if (!allowed) {
        return allowed.error();
    }
    MP_TRY(require_single_section(document.value(), "decision"));
    MP_TRY(require_single_section(document.value(), "bindings"));

    Decision decision;
    std::optional<Digest256> declared_digest;
    {
        SectionReader reader(document.value(), "decision");
        MP_ASSIGN(outcome_text, reader.take_string("outcome"));
        if (!outcome_from_name(outcome_text, decision.outcome)) {
            return make_error(Code::UnknownEnumValue, "decision outcome is not recognised");
        }
        MP_ASSIGN(replay_text, reader.take_string("replay"));
        if (!replay_disposition_from_name(replay_text, decision.replay)) {
            return make_error(Code::UnknownEnumValue, "replay disposition is not recognised");
        }
        if (reader.has("required_level")) {
            MP_ASSIGN(level_text, reader.take_string("required_level"));
            auto level = parse_level_value(level_text);
            if (!level) {
                return level.error();
            }
            decision.required_level = level.value();
        }
        if (reader.has("digest")) {
            auto digest = reader.take_digest("digest");
            if (!digest) {
                return digest.error();
            }
            declared_digest = digest.value();
        }
        MP_TRY(reader.finish());
    }

    {
        SectionReader reader(document.value(), "bindings");
        DecisionBindings& bindings = decision.bindings;
        MP_ASSIGN(policy_id_text, reader.take_string("policy_id"));
        auto policy_id = PolicyId::parse(policy_id_text);
        if (!policy_id) {
            return policy_id.error();
        }
        bindings.policy_id = policy_id.value();
        MP_ASSIGN(policy_generation_text, reader.take_string("policy_generation"));
        auto policy_generation = PolicyGeneration::parse(policy_generation_text);
        if (!policy_generation) {
            return policy_generation.error();
        }
        bindings.policy_generation = policy_generation.value();
        MP_ASSIGN(policy_digest, reader.take_digest("policy_digest"));
        bindings.policy_digest = policy_digest;
        MP_ASSIGN(control_epoch_text, reader.take_string("control_epoch"));
        auto control_epoch = ControlEpoch::parse(control_epoch_text);
        if (!control_epoch) {
            return control_epoch.error();
        }
        bindings.control_epoch = control_epoch.value();
        MP_ASSIGN(registry_revision_text, reader.take_string("registry_revision"));
        auto registry_revision = Revision::parse(registry_revision_text);
        if (!registry_revision) {
            return registry_revision.error();
        }
        bindings.registry_revision = registry_revision.value();
        MP_ASSIGN(context_id_text, reader.take_string("context_id"));
        auto context_id = ContextId::parse(context_id_text);
        if (!context_id) {
            return context_id.error();
        }
        bindings.context_id = context_id.value();
        MP_ASSIGN(request_id_text, reader.take_string("request_id"));
        auto request_id = RequestId::parse(request_id_text);
        if (!request_id) {
            return request_id.error();
        }
        bindings.request_id = request_id.value();
        MP_ASSIGN(request_digest, reader.take_digest("request_digest"));
        bindings.request_digest = request_digest;
        if (reader.has("evidence_digest")) {
            auto digest = reader.take_digest("evidence_digest");
            if (!digest) {
                return digest.error();
            }
            bindings.evidence_digest = digest.value();
        }
        if (reader.has("evidence_epoch")) {
            MP_ASSIGN(evidence_epoch_text, reader.take_string("evidence_epoch"));
            auto evidence_epoch = EvidenceEpoch::parse(evidence_epoch_text);
            if (!evidence_epoch) {
                return evidence_epoch.error();
            }
            bindings.evidence_epoch = evidence_epoch.value();
        }
        if (reader.has("interlock_digest")) {
            auto digest = reader.take_digest("interlock_digest");
            if (!digest) {
                return digest.error();
            }
            bindings.interlock_digest = digest.value();
        }
        MP_ASSIGN(evaluated_text, reader.take_string("evaluated_at"));
        auto evaluated_at = Instant::parse(evaluated_text);
        if (!evaluated_at) {
            return evaluated_at.error();
        }
        bindings.evaluated_at = evaluated_at.value();
        MP_ASSIGN(semantics_text, reader.take_u64("semantics_version"));
        if (semantics_text > 0xFFFFFFFFull) {
            return make_error(Code::ValueOutOfRange, "semantics version is out of range");
        }
        bindings.semantics_version = static_cast<std::uint32_t>(semantics_text);
        MP_ASSIGN(digest_format_text, reader.take_u64("digest_format_version"));
        if (digest_format_text > 0xFFFFFFFFull) {
            return make_error(Code::ValueOutOfRange, "digest format version is out of range");
        }
        bindings.digest_format_version = static_cast<std::uint32_t>(digest_format_text);
        MP_TRY(reader.finish());
    }

    {
        SectionReader reader(document.value(), "applied-rules");
        MP_ASSIGN(values, reader.take_all("rule"));
        for (const std::string& value : values) {
            auto id = RuleId::parse(value);
            if (!id) {
                return id.error();
            }
            decision.applied_rules.push_back(id.value());
        }
        MP_TRY(reader.finish());
    }
    {
        SectionReader reader(document.value(), "honored-exceptions");
        MP_ASSIGN(values, reader.take_all("exception"));
        for (const std::string& value : values) {
            auto id = ExceptionId::parse(value);
            if (!id) {
                return id.error();
            }
            decision.honored_exceptions.push_back(id.value());
        }
        MP_TRY(reader.finish());
    }
    {
        SectionReader reader(document.value(), "exception-bindings");
        MP_ASSIGN(values, reader.take_all("digest"));
        for (const std::string& value : values) {
            auto digest = Digest256::from_hex(value);
            if (!digest) {
                return digest.error();
            }
            decision.bindings.exception_digests.push_back(digest.value());
        }
        MP_TRY(reader.finish());
    }
    {
        SectionReader reader(document.value(), "approval-bindings");
        MP_ASSIGN(values, reader.take_all("digest"));
        for (const std::string& value : values) {
            auto digest = Digest256::from_hex(value);
            if (!digest) {
                return digest.error();
            }
            decision.bindings.approval_digests.push_back(digest.value());
        }
        MP_TRY(reader.finish());
    }

    for (const std::string& section : collect_sections(document.value(), "finding ")) {
        SectionReader reader(document.value(), section);
        Finding finding;
        MP_ASSIGN(code_text, reader.take_string("code"));
        if (!code_from_name(code_text, finding.code)) {
            return make_error(Code::UnknownEnumValue, "finding code is not recognised");
        }
        if (reader.has("rule")) {
            MP_ASSIGN(value, reader.take_string("rule"));
            auto id = RuleId::parse(value);
            if (!id) {
                return id.error();
            }
            finding.rule = id.value();
        }
        if (reader.has("exception")) {
            MP_ASSIGN(value, reader.take_string("exception"));
            auto id = ExceptionId::parse(value);
            if (!id) {
                return id.error();
            }
            finding.exception = id.value();
        }
        if (reader.has("approval")) {
            MP_ASSIGN(value, reader.take_string("approval"));
            auto id = ApprovalId::parse(value);
            if (!id) {
                return id.error();
            }
            finding.approval = id.value();
        }
        if (reader.has("class")) {
            MP_ASSIGN(value, reader.take_string("class"));
            auto id = ObligationClassId::parse(value);
            if (!id) {
                return id.error();
            }
            finding.obligation_class = id.value();
        }
        MP_ASSIGN(detail, reader.take_optional_string("detail", std::string()));
        finding.detail = detail;
        MP_TRY(reader.finish());
        decision.findings.push_back(std::move(finding));
    }

    sort_findings(decision.findings);
    std::sort(decision.applied_rules.begin(), decision.applied_rules.end());
    std::sort(decision.honored_exceptions.begin(), decision.honored_exceptions.end());
    std::sort(decision.bindings.exception_digests.begin(), decision.bindings.exception_digests.end());
    std::sort(decision.bindings.approval_digests.begin(), decision.bindings.approval_digests.end());

    if (declared_digest.has_value()) {
        if (!(declared_digest.value() == decision.digest())) {
            return make_error(Code::StoreCorrupt, "decision digest does not match its content");
        }
    }
    return decision;
}

Result<KeySet> parse_key_document(std::string_view text) {
    auto document = parse_text_document(text, kLimits);
    if (!document) {
        return document.error();
    }
    auto header = read_document_header(document.value(), kDocumentKindKeys);
    if (!header) {
        return header.error();
    }
    auto allowed = check_allowed_sections(document.value(), {"document"}, {"key "});
    if (!allowed) {
        return allowed.error();
    }
    std::vector<AuthorityKey> keys;
    for (const std::string& section : collect_sections(document.value(), "key ")) {
        SectionReader reader(document.value(), section);
        auto id = KeyId::parse(std::string_view(section).substr(4u));
        if (!id) {
            return id.error();
        }
        AuthorityKey key;
        key.id = id.value();
        MP_ASSIGN(secret_text, reader.take_string("secret"));
        auto secret = bytes_from_hex(secret_text);
        if (!secret) {
            return secret.error();
        }
        key.secret = std::move(secret.value());
        MP_TRY(reader.finish());
        keys.push_back(std::move(key));
    }
    return KeySet::create(std::move(keys));
}

#undef MP_TRY
#undef MP_ASSIGN

}  // namespace maintpol
