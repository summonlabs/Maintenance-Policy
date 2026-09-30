#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "maintpol/error.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Bounds. Every externally supplied quantity is bounded before use; a value
// beyond its bound is an error, never a truncation.
// ---------------------------------------------------------------------------
inline constexpr std::size_t kMaxIdentifierLength = 64;
inline constexpr std::size_t kMaxDescriptionLength = 256;
inline constexpr std::size_t kMaxScopeSegments = 16;
inline constexpr std::size_t kMaxScopeTextLength = 256;
inline constexpr std::size_t kMaxRulesPerPolicy = 4096;
inline constexpr std::size_t kMaxClassesPerSelector = 64;
inline constexpr std::size_t kMaxRecurrenceOccurrences = 512;
inline constexpr std::size_t kMaxExceptionsPerBundle = 1024;
inline constexpr std::size_t kMaxApprovalsPerBundle = 4096;
inline constexpr std::size_t kMaxEvidenceClasses = 256;
inline constexpr std::size_t kMaxReferenceListLength = 256;
inline constexpr std::size_t kMaxAuthoritiesPerPolicy = 64;
inline constexpr std::size_t kMaxRequestScopes = 32;
inline constexpr std::size_t kMaxRequestClasses = 64;
inline constexpr std::size_t kMaxTextDocumentBytes = 4u * 1024u * 1024u;
inline constexpr std::size_t kMaxTextLineBytes = 4096;
inline constexpr std::size_t kMaxTextLines = 200000;
inline constexpr std::size_t kMaxJournalRecords = 1000000;
inline constexpr std::size_t kMaxPolicyHistoryRecords = 1000000;
inline constexpr std::size_t kMaxEvidenceSources = 32;
inline constexpr std::size_t kMaxRecordBytes = 16u * 1024u * 1024u;
inline constexpr std::size_t kMaxStoreRecordsPerGeneration = 8;

// ---------------------------------------------------------------------------
// Text validation. All text that crosses an API or persistence boundary is
// validated as UTF-8 and bounded before it is used.
// ---------------------------------------------------------------------------
MAINTPOL_API bool is_valid_utf8(std::string_view text, std::size_t* error_offset = nullptr);

enum class IdKind : std::uint8_t {
    // Identifiers: [A-Za-z0-9][A-Za-z0-9._:-]*, used for policy, rule,
    // exception, approval, context, authority and key identities.
    Identifier,
    // Scope segments: [A-Za-z0-9][A-Za-z0-9._-]*, without ':' so that a scope
    // can never be confused with an authority-qualified identity.
    ScopeSegment,
};

MAINTPOL_API Result<std::string> validate_identifier(std::string_view text, IdKind kind);
MAINTPOL_API Result<std::string> validate_description(std::string_view text);
MAINTPOL_API bool ascii_iequals(std::string_view left, std::string_view right);

// ---------------------------------------------------------------------------
// Strongly typed string identity.
// ---------------------------------------------------------------------------
template <typename Tag>
class Str {
public:
    Str() = default;

    static Result<Str> parse(std::string_view text) {
        auto validated = validate_identifier(text, IdKind::Identifier);
        if (!validated) {
            return validated.error();
        }
        Str result;
        result.value_ = std::move(validated.value());
        return result;
    }

    static Result<Str> parse_kind(std::string_view text, IdKind kind) {
        auto validated = validate_identifier(text, kind);
        if (!validated) {
            return validated.error();
        }
        Str result;
        result.value_ = std::move(validated.value());
        return result;
    }

    bool is_set() const { return !value_.empty(); }
    const std::string& value() const { return value_; }
    std::string_view view() const { return value_; }

    friend bool operator==(const Str&, const Str&) = default;
    friend std::strong_ordering operator<=>(const Str&, const Str&) = default;

private:
    std::string value_;
};

struct TagPolicyId;
struct TagRuleId;
struct TagFacilityId;
struct TagObligationClassId;
struct TagExceptionId;
struct TagApprovalId;
struct TagAuthorityId;
struct TagKeyId;
struct TagContextId;
struct TagRequestId;
struct TagEvidenceSourceId;
struct TagPrincipalId;
struct TagInterlockId;

using PolicyId = Str<TagPolicyId>;
using RuleId = Str<TagRuleId>;
using FacilityId = Str<TagFacilityId>;
using ObligationClassId = Str<TagObligationClassId>;
using ExceptionId = Str<TagExceptionId>;
using ApprovalId = Str<TagApprovalId>;
using AuthorityId = Str<TagAuthorityId>;
using KeyId = Str<TagKeyId>;
using ContextId = Str<TagContextId>;
using RequestId = Str<TagRequestId>;
using EvidenceSourceId = Str<TagEvidenceSourceId>;
using PrincipalId = Str<TagPrincipalId>;
using InterlockId = Str<TagInterlockId>;

// ---------------------------------------------------------------------------
// Strongly typed monotonic counter. Zero is never a valid value: an unset
// counter is std::optional, not a magic number.
// ---------------------------------------------------------------------------
template <typename Tag, std::uint64_t MaxValue = (std::numeric_limits<std::uint64_t>::max)()>
class Counter {
public:
    static constexpr std::uint64_t kMaxValue = MaxValue;

    Counter() = default;

    static Result<Counter> from_value(std::uint64_t value) {
        if (value == 0) {
            return make_error(Code::ValueOutOfRange, "counter value must be at least 1");
        }
        if (value > MaxValue) {
            return make_error(Code::ValueOutOfRange, "counter value exceeds the permitted maximum");
        }
        Counter result;
        result.value_ = value;
        return result;
    }

    static Result<Counter> parse(std::string_view text) {
        if (text.empty() || text.size() > 20) {
            return make_error(Code::NumberMalformed, "counter must be a bounded decimal integer");
        }
        if (text.size() > 1 && text[0] == '0') {
            return make_error(Code::NumberMalformed, "counter must not have leading zeros");
        }
        std::uint64_t value = 0;
        for (char character : text) {
            if (character < '0' || character > '9') {
                return make_error(Code::NumberMalformed, "counter must be a decimal integer");
            }
            const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
            if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10u) {
                return make_error(Code::IntegerOverflow, "counter value overflows");
            }
            value = (value * 10u) + digit;
        }
        return from_value(value);
    }

    // Advances by exactly one; exhaustion is an error, never a wrap.
    Result<Counter> next() const {
        if (value_ >= kMaxValue) {
            return make_error(Code::IntegerOverflow, "counter cannot advance further");
        }
        Counter result;
        result.value_ = value_ + 1u;
        return result;
    }

    bool is_set() const { return value_ != 0; }
    std::uint64_t value() const { return value_; }
    std::string format() const { return std::to_string(value_); }

    friend bool operator==(const Counter&, const Counter&) = default;
    friend std::strong_ordering operator<=>(const Counter&, const Counter&) = default;

private:
    std::uint64_t value_ = 0;
};

struct TagPolicyGeneration;
struct TagRevision;
struct TagEvidenceEpoch;
struct TagControlEpoch;
struct TagSequenceNumber;
struct TagAuthorityLevel;

using PolicyGeneration = Counter<TagPolicyGeneration>;
using Revision = Counter<TagRevision>;
using EvidenceEpoch = Counter<TagEvidenceEpoch>;
using ControlEpoch = Counter<TagControlEpoch>;
using SequenceNumber = Counter<TagSequenceNumber>;
// Authority levels are a small closed ladder: 1 is the least authority, 8 the
// greatest. Escalation rules and approvals both use this scale.
using AuthorityLevel = Counter<TagAuthorityLevel, 8>;

// ---------------------------------------------------------------------------
// Scope: facility plus an optional '/'-separated path of segments.
//
// A concrete scope names an actual facility region ("FAC-1/fabric/pod-a").
// A selector may use '*' as a whole facility or as a whole segment, and
// matches a concrete scope when the facility matches and the selector
// segments are a segment-wise prefix of the concrete segments.
// ---------------------------------------------------------------------------
class ScopePath {
public:
    ScopePath() = default;

    static Result<ScopePath> parse(std::string_view text);
    static Result<ScopePath> parse_selector(std::string_view text);

    bool is_set() const { return !facility_.empty(); }
    bool has_wildcard() const { return wildcard_; }
    const std::string& facility() const { return facility_; }
    const std::vector<std::string>& segments() const { return segments_; }

    std::string format() const;
    // True when this selector covers the concrete scope.
    bool matches(const ScopePath& concrete) const;

    friend bool operator==(const ScopePath&, const ScopePath&) = default;
    friend std::strong_ordering operator<=>(const ScopePath&, const ScopePath&) = default;

private:
    static Result<ScopePath> parse_impl(std::string_view text, bool allow_wildcard);

    std::string facility_;
    std::vector<std::string> segments_;
    bool wildcard_ = false;
};

// Two concrete scopes intersect when one is a region prefix of the other.
MAINTPOL_API bool scopes_intersect(const ScopePath& left, const ScopePath& right);

// ---------------------------------------------------------------------------
// Class selector: either every obligation class or an explicit non-empty set.
// An empty explicit set is invalid, so "no classes" can never be confused
// with "all classes".
// ---------------------------------------------------------------------------
struct ClassSelector {
    bool all = false;
    std::vector<ObligationClassId> classes;

    bool matches(const ObligationClassId& candidate) const;
    std::string format() const;

    friend bool operator==(const ClassSelector&, const ClassSelector&) = default;
    friend std::strong_ordering operator<=>(const ClassSelector&, const ClassSelector&) = default;
};

}  // namespace maintpol
