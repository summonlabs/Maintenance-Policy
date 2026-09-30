#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#if defined(_WIN32) && defined(MAINTPOL_SHARED)
#  if defined(MAINTPOL_BUILDING_LIBRARY)
#    define MAINTPOL_API __declspec(dllexport)
#  else
#    define MAINTPOL_API __declspec(dllimport)
#  endif
#else
#  define MAINTPOL_API
#endif

namespace maintpol {

// ---------------------------------------------------------------------------
// Severity drives deterministic error precedence and decision outcomes.
//
//   Error      the operation failed; no decision is produced
//   Denial     the request is refused and must not be executed
//   Refusal    the request cannot be resolved (unknown); never "healthy"
//   Escalation the request needs an authority that has not approved it
//   Advisory   permitted, with a recorded advisory
//   Info       permitted, informational only
//
// Higher numeric value means higher precedence when several conditions hold
// at once. A decision reports every condition it found; the highest severity
// present determines the outcome.
// ---------------------------------------------------------------------------
enum class Severity : std::uint8_t {
    None = 0,
    Info = 1,
    Advisory = 2,
    Escalation = 3,
    Refusal = 4,
    Denial = 5,
    Error = 6,
};

enum class CodeClass : std::uint8_t {
    None = 0,
    Input,
    Time,
    Policy,
    Authority,
    PolicyState,
    Evidence,
    Evaluation,
    Store,
    Internal,
};

// The code table is the single source of truth for names, numeric values,
// classes, severities and descriptions. Numeric values are a persisted
// contract: never renumber or reuse a value.
#define MAINTPOL_CODE_TABLE(X)                                                                     \
    X(Ok, 0, None, None, "no error")                                                               \
    X(InvalidUtf8, 1, Input, Error, "input is not well formed UTF-8")                              \
    X(SyntaxInvalid, 2, Input, Error, "input does not follow the canonical text syntax")           \
    X(UnknownKey, 3, Input, Error, "key is not defined for this section")                          \
    X(DuplicateKey, 4, Input, Error, "single-valued key appears more than once")                   \
    X(MissingKey, 5, Input, Error, "required key is absent")                                       \
    X(ValueMalformed, 6, Input, Error, "value does not match the declared type")                   \
    X(ValueOutOfRange, 7, Input, Error, "value is outside the permitted range")                    \
    X(UnknownEnumValue, 8, Input, Error, "enumerated value is not recognised")                     \
    X(DuplicateIdentifier, 9, Input, Error, "identifier is declared more than once")               \
    X(TooManyItems, 10, Input, Error, "collection exceeds the permitted item count")               \
    X(DocumentTooLarge, 11, Input, Error, "document exceeds the permitted size")                   \
    X(LineTooLong, 12, Input, Error, "line exceeds the permitted length")                          \
    X(UnsupportedFormatVersion, 13, Input, Error, "document format version is not supported")      \
    X(ReservedFieldPresent, 14, Input, Error, "reserved field must be absent or zero")             \
    X(DigestMalformed, 15, Input, Error, "digest is not 64 lowercase hexadecimal characters")      \
    X(LengthMismatch, 16, Input, Error, "declared length does not match the payload")              \
    X(IntegerOverflow, 17, Input, Error, "arithmetic result is not representable")                 \
    X(TextTooLong, 18, Input, Error, "text value exceeds the permitted length")                    \
    X(NumberMalformed, 19, Input, Error, "numeric value is not a canonical decimal integer")       \
    X(UnexpectedSection, 20, Input, Error, "section is not permitted in this document kind")       \
    X(EmptyDocument, 21, Input, Error, "document contains no content")                             \
    X(TimestampMalformed, 60, Time, Error, "timestamp is not a canonical RFC 3339 instant")        \
    X(TimestampOutOfRange, 61, Time, Error, "timestamp is outside the supported instant range")    \
    X(OffsetOutOfRange, 62, Time, Error, "UTC offset is outside +/-18:00")                         \
    X(CalendarInvalid, 63, Time, Error, "civil date or time is not a real calendar value")         \
    X(IntervalReversed, 64, Time, Error, "interval end is not after interval start")               \
    X(DurationTooLong, 65, Time, Error, "duration exceeds the permitted maximum")                  \
    X(LeapSecondUnsupported, 66, Time, Error, "leap seconds are not supported")                    \
    X(TimeZoneNotSupported, 67, Time, Error, "named time zones are not supported; use an offset")  \
    X(PolicyEmpty, 90, Policy, Error, "policy declares no rules")                                  \
    X(RuleInvalid, 91, Policy, Error, "rule is internally inconsistent")                           \
    X(RuleIdConflict, 92, Policy, Error, "two rules share one rule identifier")                    \
    X(HardInterlockWaivable, 93, Policy, Error, "hard interlock must not be marked waivable")      \
    X(RecurrenceUnbounded, 94, Policy, Error, "recurrence expansion is not bounded")               \
    X(RecurrenceInvalid, 95, Policy, Error, "recurrence definition is inconsistent")               \
    X(ScopeInvalid, 96, Policy, Error, "scope selector or scope reference is invalid")             \
    X(PriorityOutOfRange, 97, Policy, Error, "rule priority is outside the permitted range")       \
    X(ThresholdInvalid, 98, Policy, Error, "threshold is not satisfiable")                         \
    X(PolicyLifecycleInvalid, 99, Policy, Error, "policy lifecycle transition is not permitted")  \
    X(SelectorInvalid, 100, Policy, Error, "selector is invalid for the rule kind")                \
    X(ClassFloorInvalid, 101, Policy, Error, "obligation class floor is invalid")                  \
    X(MacMissing, 140, Authority, Refusal, "authority MAC is absent")                                \
    X(MacInvalid, 141, Authority, Refusal, "authority MAC does not verify")                          \
    X(KeyUnknown, 142, Authority, Refusal, "no key material is available for this key identifier")   \
    X(KeyMalformed, 143, Authority, Error, "key material is malformed")                            \
    X(ExceptionNotInRegistry, 144, Authority, Refusal, "exception is not present in the registry") \
    X(ExceptionExpired, 145, Authority, Refusal, "exception is past its expiry")                   \
    X(ExceptionRevoked, 146, Authority, Refusal, "exception was revoked")                          \
    X(ExceptionNotYetValid, 147, Authority, Refusal, "exception is not yet valid")                 \
    X(ExceptionScopeMismatch, 148, Authority, Refusal, "exception does not cover this scope")      \
    X(ExceptionGenerationMismatch, 149, Authority, Refusal, "exception binds another policy")      \
    X(ExceptionWaivesHardInterlock, 150, Authority, Denial, "exception targets a hard interlock")  \
    X(ExceptionUseExhausted, 151, Authority, Refusal, "exception use budget is exhausted")         \
    X(ExceptionAuthorityInsufficient, 152, Authority, Refusal, "exception issuer lacks authority") \
    X(ExceptionClassMismatch, 153, Authority, Refusal, "exception does not cover these classes")   \
    X(ApprovalNotInRegistry, 154, Authority, Escalation, "approval is not present in the registry")\
    X(ApprovalExpired, 155, Authority, Escalation, "approval is past its expiry")                     \
    X(ApprovalRevoked, 156, Authority, Escalation, "approval was revoked")                            \
    X(ApprovalNotYetValid, 157, Authority, Escalation, "approval is not yet valid")                   \
    X(ApprovalFenced, 158, Authority, Escalation, "approval is fenced by a later policy")             \
    X(ApprovalContextMismatch, 159, Authority, Escalation, "approval binds a different request")      \
    X(ApprovalAuthorityInsufficient, 160, Authority, Escalation, "approval level is too low")      \
    X(ApprovalScopeMismatch, 161, Authority, Escalation, "approval does not cover this scope")        \
    X(ApprovalClassMismatch, 162, Authority, Escalation, "approval does not cover these classes")     \
    X(AuthorityUnknown, 163, Authority, Refusal, "authority identity is unknown to this policy")   \
    X(AuthorityLevelInsufficient, 164, Authority, Escalation, "authority level is too low")        \
    X(PolicyNotPublished, 200, PolicyState, Refusal, "policy generation is not published")         \
    X(PolicyRevoked, 201, PolicyState, Denial, "policy generation is revoked")                     \
    X(PolicySuperseded, 202, PolicyState, Refusal, "policy generation was superseded")             \
    X(PolicyGenerationStale, 203, PolicyState, Refusal, "request binds an older policy generation")\
    X(PolicyDigestMismatch, 204, PolicyState, Refusal, "policy digest does not match the request") \
    X(ReplaySuperseded, 205, PolicyState, Refusal, "replayed decision binds an older policy")      \
    X(EvidenceMissing, 230, Evidence, Refusal, "no evidence was supplied for this class")          \
    X(EvidenceUnmeasured, 231, Evidence, Refusal, "evidence states the class was not measured")    \
    X(EvidenceStale, 232, Evidence, Refusal, "evidence is older than the policy permits")          \
    X(EvidenceFromFuture, 233, Evidence, Refusal, "evidence observation is after the evaluation")  \
    X(EvidenceEpochFenced, 234, Evidence, Refusal, "evidence epoch is behind the policy fence")    \
    X(EvidenceDigestMismatch, 235, Evidence, Refusal, "evidence digest does not match its body")   \
    X(EvidenceAuthorityUnknown, 236, Evidence, Refusal, "evidence source is not a known authority")\
    X(EvidenceDuplicateClass, 237, Evidence, Error, "evidence reports one class twice")            \
    X(InterlockUnknown, 238, Evidence, Refusal, "interlock report does not cover this interlock")  \
    X(ExceptionWaiverApplied, 165, Authority, Advisory, "exception relaxed a waivable constraint") \
    X(HardInterlockViolation, 270, Evaluation, Denial, "hard interlock forbids this maintenance")  \
    X(ProtectedClassViolation, 271, Evaluation, Denial, "protected class forbids this window")     \
    X(BlackoutConflict, 272, Evaluation, Denial, "requested window intersects a blackout")         \
    X(RedundancyShortfall, 273, Evaluation, Denial, "measured redundancy is below the floor")      \
    X(SoftConstraintViolation, 274, Evaluation, Escalation, "soft constraint is violated")         \
    X(EscalationRequired, 275, Evaluation, Escalation, "escalation authority has not approved")    \
    X(NoApplicableRules, 276, Evaluation, Info, "no rule applies to this request")                 \
    X(WindowTooLong, 277, Evaluation, Denial, "requested window exceeds the policy maximum")       \
    X(SoftConstraintApproved, 278, Evaluation, Advisory, "soft constraint violation was approved") \
    X(StoreMissing, 320, Store, Error, "store path does not exist")                                \
    X(StoreLocked, 321, Store, Error, "store is owned by another writer")                          \
    X(StoreIo, 322, Store, Error, "durable storage operation failed")                              \
    X(StoreCorrupt, 323, Store, Error, "stored record failed integrity verification")              \
    X(StoreManifestInvalid, 324, Store, Error, "store manifest is not valid")                      \
    X(StoreRollbackDetected, 325, Store, Error, "store state is older than the recorded fence")    \
    X(StoreFenceRegression, 326, Store, Error, "fence epoch did not advance monotonically")        \
    X(StoreOrphanRecord, 327, Store, Error, "record exists that the manifest does not authorise")  \
    X(StoreGenerationMissing, 328, Store, Error, "manifest names a generation that is absent")     \
    X(StoreNotWritable, 329, Store, Error, "store is not writable")                                \
    X(StoreJournalCorrupt, 330, Store, Error, "journal contains a corrupt non-trailing record")    \
    X(StoreJournalTruncated, 331, Store, Error, "journal ends with an incomplete record")          \
    X(StoreJournalGap, 332, Store, Error, "journal sequence is not contiguous")                    \
    X(StoreSequenceExhausted, 333, Store, Error, "journal sequence cannot advance further")        \
    X(StorePathInvalid, 334, Store, Error, "store path is not usable")                             \
    X(StoreReadOnly, 335, Store, Error, "read-only open refuses a mutating operation")             \
    X(StoreAlreadyExists, 336, Store, Error, "store already exists at this path")                  \
    X(StoreRecordTooLarge, 337, Store, Error, "record exceeds the permitted size")                 \
    X(StoreLockUnavailable, 338, Store, Error, "exclusive lock could not be acquired")             \
    X(StoreVerifyFailed, 339, Store, Error, "store verification refused the state")                \
    X(DecisionConflict, 340, Store, Error, "two different decisions were recorded for one request") \
    X(InternalInvariant, 400, Internal, Error, "internal invariant was violated")                  \
    X(InternalUnsupported, 401, Internal, Error, "operation is not supported on this platform")

enum class Code : std::uint16_t {
#define MAINTPOL_CODE_ENUM(name, value, cls, sev, text) name = value,
    MAINTPOL_CODE_TABLE(MAINTPOL_CODE_ENUM)
#undef MAINTPOL_CODE_ENUM
};

MAINTPOL_API std::string_view to_string(Code code);
MAINTPOL_API std::string_view description(Code code);
MAINTPOL_API std::string_view to_string(Severity severity);
MAINTPOL_API std::string_view to_string(CodeClass code_class);
MAINTPOL_API Severity severity_of(Code code);
MAINTPOL_API CodeClass class_of(Code code);
MAINTPOL_API std::uint16_t value_of(Code code);
// Strict reverse mapping: an unknown numeric value is an error, never a default.
MAINTPOL_API bool code_from_value(std::uint16_t value, Code& out);
// Strict name mapping used by the canonical text format.
MAINTPOL_API bool code_from_name(std::string_view name, Code& out);
MAINTPOL_API bool severity_from_name(std::string_view name, Severity& out);

// ---------------------------------------------------------------------------
// Error: a code plus a bounded, human readable detail. Detail text is never
// used to make a decision; decisions bind codes.
// ---------------------------------------------------------------------------
struct Error {
    Code code = Code::Ok;
    std::string detail;

    Error() = default;
    Error(Code c, std::string d) : code(c), detail(std::move(d)) {}
};

MAINTPOL_API Error make_error(Code code, std::string detail = std::string());
MAINTPOL_API std::string to_string(const Error& error);

// ---------------------------------------------------------------------------
// Result<T>: value or Error. There is no "empty" success state.
// ---------------------------------------------------------------------------
template <typename T>
class Result {
public:
    Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}

    bool has_value() const noexcept { return storage_.index() == 0; }
    explicit operator bool() const noexcept { return has_value(); }

    T& value() & { return std::get<0>(storage_); }
    const T& value() const& { return std::get<0>(storage_); }
    T&& value() && { return std::get<0>(std::move(storage_)); }

    Error& error() & { return std::get<1>(storage_); }
    const Error& error() const& { return std::get<1>(storage_); }

private:
    std::variant<T, Error> storage_;
};

template <>
class Result<void> {
public:
    Result() = default;
    Result(Error error) : error_(std::move(error)), ok_(false) {}

    bool has_value() const noexcept { return ok_; }
    explicit operator bool() const noexcept { return ok_; }

    Error& error() & { return error_; }
    const Error& error() const& { return error_; }

private:
    Error error_;
    bool ok_ = true;
};

}  // namespace maintpol
