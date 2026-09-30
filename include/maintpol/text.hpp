#pragma once

#include <string>
#include <string_view>

#include "maintpol/canonical.hpp"
#include "maintpol/decision.hpp"
#include "maintpol/policy.hpp"
#include "maintpol/request.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Canonical documents.
//
// Every document starts with a [document] section that declares the format
// identifier and the document kind. Canonical serialisation is a pure
// function of the model value: field order, section order and list order are
// fixed, so two equivalent model values always serialise to identical bytes
// and therefore to identical digests.
//
//   kind = policy    [policy] [rule <id>]...
//   kind = bundle    [policy] [rule <id>]... [authority <id>]...
//                    [exception <id>]... [approval <id>]... [registry]
//   kind = request   [request] [scope]... [class]... [exception-ref]...
//                    [approval-ref]... [evidence] [evidence-class <class>]...
//                    [interlock-report] [interlock <id>]...
//   kind = decision  [decision] [bindings] [finding <n>]... [applied-rule]...
//                    [honored-exception]... [exception-binding]...
//                    [approval-binding]...
//   kind = keys      [key <id>]...
//
// Parsing is strict: unknown sections, unknown keys, duplicate single-valued
// keys, missing required keys and out of range values are all errors.
// ---------------------------------------------------------------------------
inline constexpr std::string_view kDocumentKindPolicy = "policy";
inline constexpr std::string_view kDocumentKindBundle = "bundle";
inline constexpr std::string_view kDocumentKindRequest = "request";
inline constexpr std::string_view kDocumentKindDecision = "decision";
inline constexpr std::string_view kDocumentKindKeys = "keys";

MAINTPOL_API Result<Policy> parse_policy_document(std::string_view text);
MAINTPOL_API std::string canonical_policy(const Policy& policy);

MAINTPOL_API Result<PolicyBundle> parse_bundle_document(std::string_view text);
MAINTPOL_API std::string canonical_bundle(const PolicyBundle& bundle);

MAINTPOL_API Result<EvaluationRequest> parse_request_document(std::string_view text);
MAINTPOL_API std::string canonical_evidence(const EvidenceBundle& evidence);
MAINTPOL_API std::string canonical_interlock_report(const InterlockReport& report);
MAINTPOL_API std::string canonical_request(const EvaluationRequest& request);

MAINTPOL_API Result<Decision> parse_decision_document(std::string_view text);
// Canonical decision content without the digest field: this is exactly what
// the decision digest is computed over.
MAINTPOL_API std::string canonical_decision(const Decision& decision);
// Canonical decision document including its digest, as written to disk.
MAINTPOL_API std::string decision_document(const Decision& decision);

MAINTPOL_API Result<KeySet> parse_key_document(std::string_view text);
MAINTPOL_API std::string key_document(const KeySet& keys);

// ---------------------------------------------------------------------------
// Authority MACs. The MAC covers the issuer-signed body of the record: the
// canonical section without the 'mac' field and without the registry state
// fields ('revoked_at'). Revocation therefore does not invalidate a
// signature, and a signature can never be extended by editing registry state.
// ---------------------------------------------------------------------------
MAINTPOL_API std::string canonical_exception_record(const ExceptionRecord& record);
MAINTPOL_API std::string canonical_approval_record(const ApprovalRecord& record);
MAINTPOL_API std::string exception_mac_payload(const ExceptionRecord& record);
MAINTPOL_API std::string approval_mac_payload(const ApprovalRecord& record);
MAINTPOL_API Result<bool> verify_exception_mac(const KeySet& keys, const ExceptionRecord& record);
MAINTPOL_API Result<bool> verify_approval_mac(const KeySet& keys, const ApprovalRecord& record);

}  // namespace maintpol
