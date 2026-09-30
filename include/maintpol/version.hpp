#pragma once

#include <cstdint>
#include <string_view>

namespace maintpol {

// Library release version. Kept in lock step with the CMake project version.
inline constexpr int version_major = 1;
inline constexpr int version_minor = 0;
inline constexpr int version_patch = 0;
inline constexpr std::string_view version_string = "1.0.0";

// Identifier of the canonical text document format. Documents declare this
// value; a document that declares any other value is rejected.
inline constexpr std::string_view document_format_id = "maintpol/1";

// Version of the evaluation semantics (rule precedence, refusal rules, digest
// composition). Every decision binds this value, so a semantics change fences
// previously issued decisions.
inline constexpr std::uint32_t semantics_version = 1;

// Version of the digest composition rules for canonical documents.
inline constexpr std::uint32_t digest_format_version = 1;

}  // namespace maintpol
