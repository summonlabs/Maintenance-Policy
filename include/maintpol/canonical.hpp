#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "maintpol/digest.hpp"
#include "maintpol/error.hpp"
#include "maintpol/types.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// The canonical document syntax.
//
// A document is a sequence of lines. Every line is one of:
//
//   <empty>                       ignored
//   # <comment>                   ignored; comments are never digested
//   [<section>]                   opens a section
//   <key> = <value>               adds a field to the current section
//
// Values are written bare when they consist only of printable ASCII without
// '=', '"', '\' or space, and quoted otherwise. Quoted values use "\\", "\"",
// "\n", "\r", "\t" and "\xHH" escapes and may contain valid UTF-8 directly.
// Keys match [a-z][a-z0-9_.-]*. Section names match [a-z][a-z0-9-]* and may
// carry one space separated argument, for example "[rule blackout-a]".
//
// The canonical writer always emits sections, keys and repeated values in a
// deterministic order, so canonical output is byte stable for equivalent
// inputs and round trips exactly through the reader.
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxSectionNameLength = 96;
inline constexpr std::size_t kMaxKeyLength = 48;
inline constexpr std::size_t kMaxValueLength = 4096;

// True when the value can be written without quoting.
MAINTPOL_API bool canonical_value_is_bare(std::string_view value);
// Escapes a value for canonical output (bare or quoted form).
MAINTPOL_API std::string canonical_escape(std::string_view value);
// Decodes one raw value token from a document line.
MAINTPOL_API Result<std::string> canonical_unescape(std::string_view raw);
MAINTPOL_API bool canonical_key_is_valid(std::string_view key);
MAINTPOL_API bool canonical_section_is_valid(std::string_view section);

class CanonicalWriter {
public:
    void section(std::string_view name);
    // Sections without a body argument, used for fixed structural sections.
    void field(std::string_view key, std::string_view value);
    void field(std::string_view key, const std::string& value) { field(key, std::string_view(value)); }
    void field(std::string_view key, const char* value) { field(key, std::string_view(value)); }
    void field(std::string_view key, std::uint64_t value);
    void field(std::string_view key, std::int64_t value);
    void field(std::string_view key, std::uint32_t value) { field(key, static_cast<std::uint64_t>(value)); }
    void field(std::string_view key, int value) { field(key, static_cast<std::int64_t>(value)); }
    void field(std::string_view key, bool value);
    void field(std::string_view key, const Digest256& value);

    const std::string& bytes() const { return buffer_; }
    std::string take() { return std::move(buffer_); }
    bool empty() const { return buffer_.empty(); }
    std::size_t size() const { return buffer_.size(); }

private:
    std::string buffer_;
};

// ---------------------------------------------------------------------------
// Document reader.
// ---------------------------------------------------------------------------
struct TextEntry {
    // Section the field belongs to, including any argument, for example
    // "rule blackout-a" or "policy".
    std::string section;
    std::string key;
    std::string value;
    std::size_t line = 0;
    bool is_section = false;
};

struct TextDocument {
    std::vector<TextEntry> entries;

    const TextEntry* first_section(std::string_view name) const;
    bool has_section(std::string_view name) const;
};

struct TextLimits {
    std::size_t max_bytes = kMaxTextDocumentBytes;
    std::size_t max_line_bytes = kMaxTextLineBytes;
    std::size_t max_lines = kMaxTextLines;
    std::size_t max_entries = 100000;
};

MAINTPOL_API Result<TextDocument> parse_text_document(std::string_view text, const TextLimits& limits);

// ---------------------------------------------------------------------------
// Strict section reader: every field is consumed exactly once, unknown keys
// and duplicate single-valued keys are rejected, and required keys are
// enforced by the caller through finish(). The reader borrows the document, so
// the TextDocument must outlive it.
// ---------------------------------------------------------------------------
class SectionReader {
public:
    SectionReader(const TextDocument& document, std::string section);

    bool has(std::string_view key) const;
    std::size_t count(std::string_view key) const;
    Result<std::string> take_string(std::string_view key);
    Result<std::string> take_optional_string(std::string_view key, std::string fallback);
    Result<std::vector<std::string>> take_all(std::string_view key);
    Result<std::uint64_t> take_u64(std::string_view key);
    Result<std::uint64_t> take_optional_u64(std::string_view key, std::uint64_t fallback);
    Result<bool> take_bool(std::string_view key);
    Result<bool> take_optional_bool(std::string_view key, bool fallback);
    Result<Digest256> take_digest(std::string_view key);
    Result<std::string> require_string(std::string_view key);
    Result<std::uint64_t> require_u64(std::string_view key);
    Result<bool> require_bool(std::string_view key);
    Result<Digest256> require_digest(std::string_view key);

    // Marks every not yet consumed field of this section as an unknown key.
    Result<void> finish() const;

    std::size_t line_of(std::string_view key) const;

private:
    const TextEntry* find(std::string_view key) const;
    Result<std::string> consume(std::string_view key, bool required);

    const TextDocument& document_;
    std::string section_;
    mutable std::vector<bool> consumed_;
};

// ---------------------------------------------------------------------------
// Byte level framing helpers shared by the durable store: every framed record
// is "<header>\n<payload>" with an explicit payload length and CRC so that a
// torn write is detected rather than interpreted.
// ---------------------------------------------------------------------------
MAINTPOL_API std::string frame_record(std::string_view header, std::string_view payload);
MAINTPOL_API Result<std::string> unframe_record(std::string_view record, std::string_view expected_header);

}  // namespace maintpol
