#include "maintpol/canonical.hpp"

#include <algorithm>
#include <limits>

namespace maintpol {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

bool is_bare_byte(char character) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte <= 0x20u || byte >= 0x7Fu) {
        return false;
    }
    return character != '=' && character != '"' && character != '\\';
}

int hex_digit_value(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

}  // namespace

bool canonical_value_is_bare(std::string_view value) {
    if (value.empty()) {
        return false;
    }
    for (char character : value) {
        if (!is_bare_byte(character)) {
            return false;
        }
    }
    return true;
}

std::string canonical_escape(std::string_view value) {
    if (canonical_value_is_bare(value)) {
        return std::string(value);
    }
    std::string out;
    out.reserve(value.size() + 2u);
    out.push_back('"');
    for (char character : value) {
        switch (character) {
            case '\\': out.append("\\\\"); break;
            case '"': out.append("\\\""); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default: {
                const auto byte = static_cast<unsigned char>(character);
                if (byte < 0x20u || byte == 0x7Fu) {
                    out.append("\\x");
                    out.push_back(kHexDigits[(byte >> 4u) & 0x0Fu]);
                    out.push_back(kHexDigits[byte & 0x0Fu]);
                } else {
                    out.push_back(character);
                }
                break;
            }
        }
    }
    out.push_back('"');
    return out;
}

Result<std::string> canonical_unescape(std::string_view raw) {
    if (raw.empty()) {
        return make_error(Code::ValueMalformed, "value must not be empty");
    }
    if (raw.front() != '"') {
        for (char character : raw) {
            if (!is_bare_byte(character)) {
                return make_error(Code::ValueMalformed, "bare value contains a character that must be quoted");
            }
        }
        return std::string(raw);
    }
    if (raw.size() < 2u || raw.back() != '"') {
        return make_error(Code::ValueMalformed, "quoted value is not terminated");
    }
    std::string out;
    out.reserve(raw.size() - 2u);
    for (std::size_t index = 1; index + 1u < raw.size(); ++index) {
        const char character = raw[index];
        if (character != '\\') {
            out.push_back(character);
            continue;
        }
        if (index + 2u > raw.size() - 1u) {
            return make_error(Code::ValueMalformed, "escape sequence is truncated");
        }
        const char escape = raw[index + 1u];
        ++index;
        switch (escape) {
            case '\\': out.push_back('\\'); break;
            case '"': out.push_back('"'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'x': {
                if (index + 2u > raw.size() - 1u) {
                    return make_error(Code::ValueMalformed, "hexadecimal escape is truncated");
                }
                const int high = hex_digit_value(raw[index + 1u]);
                const int low = hex_digit_value(raw[index + 2u]);
                if (high < 0 || low < 0) {
                    return make_error(Code::ValueMalformed, "hexadecimal escape is malformed");
                }
                index += 2u;
                out.push_back(static_cast<char>((high << 4) | low));
                break;
            }
            default:
                return make_error(Code::ValueMalformed, "escape sequence is not recognised");
        }
    }
    return out;
}

bool canonical_key_is_valid(std::string_view key) {
    if (key.empty() || key.size() > kMaxKeyLength) {
        return false;
    }
    if (key.front() < 'a' || key.front() > 'z') {
        return false;
    }
    for (char character : key) {
        const bool ok = (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
                        character == '_' || character == '.' || character == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool canonical_section_is_valid(std::string_view section) {
    if (section.empty() || section.size() > kMaxSectionNameLength) {
        return false;
    }
    std::size_t index = 0;
    if (section[index] < 'a' || section[index] > 'z') {
        return false;
    }
    while (index < section.size() && section[index] != ' ') {
        const char character = section[index];
        const bool ok = (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
                        character == '-';
        if (!ok) {
            return false;
        }
        ++index;
    }
    if (index == section.size()) {
        return true;
    }
    if (section[index] != ' ' || index + 1u >= section.size()) {
        return false;
    }
    const std::string_view argument = section.substr(index + 1u);
    if (argument.empty()) {
        return false;
    }
    // Section arguments are canonical values: bare, or quoted when they
    // contain spaces or other characters that must be escaped.
    if (argument.front() != '"' && argument.find(' ') != std::string_view::npos) {
        return false;
    }
    return canonical_unescape(argument).has_value();
}

void CanonicalWriter::section(std::string_view name) {
    if (!buffer_.empty()) {
        buffer_.push_back('\n');
    }
    buffer_.push_back('[');
    buffer_.append(name);
    buffer_.append("]\n");
}

void CanonicalWriter::field(std::string_view key, std::string_view value) {
    buffer_.append(key);
    buffer_.append(" = ");
    buffer_.append(canonical_escape(value));
    buffer_.push_back('\n');
}

void CanonicalWriter::field(std::string_view key, std::uint64_t value) {
    buffer_.append(key);
    buffer_.append(" = ");
    buffer_.append(std::to_string(value));
    buffer_.push_back('\n');
}

void CanonicalWriter::field(std::string_view key, std::int64_t value) {
    buffer_.append(key);
    buffer_.append(" = ");
    buffer_.append(std::to_string(value));
    buffer_.push_back('\n');
}

void CanonicalWriter::field(std::string_view key, bool value) {
    buffer_.append(key);
    buffer_.append(" = ");
    buffer_.append(value ? "true" : "false");
    buffer_.push_back('\n');
}

void CanonicalWriter::field(std::string_view key, const Digest256& value) {
    buffer_.append(key);
    buffer_.append(" = ");
    buffer_.append(value.hex());
    buffer_.push_back('\n');
}

const TextEntry* TextDocument::first_section(std::string_view name) const {
    for (const TextEntry& entry : entries) {
        if (entry.is_section && entry.section == name) {
            return &entry;
        }
    }
    return nullptr;
}

bool TextDocument::has_section(std::string_view name) const { return first_section(name) != nullptr; }

Result<TextDocument> parse_text_document(std::string_view text, const TextLimits& limits) {
    if (text.size() > limits.max_bytes) {
        return make_error(Code::DocumentTooLarge, "document exceeds the permitted size");
    }
    if (text.empty()) {
        return make_error(Code::EmptyDocument, "document is empty");
    }
    if (!is_valid_utf8(text)) {
        return make_error(Code::InvalidUtf8, "document is not valid UTF-8");
    }
    if (text.size() >= 3u && static_cast<unsigned char>(text[0]) == 0xEFu &&
        static_cast<unsigned char>(text[1]) == 0xBBu && static_cast<unsigned char>(text[2]) == 0xBFu) {
        return make_error(Code::SyntaxInvalid, "a byte order mark must not appear before the first section");
    }

    TextDocument document;
    std::size_t line_number = 0;
    std::size_t index = 0;
    std::string current_section;
    bool saw_section = false;

    while (index <= text.size()) {
        const std::size_t newline = text.find('\n', index);
        const std::size_t end = newline == std::string_view::npos ? text.size() : newline;
        std::string_view line = text.substr(index, end - index);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        index = newline == std::string_view::npos ? text.size() + 1u : newline + 1u;
        ++line_number;
        if (line_number > limits.max_lines) {
            return make_error(Code::TooManyItems, "document exceeds the permitted line count");
        }
        if (line.size() > limits.max_line_bytes) {
            return make_error(Code::LineTooLong, "line exceeds the permitted length");
        }
        if (line.empty()) {
            continue;
        }
        if (line.front() == '#') {
            continue;
        }
        if (line.front() == '[') {
            if (line.back() != ']' || line.size() < 3u) {
                return make_error(Code::SyntaxInvalid, "section header is not terminated");
            }
            const std::string_view name = line.substr(1, line.size() - 2u);
            if (!canonical_section_is_valid(name)) {
                return make_error(Code::SyntaxInvalid, "section name is not valid");
            }
            current_section.assign(name);
            saw_section = true;
            TextEntry entry;
            entry.section = current_section;
            entry.line = line_number;
            entry.is_section = true;
            document.entries.push_back(std::move(entry));
            if (document.entries.size() > limits.max_entries) {
                return make_error(Code::TooManyItems, "document exceeds the permitted field count");
            }
            continue;
        }
        if (!saw_section) {
            return make_error(Code::SyntaxInvalid, "field appears before the first section");
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string_view::npos) {
            return make_error(Code::SyntaxInvalid, "field line has no '=' separator");
        }
        std::string_view key = line.substr(0, equals);
        std::string_view raw_value = line.substr(equals + 1u);
        while (!key.empty() && key.back() == ' ') {
            key.remove_suffix(1);
        }
        while (!raw_value.empty() && raw_value.front() == ' ') {
            raw_value.remove_prefix(1);
        }
        if (!canonical_key_is_valid(key)) {
            return make_error(Code::SyntaxInvalid, "field key is not valid");
        }
        if (raw_value.empty()) {
            return make_error(Code::ValueMalformed, "field value is empty");
        }
        if (raw_value.size() > kMaxValueLength) {
            return make_error(Code::TextTooLong, "field value exceeds the permitted length");
        }
        auto decoded = canonical_unescape(raw_value);
        if (!decoded) {
            return decoded.error();
        }
        TextEntry entry;
        entry.section = current_section;
        entry.key.assign(key);
        entry.value = std::move(decoded.value());
        entry.line = line_number;
        document.entries.push_back(std::move(entry));
        if (document.entries.size() > limits.max_entries) {
            return make_error(Code::TooManyItems, "document exceeds the permitted field count");
        }
    }

    if (document.entries.empty()) {
        return make_error(Code::EmptyDocument, "document declares no section");
    }
    return document;
}

SectionReader::SectionReader(const TextDocument& document, std::string section)
    : document_(document), section_(std::move(section)) {
    consumed_.assign(document_.entries.size(), false);
}

const TextEntry* SectionReader::find(std::string_view key) const {
    for (std::size_t index = 0; index < document_.entries.size(); ++index) {
        const TextEntry& entry = document_.entries[index];
        if (!entry.is_section && entry.section == section_ && entry.key == key) {
            return &entry;
        }
    }
    return nullptr;
}

bool SectionReader::has(std::string_view key) const { return find(key) != nullptr; }

std::size_t SectionReader::count(std::string_view key) const {
    std::size_t total = 0;
    for (const TextEntry& entry : document_.entries) {
        if (!entry.is_section && entry.section == section_ && entry.key == key) {
            ++total;
        }
    }
    return total;
}

std::size_t SectionReader::line_of(std::string_view key) const {
    const TextEntry* entry = find(key);
    return entry != nullptr ? entry->line : 0;
}

Result<std::string> SectionReader::consume(std::string_view key, bool required) {
    const TextEntry* found = nullptr;
    std::size_t found_index = 0;
    std::size_t matches = 0;
    for (std::size_t index = 0; index < document_.entries.size(); ++index) {
        const TextEntry& entry = document_.entries[index];
        if (!entry.is_section && entry.section == section_ && entry.key == key) {
            if (matches == 0) {
                found = &entry;
                found_index = index;
            }
            ++matches;
        }
    }
    if (matches == 0) {
        if (required) {
            return make_error(Code::MissingKey, "required field '" + std::string(key) + "' is absent");
        }
        return make_error(Code::MissingKey, "field '" + std::string(key) + "' is absent");
    }
    if (matches > 1) {
        return make_error(Code::DuplicateKey, "field '" + std::string(key) + "' appears more than once");
    }
    consumed_[found_index] = true;
    return found->value;
}

Result<std::string> SectionReader::take_string(std::string_view key) { return consume(key, true); }

Result<std::string> SectionReader::take_optional_string(std::string_view key, std::string fallback) {
    if (find(key) == nullptr) {
        return fallback;
    }
    return consume(key, true);
}

Result<std::vector<std::string>> SectionReader::take_all(std::string_view key) {
    std::vector<std::string> values;
    for (std::size_t index = 0; index < document_.entries.size(); ++index) {
        const TextEntry& entry = document_.entries[index];
        if (!entry.is_section && entry.section == section_ && entry.key == key) {
            consumed_[index] = true;
            values.push_back(entry.value);
        }
    }
    return values;
}

Result<std::uint64_t> SectionReader::take_u64(std::string_view key) {
    auto raw = consume(key, true);
    if (!raw) {
        return raw.error();
    }
    const std::string& text = raw.value();
    if (text.empty() || text.size() > 20) {
        return make_error(Code::NumberMalformed, "field '" + std::string(key) + "' is not a decimal integer");
    }
    if (text.size() > 1 && text.front() == '0') {
        return make_error(Code::NumberMalformed, "field '" + std::string(key) + "' has leading zeros");
    }
    std::uint64_t value = 0;
    for (char character : text) {
        if (character < '0' || character > '9') {
            return make_error(Code::NumberMalformed, "field '" + std::string(key) + "' is not a decimal integer");
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
        if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10u) {
            return make_error(Code::IntegerOverflow, "field '" + std::string(key) + "' overflows");
        }
        value = (value * 10u) + digit;
    }
    return value;
}

Result<std::uint64_t> SectionReader::take_optional_u64(std::string_view key, std::uint64_t fallback) {
    if (find(key) == nullptr) {
        return fallback;
    }
    return take_u64(key);
}

Result<bool> SectionReader::take_bool(std::string_view key) {
    auto raw = consume(key, true);
    if (!raw) {
        return raw.error();
    }
    if (raw.value() == "true") {
        return true;
    }
    if (raw.value() == "false") {
        return false;
    }
    return make_error(Code::ValueMalformed, "field '" + std::string(key) + "' must be 'true' or 'false'");
}

Result<bool> SectionReader::take_optional_bool(std::string_view key, bool fallback) {
    if (find(key) == nullptr) {
        return fallback;
    }
    return take_bool(key);
}

Result<Digest256> SectionReader::take_digest(std::string_view key) {
    auto raw = consume(key, true);
    if (!raw) {
        return raw.error();
    }
    return Digest256::from_hex(raw.value());
}

Result<std::string> SectionReader::require_string(std::string_view key) { return consume(key, true); }
Result<std::uint64_t> SectionReader::require_u64(std::string_view key) { return take_u64(key); }
Result<bool> SectionReader::require_bool(std::string_view key) { return take_bool(key); }
Result<Digest256> SectionReader::require_digest(std::string_view key) { return take_digest(key); }

Result<void> SectionReader::finish() const {
    for (std::size_t index = 0; index < document_.entries.size(); ++index) {
        const TextEntry& entry = document_.entries[index];
        if (!entry.is_section && entry.section == section_ && !consumed_[index]) {
            return make_error(Code::UnknownKey, "field '" + entry.key + "' is not defined in section '" + section_ + "'");
        }
    }
    return {};
}

std::string frame_record(std::string_view header, std::string_view payload) {
    std::string out;
    out.reserve(header.size() + payload.size() + 32u);
    out.append(header);
    out.push_back('\n');
    out.append(std::to_string(payload.size()));
    out.push_back('\n');
    const std::uint32_t checksum = crc32(payload);
    for (int shift = 28; shift >= 0; shift -= 4) {
        out.push_back(kHexDigits[(checksum >> static_cast<unsigned>(shift)) & 0x0Fu]);
    }
    out.push_back('\n');
    out.append(payload);
    return out;
}

Result<std::string> unframe_record(std::string_view record, std::string_view expected_header) {
    const std::size_t first = record.find('\n');
    if (first == std::string_view::npos) {
        return make_error(Code::LengthMismatch, "framed record has no header line");
    }
    if (record.substr(0, first) != expected_header) {
        return make_error(Code::SyntaxInvalid, "framed record header does not match");
    }
    const std::size_t second = record.find('\n', first + 1u);
    if (second == std::string_view::npos) {
        return make_error(Code::LengthMismatch, "framed record has no length line");
    }
    const std::size_t third = record.find('\n', second + 1u);
    if (third == std::string_view::npos) {
        return make_error(Code::LengthMismatch, "framed record has no checksum line");
    }
    const std::string_view length_text = record.substr(first + 1u, second - first - 1u);
    const std::string_view checksum_text = record.substr(second + 1u, third - second - 1u);
    if (length_text.empty() || length_text.size() > 20) {
        return make_error(Code::NumberMalformed, "framed record length is malformed");
    }
    std::uint64_t declared = 0;
    for (char character : length_text) {
        if (character < '0' || character > '9') {
            return make_error(Code::NumberMalformed, "framed record length is malformed");
        }
        declared = (declared * 10u) + static_cast<std::uint64_t>(character - '0');
        if (declared > kMaxRecordBytes) {
            return make_error(Code::StoreRecordTooLarge, "framed record declares an oversized payload");
        }
    }
    const std::string_view payload = record.substr(third + 1u);
    if (payload.size() != declared) {
        return make_error(Code::LengthMismatch, "framed record length does not match the payload");
    }
    auto expected = bytes_from_hex(checksum_text);
    if (!expected) {
        return expected.error();
    }
    if (expected.value().size() != 4u) {
        return make_error(Code::LengthMismatch, "framed record checksum must be four bytes");
    }
    const std::uint32_t actual = crc32(payload);
    const std::uint32_t stored = (static_cast<std::uint32_t>(expected.value()[0]) << 24u) |
                                 (static_cast<std::uint32_t>(expected.value()[1]) << 16u) |
                                 (static_cast<std::uint32_t>(expected.value()[2]) << 8u) |
                                 static_cast<std::uint32_t>(expected.value()[3]);
    if (actual != stored) {
        return make_error(Code::StoreCorrupt, "framed record checksum does not match");
    }
    return std::string(payload);
}

}  // namespace maintpol
