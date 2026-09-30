#include "maintpol/types.hpp"

#include <algorithm>

namespace maintpol {
namespace {

bool is_identifier_start(char character) {
    return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
           (character >= '0' && character <= '9');
}

bool is_identifier_body(char character) {
    return is_identifier_start(character) || character == '.' || character == '_' || character == ':' ||
           character == '-';
}

bool is_scope_body(char character) {
    return is_identifier_start(character) || character == '.' || character == '_' || character == '-';
}

}  // namespace

bool is_valid_utf8(std::string_view text, std::size_t* error_offset) {
    std::size_t index = 0;
    while (index < text.size()) {
        const auto lead = static_cast<unsigned char>(text[index]);
        std::size_t extra = 0;
        std::uint32_t code_point = 0;
        if (lead < 0x80u) {
            ++index;
            continue;
        }
        if ((lead & 0xE0u) == 0xC0u) {
            extra = 1;
            code_point = lead & 0x1Fu;
            if (code_point < 0x02u) {
                if (error_offset != nullptr) { *error_offset = index; }
                return false;
            }
        } else if ((lead & 0xF0u) == 0xE0u) {
            extra = 2;
            code_point = lead & 0x0Fu;
        } else if ((lead & 0xF8u) == 0xF0u) {
            extra = 3;
            code_point = lead & 0x07u;
            if (code_point > 0x04u) {
                if (error_offset != nullptr) { *error_offset = index; }
                return false;
            }
        } else {
            if (error_offset != nullptr) { *error_offset = index; }
            return false;
        }
        if (index + extra >= text.size()) {
            if (error_offset != nullptr) { *error_offset = index; }
            return false;
        }
        for (std::size_t offset = 1; offset <= extra; ++offset) {
            const auto continuation = static_cast<unsigned char>(text[index + offset]);
            if ((continuation & 0xC0u) != 0x80u) {
                if (error_offset != nullptr) { *error_offset = index; }
                return false;
            }
            code_point = (code_point << 6u) | (continuation & 0x3Fu);
        }
        if (extra == 2 && code_point < 0x0800u) {
            if (error_offset != nullptr) { *error_offset = index; }
            return false;
        }
        if (extra == 3 && code_point < 0x10000u) {
            if (error_offset != nullptr) { *error_offset = index; }
            return false;
        }
        if (code_point > 0x10FFFFu) {
            if (error_offset != nullptr) { *error_offset = index; }
            return false;
        }
        if (code_point >= 0xD800u && code_point <= 0xDFFFu) {
            if (error_offset != nullptr) { *error_offset = index; }
            return false;
        }
        index += extra + 1u;
    }
    return true;
}

Result<std::string> validate_identifier(std::string_view text, IdKind kind) {
    if (text.empty()) {
        return make_error(Code::ValueMalformed, "identifier must not be empty");
    }
    if (text.size() > kMaxIdentifierLength) {
        return make_error(Code::TextTooLong, "identifier exceeds 64 characters");
    }
    if (!is_identifier_start(text[0])) {
        return make_error(Code::ValueMalformed, "identifier must start with an alphanumeric character");
    }
    for (std::size_t index = 1; index < text.size(); ++index) {
        const bool ok = kind == IdKind::Identifier ? is_identifier_body(text[index]) : is_scope_body(text[index]);
        if (!ok) {
            return make_error(Code::ValueMalformed, "identifier contains a character outside its permitted set");
        }
    }
    if (!is_valid_utf8(text)) {
        return make_error(Code::InvalidUtf8, "identifier is not valid UTF-8");
    }
    return std::string(text);
}

Result<std::string> validate_description(std::string_view text) {
    if (text.size() > kMaxDescriptionLength) {
        return make_error(Code::TextTooLong, "description exceeds 256 bytes");
    }
    if (!is_valid_utf8(text)) {
        return make_error(Code::InvalidUtf8, "description is not valid UTF-8");
    }
    for (char character : text) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x20u || byte == 0x7Fu) {
            return make_error(Code::ValueMalformed, "description must not contain control characters");
        }
    }
    return std::string(text);
}

bool ascii_iequals(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        char l = left[index];
        char r = right[index];
        if (l >= 'A' && l <= 'Z') {
            l = static_cast<char>(l - 'A' + 'a');
        }
        if (r >= 'A' && r <= 'Z') {
            r = static_cast<char>(r - 'A' + 'a');
        }
        if (l != r) {
            return false;
        }
    }
    return true;
}

Result<ScopePath> ScopePath::parse(std::string_view text) {
    return parse_impl(text, false);
}

Result<ScopePath> ScopePath::parse_selector(std::string_view text) {
    return parse_impl(text, true);
}

Result<ScopePath> ScopePath::parse_impl(std::string_view text, bool allow_wildcard) {
    if (text.empty()) {
        return make_error(Code::ScopeInvalid, "scope must not be empty");
    }
    if (text.size() > kMaxScopeTextLength) {
        return make_error(Code::ScopeInvalid, "scope exceeds 256 characters");
    }
    if (!is_valid_utf8(text)) {
        return make_error(Code::InvalidUtf8, "scope is not valid UTF-8");
    }
    if (text.front() == '/' || text.back() == '/') {
        return make_error(Code::ScopeInvalid, "scope must not start or end with '/'");
    }
    if (text.find("//") != std::string_view::npos) {
        return make_error(Code::ScopeInvalid, "scope must not contain an empty segment");
    }

    ScopePath result;
    std::size_t start = 0;
    std::size_t segment_index = 0;
    while (start <= text.size()) {
        const std::size_t separator = text.find('/', start);
        const std::size_t end = separator == std::string_view::npos ? text.size() : separator;
        const std::string_view segment = text.substr(start, end - start);
        if (segment.empty()) {
            return make_error(Code::ScopeInvalid, "scope must not contain an empty segment");
        }
        if (segment == "*") {
            if (!allow_wildcard) {
                return make_error(Code::ScopeInvalid, "a concrete scope must not contain a wildcard");
            }
            result.wildcard_ = true;
        } else if (segment == "." || segment == "..") {
            return make_error(Code::ScopeInvalid, "scope segment must not be '.' or '..'");
        } else {
            auto validated = validate_identifier(segment, IdKind::ScopeSegment);
            if (!validated) {
                return validated.error();
            }
        }
        if (segment_index == 0) {
            result.facility_ = std::string(segment);
        } else {
            if (result.segments_.size() >= kMaxScopeSegments) {
                return make_error(Code::ScopeInvalid, "scope exceeds 16 path segments");
            }
            result.segments_.push_back(std::string(segment));
        }
        ++segment_index;
        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1u;
    }
    if (result.facility_.empty()) {
        return make_error(Code::ScopeInvalid, "scope must name a facility");
    }
    return result;
}

std::string ScopePath::format() const {
    std::string out = facility_;
    for (const std::string& segment : segments_) {
        out.push_back('/');
        out.append(segment);
    }
    return out;
}

bool ScopePath::matches(const ScopePath& concrete) const {
    if (facility_ != concrete.facility_) {
        return false;
    }
    if (segments_.size() > concrete.segments_.size()) {
        return false;
    }
    for (std::size_t index = 0; index < segments_.size(); ++index) {
        if (segments_[index] == "*") {
            continue;
        }
        if (segments_[index] != concrete.segments_[index]) {
            return false;
        }
    }
    return true;
}

bool scopes_intersect(const ScopePath& left, const ScopePath& right) {
    if (left.facility() != right.facility()) {
        return false;
    }
    const std::size_t common = (std::min)(left.segments().size(), right.segments().size());
    for (std::size_t index = 0; index < common; ++index) {
        if (left.segments()[index] != right.segments()[index]) {
            return false;
        }
    }
    return true;
}

bool ClassSelector::matches(const ObligationClassId& candidate) const {
    if (all) {
        return true;
    }
    return std::find(classes.begin(), classes.end(), candidate) != classes.end();
}

std::string ClassSelector::format() const {
    if (all) {
        return "*";
    }
    std::string out;
    for (std::size_t index = 0; index < classes.size(); ++index) {
        if (index > 0) {
            out.push_back(',');
        }
        out.append(classes[index].value());
    }
    return out;
}

}  // namespace maintpol
