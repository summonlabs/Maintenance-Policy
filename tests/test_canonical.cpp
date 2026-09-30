#include <string>
#include <vector>

#include "harness.hpp"
#include "maintpol/canonical.hpp"

namespace {

using namespace maintpol;

std::string round_trip(const std::string& value) {
    const std::string encoded = canonical_escape(value);
    auto decoded = canonical_unescape(encoded);
    if (!decoded) {
        MP_FAIL("cannot decode: " + encoded);
    }
    return decoded.value();
}

}  // namespace

MP_TEST(canonical, escape_round_trips) {
    const std::vector<std::string> samples = {"simple",
                                              "with space",
                                              "quote\"inside",
                                              "back\\slash",
                                              "tab\tseparated",
                                              "line\nbreak",
                                              "carriage\rreturn",
                                              "[section]",
                                              "key = value",
                                              "",
                                              std::string(1u, '\x7f'),
                                              "unicode-\xC3\xA9-\xE2\x9C\x93"};
    for (const std::string& sample : samples) {
        MP_CHECK_EQ(round_trip(sample), sample);
    }
    MP_CHECK(canonical_value_is_bare("plain-token_1.2:3"));
    MP_CHECK(!canonical_value_is_bare("has space"));
    MP_CHECK(!canonical_value_is_bare("has=equals"));
    MP_CHECK(!canonical_value_is_bare(""));
    MP_CHECK(canonical_escape("has space") == "\"has space\"");
    MP_CHECK(canonical_escape("plain") == "plain");
}

MP_TEST(canonical, unescape_rejects_malformed) {
    MP_CHECK_CODE(canonical_unescape("\"unterminated"), Code::ValueMalformed);
    MP_CHECK_CODE(canonical_unescape("\"bad\\q\""), Code::ValueMalformed);
    MP_CHECK_CODE(canonical_unescape("\"bad\\x0\""), Code::ValueMalformed);
    MP_CHECK_CODE(canonical_unescape("\"bad\\xzz\""), Code::ValueMalformed);
    MP_CHECK_CODE(canonical_unescape(""), Code::ValueMalformed);
    MP_CHECK_CODE(canonical_unescape("bare\"quote"), Code::ValueMalformed);
}

MP_TEST(canonical, key_and_section_validation) {
    MP_CHECK(canonical_key_is_valid("policy_id"));
    MP_CHECK(canonical_key_is_valid("a1.b-c_d"));
    MP_CHECK(!canonical_key_is_valid(""));
    MP_CHECK(!canonical_key_is_valid("Upper"));
    MP_CHECK(!canonical_key_is_valid("1leading"));
    MP_CHECK(!canonical_key_is_valid("has space"));
    MP_CHECK(canonical_section_is_valid("policy"));
    MP_CHECK(canonical_section_is_valid("rule blackout-a"));
    MP_CHECK(canonical_section_is_valid("exception \"quoted id\""));
    MP_CHECK(!canonical_section_is_valid(""));
    MP_CHECK(!canonical_section_is_valid("Upper"));
    MP_CHECK(!canonical_section_is_valid("two args here"));
}

MP_TEST(canonical, document_parsing) {
    const std::string text =
        "# a comment\r\n"
        "\r\n"
        "[document]\n"
        "format = maintpol/1\n"
        "kind = policy\n"
        "[policy]\n"
        "policy_id = p1\n"
        "description = \"value with spaces\"\n";
    auto document = parse_text_document(text, TextLimits{});
    MP_CHECK(document.has_value());
    MP_CHECK_EQ(document.value().entries.size(), std::size_t(6));
    SectionReader reader(document.value(), "policy");
    MP_CHECK_EQ(MP_REQUIRE(reader.take_string("policy_id")), std::string("p1"));
    MP_CHECK_EQ(MP_REQUIRE(reader.take_string("description")), std::string("value with spaces"));
    MP_CHECK(reader.finish().has_value());

    SectionReader strict(document.value(), "policy");
    MP_CHECK_EQ(MP_REQUIRE(strict.take_string("policy_id")), std::string("p1"));
    MP_CHECK_CODE(strict.finish(), Code::UnknownKey);

    SectionReader missing(document.value(), "policy");
    MP_CHECK_CODE(missing.take_string("absent"), Code::MissingKey);

    const TextDocument duplicated = MP_REQUIRE(parse_text_document("[a]\nk = 1\nk = 2\n", TextLimits{}));
    SectionReader duplicate(duplicated, "a");
    MP_CHECK_CODE(duplicate.take_string("k"), Code::DuplicateKey);
}

MP_TEST(canonical, document_bounds) {
    TextLimits limits;
    limits.max_lines = 4;
    MP_CHECK_CODE(parse_text_document("[a]\nk = 1\nk = 2\nk = 3\nk = 4\n", limits), Code::TooManyItems);

    TextLimits small;
    small.max_line_bytes = 8;
    MP_CHECK_CODE(parse_text_document("[a]\nk = 123456789\n", small), Code::LineTooLong);

    TextLimits tiny;
    tiny.max_bytes = 4;
    MP_CHECK_CODE(parse_text_document("[a]\nk = 1\n", tiny), Code::DocumentTooLarge);

    MP_CHECK_CODE(parse_text_document("", TextLimits{}), Code::EmptyDocument);
    MP_CHECK_CODE(parse_text_document("# only a comment\n", TextLimits{}), Code::EmptyDocument);
    MP_CHECK_CODE(parse_text_document("k = 1\n", TextLimits{}), Code::SyntaxInvalid);
    MP_CHECK_CODE(parse_text_document("[a]\nbroken line\n", TextLimits{}), Code::SyntaxInvalid);
    MP_CHECK_CODE(parse_text_document("[a\nk = 1\n", TextLimits{}), Code::SyntaxInvalid);
    MP_CHECK_CODE(parse_text_document("[a]\nk =\n", TextLimits{}), Code::ValueMalformed);
    MP_CHECK_CODE(parse_text_document(std::string("[a]\nk = \xC3\x28\n"), TextLimits{}), Code::InvalidUtf8);
}

MP_TEST(canonical, framed_records) {
    const std::string record = frame_record("MPS-TEST-1", "payload");
    auto payload = unframe_record(record, "MPS-TEST-1");
    MP_CHECK(payload.has_value());
    MP_CHECK_EQ(payload.value(), std::string("payload"));
    MP_CHECK_CODE(unframe_record(record, "MPS-OTHER-1"), Code::SyntaxInvalid);
    MP_CHECK_CODE(unframe_record("no newline", "MPS-TEST-1"), Code::LengthMismatch);
    MP_CHECK_CODE(unframe_record("MPS-TEST-1\nno-newline", "MPS-TEST-1"), Code::LengthMismatch);
    MP_CHECK_CODE(unframe_record("MPS-TEST-1\n5\n00\npayload", "MPS-TEST-1"), Code::LengthMismatch);
    MP_CHECK_CODE(unframe_record("MPS-TEST-1\n3\ndeadbeef\npay", "MPS-TEST-1"), Code::StoreCorrupt);
    MP_CHECK_CODE(unframe_record("MPS-TEST-1\n99999999999999999999999\n00000000\nx", "MPS-TEST-1"),
                  Code::NumberMalformed);
    std::string torn = record;
    torn.pop_back();
    MP_CHECK_CODE(unframe_record(torn, "MPS-TEST-1"), Code::LengthMismatch);
}
