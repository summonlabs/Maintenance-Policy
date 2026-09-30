#include <algorithm>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"
#include "maintpol/digest.hpp"

namespace {

using namespace maintpol;

}  // namespace

MP_TEST(digest, known_answer_vectors) {
    MP_CHECK(sha256("").hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    MP_CHECK(sha256("abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    MP_CHECK(sha256(std::string(1000u, 'a')).hex() ==
             "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
    MP_CHECK(crc32("123456789") == 0xCBF43926u);
    MP_CHECK(crc32("") == 0u);
}

MP_TEST(digest, streaming_matches_one_shot) {
    std::string payload;
    for (int index = 0; index < 5000; ++index) {
        payload.push_back(static_cast<char>((index * 7) % 251));
    }
    const Digest256 expected = sha256(payload);
    const std::vector<std::size_t> chunks = {1u, 7u, 63u, 64u, 65u, 1000u};
    for (std::size_t chunk : chunks) {
        Sha256 hasher;
        std::size_t offset = 0;
        while (offset < payload.size()) {
            const std::size_t take = (std::min)(chunk, payload.size() - offset);
            hasher.update(payload.data() + offset, take);
            offset += take;
        }
        MP_CHECK(hasher.finish() == expected);
    }
}

MP_TEST(digest, hmac_known_answers) {
    MP_CHECK(hmac_sha256("Jefe", "what do ya want for nothing?").hex() ==
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    const std::string short_key(15u, 'k');
    MP_CHECK_EQ(hmac_sha256(short_key, "message").hex().size(), std::size_t(64));
}

MP_TEST(digest, hex_parsing_is_strict) {
    auto good = Digest256::from_hex(std::string(64u, '0'));
    MP_CHECK(good.has_value());
    MP_CHECK(good.value().is_zero());
    MP_CHECK_CODE(Digest256::from_hex(std::string(63u, '0')), Code::DigestMalformed);
    MP_CHECK_CODE(Digest256::from_hex(std::string(64u, 'A')), Code::DigestMalformed);
    MP_CHECK_CODE(Digest256::from_hex(std::string(64u, 'z')), Code::DigestMalformed);
    MP_CHECK_CODE(Digest256::from_hex(""), Code::DigestMalformed);
    auto bytes = bytes_from_hex("00ff10");
    MP_CHECK(bytes.has_value());
    MP_CHECK_EQ(bytes.value().size(), std::size_t(3));
    MP_CHECK_CODE(bytes_from_hex("0"), Code::ValueMalformed);
    MP_CHECK_CODE(bytes_from_hex("0g"), Code::ValueMalformed);
    MP_CHECK(to_hex_lower(0x0F1Full) == "0000000000000f1f");
}

MP_TEST(digest, constant_time_compare) {
    const std::uint8_t left[4] = {1, 2, 3, 4};
    const std::uint8_t same[4] = {1, 2, 3, 4};
    const std::uint8_t different[4] = {1, 2, 3, 5};
    MP_CHECK(constant_time_equal(left, same, 4));
    MP_CHECK(!constant_time_equal(left, different, 4));
}
