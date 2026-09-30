#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "maintpol/error.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Digest256: a 256 bit content digest. Canonical text form is exactly 64
// lowercase hexadecimal characters; any other form is rejected.
// ---------------------------------------------------------------------------
class Digest256 {
public:
    static constexpr std::size_t kBytes = 32;

    Digest256() = default;

    static Digest256 zero() { return Digest256{}; }
    static Result<Digest256> from_hex(std::string_view hex);
    static Result<Digest256> from_bytes(const std::uint8_t* data, std::size_t size);

    bool is_zero() const;

    const std::array<std::uint8_t, kBytes>& bytes() const { return bytes_; }
    std::string hex() const;

    friend bool operator==(const Digest256&, const Digest256&) = default;
    friend std::strong_ordering operator<=>(const Digest256&, const Digest256&) = default;

private:
    friend class Sha256;
    std::array<std::uint8_t, kBytes>& raw() { return bytes_; }

    std::array<std::uint8_t, kBytes> bytes_{};
};

inline bool Digest256::is_zero() const {
    for (std::uint8_t byte : bytes_) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Streaming SHA-256 (FIPS 180-4). Known-answer vectors are exercised by
// "maintpol selftest" and by the test suite.
// ---------------------------------------------------------------------------
class Sha256 {
public:
    Sha256();

    void update(const void* data, std::size_t size);
    void update(std::string_view text) { update(text.data(), text.size()); }
    Digest256 finish() const;

private:
    void process_block(const std::uint8_t* block);

    std::array<std::uint32_t, 8> state_{};
    std::uint64_t total_bits_ = 0;
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffered_ = 0;
};

MAINTPOL_API Digest256 sha256(const void* data, std::size_t size);
MAINTPOL_API Digest256 sha256(std::string_view data);
MAINTPOL_API Digest256 hmac_sha256(std::string_view key, std::string_view data);

// CRC-32/ISO-HDLC (reflected, polynomial 0xEDB88320), used for framing and
// torn-write detection. Not a security control.
MAINTPOL_API std::uint32_t crc32(const void* data, std::size_t size);
MAINTPOL_API std::uint32_t crc32(std::string_view data);
MAINTPOL_API std::uint32_t crc32_extend(std::uint32_t seed, const void* data, std::size_t size);

MAINTPOL_API std::string to_hex(const std::uint8_t* data, std::size_t size);
MAINTPOL_API Result<std::vector<std::uint8_t>> bytes_from_hex(std::string_view hex);
MAINTPOL_API std::string to_hex_lower(std::uint64_t value);

// Constant-time comparison for MAC and digest verification.
MAINTPOL_API bool constant_time_equal(const std::uint8_t* left, const std::uint8_t* right, std::size_t size);

}  // namespace maintpol
