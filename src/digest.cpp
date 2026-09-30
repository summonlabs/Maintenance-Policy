#include "maintpol/digest.hpp"

#include <cstring>

namespace maintpol {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u - count));
}

constexpr std::array<std::uint32_t, 256> make_crc32_table() {
    std::array<std::uint32_t, 256> table{};
    for (std::uint32_t i = 0; i < 256u; ++i) {
        std::uint32_t value = i;
        for (int bit = 0; bit < 8; ++bit) {
            value = (value & 1u) != 0u ? (value >> 1u) ^ 0xEDB88320u : value >> 1u;
        }
        table[i] = value;
    }
    return table;
}

constexpr std::array<std::uint32_t, 256> kCrc32Table = make_crc32_table();

constexpr char kHexDigits[] = "0123456789abcdef";

constexpr int hex_value(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    return -1;
}

}  // namespace

Result<Digest256> Digest256::from_hex(std::string_view hex) {
    if (hex.size() != kBytes * 2u) {
        return make_error(Code::DigestMalformed, "digest must be exactly 64 characters");
    }
    Digest256 result;
    for (std::size_t i = 0; i < kBytes; ++i) {
        const int high = hex_value(hex[i * 2u]);
        const int low = hex_value(hex[(i * 2u) + 1u]);
        if (high < 0 || low < 0) {
            return make_error(Code::DigestMalformed, "digest must be lowercase hexadecimal");
        }
        result.bytes_[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return result;
}

Result<Digest256> Digest256::from_bytes(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr || size != kBytes) {
        return make_error(Code::LengthMismatch, "digest requires exactly 32 bytes");
    }
    Digest256 result;
    std::memcpy(result.bytes_.data(), data, kBytes);
    return result;
}

std::string Digest256::hex() const { return to_hex(bytes_.data(), bytes_.size()); }

Sha256::Sha256() {
    state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void Sha256::process_block(const std::uint8_t* block) {
    std::uint32_t schedule[64];
    for (std::size_t i = 0; i < 16; ++i) {
        schedule[i] = (static_cast<std::uint32_t>(block[i * 4u]) << 24u) |
                      (static_cast<std::uint32_t>(block[(i * 4u) + 1u]) << 16u) |
                      (static_cast<std::uint32_t>(block[(i * 4u) + 2u]) << 8u) |
                      static_cast<std::uint32_t>(block[(i * 4u) + 3u]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(schedule[i - 15], 7) ^ rotr(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3u);
        const std::uint32_t s1 = rotr(schedule[i - 2], 17) ^ rotr(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10u);
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t choose = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + s1 + choose + kSha256K[i] + schedule[i];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) {
    if (size == 0) {
        return;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    total_bits_ += static_cast<std::uint64_t>(size) * 8u;

    if (buffered_ > 0) {
        const std::size_t needed = 64u - buffered_;
        const std::size_t take = size < needed ? size : needed;
        std::memcpy(buffer_.data() + buffered_, bytes, take);
        buffered_ += take;
        bytes += take;
        size -= take;
        if (buffered_ == 64u) {
            process_block(buffer_.data());
            buffered_ = 0;
        }
    }

    while (size >= 64u) {
        process_block(bytes);
        bytes += 64u;
        size -= 64u;
    }

    if (size > 0) {
        std::memcpy(buffer_.data(), bytes, size);
        buffered_ = size;
    }
}

Digest256 Sha256::finish() const {
    Sha256 copy = *this;
    const std::uint64_t bit_length = copy.total_bits_;

    const std::uint8_t padding = 0x80u;
    copy.update(&padding, 1);

    const std::uint8_t zero = 0x00u;
    while (copy.buffered_ != 56u) {
        copy.update(&zero, 1);
    }

    std::uint8_t length_bytes[8];
    for (std::size_t i = 0; i < 8; ++i) {
        length_bytes[7u - i] = static_cast<std::uint8_t>((bit_length >> (i * 8u)) & 0xFFu);
    }
    copy.update(length_bytes, 8);

    Digest256 result;
    std::array<std::uint8_t, Digest256::kBytes>& out = result.raw();
    for (std::size_t i = 0; i < 8; ++i) {
        out[i * 4u] = static_cast<std::uint8_t>((copy.state_[i] >> 24u) & 0xFFu);
        out[(i * 4u) + 1u] = static_cast<std::uint8_t>((copy.state_[i] >> 16u) & 0xFFu);
        out[(i * 4u) + 2u] = static_cast<std::uint8_t>((copy.state_[i] >> 8u) & 0xFFu);
        out[(i * 4u) + 3u] = static_cast<std::uint8_t>(copy.state_[i] & 0xFFu);
    }
    return result;
}

Digest256 sha256(const void* data, std::size_t size) {
    Sha256 hasher;
    hasher.update(data, size);
    return hasher.finish();
}

Digest256 sha256(std::string_view data) { return sha256(data.data(), data.size()); }

Digest256 hmac_sha256(std::string_view key, std::string_view data) {
    constexpr std::size_t kBlockSize = 64;
    std::array<std::uint8_t, kBlockSize> key_block{};

    if (key.size() > kBlockSize) {
        const Digest256 hashed_key = sha256(key);
        std::memcpy(key_block.data(), hashed_key.bytes().data(), Digest256::kBytes);
    } else if (!key.empty()) {
        std::memcpy(key_block.data(), key.data(), key.size());
    }

    std::array<std::uint8_t, kBlockSize> inner_pad{};
    std::array<std::uint8_t, kBlockSize> outer_pad{};
    for (std::size_t i = 0; i < kBlockSize; ++i) {
        inner_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36u);
        outer_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5cu);
    }

    Sha256 inner;
    inner.update(inner_pad.data(), inner_pad.size());
    inner.update(data.data(), data.size());
    const Digest256 inner_digest = inner.finish();

    Sha256 outer;
    outer.update(outer_pad.data(), outer_pad.size());
    outer.update(inner_digest.bytes().data(), inner_digest.bytes().size());
    return outer.finish();
}

std::uint32_t crc32_extend(std::uint32_t seed, const void* data, std::size_t size) {
    std::uint32_t crc = seed ^ 0xFFFFFFFFu;
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        crc = kCrc32Table[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8u);
    }
    return crc ^ 0xFFFFFFFFu;
}

std::uint32_t crc32(const void* data, std::size_t size) { return crc32_extend(0u, data, size); }

std::uint32_t crc32(std::string_view data) { return crc32(data.data(), data.size()); }

std::string to_hex(const std::uint8_t* data, std::size_t size) {
    std::string result;
    result.reserve(size * 2u);
    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(kHexDigits[data[i] >> 4u]);
        result.push_back(kHexDigits[data[i] & 0x0Fu]);
    }
    return result;
}

Result<std::vector<std::uint8_t>> bytes_from_hex(std::string_view hex) {
    if ((hex.size() % 2u) != 0u) {
        return make_error(Code::ValueMalformed, "hexadecimal input must have an even length");
    }
    std::vector<std::uint8_t> result;
    result.reserve(hex.size() / 2u);
    for (std::size_t i = 0; i < hex.size(); i += 2u) {
        const int high = hex_value(hex[i]);
        const int low = hex_value(hex[i + 1u]);
        if (high < 0 || low < 0) {
            return make_error(Code::ValueMalformed, "hexadecimal input contains a non-hexadecimal character");
        }
        result.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return result;
}

std::string to_hex_lower(std::uint64_t value) {
    std::string result(16, '0');
    for (std::size_t i = 0; i < 16; ++i) {
        result[15u - i] = kHexDigits[(value >> (i * 4u)) & 0xFu];
    }
    return result;
}

bool constant_time_equal(const std::uint8_t* left, const std::uint8_t* right, std::size_t size) {
    std::uint8_t accumulator = 0;
    for (std::size_t i = 0; i < size; ++i) {
        accumulator = static_cast<std::uint8_t>(accumulator | (left[i] ^ right[i]));
    }
    return accumulator == 0;
}

}  // namespace maintpol
