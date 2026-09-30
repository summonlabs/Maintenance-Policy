#include "maintpol/store.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "maintpol/canonical.hpp"
#include "maintpol/digest.hpp"
#include "maintpol/fileio.hpp"
#include "maintpol/text.hpp"

namespace maintpol {
namespace {

constexpr std::size_t kMaxJournalBytes = 64u * 1024u * 1024u;
constexpr std::string_view kRecordSeparator = "%%";

#define MP_TRY(expr)                       \
    do {                                   \
        auto mp_result = (expr);           \
        if (!mp_result) {                  \
            return mp_result.error();      \
        }                                  \
    } while (false)

#define MP_ASSIGN(name, expr)                                     \
    auto name##_result = (expr);                                  \
    if (!name##_result) {                                         \
        return name##_result.error();                             \
    }                                                             \
    auto name = name##_result.value()

std::string pad_generation(std::uint64_t value) {
    std::string text = std::to_string(value);
    if (text.size() < 20u) {
        text.insert(0, 20u - text.size(), '0');
    }
    return text;
}

std::string bundle_file_name(const PolicyGeneration& generation) {
    return "gen-" + pad_generation(generation.value()) + ".mpb";
}

bool parse_bundle_file_name(std::string_view name, std::uint64_t& generation) {
    constexpr std::string_view prefix = "gen-";
    constexpr std::string_view suffix = ".mpb";
    if (name.size() != prefix.size() + 20u + suffix.size()) {
        return false;
    }
    if (name.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    if (name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    std::uint64_t value = 0;
    for (std::size_t index = prefix.size(); index < prefix.size() + 20u; ++index) {
        const char character = name[index];
        if (character < '0' || character > '9') {
            return false;
        }
        value = (value * 10u) + static_cast<std::uint64_t>(character - '0');
    }
    generation = value;
    return true;
}

std::string join_path(const std::string& root, std::string_view name) {
    std::string path = root;
    if (!path.empty() && path.back() != '\\' && path.back() != '/') {
        path.push_back('\\');
    }
    path.append(name);
    return path;
}

// ---------------------------------------------------------------------------
// Framed records: "<header>\n<length>\n<crc32>\n<payload>".
// ---------------------------------------------------------------------------
struct FrameView {
    std::uint64_t offset = 0;
    std::uint64_t total_bytes = 0;
    std::string header;
    std::string payload;
};

Result<bool> next_frame(std::string_view content, std::uint64_t offset, std::string_view expected_header,
                        FrameView& frame, bool& trailing_partial) {
    trailing_partial = false;
    if (offset >= content.size()) {
        return false;
    }
    const std::size_t start = static_cast<std::size_t>(offset);
    const std::size_t header_end = content.find('\n', start);
    if (header_end == std::string_view::npos) {
        trailing_partial = true;
        return false;
    }
    const std::string_view header = content.substr(start, header_end - start);
    if (header.size() < expected_header.size() ||
        header.compare(0, expected_header.size(), expected_header) != 0) {
        return make_error(Code::StoreCorrupt, "record header does not match '" + std::string(expected_header) + "'");
    }
    // A header that carries a trailing 'header_crc' field covers itself: the
    // decision journal records identities in the header, so a bit flip there
    // must be detected without parsing the body.
    const std::string_view crc_field = " header_crc=";
    const std::size_t crc_position = header.rfind(crc_field);
    if (crc_position != std::string_view::npos) {
        const std::string_view crc_text = header.substr(crc_position + crc_field.size());
        if (crc_text.size() != 8u) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header checksum is malformed");
        }
        std::uint32_t stored = 0;
        for (char character : crc_text) {
            const int digit = character >= '0' && character <= '9'   ? character - '0'
                              : character >= 'a' && character <= 'f' ? character - 'a' + 10
                                                                     : -1;
            if (digit < 0) {
                return make_error(Code::StoreJournalCorrupt, "journal entry header checksum is malformed");
            }
            stored = (stored << 4u) | static_cast<std::uint32_t>(digit);
        }
        if (stored != crc32(header.substr(0, crc_position))) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header checksum does not match");
        }
    }
    const std::size_t length_end = content.find('\n', header_end + 1u);
    if (length_end == std::string_view::npos) {
        trailing_partial = true;
        return false;
    }
    const std::size_t checksum_end = content.find('\n', length_end + 1u);
    if (checksum_end == std::string_view::npos) {
        trailing_partial = true;
        return false;
    }
    const std::string_view length_text = content.substr(header_end + 1u, length_end - header_end - 1u);
    if (length_text.empty() || length_text.size() > 20u) {
        return make_error(Code::StoreCorrupt, "record length field is malformed");
    }
    std::uint64_t payload_bytes = 0;
    for (char character : length_text) {
        if (character < '0' || character > '9') {
            return make_error(Code::StoreCorrupt, "record length field is malformed");
        }
        payload_bytes = (payload_bytes * 10u) + static_cast<std::uint64_t>(character - '0');
        if (payload_bytes > kMaxRecordBytes) {
            return make_error(Code::StoreRecordTooLarge, "record declares an oversized payload");
        }
    }
    const std::size_t payload_start = checksum_end + 1u;
    const std::string_view checksum_text = content.substr(length_end + 1u, checksum_end - length_end - 1u);
    // A torn append stops at an arbitrary byte, so its checksum field can be
    // short but never contains anything other than hexadecimal digits. A field
    // that swallowed following content is a corrupted separator, and treating
    // it as an unacknowledged tail would silently discard a whole record.
    bool checksum_is_hex = !checksum_text.empty() && checksum_text.size() <= 8u;
    for (char character : checksum_text) {
        const bool hex = (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
        if (!hex) {
            checksum_is_hex = false;
            break;
        }
    }
    if (payload_start + payload_bytes > content.size()) {
        if (checksum_is_hex) {
            trailing_partial = true;
            return false;
        }
        return make_error(Code::StoreCorrupt,
                          "record tail is neither a complete frame nor an unacknowledged partial write");
    }
    if (checksum_text.size() != 8u || !checksum_is_hex) {
        return make_error(Code::StoreCorrupt, "record checksum field is malformed");
    }
    const std::string_view payload = content.substr(payload_start, static_cast<std::size_t>(payload_bytes));
    auto checksum = bytes_from_hex(checksum_text);
    if (!checksum) {
        return make_error(Code::StoreCorrupt, "record checksum field is malformed");
    }
    if (checksum.value().size() != 4u) {
        return make_error(Code::StoreCorrupt, "record checksum must be four bytes");
    }
    const std::uint32_t stored = (static_cast<std::uint32_t>(checksum.value()[0]) << 24u) |
                                 (static_cast<std::uint32_t>(checksum.value()[1]) << 16u) |
                                 (static_cast<std::uint32_t>(checksum.value()[2]) << 8u) |
                                 static_cast<std::uint32_t>(checksum.value()[3]);
    if (crc32(payload) != stored) {
        return make_error(Code::StoreCorrupt, "record checksum does not match its payload");
    }
    frame.offset = offset;
    frame.total_bytes = (payload_start + payload_bytes) - start;
    frame.header.assign(header);
    frame.payload.assign(payload);
    return true;
}

Result<std::vector<std::string_view>> header_fields(std::string_view header, std::string_view prefix,
                                                    const std::vector<std::string_view>& keys) {
    if (header.size() < prefix.size() || header.compare(0, prefix.size(), prefix) != 0) {
        return make_error(Code::StoreCorrupt, "record header prefix does not match");
    }
    std::string_view rest = header.substr(prefix.size());
    std::vector<std::string_view> values;
    values.reserve(keys.size());
    for (const std::string_view key : keys) {
        if (rest.empty() || rest.front() != ' ') {
            return make_error(Code::StoreCorrupt, "record header is missing field '" + std::string(key) + "'");
        }
        rest.remove_prefix(1);
        if (rest.size() <= key.size() || rest.compare(0, key.size(), key) != 0 || rest[key.size()] != '=') {
            return make_error(Code::StoreCorrupt, "record header field order is not canonical");
        }
        rest.remove_prefix(key.size() + 1u);
        const std::size_t space = rest.find(' ');
        const std::string_view value = space == std::string_view::npos ? rest : rest.substr(0, space);
        if (value.empty()) {
            return make_error(Code::StoreCorrupt, "record header field '" + std::string(key) + "' is empty");
        }
        values.push_back(value);
        if (space == std::string_view::npos) {
            rest = std::string_view();
        } else {
            rest.remove_prefix(space);
        }
    }
    if (!rest.empty()) {
        return make_error(Code::StoreCorrupt, "record header has trailing fields");
    }
    return values;
}

// ---------------------------------------------------------------------------
// Bundle records.
// ---------------------------------------------------------------------------
struct BundleRecordHeader {
    PolicyGeneration generation;
    ControlEpoch control_epoch;
    Revision registry_revision;
    Digest256 body_digest;
    std::uint64_t body_bytes = 0;
    Digest256 previous_record_digest;
};

std::string build_bundle_record(const PolicyBundle& bundle, const Digest256& previous_record_digest) {
    const std::string body = canonical_bundle(bundle);
    CanonicalWriter writer;
    writer.section("record");
    writer.field("format", kStoreFormatId);
    writer.field("kind", "bundle");
    writer.field("generation", bundle.policy().generation().value());
    writer.field("control_epoch", bundle.control_epoch().value());
    writer.field("registry_revision", bundle.registry_revision().value());
    writer.field("body_digest", sha256(body));
    writer.field("body_bytes", static_cast<std::uint64_t>(body.size()));
    writer.field("prev_record_digest", previous_record_digest);
    std::string payload = writer.take();
    payload.append(kRecordSeparator);
    payload.push_back('\n');
    payload.append(body);
    return payload;
}

Result<void> parse_bundle_record(std::string_view payload, BundleRecordHeader& header, std::string& body) {
    const std::string separator = "\n" + std::string(kRecordSeparator) + "\n";
    const std::size_t split = payload.find(separator);
    if (split == std::string_view::npos) {
        return make_error(Code::StoreCorrupt, "bundle record has no body separator");
    }
    const std::string header_text(payload.substr(0, split + 1u));
    body.assign(payload.substr(split + separator.size()));

    auto document = parse_text_document(header_text, TextLimits{});
    if (!document) {
        return document.error();
    }
    SectionReader reader(document.value(), "record");
    MP_ASSIGN(format, reader.take_string("format"));
    if (format != kStoreFormatId) {
        return make_error(Code::UnsupportedFormatVersion, "bundle record format is not supported");
    }
    MP_ASSIGN(kind, reader.take_string("kind"));
    if (kind != "bundle") {
        return make_error(Code::StoreCorrupt, "bundle record kind is not 'bundle'");
    }
    MP_ASSIGN(generation_text, reader.take_string("generation"));
    auto generation = PolicyGeneration::parse(generation_text);
    if (!generation) {
        return generation.error();
    }
    MP_ASSIGN(epoch_text, reader.take_string("control_epoch"));
    auto control_epoch = ControlEpoch::parse(epoch_text);
    if (!control_epoch) {
        return control_epoch.error();
    }
    MP_ASSIGN(revision_text, reader.take_string("registry_revision"));
    auto registry_revision = Revision::parse(revision_text);
    if (!registry_revision) {
        return registry_revision.error();
    }
    MP_ASSIGN(body_digest, reader.take_digest("body_digest"));
    MP_ASSIGN(body_bytes, reader.take_u64("body_bytes"));
    MP_ASSIGN(previous, reader.take_digest("prev_record_digest"));
    MP_TRY(reader.finish());

    if (body.size() != body_bytes) {
        return make_error(Code::LengthMismatch, "bundle record body length does not match its header");
    }
    if (!(sha256(body) == body_digest)) {
        return make_error(Code::StoreCorrupt, "bundle record body digest does not match its body");
    }
    header.generation = generation.value();
    header.control_epoch = control_epoch.value();
    header.registry_revision = registry_revision.value();
    header.body_digest = body_digest;
    header.body_bytes = body_bytes;
    header.previous_record_digest = previous;
    return {};
}

// ---------------------------------------------------------------------------
// Manifest.
// ---------------------------------------------------------------------------
std::string build_manifest_payload(const StoreInfo& info) {
    CanonicalWriter writer;
    writer.section("manifest");
    writer.field("format", kStoreFormatId);
    writer.field("store_id", info.store_id);
    writer.field("generation", info.generation.value());
    writer.field("control_epoch", info.control_epoch.value());
    writer.field("registry_revision", info.registry_revision.value());
    writer.field("record_digest", info.record_digest);
    writer.field("bundle_digest", info.bundle_digest);
    writer.field("bundle_bytes", info.bundle_bytes);
    return writer.take();
}

Result<StoreInfo> parse_manifest_payload(std::string_view payload) {
    auto document = parse_text_document(payload, TextLimits{});
    if (!document) {
        return document.error();
    }
    SectionReader reader(document.value(), "manifest");
    StoreInfo info;
    MP_ASSIGN(format, reader.take_string("format"));
    if (format != kStoreFormatId) {
        return make_error(Code::UnsupportedFormatVersion, "manifest format is not supported");
    }
    MP_ASSIGN(store_id, reader.take_string("store_id"));
    MP_ASSIGN(generation_text, reader.take_string("generation"));
    auto generation = PolicyGeneration::parse(generation_text);
    if (!generation) {
        return generation.error();
    }
    MP_ASSIGN(epoch_text, reader.take_string("control_epoch"));
    auto control_epoch = ControlEpoch::parse(epoch_text);
    if (!control_epoch) {
        return control_epoch.error();
    }
    MP_ASSIGN(revision_text, reader.take_string("registry_revision"));
    auto registry_revision = Revision::parse(revision_text);
    if (!registry_revision) {
        return registry_revision.error();
    }
    MP_ASSIGN(record_digest, reader.take_digest("record_digest"));
    MP_ASSIGN(bundle_digest, reader.take_digest("bundle_digest"));
    MP_ASSIGN(bundle_bytes, reader.take_u64("bundle_bytes"));
    MP_TRY(reader.finish());
    info.store_id = store_id;
    info.generation = generation.value();
    info.control_epoch = control_epoch.value();
    info.registry_revision = registry_revision.value();
    info.record_digest = record_digest;
    info.bundle_digest = bundle_digest;
    info.bundle_bytes = bundle_bytes;
    return info;
}

// ---------------------------------------------------------------------------
// Fence entries.
// ---------------------------------------------------------------------------
std::string build_fence_payload(const StoreInfo& info) {
    CanonicalWriter writer;
    writer.section("fence");
    writer.field("format", kStoreFormatId);
    writer.field("epoch", info.control_epoch.value());
    writer.field("generation", info.generation.value());
    writer.field("record_digest", info.record_digest);
    return writer.take();
}

Result<void> parse_fence_payload(std::string_view payload, ControlEpoch& epoch, PolicyGeneration& generation,
                                 Digest256& record_digest) {
    auto document = parse_text_document(payload, TextLimits{});
    if (!document) {
        return document.error();
    }
    SectionReader reader(document.value(), "fence");
    MP_ASSIGN(format, reader.take_string("format"));
    if (format != kStoreFormatId) {
        return make_error(Code::UnsupportedFormatVersion, "fence entry format is not supported");
    }
    MP_ASSIGN(epoch_text, reader.take_string("epoch"));
    auto parsed_epoch = ControlEpoch::parse(epoch_text);
    if (!parsed_epoch) {
        return parsed_epoch.error();
    }
    MP_ASSIGN(generation_text, reader.take_string("generation"));
    auto parsed_generation = PolicyGeneration::parse(generation_text);
    if (!parsed_generation) {
        return parsed_generation.error();
    }
    MP_ASSIGN(digest, reader.take_digest("record_digest"));
    MP_TRY(reader.finish());
    epoch = parsed_epoch.value();
    generation = parsed_generation.value();
    record_digest = digest;
    return {};
}

// ---------------------------------------------------------------------------
// File level helpers.
// ---------------------------------------------------------------------------
Result<void> publish_record(const std::string& path, std::string_view payload, const FaultPlan& faults) {
    const std::string temp = path + std::string(kTempSuffix);
    MP_TRY(write_file_durable(temp, payload));
    fault_point(faults, FaultPoint::AfterRecordTempWrite);
    fault_point(faults, FaultPoint::AfterRecordTempFlush);
    auto read_back = read_file_bounded(temp, kMaxRecordBytes);
    if (!read_back) {
        return read_back.error();
    }
    if (!(read_back.value() == payload)) {
        return make_error(Code::StoreVerifyFailed, "staged record did not read back identically");
    }
    fault_point(faults, FaultPoint::AfterRecordTempVerify);
    MP_TRY(replace_file(temp, path));
    fault_point(faults, FaultPoint::AfterRecordPublish);
    return {};
}

Result<void> publish_manifest(const std::string& root, const StoreInfo& info, const FaultPlan& faults) {
    const std::string payload = build_manifest_payload(info);
    const std::string record = frame_record(kManifestRecordHeader, payload);
    const std::string path = join_path(root, kManifestFileName);
    const std::string temp = path + std::string(kTempSuffix);
    MP_TRY(write_file_durable(temp, record));
    fault_point(faults, FaultPoint::AfterManifestTempWrite);
    fault_point(faults, FaultPoint::AfterManifestTempFlush);
    auto read_back = read_file_bounded(temp, kMaxRecordBytes);
    if (!read_back) {
        return read_back.error();
    }
    if (!(read_back.value() == record)) {
        return make_error(Code::StoreVerifyFailed, "staged manifest did not read back identically");
    }
    fault_point(faults, FaultPoint::AfterManifestTempVerify);
    MP_TRY(replace_file(temp, path));
    fault_point(faults, FaultPoint::AfterManifestPublish);
    MP_TRY(flush_directory(root));
    return {};
}

Result<void> append_fence(const std::string& root, const StoreInfo& info, const FaultPlan& faults) {
    const std::string payload = build_fence_payload(info);
    const std::string record = frame_record(kFenceRecordHeader, payload);
    MP_TRY(append_file_durable(join_path(root, kFenceFileName), record));
    // Read the tail back so that an acknowledged fence entry is proven durable.
    auto size = file_size(join_path(root, kFenceFileName));
    if (!size) {
        return size.error();
    }
    if (size.value() < record.size()) {
        return make_error(Code::StoreVerifyFailed, "fence append did not reach the file");
    }
    auto tail = read_file_range(join_path(root, kFenceFileName),
                                size.value() - static_cast<std::uint64_t>(record.size()), record.size());
    if (!tail) {
        return tail.error();
    }
    if (!(tail.value() == record)) {
        return make_error(Code::StoreVerifyFailed, "fence entry did not read back identically");
    }
    fault_point(faults, FaultPoint::AfterFenceAppend);
    return {};
}

Result<void> read_manifest(const std::string& root, StoreInfo& info) {
    const std::string path = join_path(root, kManifestFileName);
    auto exists = file_exists(path);
    if (!exists) {
        return exists.error();
    }
    if (!exists.value()) {
        return make_error(Code::StoreMissing, "store has no manifest");
    }
    auto content = read_file_bounded(path, kMaxRecordBytes);
    if (!content) {
        return content.error();
    }
    auto payload = unframe_record(content.value(), kManifestRecordHeader);
    if (!payload) {
        return payload.error();
    }
    auto parsed = parse_manifest_payload(payload.value());
    if (!parsed) {
        return parsed.error();
    }
    info = parsed.value();
    return {};
}

// Loads and verifies the record of one generation against the manifest data.
Result<PolicyBundle> load_record(const std::string& root, const StoreInfo& info, BundleRecordHeader* header_out,
                                 std::vector<std::string>* notes) {
    const std::string path = join_path(root, bundle_file_name(info.generation));
    auto exists = file_exists(path);
    if (!exists) {
        return exists.error();
    }
    if (!exists.value()) {
        return make_error(Code::StoreGenerationMissing,
                          "manifest names generation " + info.generation.format() + " but its record is absent");
    }
    auto content = read_file_bounded(path, kMaxRecordBytes);
    if (!content) {
        return content.error();
    }
    auto payload = unframe_record(content.value(), kBundleRecordHeader);
    if (!payload) {
        return payload.error();
    }
    if (!(sha256(payload.value()) == info.record_digest)) {
        return make_error(Code::StoreVerifyFailed, "published record digest does not match the manifest");
    }
    BundleRecordHeader header;
    std::string body;
    MP_TRY(parse_bundle_record(payload.value(), header, body));
    if (header.generation != info.generation) {
        return make_error(Code::StoreCorrupt, "record generation does not match the manifest");
    }
    if (header.control_epoch != info.control_epoch || header.registry_revision != info.registry_revision) {
        return make_error(Code::StoreCorrupt, "record epoch or registry revision does not match the manifest");
    }
    if (!(sha256(body) == info.bundle_digest) || body.size() != info.bundle_bytes) {
        return make_error(Code::StoreCorrupt, "record body does not match the manifest digest");
    }
    auto bundle = parse_bundle_document(body);
    if (!bundle) {
        return bundle.error();
    }
    if (bundle.value().policy().generation() != info.generation) {
        return make_error(Code::StoreCorrupt, "bundle generation does not match its record");
    }
    if (bundle.value().control_epoch() != info.control_epoch ||
        bundle.value().registry_revision() != info.registry_revision) {
        return make_error(Code::StoreCorrupt, "bundle epochs do not match its record");
    }
    if (header_out != nullptr) {
        *header_out = header;
    }
    if (notes != nullptr) {
        notes->push_back("generation " + info.generation.format() + " verified (" + info.record_digest.hex() + ")");
    }
    return bundle.value();
}

struct FenceScan {
    bool present = false;
    std::uint64_t entries = 0;
    ControlEpoch max_epoch;
    PolicyGeneration max_generation;
    Digest256 max_record_digest;
    bool trailing_partial = false;
};

Result<FenceScan> read_fence(const std::string& root) {
    FenceScan scan;
    const std::string path = join_path(root, kFenceFileName);
    auto exists = file_exists(path);
    if (!exists) {
        return exists.error();
    }
    if (!exists.value()) {
        return scan;
    }
    scan.present = true;
    auto content = read_file_bounded(path, kMaxJournalBytes);
    if (!content) {
        return content.error();
    }
    if (content.value().empty()) {
        // A fence journal that exists but holds no entry means the rollback
        // guard was lost; that is a corruption, not an empty history.
        return make_error(Code::StoreCorrupt, "fence journal is present but holds no entry");
    }
    std::uint64_t offset = 0;
    std::optional<ControlEpoch> previous_epoch;
    std::optional<PolicyGeneration> previous_generation;
    while (offset < content.value().size()) {
        FrameView frame;
        bool trailing = false;
        auto more = next_frame(content.value(), offset, kFenceRecordHeader, frame, trailing);
        if (!more) {
            if (more.has_value()) {
                break;
            }
            return more.error();
        }
        if (!more.value()) {
            if (!trailing) {
                break;
            }
            return make_error(Code::StoreCorrupt,
                              "fence journal ends with an incomplete entry, which is never authority");
        }
        ControlEpoch epoch;
        PolicyGeneration generation;
        Digest256 digest;
        MP_TRY(parse_fence_payload(frame.payload, epoch, generation, digest));
        if (previous_epoch.has_value()) {
            auto expected_epoch = previous_epoch.value().next();
            if (!expected_epoch || !(epoch == expected_epoch.value())) {
                return make_error(Code::StoreFenceRegression, "fence epochs are not strictly consecutive");
            }
        }
        if (previous_generation.has_value()) {
            auto expected_generation = previous_generation.value().next();
            if (!expected_generation || !(generation == expected_generation.value())) {
                return make_error(Code::StoreFenceRegression, "fence generations are not strictly consecutive");
            }
        }
        previous_epoch = epoch;
        previous_generation = generation;
        scan.entries += 1u;
        scan.max_epoch = epoch;
        scan.max_generation = generation;
        scan.max_record_digest = digest;
        offset += frame.total_bytes;
    }
    return scan;
}

struct JournalScan {
    bool present = false;
    std::uint64_t records = 0;
    std::uint64_t bytes = 0;
    std::uint64_t complete_bytes = 0;
    bool trailing_partial = false;
    std::vector<FrameView> frames;
};

Result<JournalScan> read_journal(const std::string& root, bool keep_frames) {
    JournalScan scan;
    const std::string path = join_path(root, kJournalFileName);
    auto exists = file_exists(path);
    if (!exists) {
        return exists.error();
    }
    if (!exists.value()) {
        return scan;
    }
    scan.present = true;
    auto content = read_file_bounded(path, kMaxJournalBytes);
    if (!content) {
        return content.error();
    }
    scan.bytes = content.value().size();
    std::uint64_t offset = 0;
    std::uint64_t expected_sequence = 1;
    while (offset < content.value().size()) {
        FrameView frame;
        bool trailing = false;
        auto more = next_frame(content.value(), offset, kDecisionRecordHeader, frame, trailing);
        if (!more) {
            return more.error();
        }
        if (!more.value()) {
            scan.trailing_partial = trailing;
            break;
        }
        const std::string expected_header_prefix = std::string(kDecisionRecordHeader);
        auto fields = header_fields(frame.header, kDecisionRecordHeader,
                                    {"seq", "context_id", "request_digest", "decision_digest", "header_crc"});
        if (!fields) {
            return fields.error();
        }
        const std::vector<std::string_view>& values = fields.value();
        if (values.size() != 5u) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header is incomplete");
        }
        // The header carries its own checksum: a bit flip anywhere in the
        // recorded identity fields is detected without parsing the body.
        const std::size_t crc_offset = frame.header.rfind(" header_crc=");
        if (crc_offset == std::string::npos) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header has no checksum");
        }
        const std::uint32_t expected_crc = crc32(std::string_view(frame.header).substr(0, crc_offset));
        std::uint32_t stored_crc = 0;
        for (char character : values[4]) {
            const int digit = character >= '0' && character <= '9'   ? character - '0'
                              : character >= 'a' && character <= 'f' ? character - 'a' + 10
                                                                     : -1;
            if (digit < 0) {
                return make_error(Code::StoreJournalCorrupt, "journal entry header checksum is malformed");
            }
            stored_crc = (stored_crc << 4u) | static_cast<std::uint32_t>(digit);
        }
        if (stored_crc != expected_crc) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header checksum does not match");
        }
        std::uint64_t sequence = 0;
        for (char character : values[0]) {
            if (character < '0' || character > '9') {
                return make_error(Code::StoreJournalCorrupt, "journal sequence is malformed");
            }
            sequence = (sequence * 10u) + static_cast<std::uint64_t>(character - '0');
        }
        if (sequence != expected_sequence) {
            return make_error(Code::StoreJournalGap, "journal sequence is not contiguous");
        }
        expected_sequence += 1u;
        scan.records += 1u;
        offset += frame.total_bytes;
        scan.complete_bytes = offset;
        if (keep_frames) {
            scan.frames.push_back(std::move(frame));
        }
    }
    return scan;
}

Result<DecisionRecord> decode_journal_frame(const FrameView& frame) {
    auto fields = header_fields(frame.header, kDecisionRecordHeader,
                                {"seq", "context_id", "request_digest", "decision_digest", "header_crc"});
    if (!fields) {
        return fields.error();
    }
    const std::vector<std::string_view>& values = fields.value();
    if (values.size() != 5u) {
        return make_error(Code::StoreJournalCorrupt, "journal entry header is incomplete");
    }
    const std::size_t crc_offset = frame.header.rfind(" header_crc=");
    if (crc_offset == std::string::npos) {
        return make_error(Code::StoreJournalCorrupt, "journal entry header has no checksum");
    }
    const std::uint32_t expected_crc = crc32(std::string_view(frame.header).substr(0, crc_offset));
    std::uint32_t stored_crc = 0;
    for (char character : values[4]) {
        const int digit = character >= '0' && character <= '9'   ? character - '0'
                          : character >= 'a' && character <= 'f' ? character - 'a' + 10
                                                                 : -1;
        if (digit < 0) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header checksum is malformed");
        }
        stored_crc = (stored_crc << 4u) | static_cast<std::uint32_t>(digit);
    }
    if (stored_crc != expected_crc) {
        return make_error(Code::StoreJournalCorrupt, "journal entry header checksum does not match");
    }
    std::uint64_t sequence = 0;
    for (char character : values[0]) {
        if (character < '0' || character > '9') {
            return make_error(Code::StoreJournalCorrupt, "journal sequence is malformed");
        }
        sequence = (sequence * 10u) + static_cast<std::uint64_t>(character - '0');
    }
    auto parsed_sequence = SequenceNumber::from_value(sequence);
    if (!parsed_sequence) {
        return parsed_sequence.error();
    }
    auto context_id = ContextId::parse(values[1]);
    if (!context_id) {
        return context_id.error();
    }
    auto request_digest = Digest256::from_hex(values[2]);
    if (!request_digest) {
        return request_digest.error();
    }
    auto decision_digest = Digest256::from_hex(values[3]);
    if (!decision_digest) {
        return decision_digest.error();
    }
    auto decision = parse_decision_document(frame.payload);
    if (!decision) {
        return decision.error();
    }
    if (!(decision.value().digest() == decision_digest.value())) {
        return make_error(Code::StoreJournalCorrupt, "journal entry decision digest does not match its body");
    }
    if (!(decision.value().bindings.request_digest == request_digest.value())) {
        return make_error(Code::StoreJournalCorrupt, "journal entry request digest does not match its body");
    }
    if (!(decision.value().bindings.context_id == context_id.value())) {
        return make_error(Code::StoreJournalCorrupt, "journal entry context does not match its body");
    }
    DecisionRecord record;
    record.sequence = parsed_sequence.value();
    record.context_id = context_id.value();
    record.request_digest = request_digest.value();
    record.decision_digest = decision_digest.value();
    record.decision = decision.value();
    return record;
}

// ---------------------------------------------------------------------------
// Full store scan.
// ---------------------------------------------------------------------------
Result<RecoveryReport> scan_store_detailed(const std::string& root, bool read_only, bool repair, StoreInfo& info) {
    RecoveryReport report;
    auto names = list_directory_names(root);
    if (!names) {
        return names.error();
    }

    auto read = read_manifest(root, info);
    if (!read) {
        return read.error();
    }
    report.manifest_present = true;

    BundleRecordHeader header;
    auto bundle = load_record(root, info, &header, &report.notes);
    if (!bundle) {
        return bundle.error();
    }
    report.manifest_verified = true;

    auto fence = read_fence(root);
    if (!fence) {
        return fence.error();
    }
    report.fence_present = fence.value().present;
    report.fence_entries = fence.value().entries;
    if (fence.value().present) {
        info.fence_epoch = fence.value().max_epoch.value();
        info.fence_generation = fence.value().max_generation.value();
        if (info.control_epoch < fence.value().max_epoch || info.generation < fence.value().max_generation) {
            report.rollback_detected = true;
            return make_error(Code::StoreRollbackDetected,
                              "manifest is older than the recorded fence (manifest epoch " +
                                  info.control_epoch.format() + ", fence epoch " +
                                  fence.value().max_epoch.format() + ")");
        }
    }

    for (const std::string& name : names.value()) {
        std::uint64_t generation = 0;
        if (parse_bundle_file_name(name, generation)) {
            auto parsed = PolicyGeneration::from_value(generation);
            if (parsed) {
                if (parsed.value() == info.generation) {
                    report.published_generations.push_back(parsed.value());
                } else if (parsed.value() > info.generation) {
                    report.orphan_generations.push_back(parsed.value());
                }
            }
            continue;
        }
        if (name.size() > kTempSuffix.size() &&
            name.compare(name.size() - kTempSuffix.size(), kTempSuffix.size(), kTempSuffix) == 0) {
            if (repair && !read_only) {
                MP_TRY(remove_file(join_path(root, name)));
                report.removed_temporary_files.push_back(name);
            } else {
                report.notes.push_back("temporary file present: " + name);
            }
        }
    }

    if (!report.orphan_generations.empty()) {
        std::sort(report.orphan_generations.begin(), report.orphan_generations.end());
        for (const PolicyGeneration& orphan : report.orphan_generations) {
            report.notes.push_back("generation " + orphan.format() +
                                   " has a published record that the manifest does not authorise");
        }
    }

    auto journal = read_journal(root, false);
    if (!journal) {
        return journal.error();
    }
    report.journal_records = journal.value().records;
    report.journal_bytes = journal.value().bytes;
    report.journal_trailing_partial = journal.value().trailing_partial;
    if (journal.value().trailing_partial) {
        if (repair && !read_only) {
            MP_TRY(truncate_file(join_path(root, kJournalFileName), journal.value().complete_bytes));
            report.journal_repaired = true;
            report.notes.push_back("truncated an unacknowledged trailing journal entry");
        } else {
            report.notes.push_back("journal ends with an incomplete entry; it is not authority");
        }
    }
    return report;
}

std::string make_store_id(const Digest256& seed) {
    const Digest256 digest = sha256("maintpol-store:" + seed.hex());
    return "store-" + digest.hex().substr(0, 16);
}

}  // namespace

std::string_view to_string(DecisionWriteResult result) {
    switch (result) {
        case DecisionWriteResult::Appended: return "appended";
        case DecisionWriteResult::AlreadyRecorded: return "already-recorded";
    }
    return "unknown";
}

PolicyStore::~PolicyStore() = default;
PolicyStore::PolicyStore(PolicyStore&& other) noexcept = default;
PolicyStore& PolicyStore::operator=(PolicyStore&& other) noexcept = default;

Result<PolicyStore> PolicyStore::create(const std::string& root, const PolicyBundle& initial_bundle,
                                        const FaultPlan& faults) {
    auto normalized = normalize_root_path(root);
    if (!normalized) {
        return normalized.error();
    }
    auto exists = directory_exists(normalized.value());
    if (!exists) {
        return exists.error();
    }
    if (exists.value()) {
        auto names = list_directory_names(normalized.value());
        if (!names) {
            return names.error();
        }
        if (!names.value().empty()) {
            return make_error(Code::StoreAlreadyExists, "store root is not empty: " + normalized.value());
        }
    } else {
        MP_TRY(create_directory(normalized.value(), false));
    }

    PolicyStore store;
    store.root_ = normalized.value();
    auto lock = WriterLock::acquire_exclusive(join_path(store.root_, kLockFileName));
    if (!lock) {
        return lock.error();
    }
    store.lock_ = std::move(lock.value());
    store.read_only_ = false;

    StoreInfo info;
    info.generation = initial_bundle.policy().generation();
    info.control_epoch = initial_bundle.control_epoch();
    info.registry_revision = initial_bundle.registry_revision();
    const std::string body = canonical_bundle(initial_bundle);
    info.bundle_digest = sha256(body);
    info.bundle_bytes = body.size();

    const std::string record = build_bundle_record(initial_bundle, Digest256::zero());
    info.record_digest = sha256(record);
    info.store_id = make_store_id(info.record_digest);

    MP_TRY(publish_record(join_path(store.root_, bundle_file_name(info.generation)),
                          frame_record(kBundleRecordHeader, record), faults));
    MP_TRY(publish_manifest(store.root_, info, faults));
    MP_TRY(append_fence(store.root_, info, faults));

    store.info_ = info;
    RecoveryReport report;
    report.manifest_present = true;
    report.manifest_verified = true;
    report.fence_present = true;
    report.fence_entries = 1;
    report.notes.push_back("store created at generation " + info.generation.format());
    store.recovery_ = report;
    return store;
}

Result<PolicyStore> PolicyStore::open(const std::string& root, bool read_only, const FaultPlan& faults) {
    auto normalized = normalize_root_path(root);
    if (!normalized) {
        return normalized.error();
    }
    auto exists = directory_exists(normalized.value());
    if (!exists) {
        return exists.error();
    }
    if (!exists.value()) {
        return make_error(Code::StoreMissing, "store root does not exist: " + normalized.value());
    }

    PolicyStore store;
    store.root_ = normalized.value();
    store.read_only_ = read_only;
    const std::string lock_path = join_path(store.root_, kLockFileName);
    if (read_only) {
        // A reader takes no lock; it only requires that the store was created
        // with its writer lock file in place.
        auto present = file_exists(lock_path);
        if (!present) {
            return present.error();
        }
        if (!present.value()) {
            return make_error(Code::StoreLockUnavailable, "store has no writer lock file");
        }
    } else {
        auto lock = WriterLock::acquire_exclusive(lock_path);
        if (!lock) {
            return lock.error();
        }
        store.lock_ = std::move(lock.value());
    }

    StoreInfo info;
    auto report = scan_store_detailed(store.root_, read_only, !read_only, info);
    if (!report) {
        return report.error();
    }
    store.info_ = info;
    store.recovery_ = report.value();
    auto journal = read_journal(store.root_, true);
    if (!journal) {
        return journal.error();
    }
    for (const FrameView& frame : journal.value().frames) {
        auto fields = header_fields(frame.header, kDecisionRecordHeader,
                                    {"seq", "context_id", "request_digest", "decision_digest", "header_crc"});
        if (!fields) {
            return fields.error();
        }
        const std::vector<std::string_view>& values = fields.value();
        if (values.size() != 5u) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header is incomplete");
        }
        store.decision_index_[std::string(values[2])] = std::string(values[3]);
    }
    store.journal_records_ = journal.value().records;
    (void)faults;
    return store;
}

Result<PolicyStore> PolicyStore::inspect(const std::string& root) { return open(root, true); }

Result<PolicyBundle> PolicyStore::load_bundle() const { return load_generation(info_.generation); }

Result<PolicyBundle> PolicyStore::load_generation(PolicyGeneration generation) const {
    StoreInfo info;
    if (generation == info_.generation) {
        info = info_;
    } else {
        auto history_records = history();
        if (!history_records) {
            return history_records.error();
        }
        bool found = false;
        for (const StoreInfo& candidate : history_records.value()) {
            if (candidate.generation == generation) {
                info = candidate;
                found = true;
                break;
            }
        }
        if (!found) {
            return make_error(Code::StoreGenerationMissing,
                              "generation " + generation.format() + " has no published record");
        }
    }
    return load_record(root_, info, nullptr, nullptr);
}

Result<std::vector<StoreInfo>> PolicyStore::history() const {
    auto names = list_directory_names(root_);
    if (!names) {
        return names.error();
    }
    std::vector<StoreInfo> entries;
    for (const std::string& name : names.value()) {
        std::uint64_t generation = 0;
        if (!parse_bundle_file_name(name, generation)) {
            continue;
        }
        const std::string path = join_path(root_, name);
        auto content = read_file_bounded(path, kMaxRecordBytes);
        if (!content) {
            return content.error();
        }
        auto payload = unframe_record(content.value(), kBundleRecordHeader);
        if (!payload) {
            return payload.error();
        }
        BundleRecordHeader header;
        std::string body;
        MP_TRY(parse_bundle_record(payload.value(), header, body));
        StoreInfo info;
        info.store_id = info_.store_id;
        info.generation = header.generation;
        info.control_epoch = header.control_epoch;
        info.registry_revision = header.registry_revision;
        info.record_digest = sha256(payload.value());
        info.bundle_digest = header.body_digest;
        info.bundle_bytes = header.body_bytes;
        info.fence_epoch = info_.fence_epoch;
        info.fence_generation = info_.fence_generation;
        entries.push_back(info);
    }
    std::sort(entries.begin(), entries.end(),
              [](const StoreInfo& left, const StoreInfo& right) { return left.generation < right.generation; });
    return entries;
}

Result<StoreInfo> PolicyStore::commit(const PolicyBundle& bundle, const FaultPlan& faults) {
    if (read_only_) {
        return make_error(Code::StoreReadOnly, "store was opened read-only");
    }
    auto next_generation = info_.generation.next();
    if (!next_generation) {
        return next_generation.error();
    }
    if (!(bundle.policy().generation() == next_generation.value())) {
        return make_error(Code::StoreFenceRegression,
                          "a new bundle must bind generation " + next_generation.value().format() +
                              ", not " + bundle.policy().generation().format());
    }
    auto next_epoch = info_.control_epoch.next();
    if (!next_epoch) {
        return next_epoch.error();
    }
    if (!(bundle.control_epoch() == next_epoch.value())) {
        return make_error(Code::StoreFenceRegression,
                          "a new bundle must bind control epoch " + next_epoch.value().format() +
                              ", not " + bundle.control_epoch().format());
    }
    const bool registry_same = bundle.registry_revision() == info_.registry_revision;
    auto next_revision = info_.registry_revision.next();
    if (!next_revision) {
        return next_revision.error();
    }
    const bool registry_next = bundle.registry_revision() == next_revision.value();
    if (!registry_same && !registry_next) {
        return make_error(Code::StoreFenceRegression,
                          "registry revision must stay at " + info_.registry_revision.format() +
                              " or advance to " + next_revision.value().format());
    }

    const std::string body = canonical_bundle(bundle);
    StoreInfo next;
    next.store_id = info_.store_id;
    next.generation = bundle.policy().generation();
    next.control_epoch = bundle.control_epoch();
    next.registry_revision = bundle.registry_revision();
    next.bundle_digest = sha256(body);
    next.bundle_bytes = body.size();
    const std::string record = build_bundle_record(bundle, info_.record_digest);
    next.record_digest = sha256(record);
    next.fence_epoch = info_.fence_epoch;
    next.fence_generation = info_.fence_generation;

    MP_TRY(publish_record(join_path(root_, bundle_file_name(next.generation)),
                          frame_record(kBundleRecordHeader, record), faults));
    MP_TRY(publish_manifest(root_, next, faults));

    StoreInfo fenced = next;
    fenced.fence_epoch = next.control_epoch.value();
    fenced.fence_generation = next.generation.value();
    MP_TRY(append_fence(root_, fenced, faults));

    info_ = fenced;
    recovery_.notes.push_back("published generation " + info_.generation.format());
    return info_;
}

Result<void> PolicyStore::compact(const FaultPlan& faults) {
    if (read_only_) {
        return make_error(Code::StoreReadOnly, "store was opened read-only");
    }
    (void)faults;
    // Collapse the fence journal to the highest entry it already contains. The
    // rollback invariant (highest epoch ever published) is preserved exactly,
    // so a reader that accepted the old journal accepts the compacted one.
    if (info_.fence_epoch != 0) {
        StoreInfo fenced = info_;
        fenced.control_epoch = ControlEpoch::from_value(info_.fence_epoch).value();
        fenced.generation = PolicyGeneration::from_value(info_.fence_generation).value();
        const std::string record = frame_record(kFenceRecordHeader, build_fence_payload(fenced));
        const std::string path = join_path(root_, kFenceFileName);
        const std::string temp = path + std::string(kTempSuffix);
        MP_TRY(write_file_durable(temp, record));
        auto read_back = read_file_bounded(temp, kMaxRecordBytes);
        if (!read_back) {
            return read_back.error();
        }
        if (!(read_back.value() == record)) {
            return make_error(Code::StoreVerifyFailed, "compacted fence did not read back identically");
        }
        MP_TRY(replace_file(temp, path));
    }
    for (const PolicyGeneration& orphan : recovery_.orphan_generations) {
        MP_TRY(remove_file(join_path(root_, bundle_file_name(orphan))));
        recovery_.removed_orphans.push_back(orphan);
    }
    recovery_.orphan_generations.clear();
    auto names = list_directory_names(root_);
    if (!names) {
        return names.error();
    }
    for (const std::string& name : names.value()) {
        if (name.size() > kTempSuffix.size() &&
            name.compare(name.size() - kTempSuffix.size(), kTempSuffix.size(), kTempSuffix) == 0) {
            MP_TRY(remove_file(join_path(root_, name)));
            recovery_.removed_temporary_files.push_back(name);
        }
    }
    MP_TRY(flush_directory(root_));
    return {};
}

Result<DecisionWriteResult> PolicyStore::record_decision(const Decision& decision, const FaultPlan& faults) {
    if (read_only_) {
        return make_error(Code::StoreReadOnly, "store was opened read-only");
    }
    if (!(decision.bindings.policy_generation == info_.generation) ||
        !(decision.bindings.control_epoch == info_.control_epoch)) {
        return make_error(Code::StoreFenceRegression,
                          "decision binds a policy generation or control epoch that is not authoritative");
    }
    const Digest256 decision_digest = decision.digest();
    const std::string request_key = decision.bindings.request_digest.hex();
    const auto existing = decision_index_.find(request_key);
    if (existing != decision_index_.end()) {
        if (existing->second == decision_digest.hex()) {
            return DecisionWriteResult::AlreadyRecorded;
        }
        return make_error(Code::DecisionConflict,
                          "a different decision is already recorded for this request digest");
    }

    const std::uint64_t sequence = journal_records_ + 1u;
    if (sequence > static_cast<std::uint64_t>(kMaxJournalRecords)) {
        return make_error(Code::StoreSequenceExhausted, "decision journal reached its record limit");
    }
    std::string header(kDecisionRecordHeader);
    header.append(" seq=");
    header.append(std::to_string(sequence));
    header.append(" context_id=");
    header.append(decision.bindings.context_id.value());
    header.append(" request_digest=");
    header.append(decision.bindings.request_digest.hex());
    header.append(" decision_digest=");
    header.append(decision_digest.hex());
    const std::uint32_t header_checksum = crc32(header);
    header.append(" header_crc=");
    for (int shift = 28; shift >= 0; shift -= 4) {
        header.push_back("0123456789abcdef"[(header_checksum >> static_cast<unsigned>(shift)) & 0x0Fu]);
    }
    const std::string record = frame_record(header, decision_document(decision));

    fault_point(faults, FaultPoint::BeforeJournalFlush);
    MP_TRY(append_file_durable(join_path(root_, kJournalFileName), record));
    fault_point(faults, FaultPoint::AfterJournalFlush);
    auto size = file_size(join_path(root_, kJournalFileName));
    if (!size) {
        return size.error();
    }
    if (size.value() < record.size()) {
        return make_error(Code::StoreVerifyFailed, "journal append did not reach the file");
    }
    auto tail = read_file_range(join_path(root_, kJournalFileName),
                                size.value() - static_cast<std::uint64_t>(record.size()), record.size());
    if (!tail) {
        return tail.error();
    }
    if (!(tail.value() == record)) {
        return make_error(Code::StoreVerifyFailed, "journal entry did not read back identically");
    }
    decision_index_[request_key] = decision_digest.hex();
    journal_records_ += 1u;
    return DecisionWriteResult::Appended;
}

Result<std::vector<DecisionRecord>> PolicyStore::list_decisions(std::size_t max_records) const {
    auto journal = read_journal(root_, true);
    if (!journal) {
        return journal.error();
    }
    std::vector<DecisionRecord> records;
    for (const FrameView& frame : journal.value().frames) {
        if (records.size() >= max_records) {
            break;
        }
        auto record = decode_journal_frame(frame);
        if (!record) {
            return record.error();
        }
        records.push_back(std::move(record.value()));
    }
    return records;
}

Result<std::optional<DecisionRecord>> PolicyStore::find_decision(const ContextId& context_id,
                                                                 const Digest256& request_digest) const {
    auto journal = read_journal(root_, true);
    if (!journal) {
        return journal.error();
    }
    for (const FrameView& frame : journal.value().frames) {
        auto fields = header_fields(frame.header, kDecisionRecordHeader,
                                    {"seq", "context_id", "request_digest", "decision_digest", "header_crc"});
        if (!fields) {
            return fields.error();
        }
        const std::vector<std::string_view>& values = fields.value();
        if (values.size() != 5u) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header is incomplete");
        }
        if (values[1] != context_id.value()) {
            continue;
        }
        auto stored = Digest256::from_hex(values[2]);
        if (!stored) {
            return stored.error();
        }
        if (!(stored.value() == request_digest)) {
            continue;
        }
        auto record = decode_journal_frame(frame);
        if (!record) {
            return record.error();
        }
        return std::optional<DecisionRecord>(std::move(record.value()));
    }
    return std::optional<DecisionRecord>();
}

Result<std::vector<PriorDecisionRecord>> PolicyStore::prior_decisions(const ContextId& context_id) const {
    auto journal = read_journal(root_, true);
    if (!journal) {
        return journal.error();
    }
    std::vector<PriorDecisionRecord> records;
    for (const FrameView& frame : journal.value().frames) {
        auto fields = header_fields(frame.header, kDecisionRecordHeader,
                                    {"seq", "context_id", "request_digest", "decision_digest", "header_crc"});
        if (!fields) {
            return fields.error();
        }
        const std::vector<std::string_view>& values = fields.value();
        if (values.size() != 5u) {
            return make_error(Code::StoreJournalCorrupt, "journal entry header is incomplete");
        }
        if (values[1] != context_id.value()) {
            continue;
        }
        auto record = decode_journal_frame(frame);
        if (!record) {
            return record.error();
        }
        PriorDecisionRecord prior;
        prior.context_id = record.value().context_id;
        prior.request_id = record.value().decision.bindings.request_id;
        prior.request_digest = record.value().request_digest;
        prior.decision_digest = record.value().decision_digest;
        prior.decision = record.value().decision;
        records.push_back(std::move(prior));
    }
    return records;
}

Result<std::vector<std::string>> PolicyStore::verify() const {
    std::vector<std::string> notes;
    StoreInfo info;
    MP_TRY(read_manifest(root_, info));
    notes.push_back("manifest: store " + info.store_id + ", generation " + info.generation.format() +
                    ", control epoch " + info.control_epoch.format());
    BundleRecordHeader header;
    MP_TRY(load_record(root_, info, &header, &notes));
    if (!header.previous_record_digest.is_zero()) {
        notes.push_back("record chain: previous record digest " + header.previous_record_digest.hex());
    }

    auto entries = history();
    if (!entries) {
        return entries.error();
    }
    notes.push_back("published generations: " + std::to_string(entries.value().size()));
    for (const StoreInfo& entry : entries.value()) {
        notes.push_back("  generation " + entry.generation.format() + " record " + entry.record_digest.hex() +
                        " bundle " + entry.bundle_digest.hex());
    }

    auto fence = read_fence(root_);
    if (!fence) {
        return fence.error();
    }
    if (fence.value().present) {
        notes.push_back("fence entries: " + std::to_string(fence.value().entries) + ", highest epoch " +
                        fence.value().max_epoch.format());
        if (info.control_epoch < fence.value().max_epoch) {
            return make_error(Code::StoreRollbackDetected, "manifest is behind the fence");
        }
    } else {
        notes.push_back("fence journal is absent");
    }

    auto journal = read_journal(root_, true);
    if (!journal) {
        return journal.error();
    }
    notes.push_back("journal records: " + std::to_string(journal.value().records));
    if (journal.value().trailing_partial) {
        notes.push_back("journal ends with an incomplete entry; it is not authority");
    }
    for (const FrameView& frame : journal.value().frames) {
        MP_TRY(decode_journal_frame(frame));
    }
    if (!recovery_.orphan_generations.empty()) {
        notes.push_back("orphan records not authorised by the manifest: " +
                        std::to_string(recovery_.orphan_generations.size()));
    }
    return notes;
}

#undef MP_TRY
#undef MP_ASSIGN

}  // namespace maintpol
