#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "maintpol/decision.hpp"
#include "maintpol/engine.hpp"
#include "maintpol/error.hpp"
#include "maintpol/fault.hpp"
#include "maintpol/lock.hpp"
#include "maintpol/policy.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Durable policy store.
//
// Layout of a store root:
//
//   LOCK          single-writer lock file (kernel released on process death)
//   CURRENT       authoritative manifest; its replacement is the commit point
//   FENCE         append-only fence journal used for rollback detection
//   gen-<N>.mpb   published policy bundle records, one per generation
//   decisions.mpd append-only decision journal
//
// Every record is a framed payload: a header line, an exact payload length and
// a CRC-32 of the payload. Bundle records carry their own body digest and the
// digest of the previous record, forming a hash chain across generations.
//
// Commit protocol for a new generation:
//   stage record -> flush -> read back and verify -> publish record name
//   stage manifest -> flush -> read back and verify -> replace CURRENT
//   append fence entry -> flush -> read back and verify
//
// The replacement of CURRENT is the commit point. A crash before it leaves the
// previous generation authoritative; a crash after it leaves the new
// generation authoritative with the fence one entry behind, which recovery
// accepts (a fence that runs ahead of the manifest is treated as a rollback
// and fails closed).
// ---------------------------------------------------------------------------
inline constexpr std::string_view kStoreFormatId = "maintpol-store/1";
inline constexpr std::string_view kManifestRecordHeader = "MPS-MANIFEST-1";
inline constexpr std::string_view kBundleRecordHeader = "MPS-BUNDLE-1";
inline constexpr std::string_view kFenceRecordHeader = "MPS-FENCE-1";
inline constexpr std::string_view kDecisionRecordHeader = "MPS-DECISION-1";
inline constexpr std::string_view kLockFileName = "LOCK";
inline constexpr std::string_view kManifestFileName = "CURRENT";
inline constexpr std::string_view kFenceFileName = "FENCE";
inline constexpr std::string_view kJournalFileName = "decisions.mpd";
inline constexpr std::string_view kTempSuffix = ".tmp";

struct StoreInfo {
    std::string store_id;
    PolicyGeneration generation;
    ControlEpoch control_epoch;
    Revision registry_revision;
    Digest256 record_digest;
    Digest256 bundle_digest;
    std::uint64_t bundle_bytes = 0;
    std::uint64_t fence_epoch = 0;
    std::uint64_t fence_generation = 0;

    friend bool operator==(const StoreInfo&, const StoreInfo&) = default;
};

struct RecoveryReport {
    bool manifest_present = false;
    bool manifest_verified = false;
    bool fence_present = false;
    std::uint64_t fence_entries = 0;
    bool rollback_detected = false;
    bool journal_trailing_partial = false;
    bool journal_repaired = false;
    std::uint64_t journal_records = 0;
    std::uint64_t journal_bytes = 0;
    std::vector<PolicyGeneration> published_generations;
    std::vector<PolicyGeneration> orphan_generations;
    std::vector<PolicyGeneration> removed_orphans;
    std::vector<std::string> removed_temporary_files;
    std::vector<std::string> notes;
};

struct DecisionRecord {
    SequenceNumber sequence;
    ContextId context_id;
    Digest256 request_digest;
    Digest256 decision_digest;
    Decision decision;

    friend bool operator==(const DecisionRecord&, const DecisionRecord&) = default;
};

enum class DecisionWriteResult : std::uint8_t { Appended = 1, AlreadyRecorded = 2 };

MAINTPOL_API std::string_view to_string(DecisionWriteResult result);

class PolicyStore {
public:
    PolicyStore() = default;
    ~PolicyStore();
    PolicyStore(PolicyStore&& other) noexcept;
    PolicyStore& operator=(PolicyStore&& other) noexcept;
    PolicyStore(const PolicyStore&) = delete;
    PolicyStore& operator=(const PolicyStore&) = delete;

    // Creates a store whose first authoritative generation is the bundle's own
    // generation. The directory must not already contain a store.
    static Result<PolicyStore> create(const std::string& root, const PolicyBundle& initial_bundle,
                                      const FaultPlan& faults = FaultPlan{});
    // Opens an existing store, verifying its integrity before returning.
    static Result<PolicyStore> open(const std::string& root, bool read_only,
                                    const FaultPlan& faults = FaultPlan{});
    // Read-only inspection: same integrity and rollback rules as open, never
    // repairs, never creates.
    static Result<PolicyStore> inspect(const std::string& root);

    bool read_only() const { return read_only_; }
    const std::string& root() const { return root_; }
    const StoreInfo& info() const { return info_; }
    const RecoveryReport& recovery() const { return recovery_; }

    Result<PolicyBundle> load_bundle() const;
    Result<PolicyBundle> load_generation(PolicyGeneration generation) const;
    Result<std::vector<StoreInfo>> history() const;

    // Publishes a new generation. The bundle must bind the next generation and
    // the next control epoch exactly; the store never invents authority.
    Result<StoreInfo> commit(const PolicyBundle& bundle, const FaultPlan& faults = FaultPlan{});
    Result<void> compact(const FaultPlan& faults = FaultPlan{});

    Result<DecisionWriteResult> record_decision(const Decision& decision, const FaultPlan& faults = FaultPlan{});
    Result<std::vector<DecisionRecord>> list_decisions(std::size_t max_records) const;
    Result<std::optional<DecisionRecord>> find_decision(const ContextId& context_id,
                                                        const Digest256& request_digest) const;
    Result<std::vector<PriorDecisionRecord>> prior_decisions(const ContextId& context_id) const;

    // Full re-verification of every published record, fence entry and journal
    // entry. Returns human readable notes; an integrity failure is an error.
    Result<std::vector<std::string>> verify() const;

private:
    std::string root_;
    bool read_only_ = false;
    WriterLock lock_;
    StoreInfo info_;
    RecoveryReport recovery_;
    // The decision journal is scanned once when the store is opened. While the
    // writer lock is held this index is authoritative, so recording a decision
    // never re-reads the journal and the write path stays proportional to the
    // record being appended rather than to the history behind it.
    std::map<std::string, std::string> decision_index_;
    std::uint64_t journal_records_ = 0;
};

}  // namespace maintpol
