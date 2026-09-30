#include "commands.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "maintpol/digest.hpp"
#include "maintpol/engine.hpp"
#include "maintpol/fault.hpp"
#include "maintpol/fileio.hpp"
#include "maintpol/selftest.hpp"
#include "maintpol/store.hpp"
#include "maintpol/text.hpp"
#include "maintpol/version.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace maintpol::cli {
namespace {

class Options {
public:
    Options(std::vector<std::string> arguments, std::set<std::string> valued, std::set<std::string> boolean)
        : valued_(std::move(valued)), boolean_(std::move(boolean)) {
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            const std::string& token = arguments[index];
            if (token.size() > 2u && token.compare(0, 2, "--") == 0) {
                const std::string name = token.substr(2);
                if (boolean_.count(name) != 0u) {
                    flags_.insert(name);
                    continue;
                }
                if (valued_.count(name) == 0u) {
                    unknown_.push_back(name);
                    continue;
                }
                if (index + 1u >= arguments.size()) {
                    missing_.push_back(name);
                    continue;
                }
                values_[name] = arguments[++index];
                continue;
            }
            positional_.push_back(token);
        }
    }

    const std::vector<std::string>& positional() const { return positional_; }
    bool has(const std::string& name) const { return flags_.count(name) != 0u; }

    std::optional<std::string> value(const std::string& name) const {
        const auto found = values_.find(name);
        if (found == values_.end()) {
            return std::nullopt;
        }
        return found->second;
    }

    Result<std::string> require(const std::string& name) const {
        const auto found = values_.find(name);
        if (found == values_.end()) {
            return make_error(Code::MissingKey, "option --" + name + " is required");
        }
        return found->second;
    }

    Result<std::uint64_t> number(const std::string& name, std::uint64_t fallback) const {
        const auto found = values_.find(name);
        if (found == values_.end()) {
            return fallback;
        }
        if (found->second.empty() || found->second.size() > 20u) {
            return make_error(Code::NumberMalformed, "option --" + name + " must be a decimal integer");
        }
        std::uint64_t value = 0;
        for (char character : found->second) {
            if (character < '0' || character > '9') {
                return make_error(Code::NumberMalformed, "option --" + name + " must be a decimal integer");
            }
            value = (value * 10u) + static_cast<std::uint64_t>(character - '0');
        }
        return value;
    }

    Result<void> validate() const {
        if (!unknown_.empty()) {
            return make_error(Code::UnknownKey, "unknown option --" + unknown_.front());
        }
        if (!missing_.empty()) {
            return make_error(Code::MissingKey, "option --" + missing_.front() + " requires a value");
        }
        return {};
    }

private:
    std::set<std::string> valued_;
    std::set<std::string> boolean_;
    std::map<std::string, std::string> values_;
    std::set<std::string> flags_;
    std::vector<std::string> positional_;
    std::vector<std::string> unknown_;
    std::vector<std::string> missing_;
};

int report(const Error& error) {
    std::cerr << "maintpol: " << to_string(error.code);
    if (!error.detail.empty()) {
        std::cerr << ": " << error.detail;
    }
    std::cerr << "\n";
    return kExitError;
}

int report_usage(std::string_view message) {
    std::cerr << "maintpol: " << message << "\n";
    std::cerr << "run 'maintpol help' for usage\n";
    return kExitError;
}

Result<std::string> read_text_file(const std::string& path) {
    return read_file_bounded(path, kMaxTextDocumentBytes);
}

Result<void> write_text_file(const std::string& path, std::string_view content) {
    return write_file_durable(path, content);
}

Result<FaultPlan> fault_plan_from(const Options& options) {
    FaultPlan plan;
    const auto name = options.value("fault-crash-at");
    if (!name.has_value()) {
        return plan;
    }
    if (!fault_point_from_name(name.value(), plan.crash_at)) {
        return make_error(Code::UnknownEnumValue, "fault point '" + name.value() + "' is not recognised");
    }
    return plan;
}

Result<KeySet> load_keys(const Options& options) {
    const auto path = options.value("keys");
    if (!path.has_value()) {
        return KeySet{};
    }
    auto text = read_text_file(path.value());
    if (!text) {
        return text.error();
    }
    return parse_key_document(text.value());
}

int decision_exit_code(Outcome outcome) {
    switch (outcome) {
        case Outcome::Allow: return kExitOk;
        case Outcome::RequireEscalation: return kExitEscalation;
        case Outcome::Unknown: return kExitUnknown;
        case Outcome::Deny: return kExitDeny;
    }
    return kExitUnknown;
}

void print_decision(std::ostream& stream, const Decision& decision, bool document) {
    stream << "outcome = " << to_string(decision.outcome) << "\n";
    stream << "replay = " << to_string(decision.replay) << "\n";
    stream << "policy = " << decision.bindings.policy_id.value() << " generation "
           << decision.bindings.policy_generation.format() << " digest "
           << decision.bindings.policy_digest.hex() << "\n";
    stream << "control_epoch = " << decision.bindings.control_epoch.format()
           << " registry_revision = " << decision.bindings.registry_revision.format() << "\n";
    stream << "request_digest = " << decision.bindings.request_digest.hex() << "\n";
    if (decision.required_level.has_value()) {
        stream << "required_level = " << decision.required_level.value().format() << "\n";
    }
    stream << "applied_rules = " << decision.applied_rules.size()
           << " honored_exceptions = " << decision.honored_exceptions.size() << "\n";
    for (const Finding& finding : decision.findings) {
        stream << "finding: " << to_string(finding.code) << " [" << to_string(finding.severity()) << "]";
        if (finding.rule.has_value()) {
            stream << " rule=" << finding.rule.value().value();
        }
        if (finding.exception.has_value()) {
            stream << " exception=" << finding.exception.value().value();
        }
        if (finding.approval.has_value()) {
            stream << " approval=" << finding.approval.value().value();
        }
        if (finding.obligation_class.has_value()) {
            stream << " class=" << finding.obligation_class.value().value();
        }
        if (!finding.detail.empty()) {
            stream << " - " << finding.detail;
        }
        stream << "\n";
    }
    stream << "decision_digest = " << decision.digest().hex() << "\n";
    if (document) {
        stream << decision_document(decision);
    }
}

Result<std::vector<std::uint8_t>> random_bytes(std::size_t count) {
    std::vector<std::uint8_t> buffer(count);
#if defined(_WIN32)
    const NTSTATUS status = BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        return make_error(Code::InternalUnsupported, "the operating system random source failed");
    }
    return buffer;
#else
    const int descriptor = ::open("/dev/urandom", O_RDONLY);
    if (descriptor < 0) {
        return make_error(Code::InternalUnsupported, "the operating system random source is unavailable");
    }
    std::size_t offset = 0;
    while (offset < buffer.size()) {
        const ssize_t read = ::read(descriptor, buffer.data() + offset, buffer.size() - offset);
        if (read <= 0) {
            ::close(descriptor);
            return make_error(Code::InternalUnsupported, "the operating system random source failed");
        }
        offset += static_cast<std::size_t>(read);
    }
    ::close(descriptor);
    return buffer;
#endif
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------
int command_version() {
    std::cout << "maintpol " << version_string << "\n";
    std::cout << "document format " << document_format_id << "\n";
    std::cout << "evaluation semantics version " << semantics_version << "\n";
    std::cout << "digest composition version " << digest_format_version << "\n";
    std::cout << "store format " << kStoreFormatId << "\n";
    return kExitOk;
}

int command_selftest(const Options& options) {
    const SelfTestReport report = run_self_tests();
    if (!options.has("quiet")) {
        for (const SelfTestResult& result : report.results) {
            std::cout << (result.passed ? "ok   " : "FAIL ") << result.name;
            if (!result.passed) {
                std::cout << " - " << result.detail;
            }
            std::cout << "\n";
        }
    }
    std::cout << report.passed_count() << " passed, " << report.failed_count() << " failed\n";
    return report.all_passed() ? kExitOk : kExitError;
}

int command_digest(const Options& options) {
    if (options.positional().empty()) {
        return report_usage("digest requires a file path");
    }
    auto content = read_text_file(options.positional()[0]);
    if (!content) {
        return report(content.error());
    }
    std::cout << "file_digest = " << sha256(content.value()).hex() << "\n";
    if (options.has("canonical")) {
        if (auto policy = parse_policy_document(content.value())) {
            const std::string canonical = canonical_policy(policy.value());
            std::cout << "kind = policy\n";
            std::cout << "canonical_digest = " << sha256(canonical).hex() << "\n";
            std::cout << "canonical_bytes = " << canonical.size() << "\n";
            return kExitOk;
        }
        if (auto bundle = parse_bundle_document(content.value())) {
            const std::string canonical = canonical_bundle(bundle.value());
            std::cout << "kind = bundle\n";
            std::cout << "canonical_digest = " << sha256(canonical).hex() << "\n";
            std::cout << "canonical_bytes = " << canonical.size() << "\n";
            return kExitOk;
        }
        if (auto request = parse_request_document(content.value())) {
            const std::string canonical = canonical_request(request.value());
            std::cout << "kind = request\n";
            std::cout << "canonical_digest = " << sha256(canonical).hex() << "\n";
            std::cout << "canonical_bytes = " << canonical.size() << "\n";
            return kExitOk;
        }
        if (auto decision = parse_decision_document(content.value())) {
            std::cout << "kind = decision\n";
            std::cout << "canonical_digest = " << decision.value().digest().hex() << "\n";
            return kExitOk;
        }
        return report(make_error(Code::UnexpectedSection, "the document kind could not be determined"));
    }
    return kExitOk;
}

int command_policy(const Options& options) {
    if (options.positional().size() < 2u) {
        return report_usage("policy requires an action and a file path");
    }
    const std::string& action = options.positional()[0];
    const std::string& path = options.positional()[1];
    auto content = read_text_file(path);
    if (!content) {
        return report(content.error());
    }
    if (action == "validate") {
        if (auto policy = parse_policy_document(content.value())) {
            std::cout << "ok policy " << policy.value().id().value() << " generation "
                      << policy.value().generation().format() << " rules " << policy.value().rules().size()
                      << " digest " << policy.value().digest().hex() << "\n";
            return kExitOk;
        }
        if (auto bundle = parse_bundle_document(content.value())) {
            std::cout << "ok bundle policy " << bundle.value().policy().id().value() << " generation "
                      << bundle.value().policy().generation().format() << " control epoch "
                      << bundle.value().control_epoch().format() << " authorities "
                      << bundle.value().authorities().size() << " exceptions "
                      << bundle.value().exceptions().size() << " approvals "
                      << bundle.value().approvals().size() << " digest "
                      << bundle.value().digest().hex() << "\n";
            return kExitOk;
        }
        return report(make_error(Code::UnexpectedSection, "the document is neither a policy nor a bundle"));
    }
    if (action == "canonicalize") {
        std::string canonical;
        if (auto policy = parse_policy_document(content.value())) {
            canonical = canonical_policy(policy.value());
        } else if (auto bundle = parse_bundle_document(content.value())) {
            canonical = canonical_bundle(bundle.value());
        } else if (auto request = parse_request_document(content.value())) {
            canonical = canonical_request(request.value());
        } else if (auto decision = parse_decision_document(content.value())) {
            canonical = decision_document(decision.value());
        } else {
            return report(make_error(Code::UnexpectedSection, "the document kind could not be determined"));
        }
        const auto out = options.value("out");
        if (out.has_value()) {
            auto written = write_text_file(out.value(), canonical);
            if (!written) {
                return report(written.error());
            }
            std::cout << "wrote " << canonical.size() << " bytes\n";
            return kExitOk;
        }
        std::cout << canonical;
        return kExitOk;
    }
    return report_usage("unknown policy action '" + action + "'");
}

int command_keys(const Options& options) {
    if (options.positional().empty()) {
        return report_usage("keys requires an action");
    }
    const std::string& action = options.positional()[0];
    if (action == "generate") {
        if (options.positional().size() < 2u) {
            return report_usage("keys generate requires a key identifier");
        }
        auto id = KeyId::parse(options.positional()[1]);
        if (!id) {
            return report(id.error());
        }
        auto secret = random_bytes(32);
        if (!secret) {
            return report(secret.error());
        }
        AuthorityKey key;
        key.id = id.value();
        key.secret = secret.value();
        std::vector<AuthorityKey> keys;
        keys.push_back(std::move(key));
        auto set = KeySet::create(std::move(keys));
        if (!set) {
            return report(set.error());
        }
        const std::string document = key_document(set.value());
        const auto out = options.value("out");
        if (out.has_value()) {
            auto written = write_text_file(out.value(), document);
            if (!written) {
                return report(written.error());
            }
            std::cout << "wrote key material for " << id.value().value() << " to " << out.value() << "\n";
            std::cout << "key material is a secret: protect the file and do not commit it\n";
            return kExitOk;
        }
        std::cout << document;
        return kExitOk;
    }
    if (action == "show") {
        if (options.positional().size() < 2u) {
            return report_usage("keys show requires a key file");
        }
        auto content = read_text_file(options.positional()[1]);
        if (!content) {
            return report(content.error());
        }
        auto set = parse_key_document(content.value());
        if (!set) {
            return report(set.error());
        }
        for (const AuthorityKey& key : set.value().keys()) {
            std::cout << "key " << key.id.value() << " bytes " << key.secret.size() << "\n";
        }
        std::cout << set.value().size() << " keys\n";
        return kExitOk;
    }
    return report_usage("unknown keys action '" + action + "'");
}

int command_store(const Options& options) {
    if (options.positional().size() < 2u) {
        return report_usage("store requires an action and a directory");
    }
    const std::string& action = options.positional()[0];
    const std::string& root = options.positional()[1];
    auto faults = fault_plan_from(options);
    if (!faults) {
        return report(faults.error());
    }

    if (action == "init") {
        auto bundle_path = options.require("bundle");
        if (!bundle_path) {
            return report(bundle_path.error());
        }
        auto content = read_text_file(bundle_path.value());
        if (!content) {
            return report(content.error());
        }
        auto bundle = parse_bundle_document(content.value());
        if (!bundle) {
            return report(bundle.error());
        }
        auto store = PolicyStore::create(root, bundle.value(), faults.value());
        if (!store) {
            return report(store.error());
        }
        const StoreInfo& info = store.value().info();
        std::cout << "store_id = " << info.store_id << "\n";
        std::cout << "generation = " << info.generation.format() << "\n";
        std::cout << "control_epoch = " << info.control_epoch.format() << "\n";
        std::cout << "registry_revision = " << info.registry_revision.format() << "\n";
        std::cout << "record_digest = " << info.record_digest.hex() << "\n";
        return kExitOk;
    }
    if (action == "put") {
        auto bundle_path = options.require("bundle");
        if (!bundle_path) {
            return report(bundle_path.error());
        }
        auto content = read_text_file(bundle_path.value());
        if (!content) {
            return report(content.error());
        }
        auto bundle = parse_bundle_document(content.value());
        if (!bundle) {
            return report(bundle.error());
        }
        auto store = PolicyStore::open(root, false, faults.value());
        if (!store) {
            return report(store.error());
        }
        auto info = store.value().commit(bundle.value(), faults.value());
        if (!info) {
            return report(info.error());
        }
        std::cout << "generation = " << info.value().generation.format() << "\n";
        std::cout << "control_epoch = " << info.value().control_epoch.format() << "\n";
        std::cout << "registry_revision = " << info.value().registry_revision.format() << "\n";
        std::cout << "record_digest = " << info.value().record_digest.hex() << "\n";
        return kExitOk;
    }
    if (action == "show" || action == "inspect") {
        // Both actions inspect: neither takes the writer lock, so an operator
        // can always look at a store that a writer currently owns.
        const bool read_only = true;
        auto store = PolicyStore::open(root, read_only);
        if (!store) {
            return report(store.error());
        }
        const StoreInfo& info = store.value().info();
        std::cout << "store_id = " << info.store_id << "\n";
        std::cout << "generation = " << info.generation.format() << "\n";
        std::cout << "control_epoch = " << info.control_epoch.format() << "\n";
        std::cout << "registry_revision = " << info.registry_revision.format() << "\n";
        std::cout << "record_digest = " << info.record_digest.hex() << "\n";
        std::cout << "bundle_digest = " << info.bundle_digest.hex() << "\n";
        std::cout << "bundle_bytes = " << info.bundle_bytes << "\n";
        std::cout << "fence_epoch = " << info.fence_epoch << "\n";
        std::cout << "mode = " << (read_only ? "read-only" : "read-write") << "\n";
        const RecoveryReport& recovery = store.value().recovery();
        std::cout << "recovery: manifest=" << (recovery.manifest_present ? "present" : "absent")
                  << " verified=" << (recovery.manifest_verified ? "yes" : "no")
                  << " fence_entries=" << recovery.fence_entries
                  << " journal_records=" << recovery.journal_records
                  << " journal_trailing_partial=" << (recovery.journal_trailing_partial ? "yes" : "no")
                  << " orphans=" << recovery.orphan_generations.size() << "\n";
        for (const std::string& note : recovery.notes) {
            std::cout << "note: " << note << "\n";
        }
        return kExitOk;
    }
    if (action == "verify") {
        auto store = PolicyStore::open(root, true);
        if (!store) {
            return report(store.error());
        }
        auto notes = store.value().verify();
        if (!notes) {
            return report(notes.error());
        }
        for (const std::string& note : notes.value()) {
            std::cout << note << "\n";
        }
        std::cout << "verified\n";
        return kExitOk;
    }
    if (action == "history") {
        auto store = PolicyStore::open(root, true);
        if (!store) {
            return report(store.error());
        }
        auto entries = store.value().history();
        if (!entries) {
            return report(entries.error());
        }
        for (const StoreInfo& entry : entries.value()) {
            std::cout << "generation " << entry.generation.format() << " control_epoch "
                      << entry.control_epoch.format() << " registry_revision "
                      << entry.registry_revision.format() << " record " << entry.record_digest.hex()
                      << " bundle " << entry.bundle_digest.hex() << "\n";
        }
        std::cout << entries.value().size() << " published generations\n";
        return kExitOk;
    }
    if (action == "get") {
        auto store = PolicyStore::open(root, true);
        if (!store) {
            return report(store.error());
        }
        auto generation_number = options.number("generation", store.value().info().generation.value());
        if (!generation_number) {
            return report(generation_number.error());
        }
        auto generation = PolicyGeneration::from_value(generation_number.value());
        if (!generation) {
            return report(generation.error());
        }
        auto bundle = store.value().load_generation(generation.value());
        if (!bundle) {
            return report(bundle.error());
        }
        const std::string document = canonical_bundle(bundle.value());
        const auto out_path = options.value("out");
        if (out_path.has_value()) {
            auto written = write_text_file(out_path.value(), document);
            if (!written) {
                return report(written.error());
            }
            std::cout << "wrote " << document.size() << " bytes\n";
            return kExitOk;
        }
        std::cout << document;
        return kExitOk;
    }
    if (action == "decisions") {
        auto store = PolicyStore::open(root, true);
        if (!store) {
            return report(store.error());
        }
        auto limit = options.number("limit", 1000);
        if (!limit) {
            return report(limit.error());
        }
        auto records = store.value().list_decisions(static_cast<std::size_t>(limit.value()));
        if (!records) {
            return report(records.error());
        }
        for (const DecisionRecord& record : records.value()) {
            std::cout << "sequence " << record.sequence.format() << " context " << record.context_id.value()
                      << " request " << record.request_digest.hex() << " decision "
                      << record.decision_digest.hex() << " outcome " << to_string(record.decision.outcome)
                      << "\n";
        }
        std::cout << records.value().size() << " journal records\n";
        return kExitOk;
    }
    if (action == "compact") {
        auto store = PolicyStore::open(root, false, faults.value());
        if (!store) {
            return report(store.error());
        }
        auto compacted = store.value().compact(faults.value());
        if (!compacted) {
            return report(compacted.error());
        }
        const RecoveryReport& recovery = store.value().recovery();
        std::cout << "removed_orphans = " << recovery.removed_orphans.size() << "\n";
        std::cout << "removed_temporary_files = " << recovery.removed_temporary_files.size() << "\n";
        std::cout << "compacted\n";
        return kExitOk;
    }
    return report_usage("unknown store action '" + action + "'");
}

int command_eval(const Options& options) {
    auto request_path = options.require("request");
    if (!request_path) {
        return report(request_path.error());
    }
    auto request_text = read_text_file(request_path.value());
    if (!request_text) {
        return report(request_text.error());
    }
    auto request = parse_request_document(request_text.value());
    if (!request) {
        return report(request.error());
    }
    auto keys = load_keys(options);
    if (!keys) {
        return report(keys.error());
    }

    const bool use_store = options.value("store").has_value();
    const auto bundle_path = options.value("bundle");
    if (use_store == bundle_path.has_value()) {
        return report_usage("eval requires exactly one of --store or --bundle");
    }

    auto faults = fault_plan_from(options);
    if (!faults) {
        return report(faults.error());
    }

    std::optional<PolicyStore> store;
    PolicyBundle bundle;
    std::vector<PriorDecisionRecord> prior;
    if (use_store) {
        const bool record = options.has("record");
        auto opened = PolicyStore::open(options.value("store").value(), !record);
        if (!opened) {
            return report(opened.error());
        }
        store = std::move(opened.value());
        auto loaded = store->load_bundle();
        if (!loaded) {
            return report(loaded.error());
        }
        bundle = loaded.value();
        if (record) {
            auto history = store->prior_decisions(request.value().context_id());
            if (!history) {
                return report(history.error());
            }
            prior = history.value();
        }
    } else {
        auto content = read_text_file(bundle_path.value());
        if (!content) {
            return report(content.error());
        }
        auto loaded = parse_bundle_document(content.value());
        if (!loaded) {
            return report(loaded.error());
        }
        bundle = loaded.value();
    }

    EvaluationLimits limits;
    auto decision = evaluate(bundle, keys.value(), request.value(), prior, limits);
    if (!decision) {
        return report(decision.error());
    }

    if (options.has("record")) {
        if (!store.has_value()) {
            return report_usage("--record requires --store");
        }
        auto recorded = store->record_decision(decision.value(), faults.value());
        if (!recorded) {
            return report(recorded.error());
        }
        if (recorded.value() == DecisionWriteResult::AlreadyRecorded) {
            std::cout << "journal = already-recorded\n";
        } else {
            std::cout << "journal = appended\n";
        }
    }

    print_decision(std::cout, decision.value(), options.has("document"));
    const auto out_path = options.value("out");
    if (out_path.has_value()) {
        auto written = write_text_file(out_path.value(), decision_document(decision.value()));
        if (!written) {
            return report(written.error());
        }
    }
    return decision_exit_code(decision.value().outcome);
}

int command_bench(const Options& options) {
    auto store_path = options.require("store");
    if (!store_path) {
        return report(store_path.error());
    }
    auto request_path = options.require("request");
    if (!request_path) {
        return report(request_path.error());
    }
    auto iterations = options.number("iterations", 100);
    if (!iterations) {
        return report(iterations.error());
    }
    if (iterations.value() == 0 || iterations.value() > 1000000u) {
        return report(make_error(Code::ValueOutOfRange, "iterations must be between 1 and 1000000"));
    }
    auto request_text = read_text_file(request_path.value());
    if (!request_text) {
        return report(request_text.error());
    }
    auto request = parse_request_document(request_text.value());
    if (!request) {
        return report(request.error());
    }
    auto keys = load_keys(options);
    if (!keys) {
        return report(keys.error());
    }
    auto store = PolicyStore::open(store_path.value(), false);
    if (!store) {
        return report(store.error());
    }
    auto bundle = store.value().load_bundle();
    if (!bundle) {
        return report(bundle.error());
    }

    std::vector<EvaluationRequest> requests;
    requests.reserve(static_cast<std::size_t>(iterations.value()));
    for (std::uint64_t index = 0; index < iterations.value(); ++index) {
        auto request_id = RequestId::parse("bench-" + std::to_string(index));
        if (!request_id) {
            return report(request_id.error());
        }
        auto tuned = EvaluationRequest::create(
            request.value().context_id(), request_id.value(), request.value().scopes(),
            request.value().classes(), request.value().window(), request.value().requested_by(),
            request.value().expected_generation(), request.value().expected_policy_digest(),
            request.value().exceptions(), request.value().approvals(), request.value().evidence(),
            request.value().interlocks(), request.value().concurrent_maintenance(),
            request.value().evaluated_at());
        if (!tuned) {
            return report(tuned.error());
        }
        requests.push_back(std::move(tuned.value()));
    }

    EvaluationLimits limits;
    std::vector<double> pure_micros;
    pure_micros.reserve(requests.size());
    for (const EvaluationRequest& candidate : requests) {
        const auto start = std::chrono::steady_clock::now();
        auto decision = evaluate(bundle.value(), keys.value(), candidate, {}, limits);
        const auto finish = std::chrono::steady_clock::now();
        if (!decision) {
            return report(decision.error());
        }
        pure_micros.push_back(std::chrono::duration<double, std::micro>(finish - start).count());
    }

    std::vector<double> durable_micros;
    durable_micros.reserve(requests.size());
    for (const EvaluationRequest& candidate : requests) {
        const auto start = std::chrono::steady_clock::now();
        auto decision = evaluate(bundle.value(), keys.value(), candidate, {}, limits);
        if (!decision) {
            return report(decision.error());
        }
        auto recorded = store.value().record_decision(decision.value());
        const auto finish = std::chrono::steady_clock::now();
        if (!recorded) {
            return report(recorded.error());
        }
        durable_micros.push_back(std::chrono::duration<double, std::micro>(finish - start).count());
    }

    auto summarise = [](std::vector<double>& samples, std::string_view label, std::string_view provenance) {
        std::sort(samples.begin(), samples.end());
        double total = 0.0;
        for (double sample : samples) {
            total += sample;
        }
        const double mean = samples.empty() ? 0.0 : total / static_cast<double>(samples.size());
        const double median = samples.empty() ? 0.0 : samples[samples.size() / 2u];
        std::cout << label << ": completed_operations = " << samples.size() << " provenance = " << provenance
                  << "\n";
        std::cout << "  mean_us = " << mean << " median_us = " << median
                  << " min_us = " << (samples.empty() ? 0.0 : samples.front())
                  << " max_us = " << (samples.empty() ? 0.0 : samples.back()) << "\n";
    };
    std::cout << "single_host = true host_processors = not_reported iterations = " << iterations.value()
              << "\n";
    summarise(pure_micros, "evaluation", "SYNTHETIC (in-memory evaluation, no durable write)");
    summarise(durable_micros, "evaluation+decision_record",
              "REAL (durable append with flush and read-back verification)");
    return kExitOk;
}

void print_help() {
    std::cout <<
        "maintpol " << version_string << " - facility maintenance policy evaluation runtime\n"
        "\n"
        "usage:\n"
        "  maintpol version\n"
        "  maintpol selftest [--quiet]\n"
        "  maintpol digest <file> [--canonical]\n"
        "  maintpol policy validate <file>\n"
        "  maintpol policy canonicalize <file> [--out <file>]\n"
        "  maintpol keys generate <key-id> [--out <file>]\n"
        "  maintpol keys show <file>\n"
        "  maintpol store init <dir> --bundle <file> [--fault-crash-at <point>]\n"
        "  maintpol store put <dir> --bundle <file> [--fault-crash-at <point>]\n"
        "  maintpol store show|inspect|verify|history|compact <dir>\n"
        "  maintpol store get <dir> [--generation <n>] [--out <file>]\n"
        "  maintpol store decisions <dir> [--limit <n>]\n"
        "  maintpol eval (--store <dir> | --bundle <file>) --request <file>\n"
        "                [--keys <file>] [--record] [--document] [--out <file>]\n"
        "  maintpol bench --store <dir> --request <file> --iterations <n> [--keys <file>]\n"
        "\n"
        "exit codes: 0 allow or success, 1 error, 2 deny, 3 unknown, 4 escalation required\n";
}

}  // namespace

int run(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        print_help();
        return kExitOk;
    }
    const std::string& command = arguments[0];
    const std::vector<std::string> rest(arguments.begin() + 1, arguments.end());

    const std::set<std::string> common_flags = {"quiet",      "canonical", "record",  "document",
                                                "help",       "verbose",   "force"};
    const std::set<std::string> common_values = {"out", "bundle", "store", "request", "keys",
                                                 "generation", "limit", "iterations", "fault-crash-at"};

    if (command == "help" || command == "--help" || command == "-h") {
        print_help();
        return kExitOk;
    }
    if (command == "version" || command == "--version") {
        return command_version();
    }

    Options options(rest, common_values, common_flags);
    if (auto valid = options.validate(); !valid) {
        return report(valid.error());
    }

    if (command == "selftest") {
        return command_selftest(options);
    }
    if (command == "digest") {
        return command_digest(options);
    }
    if (command == "policy") {
        return command_policy(options);
    }
    if (command == "keys") {
        return command_keys(options);
    }
    if (command == "store") {
        return command_store(options);
    }
    if (command == "eval") {
        return command_eval(options);
    }
    if (command == "bench") {
        return command_bench(options);
    }
    return report_usage("unknown command '" + command + "'");
}

}  // namespace maintpol::cli
