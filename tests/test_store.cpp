#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"
#include "maintpol/fileio.hpp"
#include "maintpol/store.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

PolicyBundle bundle_for(PolicyGeneration generation, ControlEpoch epoch, Revision revision) {
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z")}},
                                      generation);
    std::vector<AuthorityRecord> authorities;
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(6));
    authority.description = "facility change authority";
    authorities.push_back(authority);
    return make_bundle(policy, authorities, {}, {}, epoch, revision);
}

PolicyBundle first_bundle() {
    return bundle_for(MP_REQUIRE(PolicyGeneration::from_value(1)), MP_REQUIRE(ControlEpoch::from_value(1)),
                      MP_REQUIRE(Revision::from_value(1)));
}

std::string store_file(const std::string& root, const std::string& name) { return root + "\\" + name; }

// Flips one bit in a file and reports whether the resulting store is rejected.
std::string escaped_bytes(const std::string& content, std::size_t offset) {
    const std::size_t start = offset > 12u ? offset - 12u : 0u;
    const std::size_t end = (std::min)(content.size(), offset + 13u);
    std::string text;
    for (std::size_t index = start; index < end; ++index) {
        const auto byte = static_cast<unsigned char>(content[index]);
        if (byte >= 0x20u && byte < 0x7Fu) {
            text.push_back(static_cast<char>(byte));
        } else {
            text.push_back('.');
        }
    }
    return text;
}

bool flip_byte_and_open(const std::string& root, const std::string& file, std::size_t offset) {
    const std::string path = store_file(root, file);
    std::string content = read_text_file(path);
    content[offset] = static_cast<char>(static_cast<unsigned char>(content[offset]) ^ 0x01u);
    MP_REQUIRE(write_file_durable(path, content));
    auto opened = PolicyStore::open(root, false);
    const bool rejected = !opened.has_value();
    content[offset] = static_cast<char>(static_cast<unsigned char>(content[offset]) ^ 0x01u);
    MP_REQUIRE(write_file_durable(path, content));
    return rejected;
}

}  // namespace

MP_TEST(store, create_open_and_publish) {
    const std::string root = make_temp_directory("store-basic");
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
        MP_CHECK_EQ(store.value().info().generation.value(), std::uint64_t(1));
        MP_CHECK(!store.value().info().record_digest.is_zero());

        // A second writer cannot open the store at all while the first holds it.
        auto second = PolicyStore::open(root, false);
        MP_CHECK_CODE(second, Code::StoreLocked);

        // A reader is concurrent by design.
        auto reader = PolicyStore::open(root, true);
        MP_CHECK_OK(reader);
        MP_CHECK_EQ(reader.value().info().generation.value(), std::uint64_t(1));

        auto next = store.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(2)),
                                                    MP_REQUIRE(ControlEpoch::from_value(2)),
                                                    MP_REQUIRE(Revision::from_value(1))));
        MP_CHECK_OK(next);
        MP_CHECK_EQ(next.value().generation.value(), std::uint64_t(2));
        MP_CHECK_EQ(next.value().record_digest.hex().size(), std::size_t(64));

        auto history = store.value().history();
        MP_CHECK_OK(history);
        MP_CHECK_EQ(history.value().size(), std::size_t(2));
        MP_CHECK_EQ(history.value().front().generation.value(), std::uint64_t(1));
        MP_CHECK_EQ(history.value().back().generation.value(), std::uint64_t(2));
        MP_CHECK(!(history.value().front().record_digest == history.value().back().record_digest));

        auto loaded = store.value().load_generation(MP_REQUIRE(PolicyGeneration::from_value(1)));
        MP_CHECK_OK(loaded);
        MP_CHECK_EQ(loaded.value().policy().generation().value(), std::uint64_t(1));
        auto absent = store.value().load_generation(MP_REQUIRE(PolicyGeneration::from_value(9)));
        MP_CHECK_CODE(absent, Code::StoreGenerationMissing);

        auto notes = store.value().verify();
        MP_CHECK_OK(notes);
        MP_CHECK(notes.value().size() >= 3u);
    }
    {
        auto reopened = PolicyStore::open(root, true);
        MP_CHECK_OK(reopened);
        MP_CHECK_EQ(reopened.value().info().generation.value(), std::uint64_t(2));
    }
    remove_temp_directory(root);
}

MP_TEST(store, generation_and_epoch_must_advance_by_one) {
    const std::string root = make_temp_directory("store-fence");
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
        MP_CHECK_CODE(store.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(3)),
                                                      MP_REQUIRE(ControlEpoch::from_value(2)),
                                                      MP_REQUIRE(Revision::from_value(1)))),
                      Code::StoreFenceRegression);
        MP_CHECK_CODE(store.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(1)),
                                                      MP_REQUIRE(ControlEpoch::from_value(2)),
                                                      MP_REQUIRE(Revision::from_value(1)))),
                      Code::StoreFenceRegression);
        MP_CHECK_CODE(store.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(2)),
                                                      MP_REQUIRE(ControlEpoch::from_value(5)),
                                                      MP_REQUIRE(Revision::from_value(1)))),
                      Code::StoreFenceRegression);
        MP_CHECK_CODE(store.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(2)),
                                                      MP_REQUIRE(ControlEpoch::from_value(2)),
                                                      MP_REQUIRE(Revision::from_value(5)))),
                      Code::StoreFenceRegression);
        MP_CHECK(store.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(2)),
                                                 MP_REQUIRE(ControlEpoch::from_value(2)),
                                                 MP_REQUIRE(Revision::from_value(2))))
                     .has_value());
        MP_CHECK_EQ(store.value().info().generation.value(), std::uint64_t(2));
    }
    remove_temp_directory(root);
}

MP_TEST(store, path_validation) {
    MP_CHECK_CODE(PolicyStore::open("relative\\path", true), Code::StorePathInvalid);
    MP_CHECK_CODE(PolicyStore::open("C:\\temp\\..\\escape", true), Code::StorePathInvalid);
    MP_CHECK_CODE(PolicyStore::open("C:\\temp\\aux", true), Code::StorePathInvalid);
    MP_CHECK_CODE(PolicyStore::open("C:\\temp\\con.store", true), Code::StorePathInvalid);
    const std::string missing = make_temp_directory("store-missing");
    remove_temp_directory(missing);
    MP_CHECK_CODE(PolicyStore::open(missing, true), Code::StoreMissing);
    const std::string non_empty = make_temp_directory("store-nonempty");
    write_temp_file(non_empty, "file.txt", "content");
    MP_CHECK_CODE(PolicyStore::create(non_empty, first_bundle()), Code::StoreAlreadyExists);
    remove_temp_directory(non_empty);
}

MP_TEST(store, read_only_refuses_mutation) {
    const std::string root = make_temp_directory("store-readonly");
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
    }
    {
        auto reader = PolicyStore::open(root, true);
        MP_CHECK_OK(reader);
        MP_CHECK(reader.value().read_only());
        MP_CHECK_CODE(reader.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(2)),
                                                       MP_REQUIRE(ControlEpoch::from_value(2)),
                                                       MP_REQUIRE(Revision::from_value(1)))),
                      Code::StoreReadOnly);
        Decision decision;
        MP_CHECK_CODE(reader.value().record_decision(decision), Code::StoreReadOnly);
        MP_CHECK_CODE(reader.value().compact(), Code::StoreReadOnly);
    }
    remove_temp_directory(root);
}

MP_TEST(store, decision_journal_round_trip) {
    const std::string root = make_temp_directory("store-journal");
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
        const PolicyBundle bundle = MP_REQUIRE(store.value().load_bundle());

        RequestSpec spec;
        const Decision decision = evaluate_spec(bundle, KeySet{}, spec);
        auto first = store.value().record_decision(decision);
        MP_CHECK(first.has_value());
        MP_CHECK(first.value() == DecisionWriteResult::Appended);
        auto repeated = store.value().record_decision(decision);
        MP_CHECK_OK(repeated);
        MP_CHECK(repeated.value() == DecisionWriteResult::AlreadyRecorded);

        Decision conflicting = decision;
        conflicting.findings.clear();
        conflicting.outcome = Outcome::Allow;
        MP_CHECK_CODE(store.value().record_decision(conflicting), Code::DecisionConflict);

        auto records = store.value().list_decisions(10);
        MP_CHECK_OK(records);
        MP_CHECK_EQ(records.value().size(), std::size_t(1));
        MP_CHECK_EQ(records.value().front().sequence.value(), std::uint64_t(1));
        MP_CHECK(records.value().front().decision_digest == decision.digest());

        const EvaluationRequest request = build_request(spec);
        auto found = store.value().find_decision(request.context_id(), request.digest());
        MP_CHECK_OK(found);
        MP_CHECK(found.value().has_value());
        auto absent = store.value().find_decision(MP_REQUIRE(ContextId::parse("other-context")), request.digest());
        MP_CHECK_OK(absent);
        MP_CHECK(!absent.value().has_value());

        auto prior = store.value().prior_decisions(request.context_id());
        MP_CHECK_OK(prior);
        MP_CHECK_EQ(prior.value().size(), std::size_t(1));
        MP_CHECK(prior.value().front().request_digest == request.digest());

        const Decision replayed = evaluate_spec(bundle, KeySet{}, spec, prior.value());
        MP_CHECK(replayed.replay == ReplayDisposition::Replayed);
        MP_CHECK_EQ(replayed.digest().hex(), decision.digest().hex());

        Decision stale = decision;
        stale.bindings.policy_generation = MP_REQUIRE(PolicyGeneration::from_value(9));
        MP_CHECK_CODE(store.value().record_decision(stale), Code::StoreFenceRegression);
    }
    remove_temp_directory(root);
}

MP_TEST(store, corruption_and_truncation_sweeps) {
    const std::string root = make_temp_directory("store-corruption");
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
        const PolicyBundle bundle = MP_REQUIRE(store.value().load_bundle());
        MP_CHECK(store.value().record_decision(evaluate_spec(bundle, KeySet{}, RequestSpec{})).has_value());
    }

    const std::vector<std::string> files = {"CURRENT", "FENCE", "decisions.mpd", "gen-00000000000000000001.mpb"};
    for (const std::string& file : files) {
        const std::string path = store_file(root, file);
        const std::string original = read_text_file(path);
        MP_CHECK(original.size() > 8u);

        for (std::size_t length = 0; length < original.size(); ++length) {
            MP_REQUIRE(write_file_durable(path, original.substr(0, length)));
            auto opened = PolicyStore::open(root, true);
            if (file == "decisions.mpd") {
                // A torn append is never authority; the store must either
                // refuse or report an incomplete tail.
                if (opened.has_value()) {
                    MP_CHECK(opened.value().recovery().journal_trailing_partial ||
                             opened.value().recovery().journal_records == 0u);
                }
            } else {
                MP_CHECK(!opened.has_value());
            }
        }
        MP_REQUIRE(write_file_durable(path, original));

        for (std::size_t offset = 0; offset < original.size(); ++offset) {
            if (!flip_byte_and_open(root, file, offset)) {
                MP_FAIL("undetected corruption in " + file + " at offset " + std::to_string(offset) +
                        " byte=" + std::to_string(static_cast<unsigned>(static_cast<unsigned char>(
                                      original[offset]))) +
                        " context=[" + escaped_bytes(original, offset) + "] size=" +
                        std::to_string(original.size()));
            }
        }
    }
    {
        auto reopened = PolicyStore::open(root, true);
        MP_CHECK_OK(reopened);
        MP_CHECK_EQ(reopened.value().recovery().journal_records, std::uint64_t(1));
    }
    remove_temp_directory(root);
}

MP_TEST(store, rollback_of_the_manifest_is_detected) {
    const std::string root = make_temp_directory("store-rollback");
    std::string old_manifest;
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
        old_manifest = read_text_file(store_file(root, "CURRENT"));
        MP_CHECK(store.value().commit(bundle_for(MP_REQUIRE(PolicyGeneration::from_value(2)),
                                                 MP_REQUIRE(ControlEpoch::from_value(2)),
                                                 MP_REQUIRE(Revision::from_value(1))))
                     .has_value());
    }
    MP_REQUIRE(write_file_durable(store_file(root, "CURRENT"), old_manifest));
    MP_CHECK_CODE(PolicyStore::open(root, true), Code::StoreRollbackDetected);
    MP_CHECK_CODE(PolicyStore::inspect(root), Code::StoreRollbackDetected);
    remove_temp_directory(root);
}

MP_TEST(store, orphan_records_are_reported_and_never_adopted) {
    const std::string root = make_temp_directory("store-orphan");
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
    }
    // A record for generation 2 without a manifest for it is exactly the state
    // a crash before the commit point leaves behind.
    const std::string record = read_text_file(store_file(root, "gen-00000000000000000001.mpb"));
    MP_REQUIRE(write_file_durable(store_file(root, "gen-00000000000000000002.mpb"), record));
    {
        auto opened = PolicyStore::open(root, true);
        MP_CHECK_OK(opened);
        MP_CHECK_EQ(opened.value().info().generation.value(), std::uint64_t(1));
        MP_CHECK_EQ(opened.value().recovery().orphan_generations.size(), std::size_t(1));
        auto notes = opened.value().verify();
        MP_CHECK_OK(notes);
    }
    {
        auto writer = PolicyStore::open(root, false);
        MP_CHECK_OK(writer);
        MP_CHECK(writer.value().compact().has_value());
        MP_CHECK_EQ(writer.value().recovery().removed_orphans.size(), std::size_t(1));
    }
    {
        auto after = PolicyStore::open(root, true);
        MP_CHECK_OK(after);
        MP_CHECK(after.value().recovery().orphan_generations.empty());
    }
    remove_temp_directory(root);
}

MP_TEST(store, journal_tail_is_repaired_only_by_a_writer) {
    const std::string root = make_temp_directory("store-tail");
    {
        auto store = PolicyStore::create(root, first_bundle());
        MP_CHECK_OK(store);
        const PolicyBundle bundle = MP_REQUIRE(store.value().load_bundle());
        MP_CHECK(store.value().record_decision(evaluate_spec(bundle, KeySet{}, RequestSpec{})).has_value());
    }
    const std::string journal_path = store_file(root, "decisions.mpd");
    const std::string complete = read_text_file(journal_path);
    MP_REQUIRE(write_file_durable(journal_path, complete.substr(0, complete.size() - 5u)));

    {
        auto reader = PolicyStore::open(root, true);
        MP_CHECK_OK(reader);
        MP_CHECK(reader.value().recovery().journal_trailing_partial);
        MP_CHECK(!reader.value().recovery().journal_repaired);
        MP_CHECK_EQ(reader.value().recovery().journal_records, std::uint64_t(0));
        MP_CHECK_EQ(read_text_file(journal_path).size(), complete.size() - 5u);
    }
    {
        auto writer = PolicyStore::open(root, false);
        MP_CHECK_OK(writer);
        MP_CHECK(writer.value().recovery().journal_repaired);
        MP_CHECK_EQ(read_text_file(journal_path).size(), std::size_t(0));
    }
    remove_temp_directory(root);
}
