#include <cstdint>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"
#include "maintpol/store.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

// The stages of a generation commit.
std::vector<std::string> commit_fault_points() {
    std::vector<std::string> points;
    for (std::uint8_t value = static_cast<std::uint8_t>(FaultPoint::AfterRecordTempWrite);
         value <= static_cast<std::uint8_t>(FaultPoint::AfterFenceAppend); ++value) {
        points.emplace_back(to_string(static_cast<FaultPoint>(value)));
    }
    MP_CHECK(points.size() == 9u);
    return points;
}

// The stages of an append to the decision journal.
std::vector<std::string> journal_fault_points() {
    return {std::string(to_string(FaultPoint::BeforeJournalFlush)),
            std::string(to_string(FaultPoint::AfterJournalFlush))};
}

}  // namespace

MP_TEST(multiprocess, writer_exclusion_between_processes) {
    if (cli_path().empty()) {
        MP_FAIL("MAINTPOL_CLI is not set");
    }
    const std::string root = make_temp_directory("mp-exclusion");
    const std::string store_root = root + "\\store";
    const std::string bundle_path = write_temp_file(root, "bundle-2.txt",
                                                    canonical_bundle(bundle_for_generation(2, 2, 1)));
    {
        auto store = PolicyStore::create(store_root, bundle_for_generation(1, 1, 1));
        MP_CHECK(store.has_value());
        std::string output;
        // A second process cannot become the writer.
        const int blocked = run_process({cli_path(), "store", "put", store_root, "--bundle", bundle_path}, &output);
        MP_CHECK_EQ(blocked, 1);
        MP_CHECK(output.find("StoreLocked") != std::string::npos);
        // But it may read.
        const int read = run_process({cli_path(), "store", "show", store_root}, &output);
        MP_CHECK_EQ(read, 0);
        MP_CHECK(output.find("generation = 1") != std::string::npos);
        const int verified = run_process({cli_path(), "store", "verify", store_root}, &output);
        MP_CHECK_EQ(verified, 0);
    }
    // Once the writer is gone the other process can publish.
    std::string output;
    const int published = run_process({cli_path(), "store", "put", store_root, "--bundle", bundle_path}, &output);
    MP_CHECK_EQ(published, 0);
    MP_CHECK(output.find("generation = 2") != std::string::npos);
    remove_temp_directory(root);
}

MP_TEST(multiprocess, lock_is_released_when_the_writer_is_killed) {
    if (helper_path().empty()) {
        MP_FAIL("MAINTPOL_HELPER is not set");
    }
    const std::string root = make_temp_directory("mp-kill");
    {
        auto store = PolicyStore::create(root, bundle_for_generation(1, 1, 1));
        MP_CHECK(store.has_value());
    }
    ChildProcess child = start_process({helper_path(), "hold-exclusive", root, "30000"});
    MP_CHECK(child.valid());
    std::string pid_line;
    std::string locked_line;
    MP_CHECK(child.read_line(pid_line));
    MP_CHECK(child.read_line(locked_line));
    MP_CHECK_EQ(pid_line.rfind("pid ", 0), std::size_t(0));
    MP_CHECK_EQ(locked_line, std::string("locked"));

    // The live writer excludes us.
    MP_CHECK_CODE(PolicyStore::open(root, false), Code::StoreLocked);
    // The kernel releases the lock when the process dies.
    child.terminate();
    child.wait();

    bool reopened = false;
    for (int attempt = 0; attempt < 50 && !reopened; ++attempt) {
        auto store = PolicyStore::open(root, false);
        if (store.has_value()) {
            reopened = true;
            MP_CHECK(store.value().verify().has_value());
        }
    }
    MP_CHECK(reopened);
    remove_temp_directory(root);
}

MP_TEST(multiprocess, crash_at_every_commit_stage_leaves_one_authoritative_generation) {
    if (cli_path().empty()) {
        MP_FAIL("MAINTPOL_CLI is not set");
    }
    for (const std::string& point : commit_fault_points()) {
        const std::string root = make_temp_directory("mp-crash-" + point);
        const std::string store_root = root + "\\store";
        {
            auto store = PolicyStore::create(store_root, bundle_for_generation(1, 1, 1));
            MP_CHECK(store.has_value());
        }
        const std::string bundle_path = write_temp_file(root, "bundle-2.txt",
                                                        canonical_bundle(bundle_for_generation(2, 2, 1)));
        std::string output;
        const int crashed = run_process(
            {cli_path(), "store", "put", store_root, "--bundle", bundle_path, "--fault-crash-at", point}, &output);
        if (crashed == 0) {
            MP_FAIL("stage " + point + ": the process did not terminate abruptly, output: " + output);
        }

        const bool after_commit_point = point == "after-manifest-publish" || point == "after-fence-append";
        const std::uint64_t expected = after_commit_point ? 2u : 1u;
        {
            // Recovery must present exactly one authoritative generation.
            auto store = PolicyStore::open(store_root, true);
            if (!store.has_value()) {
                MP_FAIL("stage " + point + ": store did not reopen: " +
                        std::string(to_string(store.error().code)) + " - " + store.error().detail);
            }
            const std::uint64_t generation = store.value().info().generation.value();
            if (generation != expected) {
                MP_FAIL("stage " + point + ": expected generation " + std::to_string(expected) + " but found " +
                        std::to_string(generation));
            }
            const PolicyBundle bundle = MP_REQUIRE(store.value().load_bundle());
            MP_CHECK_EQ(bundle.policy().generation().value(), generation);
            MP_CHECK(store.value().verify().has_value());
            if (point == "after-record-publish") {
                // The record was published but the manifest was not: it is an
                // orphan and must never be adopted on its own.
                MP_CHECK_EQ(store.value().recovery().orphan_generations.size(), std::size_t(1));
            }
        }
        {
            // A writer repairs any staging residue left behind by the crash.
            auto writer = PolicyStore::open(store_root, false);
            MP_CHECK(writer.has_value());
            MP_CHECK(writer.value().verify().has_value());
            MP_CHECK_EQ(writer.value().info().generation.value(), expected);
        }
        remove_temp_directory(root);
    }
}

MP_TEST(multiprocess, crash_during_journal_append_is_recovered) {
    if (cli_path().empty()) {
        MP_FAIL("MAINTPOL_CLI is not set");
    }
    for (const std::string& point : journal_fault_points()) {
        const std::string root = make_temp_directory("mp-journal-" + point);
        const std::string store_root = root + "\\store";
        {
            auto store = PolicyStore::create(store_root, bundle_for_generation(1, 1, 1));
            MP_CHECK(store.has_value());
        }
        const std::string request_path = write_temp_file(root, "request.txt", request_document(RequestSpec{}));
        std::string output;
        const int crashed = run_process({cli_path(), "eval", "--store", store_root, "--request", request_path,
                                         "--record", "--fault-crash-at", point},
                                        &output);
        if (crashed == 0) {
            MP_FAIL("stage " + point + ": the process did not terminate abruptly, output: " + output);
        }
        auto store = PolicyStore::open(store_root, true);
        if (!store.has_value()) {
            MP_FAIL("stage " + point + ": store did not reopen: " + std::string(to_string(store.error().code)) +
                    " - " + store.error().detail);
        }
        // Before the flush the entry cannot exist; after it, the entry is
        // durable and must be readable, and neither case may confuse the store.
        const std::uint64_t records = store.value().recovery().journal_records;
        if (point == "before-journal-flush" && records != 0u) {
            MP_FAIL("stage " + point + ": an unflushed entry is visible");
        }
        if (point == "after-journal-flush" && records != 1u) {
            MP_FAIL("stage " + point + ": expected one durable entry but found " + std::to_string(records));
        }
        MP_CHECK_OK(store.value().verify());
        if (records == 1u) {
            auto listing = store.value().list_decisions(10);
            MP_CHECK_OK(listing);
            MP_CHECK_EQ(listing.value().size(), std::size_t(1));
        }
        remove_temp_directory(root);
    }
}

MP_TEST(multiprocess, many_readers_see_a_consistent_store) {
    if (cli_path().empty()) {
        MP_FAIL("MAINTPOL_CLI is not set");
    }
    const std::string root = make_temp_directory("mp-readers");
    {
        auto store = PolicyStore::create(root, bundle_for_generation(1, 1, 1));
        MP_CHECK(store.has_value());
    }
    const std::string request_path = write_temp_file(root, "request.txt", request_document(RequestSpec{}));
    for (int index = 0; index < 4; ++index) {
        std::string output;
        const int exit_code = run_process({helper_path(), "eval-store", root, request_path}, &output);
        MP_CHECK_EQ(exit_code, 0);
        MP_CHECK(output.find("allow") != std::string::npos || output.find("deny") != std::string::npos ||
                 output.find("unknown") != std::string::npos);
    }
    remove_temp_directory(root);
}
