#include <algorithm>
#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

struct CliResult {
    int exit_code = 0;
    std::string output;
};

CliResult run_cli(std::vector<std::string> arguments) {
    if (cli_path().empty()) {
        MP_FAIL("MAINTPOL_CLI is not set");
    }
    arguments.insert(arguments.begin(), cli_path());
    CliResult result;
    result.exit_code = run_process(arguments, &result.output);
    return result;
}

std::vector<AuthorityRecord> default_authorities() {
    std::vector<AuthorityRecord> authorities;
    AuthorityRecord authority;
    authority.id = MP_REQUIRE(AuthorityId::parse("authority-1"));
    authority.level = MP_REQUIRE(AuthorityLevel::from_value(6));
    authority.description = "facility change authority";
    authorities.push_back(authority);
    return authorities;
}

struct CliFixture {
    std::string root;
    std::string store_root;
    std::string bundle_path;
    std::string request_path;
};

CliFixture make_fixture(const std::string& label) {
    CliFixture fixture;
    fixture.root = make_temp_directory(label);
    fixture.store_root = fixture.root + "\\store";
    const Policy policy = make_policy({Rule{blackout_rule("blackout-a", "FAC-1/*", "2026-03-01T00:00:00Z",
                                                          "2026-03-01T06:00:00Z")},
                                       Rule{redundancy_rule("redundancy-a", "FAC-1/*", "power", 2)},
                                       Rule{soft_constraint_rule("soft-a", "FAC-1/*", 1)},
                                       Rule{escalation_rule_with_window("escalation-a", "FAC-1/*", 5, "PT3H")}});
    const PolicyBundle bundle = make_bundle(policy, default_authorities());
    fixture.bundle_path = write_temp_file(fixture.root, "bundle.txt", canonical_bundle(bundle));
    fixture.request_path = write_temp_file(fixture.root, "request.txt", request_document(RequestSpec{}));
    return fixture;
}

PolicyBundle store_bundle(std::uint64_t generation, std::uint64_t epoch) {
    return bundle_for_generation(generation, epoch, 1);
}

}  // namespace

MP_TEST(cli, version_and_selftest) {
    const CliResult version = run_cli({"version"});
    MP_CHECK_EQ(version.exit_code, 0);
    MP_CHECK(version.output.find("maintpol 1.0.0") != std::string::npos);
    MP_CHECK(version.output.find("maintpol/1") != std::string::npos);
    const CliResult selftest = run_cli({"selftest", "--quiet"});
    MP_CHECK_EQ(selftest.exit_code, 0);
    MP_CHECK(selftest.output.find("0 failed") != std::string::npos);
    const CliResult help = run_cli({"help"});
    MP_CHECK_EQ(help.exit_code, 0);
    MP_CHECK(help.output.find("usage:") != std::string::npos);
    const CliResult unknown = run_cli({"nonsense"});
    MP_CHECK_EQ(unknown.exit_code, 1);
    const CliResult bad_option = run_cli({"store", "show", "--nonsense", "x"});
    MP_CHECK_EQ(bad_option.exit_code, 1);
}

MP_TEST(cli, policy_validation_and_canonicalisation) {
    const CliFixture fixture = make_fixture("cli-policy");
    const CliResult valid = run_cli({"policy", "validate", fixture.bundle_path});
    MP_CHECK_EQ(valid.exit_code, 0);
    MP_CHECK(valid.output.find("ok bundle") != std::string::npos);

    const std::string out_path = fixture.root + "\\canonical.txt";
    const CliResult canonical = run_cli({"policy", "canonicalize", fixture.bundle_path, "--out", out_path});
    MP_CHECK_EQ(canonical.exit_code, 0);
    MP_CHECK_EQ(read_text_file(out_path), read_text_file(fixture.bundle_path));

    const CliResult digest = run_cli({"digest", fixture.bundle_path, "--canonical"});
    MP_CHECK_EQ(digest.exit_code, 0);
    MP_CHECK(digest.output.find("kind = bundle") != std::string::npos);
    MP_CHECK(digest.output.find("canonical_digest = ") != std::string::npos);

    const std::string broken_path = write_temp_file(fixture.root, "broken.txt", "[document]\nformat = maintpol/1\n");
    const CliResult broken = run_cli({"policy", "validate", broken_path});
    MP_CHECK_EQ(broken.exit_code, 1);

    const std::string missing_path = fixture.root + "\\absent.txt";
    const CliResult missing = run_cli({"policy", "validate", missing_path});
    MP_CHECK_EQ(missing.exit_code, 1);
    remove_temp_directory(fixture.root);
}

MP_TEST(cli, key_material_round_trip) {
    const std::string root = make_temp_directory("cli-keys");
    const std::string key_path = root + "\\keys.txt";
    const CliResult generated = run_cli({"keys", "generate", "key-1", "--out", key_path});
    MP_CHECK_EQ(generated.exit_code, 0);
    const std::string document = read_text_file(key_path);
    MP_CHECK(document.find("kind = keys") != std::string::npos);
    MP_CHECK(parse_key_document(document).has_value());
    const CliResult shown = run_cli({"keys", "show", key_path});
    MP_CHECK_EQ(shown.exit_code, 0);
    MP_CHECK(shown.output.find("key key-1") != std::string::npos);
    // The secret itself is never echoed by 'keys show'.
    MP_CHECK(shown.output.find("secret") == std::string::npos);
    const CliResult bad = run_cli({"keys", "generate", "bad id", "--out", key_path});
    MP_CHECK_EQ(bad.exit_code, 1);
    remove_temp_directory(root);
}

MP_TEST(cli, store_lifecycle) {
    const CliFixture fixture = make_fixture("cli-store");
    const CliResult init = run_cli({"store", "init", fixture.store_root, "--bundle", fixture.bundle_path});
    MP_CHECK_EQ(init.exit_code, 0);
    MP_CHECK(init.output.find("generation = 1") != std::string::npos);

    // Inspection never takes the writer lock, so it works even while another
    // process owns the store.
    const CliResult show = run_cli({"store", "show", fixture.store_root});
    MP_CHECK_EQ(show.exit_code, 0);
    MP_CHECK(show.output.find("generation = 1") != std::string::npos);
    MP_CHECK(show.output.find("mode = read-only") != std::string::npos);

    const CliResult inspect = run_cli({"store", "inspect", fixture.store_root});
    MP_CHECK_EQ(inspect.exit_code, 0);
    MP_CHECK(inspect.output.find("mode = read-only") != std::string::npos);

    const CliResult verify = run_cli({"store", "verify", fixture.store_root});
    MP_CHECK_EQ(verify.exit_code, 0);
    MP_CHECK(verify.output.find("verified") != std::string::npos);

    const CliResult history_one = run_cli({"store", "history", fixture.store_root});
    MP_CHECK_EQ(history_one.exit_code, 0);
    MP_CHECK(history_one.output.find("1 published generations") != std::string::npos);

    const CliResult get = run_cli({"store", "get", fixture.store_root});
    MP_CHECK_EQ(get.exit_code, 0);
    MP_CHECK(get.output.find("kind = bundle") != std::string::npos);

    // Publishing the next generation requires the exact next generation and epoch.
    const std::string next_path = write_temp_file(fixture.root, "bundle-2.txt",
                                                  canonical_bundle(store_bundle(2, 2)));
    const CliResult put = run_cli({"store", "put", fixture.store_root, "--bundle", next_path});
    MP_CHECK_EQ(put.exit_code, 0);
    MP_CHECK(put.output.find("generation = 2") != std::string::npos);
    const CliResult repeated = run_cli({"store", "put", fixture.store_root, "--bundle", next_path});
    MP_CHECK_EQ(repeated.exit_code, 1);
    MP_CHECK(repeated.output.find("StoreFenceRegression") != std::string::npos);

    const CliResult history_two = run_cli({"store", "history", fixture.store_root});
    MP_CHECK_EQ(history_two.exit_code, 0);
    MP_CHECK(history_two.output.find("2 published generations") != std::string::npos);

    const CliResult compact = run_cli({"store", "compact", fixture.store_root});
    MP_CHECK_EQ(compact.exit_code, 0);
    MP_CHECK(compact.output.find("compacted") != std::string::npos);
    const CliResult verify_after = run_cli({"store", "verify", fixture.store_root});
    MP_CHECK_EQ(verify_after.exit_code, 0);
    remove_temp_directory(fixture.root);
}

MP_TEST(cli, evaluation_exit_codes) {
    const CliFixture fixture = make_fixture("cli-eval");
    const CliResult init = run_cli({"store", "init", fixture.store_root, "--bundle", fixture.bundle_path});
    MP_CHECK_EQ(init.exit_code, 0);

    // The request lies outside the blackout window, exceeds the escalation
    // window threshold and violates a soft constraint, so it needs escalation.
    RequestSpec escalation;
    escalation.window_start = "2026-03-02T01:00:00Z";
    escalation.window_end = "2026-03-02T06:00:00Z";
    escalation.evaluated_at = "2026-03-02T00:30:00Z";
    escalation.concurrent_maintenance = 3;
    escalation.evidence_observed_at = "2026-03-02T00:00:00Z";
    escalation.evidence_classes.front().observed_at = "2026-03-02T00:00:00Z";
    escalation.interlock_observed_at = "2026-03-02T00:00:00Z";
    const std::string escalation_path = write_temp_file(fixture.root, "escalation.txt",
                                                        request_document(escalation));
    const CliResult escalated = run_cli({"eval", "--store", fixture.store_root, "--request", escalation_path});
    if (escalated.exit_code != 4) {
        MP_FAIL("expected escalation, got exit " + std::to_string(escalated.exit_code) + ": " + escalated.output);
    }
    MP_CHECK(escalated.output.find("outcome = require-escalation") != std::string::npos);
    MP_CHECK(escalated.output.find("SoftConstraintViolation") != std::string::npos);

    // Inside the blackout window the request is denied.
    RequestSpec denied;
    denied.window_start = "2026-03-01T01:00:00Z";
    denied.window_end = "2026-03-01T02:00:00Z";
    const std::string denied_path = write_temp_file(fixture.root, "denied.txt", request_document(denied));
    const CliResult deny = run_cli({"eval", "--store", fixture.store_root, "--request", denied_path});
    MP_CHECK_EQ(deny.exit_code, 2);
    MP_CHECK(deny.output.find("outcome = deny") != std::string::npos);
    MP_CHECK(deny.output.find("BlackoutConflict") != std::string::npos);

    // Without evidence the request cannot be resolved.
    RequestSpec unknown;
    unknown.window_start = "2026-03-02T01:00:00Z";
    unknown.window_end = "2026-03-02T02:00:00Z";
    unknown.evaluated_at = "2026-03-02T00:30:00Z";
    unknown.include_evidence = false;
    const std::string unknown_path = write_temp_file(fixture.root, "unknown.txt", request_document(unknown));
    const CliResult unresolved = run_cli({"eval", "--store", fixture.store_root, "--request", unknown_path});
    MP_CHECK_EQ(unresolved.exit_code, 3);
    MP_CHECK(unresolved.output.find("outcome = unknown") != std::string::npos);

    // A request that binds the wrong generation is refused.
    RequestSpec stale;
    stale.window_start = "2026-03-02T01:00:00Z";
    stale.window_end = "2026-03-02T02:00:00Z";
    stale.evaluated_at = "2026-03-02T00:30:00Z";
    stale.expected_generation = 7;
    const std::string stale_path = write_temp_file(fixture.root, "stale.txt", request_document(stale));
    const CliResult refused = run_cli({"eval", "--store", fixture.store_root, "--request", stale_path});
    MP_CHECK_EQ(refused.exit_code, 3);
    MP_CHECK(refused.output.find("PolicyGenerationStale") != std::string::npos);

    // Evaluating against a bundle file, with the decision document emitted.
    const CliResult from_bundle = run_cli({"eval", "--bundle", fixture.bundle_path, "--request", denied_path,
                                           "--document"});
    MP_CHECK_EQ(from_bundle.exit_code, 2);
    MP_CHECK(from_bundle.output.find("kind = decision") != std::string::npos);

    // Missing arguments are usage errors.
    const CliResult both = run_cli({"eval", "--bundle", fixture.bundle_path, "--store", fixture.store_root,
                                    "--request", denied_path});
    MP_CHECK_EQ(both.exit_code, 1);
    remove_temp_directory(fixture.root);
}

MP_TEST(cli, recording_and_replay) {
    const CliFixture fixture = make_fixture("cli-record");
    const CliResult init = run_cli({"store", "init", fixture.store_root, "--bundle", fixture.bundle_path});
    MP_CHECK_EQ(init.exit_code, 0);
    RequestSpec spec;
    spec.window_start = "2026-03-02T01:00:00Z";
    spec.window_end = "2026-03-02T02:00:00Z";
    spec.evaluated_at = "2026-03-02T00:30:00Z";
    spec.evidence_observed_at = "2026-03-02T00:00:00Z";
    spec.evidence_classes.front().observed_at = "2026-03-02T00:00:00Z";
    spec.interlock_observed_at = "2026-03-02T00:00:00Z";
    const std::string request_path = write_temp_file(fixture.root, "record.txt", request_document(spec));

    const CliResult first = run_cli({"eval", "--store", fixture.store_root, "--request", request_path, "--record"});
    if (first.exit_code != 0) {
        MP_FAIL("expected a permitted decision, got exit " + std::to_string(first.exit_code) + ": " + first.output);
    }
    MP_CHECK(first.output.find("journal = appended") != std::string::npos);
    MP_CHECK(first.output.find("outcome = allow") != std::string::npos);

    const CliResult second = run_cli({"eval", "--store", fixture.store_root, "--request", request_path, "--record"});
    MP_CHECK_EQ(second.exit_code, 0);
    MP_CHECK(second.output.find("journal = already-recorded") != std::string::npos);
    MP_CHECK(second.output.find("replay = replayed") != std::string::npos);

    const CliResult decisions = run_cli({"store", "decisions", fixture.store_root});
    MP_CHECK_EQ(decisions.exit_code, 0);
    MP_CHECK(decisions.output.find("1 journal records") != std::string::npos);
    remove_temp_directory(fixture.root);
}
