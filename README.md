# Maintenance Policy

Facility maintenance policy evaluation runtime.

`maintpol` decides whether a proposed maintenance window may proceed. It is a decision service, not a
scheduler: given an authoritative policy bundle, an attributed evidence set, and a maintenance
request, it returns a deterministic verdict with the exact rule, exception, approval, generation and
digest that produced it.

## The core question

> May this maintenance, on this facility scope, for these obligation classes, in this window, proceed
> under the policy generation that is authoritative right now?

The answer is one of four outcomes, and every one of them is attributable:

| Outcome | Meaning |
| --- | --- |
| `allow` | Nothing in policy forbids the work, and every constraint that applies is satisfied. |
| `require-escalation` | A soft constraint is violated or an escalation rule triggered, and no authority at the required level has approved this exact request. |
| `unknown` | The question cannot be resolved: evidence is missing, stale, unmeasured, fenced, or an authority is defective. This is a refusal, never a silent "healthy". |
| `deny` | Policy forbids the work: a hard interlock, a protected class, a blackout window, a redundancy floor, a revoked policy generation. |

## Owned boundary

This repository owns:

* canonical maintenance-policy definitions and their lifecycle;
* time-window and blackout semantics, including bounded recurrence;
* typed redundancy and protection requirements;
* protected obligation classes;
* escalation requirements and their approval bindings;
* explicit maintenance exceptions (waivers) with scope, authority, reason, expiry and revocation;
* deterministic evaluation of a maintenance context against a policy;
* generation-bound verdicts and stale-authority fencing;
* a durable, integrity-checked store for published policy generations, the exception and approval
  registry, and the decision journal.

## Explicit non-ownership

This repository does **not**:

* schedule or execute maintenance;
* drain workloads or fabric;
* actuate power or cooling;
* respond to incidents;
* own the tenant, service-class or obligation-class registry;
* measure redundancy, capacity, or interlock state. Those measurements are consumed as attributed
  evidence from the systems that own them.

Where an external authority owns an effect, this runtime only evaluates a bounded request and records
a verdict. It never performs or simulates the external effect.

## Principal invariants

1. **Observation is not authority.** An evidence report is data; a verdict is authority only after it
   binds the exact policy generation, control epoch, registry revision and request digest.
2. **Missing is never healthy.** Absent, unmeasured, stale, future-dated or epoch-fenced evidence
   produces `unknown`, never `allow`. A request that declares no affected obligation classes cannot
   satisfy a class-scoped requirement; the omission is a refusal.
3. **Hard safety interlocks are non-waivable.** A hard interlock or protected-class rule can never be
   relaxed. A document that marks one waivable is rejected at parse time, and a request that presents
   an exception targeting one is denied.
4. **Waivers are never self-granted.** A request carries references only. Exceptions and approvals are
   always resolved against the authoritative registry, and their issuer-signed body must verify under
   supplied key material.
5. **Policy changes fence old authority.** Approvals and exceptions bind the policy generation and the
   policy digest. A new generation invalidates both without any extra step.
6. **Replay is resolved before staleness.** A repeated request with the same identity and digest
   returns the recorded decision, which is what makes a lost response safe to retry. A replay that
   binds an older generation is reported as superseded and never restores the authority it once had.
7. **Determinism.** Equivalent authoritative inputs produce byte-identical canonical documents and
   therefore identical digests. Rule declaration order, insertion order and evaluation repetition
   never change a verdict.
8. **Bounded everything.** Every externally supplied quantity is bounded before use; every arithmetic
   step that could overflow is checked, and a counter never wraps silently.

## Authority, generations and fencing

| Field | Owner | Invalidates |
| --- | --- | --- |
| `policy_generation` | the committing operator | every approval and exception issued against an earlier generation; every decision bound to it |
| `policy_digest` | the canonical policy document | the same, at content level: any rule change changes the digest |
| `control_epoch` | the store | previous live authority: a stale manifest is detected against the fence journal |
| `registry_revision` | the store | registry-only edits (exceptions, approvals) without a policy change |
| `evidence_epoch` | the measuring system | evidence older than the policy fence (`min_evidence_epoch`) |
| `request_digest` | the caller | approvals: an approval authorises one exact request |
| `semantics_version` | this repository | decisions issued under older evaluation semantics |

A decision binds all of them, together with the digests of the evidence set, the interlock report,
every referenced exception and every referenced approval.

### Store-level fencing

A new generation must be exactly `current + 1`, a new control epoch exactly `current + 1`, and the
registry revision must stay or advance by one. The store never invents authority for the caller, and
it never adopts a record that the manifest does not name. A manifest that is older than the highest
fence entry is treated as a rollback and the store refuses to open.

## Lifecycle model

Policy generations move `draft -> published -> superseded -> revoked`, with `draft -> revoked` and
`published -> revoked` also permitted. Only `published` authorises decisions; `draft` and
`superseded` are refusals, `revoked` is a denial. Exceptions carry `issued_at`, `not_before`,
`expires_at` and an optional `revoked_at`; approvals carry the same window plus the exact request
digest they authorise. Revocation is registry state and is excluded from the signed body, so revoking
a record never invalidates its signature and a signature can never be extended by editing registry
state.

## Canonical document format

Every document - policy, bundle, request, decision, key material - is a UTF-8 text document with the
same syntax:

```
[document]
format = maintpol/1
kind = bundle
[policy]
policy_id = policy-a
generation = 3
...
[rule blackout-a]
kind = blackout
priority = 100
scope = "FAC-1/*"
classes = "*"
window = "2026-03-01T00:00:00Z 2026-03-01T06:00:00Z"
```

* Sections are `[name]` or `[name argument]`; keys match `[a-z][a-z0-9_.-]*`.
* Values are bare, or quoted with `\\`, `\"`, `\n`, `\r`, `\t`, `\xHH` escapes.
* Parsing is strict: unknown sections, unknown keys, duplicate single-valued keys, missing required
  keys, impossible enum values, malformed digests, out-of-range numbers and unbounded collections are
  all errors with a stable code.
* Serialisation is canonical: fixed section order, fixed field order, sorted lists. Two equivalent
  model values always produce identical bytes, and the bytes are what the digests cover.
* A byte order mark before the first section is rejected.

### Time model

Instants are exact UTC points on the proleptic Gregorian timeline, stored as signed nanoseconds since
the Unix epoch. The supported range is:

```
1677-09-21T00:12:43.145224192Z  ..  2262-04-11T23:47:16.854775807Z
```

Text form is `YYYY-MM-DDTHH:MM:SS.fffffffffZ`; an explicit numeric offset (`+HH:MM`) is accepted and
normalised to UTC. Civil dates are validated (leap years, month lengths), year `0000` is rejected,
leap seconds are rejected rather than smeared, and named time zones are not supported: callers supply
an offset. All blackout intervals are half-open `[start, end)`: the start instant is inside the
window, the end instant is not. Two intervals that merely touch do not intersect.

### Recurrence

Recurrence is bounded by construction: a period kind (`daily`, `weekly`, `monthly`), an origin, a
fixed offset, a per-period window start offset, a duration, and a period count of at most 512. The
expansion is materialised deterministically at evaluation time. A monthly recurrence whose day does
not exist in a month yields no window for that period rather than being clamped. Overlapping blackout
periods are merged into a minimal canonical set, and merging is idempotent so the canonical form is
stable across a serialisation round trip.

## Evaluation semantics

The engine is a pure function of `(bundle, keys, request, prior decisions)`. It never reads a clock,
never touches the file system and never mutates its inputs; callers supply the authoritative
evaluation instant. Stages run in a fixed order and **every** condition found is reported, with the
highest severity present deciding the outcome:

```
1.  request shape errors                      -> an error, not a decision
2.  replay resolution                         -> before ordinary staleness rejection
3.  policy lifecycle                          -> draft / superseded / revoked
4.  generation and digest fence
5.  evidence: presence, freshness, epoch, source trust
6.  hard interlocks                           -> unknown is not inactive
7.  protected classes                         -> never waivable
8.  blackout windows                          -> waivable by a valid exception
9.  redundancy floors                         -> waivable only when the rule says so
10. soft constraints                          -> resolved by an approval at the required level
11. escalation and approval verification
```

Severity precedence is fixed and documented in `include/maintpol/error.hpp`:
`denial > refusal > escalation > advisory > info`. A finding attributes the condition to the smallest
set of inputs that produced it (rule, exception, approval, obligation class, or plain code), and
findings are sorted deterministically by severity, code and attribution.

Refusal codes never become permissive: `unknown` means the runtime could not establish that the work
is permitted.

## The store

```
<root>/
  LOCK          single-writer lock file
  CURRENT       authoritative manifest; replacing it is the commit point
  FENCE         append-only fence journal used for rollback detection
  gen-<N>.mpb   published policy bundle records, one per generation
  decisions.mpd append-only decision journal
```

Every record is framed as `header\n<exact payload length>\n<crc32>\n<payload>`. The commit protocol
for a new generation is:

```
stage record -> flush -> read back and verify -> publish the record name
stage manifest -> flush -> read back and verify -> replace CURRENT   <- commit point
append fence entry -> flush -> read back and verify
```

* A crash before the commit point leaves the previous generation authoritative. A record published
  without a manifest is an *orphan*: it is reported, never adopted, and removed by compaction.
* A crash after the commit point leaves the new generation authoritative with the fence one entry
  behind. Recovery accepts a lagging fence; a fence that runs *ahead* of the manifest is a rollback
  and fails closed.
* A torn trailing append to the journal is not authority and is truncated only by a writer; before
  the flush the entry cannot be seen, after the flush it is durable and must be readable. A damaged
  separator that merely looks like a torn write is reported as corruption instead of being discarded.
* Bundle records carry their body digest and the digest of the previous record, forming a chain
  across generations.
* Rollback protection is the fence journal. Compaction collapses it to the highest entry it already
  contains, so a reader that accepted the old journal accepts the compacted one.

## Concurrency model

The store is **single-writer, many-reader**:

* A writer holds an exclusive OS lock (`LOCK`) for the lifetime of the handle: on Windows the file is
  opened with read-only sharing and an exclusive byte-range lock, on POSIX with `flock(LOCK_EX)`.
  A second writer cannot even open the lock file.
* The kernel releases the lock when the process dies, so a crashed writer never leaves a stale lock;
  this is covered by a test that kills a writer while it holds the store.
* Readers take no lock. Published state is replaced atomically, so a reader observes either the
  previous or the new generation and never a partial one. Read-only inspection obeys the same
  integrity and rollback rules as an ordinary open and never repairs anything.
* Inside the library there is no shared mutable state: the engine is a pure function and a store's
  state is confined to one owning handle. There are no locks held across callbacks, no lock upgrades,
  no re-entrant acquisition and no blocking I/O performed while holding an internal lock. The writer
  lock is acquired in `open`/`create` and released by the owning object's destructor; no code path
  acquires it twice. Public operations are synchronous and single-threaded by design, so the library
  makes no thread-safety claim beyond that: separate handles, plus the writer-exclusion guarantee
  above, are what concurrency is built on.
* Decision-journal duplicate detection uses an index built once under the writer lock, so the write
  path does not re-read the journal and cannot observe a partial append from itself.

## Error semantics

Codes are a persisted contract: the numeric value of a code is part of canonical documents and of
every decision digest, and codes are never renumbered or reused. `include/maintpol/error.hpp` is the
single source of truth, with a class (input, time, policy, authority, policy state, evidence,
evaluation, store, internal), a severity, and a description per code. An unknown numeric code is an
error, never a default.

## Command line

```
maintpol version
maintpol selftest [--quiet]
maintpol digest <file> [--canonical]
maintpol policy validate <file>
maintpol policy canonicalize <file> [--out <file>]
maintpol keys generate <key-id> [--out <file>]
maintpol keys show <file>
maintpol store init <dir> --bundle <file> [--fault-crash-at <point>]
maintpol store put <dir> --bundle <file> [--fault-crash-at <point>]
maintpol store show|inspect|verify|history|compact <dir>
maintpol store get <dir> [--generation <n>] [--out <file>]
maintpol store decisions <dir> [--limit <n>]
maintpol eval (--store <dir> | --bundle <file>) --request <file> [--keys <file>] [--record] [--document]
maintpol bench --store <dir> --request <file> --iterations <n> [--keys <file>]
```

Exit codes are part of the contract: `0` allowed (or command success), `1` usage, input or storage
error, `2` denied, `3` unknown, `4` escalation required.

`--fault-crash-at <point>` terminates the process abruptly at a named stage of a durable commit. It
exists so that crash consistency can be tested against real processes: the store is reopened
afterwards and must present exactly one authoritative generation.

Authoritative state:

* `eval` never trusts the request for authority. Exceptions and approvals named by a request are
  looked up in the registry, and their MACs are verified with key material supplied through `--keys`.
* `store show`, `store verify`, `store history`, `store decisions` and `store get` are read-only and
  therefore work while another process owns the store.
* `store put` requires the document to declare exactly the next generation and control epoch; the
  store refuses to guess.

A short session:

```
$ maintpol store init /srv/maintpol --bundle bundle-1.txt
$ maintpol eval --store /srv/maintpol --request request-1.txt
outcome = deny
finding: BlackoutConflict [denial] rule=blackout-a - requested window intersects [...]
```

## Library integration

```cpp
#include "maintpol/engine.hpp"
#include "maintpol/store.hpp"

auto bundle  = maintpol::parse_bundle_document(document);          // strict and bounded
auto store   = maintpol::PolicyStore::open("/srv/maintpol", true); // read-only inspection
auto request = maintpol::parse_request_document(request_document);

auto keys = maintpol::KeySet::create(key_material);
auto decision = maintpol::evaluate(bundle.value(), keys.value(), request.value());
if (decision) {
    use(decision.value().outcome, decision.value().findings, decision.value().digest());
}
```

Everything public is in `include/maintpol/`. The engine returns `Result<T>`, which carries either a
value or an `Error` with a stable code and a bounded detail string; there is no "empty success" state.

## Build, install and consume

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix /opt/maintpol
```

The package exports a namespaced target:

```cmake
find_package(maintpol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE SummonLabs::maintpol)
```

Options: `MAINTPOL_BUILD_CLI`, `MAINTPOL_BUILD_TESTS`, `MAINTPOL_WARNINGS_AS_ERRORS`,
`MAINTPOL_ENABLE_ASAN`. First-party code is built with `/W4 /WX /permissive-` on MSVC and
`-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow` plus `-Werror` elsewhere.

`examples/downstream` is an independent out-of-tree consumer that links only against an installed
prefix and exercises evaluation, store publication, decision recording, replay and a generation
fence.

## Validation performed

All of the following was run on this repository as committed.

| Validation | Result |
| --- | --- |
| Release build, MSVC 19.44 (/W4 /WX /permissive-), C++20, x64 | clean, no warnings |
| Debug build | clean, no warnings |
| Release test suite (13 CTest tests: unit, integration, end-to-end CLI, property, adversarial, multiprocess, store) | 75 of 75 cases passed |
| Debug test suite | 75 of 75 cases passed |
| AddressSanitizer (/fsanitize=address, Debug, MSVC ASan runtime) | 13 of 13 CTest tests passed, no reports |
| maintpol selftest known-answer suite | 38 of 38 passed |
| Corruption sweep against real persisted files | every single-bit flip in CURRENT, FENCE, the bundle record and the decision journal is rejected; every truncation is rejected or classified as an unacknowledged tail |
| Crash consistency with real abrupt process death at each of 9 commit stages and 2 journal stages | exactly one authoritative generation afterwards, with content matched to that generation |
| Multi-process writer exclusion, and kernel lock release after termination | second writer refused, readers permitted, lock released on death |
| Installed package and independent downstream consumer | configure, build and run against the installed prefix, all exercised behaviours verified |

The corruption and crash tests manipulate real files in a real store; the crash tests terminate real
child processes at named stages and reopen the store afterwards. They are not simulated with mocks.

## Hardening defects found and fixed

Real defects that the validation above found in earlier revisions of this code, and their fixes:

1. **Calendar conversion was wrong for every month after February** (mis-parenthesised day-of-year
   formula), which shifted every computed instant. Caught by the known-answer calendar vectors.
2. **Undefined behaviour in checked multiplication** let the optimiser simplify the overflow check
   away, so the minimum representable instant could not be constructed in Release builds. The
   multiply is now performed on unsigned magnitudes.
3. **Bundle records were published without their frame**, so a store written by one revision could
   not be read by the manifest path. Found by the store round-trip test.
4. **Frame checksums were written as 16 hexadecimal characters instead of 8**, which every reader
   rejected. Found by the framing test.
5. **The decision digest covered the replay disposition**, so a replayed decision had a different
   digest from the decision it replayed, defeating idempotency. The disposition is transport metadata
   and is now excluded from the digest.
6. **Journal identities were not covered by any checksum**: flipping a bit in a recorded request
   digest was undetected. Entry headers now carry their own CRC, verified at the frame layer.
7. **A corrupted separator could masquerade as a torn append**, which would have silently discarded a
   complete record. A tail is accepted as unacknowledged only when its checksum field is short and
   hexadecimal; anything else is corruption and fails closed.
8. **An existing but empty fence journal silently disabled rollback detection.** A present fence with
   no entry is now corruption.
9. **A request could bypass a redundancy floor by declaring no affected classes**, because the rule
   then evaluated its own class list. The omission is now a refusal.
10. **Recurring blackout windows were validated but never expanded during evaluation**, so a
    recurrence never fired. Evaluation now works on the expansion.
11. **Rule windows were normalised on a copy**, so overlapping blackout periods were not merged in the
    stored policy.
12. **A missing store path was reported as an I/O failure** rather than as absence, because the
    directory probe propagated a "not found" error.
13. **The decision-recording path re-read the whole journal** on every append to detect duplicates,
    which made the durable write path quadratic in journal history. Recording is now answered from an
    index built once under the writer lock, and every append is verified by reading the appended bytes
    back from the file.
14. **A defective approval was classified as an integrity error** that denied the request outright.
    It is now an unsatisfied escalation, except for a MAC that does not verify, which is a refusal
    that retrying cannot resolve.

## Benchmarks

Methodology: single host, Windows 11, MSVC 19.44 x64, Release, NTFS, 16 logical processors, a fresh
store per run and 500 iterations. Every reported operation is a **completed** operation: the durable
figure includes the append, the device flush and the read-back verification, not a submission. Both
figures are produced by the same command, on the same data, in the same process:

```
maintpol bench --store <dir> --request <request> --iterations 500
```

| Operation | Provenance | Mean | Median | Min | Max |
| --- | --- | --- | --- | --- | --- |
| Policy evaluation (in memory) | SYNTHETIC | 11.4 us | 11.0 us | 10.6 us | 54.2 us |
| Evaluation + durable decision record (append, flush, read-back verify) | REAL | 4913.6 us | 4817.9 us | 1813.4 us | 19135.4 us |

* SYNTHETIC means no durable write is involved; it measures the decision engine alone.
* REAL means the complete durable path, including the device flush, which dominates the figure.
* No physical hardware behaviour is claimed: these are single-host measurements of this software and
  they say nothing about a specific facility's storage subsystem.
* An earlier revision that re-read the journal on every append measured 8544.0 us mean and 9037.4 us
  median for the same REAL operation over 1000 iterations on a growing journal on the same host. The
  figures above come from the corrected revision. The two runs compare this software's write path,
  not storage hardware, and are not a controlled benchmark of any other change.

## Unsupported and unvalidated behaviour

* **Platform:** validated on Windows x64 with MSVC 19.44 only. The POSIX code paths (locking, durable
  file operations, process helpers) are implemented and mirror the Windows behaviour, but were not
  executed in this environment and are therefore unvalidated.
* **Shared library builds:** the package builds and installs as a static library by default. A
  BUILD_SHARED_LIBS configuration was not validated on this host.
* **Sanitizers:** only AddressSanitizer was available and was run. Undefined-behaviour and thread
  sanitizers were not available with the installed toolchain and were not run.
* **Timezone database:** named time zones are deliberately not supported. Only explicit numeric UTC
  offsets are accepted; a caller that needs civil-time rules must resolve them itself.
* **Cryptography:** key material is HMAC-SHA256 with keys supplied out of band. There is no
  certificate or public-key infrastructure, no key distribution and no key revocation; provisioning,
  protecting and rotating key material is the operator's responsibility.
* **Scale:** the store keeps every published generation and the whole decision journal. Bounds are
  enforced (4096 rules, 1024 exceptions, 4096 approvals, 1,000,000 journal records, 16 MiB records),
  but no long-running or multi-terabyte deployment was exercised.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
