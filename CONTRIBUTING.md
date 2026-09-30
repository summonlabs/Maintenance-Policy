# Contributing to Maintenance Policy

Thanks for your interest in improving Maintenance Policy. This guide explains how to
propose changes, what a contribution is expected to satisfy, and how the review
process works.

## License and contribution terms

Maintenance Policy is released under the [Apache License, Version 2.0](LICENSE).
Attribution and trademark information is recorded in [NOTICE](NOTICE).

Contributions are accepted under the same license on an **inbound = outbound** basis,
as set out in section 5 of the Apache License 2.0 ("Submission of Contributions"):

> Unless You explicitly state otherwise, any Contribution intentionally submitted for
> inclusion in the Work by You to the Licensor shall be under the terms and conditions
> of this License, without any additional terms or conditions.

In practice, this means:

- **There is no CLA.** You are not asked to sign a Contributor License Agreement.
- **There is no copyright assignment.** You retain the copyright in your contribution;
  you simply license it to the project under the Apache License 2.0.
- By opening a pull request you confirm that you have the right to submit the work,
  that it is your original creation or is otherwise compatible with the Apache
  License 2.0, and that you intend it for inclusion in this project.
- Do not copy code from another project unless its license is compatible with the
  Apache License 2.0 and you preserve the required copyright, attribution, and notice
  information. If you are unsure whether something is compatible, open an issue and
  ask before you write the code.
- New files are covered by the project license. A short
  `SPDX-License-Identifier: Apache-2.0` line is welcome but not required.
- Do not relicense the project, and do not add terms that conflict with the license.

## Ways to contribute

- Report a bug or request a feature by opening an issue with a clear description.
- Send a focused pull request for a bug fix, a test gap, or a documented feature.
- Improve documentation and examples where they are wrong or incomplete.
- Report security-sensitive problems privately, as described below.

For anything larger than a small fix, open an issue first so the design can be agreed
before you invest significant time.

## Development environment

Building requires:

- A C++20-capable compiler: MSVC 19.3x (Visual Studio 2022) or newer, GCC 11 or
  newer, or Clang 14 or newer.
- CMake 3.20 or newer, with CTest available.
- No additional runtime dependencies; the build and test tooling comes from CMake and
  your compiler toolchain.

### Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

On multi-configuration generators (Visual Studio, Xcode) keep the `--config Release`
argument and pass `-C Release` to CTest so the matching test binaries are run. Debug
builds are useful while developing, but also confirm that a Release build and the full
test suite pass before you open a pull request.

## What a pull request must satisfy

1. **The build is clean.** The project builds from a fresh configure with no errors.
2. **The test suite passes.** Run the complete CTest suite locally and make sure every
   test succeeds. Do not disable, skip, or weaken an existing test to make a change
   pass; if a test looks wrong, explain why in the pull request.
3. **Strict warnings stay clean.** The build enables aggressive warnings and treats them
   as errors:
   - MSVC: `/W4 /WX /permissive-`
   - GCC and Clang: `-Wall -Wextra -Wpedantic -Werror`

   Fix the warning rather than suppressing it. If a suppression is genuinely
   unavoidable, state the reason and its scope in the pull request description.
4. **No new third-party runtime dependencies.** Standard library and already-present
   dependencies only. A new build- or test-only tool may be discussed in an issue
   first; anything that ships in the runtime artifact should be justified explicitly.
5. **No telemetry.** The code must not phone home, collect analytics, or transmit user
   data. Nothing in the library should contact the network unless a documented,
   user-invoked API explicitly does so.
6. **Deterministic behavior.** For equivalent authoritative inputs, results must be
   identical from run to run. In particular, do not depend on hash or unordered
   container iteration order, wall-clock time, locale, thread scheduling, address
   values, or uninitialized memory. If something is intentionally unordered, make the
   ordering explicit and stable at the boundary where it is observed.
7. **No unresolved work in the change.** No `TODO`, `FIXME`, placeholder, stub, or
   commented-out code, and no stray debug prints. Diagnostic output belongs in tests,
   behind a documented logging facility, or nowhere at all.
8. **Tests are required for behavior changes.** A bug fix needs a regression test that
   fails before the fix and passes after it. A new behavior needs unit tests covering
   its normal path and its error paths. Changed public behavior needs its documentation
   and tests updated in the same pull request.
9. **The diff stays focused.** Keep formatting consistent with the surrounding code,
   avoid drive-by reformatting, and do not mix unrelated cleanups into a functional
   change. Keep generated files and build output out of the commit.
10. **Public interfaces are treated carefully.** Call out any change to a public header,
    API, or observable contract in the pull request description, along with the
    compatibility impact.

## Commit messages

- Write a short imperative subject line, 72 characters or fewer, with no trailing
  period: `Fix window boundary when the policy is empty`, not `Fixed some stuff`.
- Leave one blank line, then explain what changed and, more importantly, why. Wrap the
  body at roughly 72 columns.
- Reference the issue when one exists, for example `Fixes #41`.
- Keep one logical change per commit. A reviewer should be able to read the history and
  understand each step.
- Do not add attribution tags for tools or assistants.

Example:

```
Fix evaluation of an empty maintenance window

An empty window was treated as "always allowed", which let maintenance
run during protected periods. Treat an empty window as "nothing
allowed" and cover both cases with regression tests.

Fixes #41.
```

## Reporting security-sensitive issues

Please do not open a public issue for a suspected vulnerability, and do not include
exploit details in a pull request, a public discussion, or a log pasted into an issue.

Instead, report it privately:

- Use GitHub's private vulnerability reporting for this repository (the **Security**
  tab, then **Report a vulnerability**) when it is available.
- If that is not available, contact the maintainers directly through the contact
  address published on the Summon Software Labs organization profile, and ask for a
  private channel before sending details.

A useful report includes the affected version or commit, a description of the problem,
the impact you believe it has, and a minimal reproduction if you have one. Please allow
the maintainers a reasonable amount of time to investigate and ship a fix before
disclosing the issue publicly. Reports are acknowledged as quickly as possible, and
reporters are credited in the fix unless they prefer otherwise.

## Review process

- Maintainers review pull requests and may request changes; the discussion happens in
  the pull request.
- Automated checks must pass before a change is merged.
- Small, focused pull requests are reviewed fastest. Large changes are easier to accept
  when they are split into reviewable steps.
- A contribution may be declined if it conflicts with the project's scope, adds a
  dependency or an interface the project does not want to maintain, or cannot be
  supported by tests. When that happens, the reason is explained in the pull request.
- Be respectful and precise in review discussions. Critique the code, not the person.

## Questions

If something in this document is unclear, or if a change you want to make does not fit
any of the categories above, open an issue and ask. It is better to clarify the
expectations first than to rework a finished contribution.
