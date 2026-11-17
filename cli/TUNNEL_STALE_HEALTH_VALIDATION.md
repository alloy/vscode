# Tunnel stale-health acceptance validation

## Scope and source identities

Independent offline validation on Windows x64, completed on 2026-11-17. This note contains source identities, locally measured test results, reproduction commands, and limitations only. It does not contain private incident observations, authentication logs, credentials, session data, or binary artifacts.

| Revision | Tested commit | Parent |
| --- | --- | --- |
| Baseline with validation tests | `ee1d6550c8cfe557001601ea974676e4a7808585` | `69047191fc427f2f92828279aae1d90d8eeda7ab` |
| Original proposal with validation tests | `032e9f6e1cd702577986a2ef229cdd468b6418e6` | `a6f0795203809e7137844e68942148529c7c098f` |
| Acceptance revision | `5593057dbedea6bad3b904cc75605f23446b645b` | `032e9f6e1cd702577986a2ef229cdd468b6418e6` |

The acceptance revision's exact HEAD and sole parent were verified before testing in a separate worktree. The original source/test controls and their existing artifacts were preserved.

## Review and behavioral results

The acceptance diff records disconnection before awaiting relay-close cleanup and before manager shutdown can block. Its conditional cleanup preserves an existing specific failure reason. A watch-backed observer follows the currently registered manager's status and emits human-readable and machine-readable reconnect readiness.

All nine original relay test bodies, all five original RPC test bodies, and the shared reconnect assertions were retained unchanged. RPC fixture initialization now uses the production status-registration method and a broadcast logger consistent with production's logger wiring. Production machine-status broadcast installation was inspected separately.

| Fresh run | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| Baseline behavioral control | 5 | 9 | 0 |
| Original-proposal behavioral control | 12 | 2 | 0 |
| Acceptance behavioral cases | 16 | 0 | 0 |
| Acceptance surrounding tunnel suite | 123 | 0 | 0 |

The surrounding selector filtered out 90 unrelated library tests; those tests were not run.

Both original acceptance failures reproduce at runtime on the original-proposal control and pass on the acceptance revision:

- `close_request_disconnects_before_blocked_cleanup`
- `reconnect_after_disconnected_attachment_produces_readiness`

The two added observer cases also pass:

- `reconnect_observer_reports_each_connection_without_disconnect_readiness`
- `reconnect_observer_follows_replacement_instead_of_old_manager`

The baseline and original-proposal failures are intentional negative controls, not successful test runs. All controls compiled; compilation failures from missing acceptance APIs were not used as evidence.

## Build, lint, and formatting

| Check on acceptance revision | Result |
| --- | --- |
| CLI debug build | Pass |
| `cargo check --all-targets` | Pass |
| Normal `cargo clippy --all-targets` | Pass, with existing warnings |
| Strict Clippy with `-D warnings` | Fail: 11 existing findings in source files unchanged by acceptance |
| Changed-file rustfmt | Pass |
| Git whitespace check | Pass |
| Whole-crate formatting | Fail: diagnostics identical to the original-proposal control after checkout-path normalization |

The strict Clippy findings comprise nine redundant formatting borrows and two `manual_clear` findings. No unrelated lint or formatting fixes were made.

The build used Rust 1.100.0 (`0ef1bc386059596dada8fb65b50425aab2ea637a`), the `x86_64-pc-windows-msvc` host, repository static-CRT flags, and matching `x64-windows-static` OpenSSL. The contributing guide's `static-md` triplet did not match those CRT flags in the earlier control build.

Stable configuration was checked before building: product quality `stable`, product commit `69047191fc427f2f92828279aae1d90d8eeda7ab`, application `code`, and server application `code-server`. No development server-path override was present. A previously absent target directory excluded stale CLI artifacts; emitted build-script configuration and the resulting x64 PE architecture were subsequently checked.

An initial post-build provenance audit assumed an older Cargo output layout and failed closed. The local audit was adapted to Cargo's `code-cli\<fingerprint>\run\stdout` layout and verification completed without Rust source or test changes.

The resulting artifact was an unsigned debug build, not a deployed pilot. Its `--version` output identifies the Stable product's distribution commit, not the acceptance source commit. Source identity must therefore be established from the verified checkout and fresh-build provenance, not `--version` alone. Actual remote server selection was not exercised.

## Reproduction

Use independent worktrees at the exact commits above. Run from each worktree's `cli` directory in an x64 Visual Studio developer shell, using the existing Rust toolchain and matching static-CRT OpenSSL. Set the two installation-specific paths below; do not substitute a default OSS product configuration when validating Stable compatibility.

```powershell
$env:OPENSSL_DIR = '<path to x64-windows-static OpenSSL prefix>'
$env:OPENSSL_STATIC = '1'
$env:VSCODE_CLI_PRODUCT_JSON = '<path to Stable product.json>'
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP ('vscode-tunnel-validation-' + [guid]::NewGuid().ToString('N'))
$env:CARGO_BUILD_JOBS = '4'

cargo test --offline --locked --lib stale_health_regression -- --test-threads=1
cargo test --offline --locked --lib tunnels:: -- --test-threads=1
cargo check --offline --locked --all-targets
cargo clippy --offline --locked --all-targets -- -D warnings
cargo clippy --offline --locked --all-targets
rustfmt --edition 2021 --config skip_children=true --check src\tunnels\dev_tunnels.rs src\tunnels\singleton_server.rs src\tunnels\stale_health_rpc_tests.rs
cargo fmt --all -- --check
cargo build --offline --locked --bin code
git diff --check
```

The recorded runs used cached locked dependencies with `--offline`. A new environment must first restore the required locked dependencies if its cache is incomplete. Run commands separately so the expected strict-lint and whole-crate-format failures do not prevent subsequent checks.

For the paired negative controls, rerun the focused `stale_health_regression` command on each unchanged control worktree. Each control contains 14 cases; acceptance contains 16. Do not copy acceptance-only tests onto older controls and count resulting compilation errors as negative controls.

## Limits and acceptance status

These results validate controlled offline status/lifecycle and readiness behavior, not production authentication or end-to-end availability.

- Relay connection, endpoint, close, and token dependencies are synthetic; no production authentication or networking faults were injected.
- RPC fixtures use isolated temporary singleton locks and real local JSON-RPC. Machine events are captured through shared process-global test sinks, so separate-process machine-event delivery and remote relay/AHP initialization are not established by these tests.
- The two added cases simulate repeated status transitions and replacement registrations, not repeated physical SDK relay connections.
- Watch channels retain the latest state rather than a lossless transition history. Exhaustive cross-thread/generation races and observer starvation are not proven.
- Independent external Agents-client connection and existing-session acceptance are **blocked / not performed**. No live pilot or deployment was performed.
- Credential validity, credential-cache recovery, signed/release/LTO builds, cross-platform behavior, sleep/logon/fleet tests, and long-term soak remain unvalidated. There is no zero-downtime or recurrence-prevention claim.
