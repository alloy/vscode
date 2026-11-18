<!-- Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License. -->

# Isolated native tunnel recovery demonstration

The opt-in fixture runs production `Auth` storage/loading, the production singleton RPC server, and the shared production `ActiveTunnelManager::run_tunnel` lifecycle. It launches the normal compiled CLI executable as separate subprocesses; the singleton itself lives in the library-test process. Actual commands, subprocess stdout/stderr, status JSON, human readiness, machine events, and singleton identity are printed with source labels.

```powershell
& $Binary --cli-data-dir $IsolatedProfile tunnel user login --provider microsoft --access-token synthetic-demo-credential-v1
& $Binary --cli-data-dir $IsolatedProfile tunnel status
& $Binary --cli-data-dir $IsolatedProfile --verbose tunnel --machine-status --accept-server-license-terms
& $Binary --cli-data-dir $IsolatedProfile tunnel user login --provider microsoft --access-token synthetic-demo-credential-v2
```

Every CLI child receives `VSCODE_CLI_USE_FILE_KEYCHAIN=1`; the fixture does not change the process-wide keychain environment. Foreground `--verbose` exposes the production debug-level `is listening for incoming connections` message after each reconnect, separately from the human banner and `__VSCODE_CLI_STATUS__` events.

## Fixed checkout

Use the normal host Rust/C++/OpenSSL build environment. From `cli`:

```powershell
$env:RUSTUP_TOOLCHAIN = 'stable'
cargo build --bin code
.\scripts\test-native-recovery.ps1 -Binary .\target\debug\code.exe -Expectation Fixed |
    Tee-Object .\target\native-recovery-fixed.log
```

The binary path is mandatory and must name the normal executable built from the checkout under test, not an installed CLI or test harness. Supply the actual artifact path if your Cargo target directory differs. The runner identifies the source commit, modified source files, exact binary path, and binary SHA-256, then runs the ignored fixture with stdout capture disabled. It restores its test environment variables and Rust toolchain selection on exit.

## One-command baseline negative controls

From `cli` in this branch, with the same build environment:

```powershell
.\scripts\test-native-recovery-baseline.ps1
```

No manual patch copying is required. An optional `-BaselineDirectory .\target\native-baseline-review` chooses a different **new, nonexistent** worktree directory; existing directories are never overwritten.

The helper performs these steps:

1. Creates a clean detached worktree at the exact baseline `5593057dbedea6bad3b904cc75605f23446b645b`, by default under `cli\target\native-baseline-<UUID>`, and verifies its commit and initial clean status.
2. Copies only the two CLI demo Rust fixtures, the shared Auth reload Rust testcase, and the existing demo runner, verifying byte-identical hashes. It appends three `#[cfg(test)]` module includes; no production implementation is copied or changed.
3. Runs `auth::storage_reload_regression::credential_reloads_external_login`. The negative control is accepted **only** for exit 101 with its unique final assertion reporting cached `"synthetic-auth-reload-a"` versus expected `"synthetic-auth-reload-b"` and exactly one failing test. Compilation errors, other assertion failures, and unexpected success fail the helper.
4. Builds the baseline's normal CLI and obtains its executable path from Cargo's actual artifact output. By default it explicitly selects that worktree's own `cli\target`, protecting the candidate's artifacts. An existing caller `CARGO_TARGET_DIR` is honored with a warning: unset it or choose a dedicated baseline directory rather than sharing the candidate target.
5. Invokes the identical demo runner with `-Expectation Baseline`, expecting the still-responsive singleton to report Disconnected after the rejected worker terminates and a separate normal CLI login writes the replacement credential.

The named worktree is retained for inspection on success or failure; the helper never recursively removes it or uses force Git operations. Evidence is retained under its `cli\target\native-baseline-evidence`: the Auth negative-control log, normal CLI build output, actual CLI demonstration output, copied-fixture SHA-256 manifest, and instrumentation-only module-include patch. Inspect source changes with `git -C <printed-worktree> diff` and `git -C <printed-worktree> status --short`.

The fixture's local successful-close adapter supports both the baseline's string callback and the hardened lifecycle's typed close result, without altering either production loop. `Baseline` changes only the final expected observation, not fault injection or recovery instrumentation.

## Observed before/after result

Both controls have been exercised: the unchanged baseline failed the Auth reload assertion with cached A instead of B, and its real-CLI demonstration observed `worker_finished=true recovered=false`. The fixed demonstration observed `worker_finished=false recovered=true`, preserved singleton identity, and received fresh human and machine readiness through the already-attached normal CLI.

The real-CLI scenario is: initial Connected and attachment readiness; synthetic transient relay failure and Disconnected; same-worker reconnect and fresh readiness; synthetic credential keepalive rejection and Disconnected without false readiness; separate normal CLI login writing the replacement token; then either baseline termination or fixed same-singleton recovery. Re-run the commands to capture current timestamps, PIDs, hashes, and output rather than treating example labels as a transcript.

These are unsigned debug builds, not installed services. Build-time product metadata, including a product commit/version printed by the CLI, is not proof of the source SHA used for an instrumented baseline. Use the verified Git worktree identity, recorded source changes, Cargo artifact path, and binary hash for source/artifact attribution.

## Offline validation

The hardened library suite passed 239 tests with no failures and one deliberately ignored CLI demonstration, which passed separately through the published runner. This includes 16 Auth tests and 134 tunnel tests, including all 10 new native lifecycle cases. All-target check, normal all-target Clippy, changed-file Rust formatting, PowerShell parsing, and whitespace checks passed. Clippy retains 11 existing source diagnostics outside modified lines, plus the existing unused `open` dependency warning.

The prior keepalive regression now waits for the endpoint error instead of worker termination, retains its disconnected/error assertions, and additionally requires the worker to survive and reconnect after confirmed cleanup. Its controlled provider records an actual synthetic rejection so transient errors are not mislabeled invalid authentication. The close callback now returns a typed result instead of a display string; original readiness assertions remain. Tokio's dev-only `test-util` feature permits deterministic deadline/backoff tests.

The baseline helper was also exercised end to end using its default isolated target: the shared Auth assertion failed for the expected cached A/B values, its normal CLI demonstration observed the dead-worker outcome, and all four copied fixtures matched the hardened checkout byte for byte. These offline results do not replace a separately approved live canary with independent discovery and existing-session continuation.

## Native recovery behavior and limits

Production Auth now reloads backing storage rather than relying on a process-local cached login, permits provider-supported silent refresh, and restricts implicit background authentication from launching device login. Explicit `tunnel user login` remains available. Focused Auth tests cover refresh, credential rejection versus transient failures, external replacement, concurrency, and no-prompt behavior; the CLI demo deliberately uses non-expiring Microsoft synthetic access tokens without refresh tokens, so `get_credential()` does not perform OAuth HTTP.

The lifecycle supervises keepalive failures and retries credential acquisition and relay establishment rather than abandoning the worker. Connected/Disconnected remain the primary wire states; optional recovery detail distinguishes Connecting, Retrying, AuthenticationRequired, Closing, CleanupBlocked, and Failed. A recovery/retry state is not readiness: fresh readiness follows an actual successful relay connection.

An SDK relay handle's dropped task handle does not prove its worker stopped. Recovery explicitly closes the old SDK relay before replacement. Blocked cleanup reports `CleanupBlocked`; failed cleanup or a worker panic reports `Failed`. Both refuse duplicate replacement relays rather than claiming recovery. The demo supplies synthetic successful SDK close; focused lifecycle tests cover blocked/failed cleanup and keepalive completion handling.

Native OS keyring operations can be uncancellable. Storage serialization and request supervision do not make a blocked operating-system call cancellable or guarantee recovery from it. Credential rechecks reduce stale refresh overwrites but are not an atomic cross-process compare-and-swap; another process can still change storage in the remaining race window. These limits are not exercised by synthetic file credentials.

## Exact synthetic boundary and isolation

SDK relay futures, SDK close, SDK credential acceptance/rejection, and keepalive rejection are synthetic. Credential writes use the normal CLI `tunnel user login` command and production file-keychain serialization; a long-lived production `Auth::get_credential()` loads them for the relay lifecycle. This is real Auth storage/CLI login/RPC/lifecycle integration, **not** live OAuth refresh, provider revocation, `Auth::keep_token_alive()`, native keyring, management-service, live relay, external client discovery, or existing remote-session integration.

Before constructing Auth, the CLI demo requires a nonempty isolated `token.json`; before credential acquisition, guards require a known synthetic Microsoft credential without expiry or refresh token. The shared Auth reload testcase similarly precreates its private file before either Auth instance exists. Existing files select file storage, preventing global keyring reads/writes. The strings printed by these fixtures are intentionally synthetic, not real credentials.

Each CLI demonstration owns a genuine exclusive singleton lock under a unique `cli\target\native-recovery-demo\profile-*` directory before launching any CLI child, and every invocation explicitly supplies that profile. No default profile, network login, live relay, service installation, watchdog, or AHP session is used or modified. `tunnel status` may inspect the existing service-registration flag; that flag is not an installation change or service-health assertion. Foreground children are killed/waited on and private profiles removed at exit. No shipping fixture feature, runtime dependency, or production command is added; test builds enable Tokio's existing virtual-time support.
