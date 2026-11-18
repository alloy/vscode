# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
[CmdletBinding()]
param(
	[string] $BaselineDirectory
)

$ErrorActionPreference = 'Stop'
$baselineCommit = '5593057dbedea6bad3b904cc75605f23446b645b'
$cliRoot = Split-Path -Parent $PSScriptRoot
$repository = Split-Path -Parent $cliRoot
if ([string]::IsNullOrWhiteSpace($BaselineDirectory)) {
	$BaselineDirectory = Join-Path $cliRoot "target\native-baseline-$([guid]::NewGuid().ToString('N'))"
}
elseif (-not [System.IO.Path]::IsPathRooted($BaselineDirectory)) {
	$BaselineDirectory = Join-Path (Get-Location).Path $BaselineDirectory
}
$BaselineDirectory = [System.IO.Path]::GetFullPath($BaselineDirectory)
if (Test-Path -LiteralPath $BaselineDirectory) {
	throw "Refusing to overwrite an existing baseline directory: $BaselineDirectory"
}
if ($env:CARGO_TARGET_DIR) {
	Write-Warning "Caller CARGO_TARGET_DIR=$env:CARGO_TARGET_DIR is inherited. Avoid a shared candidate target: unset it or select a dedicated baseline target before running."
}

function Invoke-CargoCapture {
	param([string[]] $CargoArguments, [string] $LogPath, [switch] $BuildJson)
	$ErrorActionPreference = 'Continue'
	$PSNativeCommandUseErrorActionPreference = $false
	$lines = [System.Collections.Generic.List[string]]::new()
	& cargo @CargoArguments 2>&1 | ForEach-Object {
		$line = $_.ToString()
		$lines.Add($line)
		if ($BuildJson -and $line.StartsWith('{')) {
			try {
				$message = $line | ConvertFrom-Json -ErrorAction Stop
				if ($message.reason -eq 'compiler-message') {
					Write-Host $message.message.rendered
				}
			}
			catch {
				Write-Host $line
			}
		}
		else {
			Write-Host $line
		}
	}
	$exitCode = $LASTEXITCODE
	$ErrorActionPreference = 'Stop'
	[System.IO.File]::WriteAllLines($LogPath, $lines)
	[pscustomobject]@{ ExitCode = $exitCode; Text = ($lines -join "`n"); Lines = $lines }
}

& git -C $repository worktree add --detach $BaselineDirectory $baselineCommit
if ($LASTEXITCODE -ne 0) {
	throw 'Could not create the detached baseline worktree'
}
Write-Output "[source=baseline-helper retained_worktree=$BaselineDirectory]"
$actualCommit = & git -C $BaselineDirectory rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $baselineCommit) {
	throw "Baseline identity mismatch: $actualCommit"
}
$initialStatus = & git -C $BaselineDirectory status --porcelain
if ($LASTEXITCODE -ne 0 -or $initialStatus) {
	throw 'New baseline worktree is not clean'
}

$fixtures = @(
	'cli\src\tunnels\native_recovery_cli_tests.rs',
	'cli\src\tunnels\native_recovery_rpc_fixture.rs',
	'cli\src\auth_storage_reload_tests.rs',
	'cli\scripts\test-native-recovery.ps1'
)
$hashes = foreach ($file in $fixtures) {
	$source = Join-Path $repository $file
	$destination = Join-Path $BaselineDirectory $file
	$null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination)
	Copy-Item -LiteralPath $source -Destination $destination
	$hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
	if ($hash -ne (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash) {
		throw "Copied fixture differs: $file"
	}
	"$hash $file"
}
$includes = @{
	'cli\src\auth.rs' = "#[cfg(test)]`n#[path = `"auth_storage_reload_tests.rs`"]`nmod storage_reload_regression;"
	'cli\src\tunnels\dev_tunnels.rs' = "#[cfg(test)]`n#[path = `"native_recovery_cli_tests.rs`"]`nmod native_recovery_cli_tests;"
	'cli\src\tunnels\singleton_server.rs' = "#[cfg(test)]`n#[path = `"native_recovery_rpc_fixture.rs`"]`npub(super) mod native_recovery_rpc_fixture;"
}
$utf8 = [System.Text.UTF8Encoding]::new($false)
foreach ($file in $includes.Keys) {
	[System.IO.File]::AppendAllText((Join-Path $BaselineDirectory $file), "`n$($includes[$file])`n", $utf8)
}
$evidence = Join-Path $BaselineDirectory 'cli\target\native-baseline-evidence'
$null = New-Item -ItemType Directory -Force -Path $evidence
[System.IO.File]::WriteAllLines((Join-Path $evidence 'fixture-sha256.txt'), [string[]] $hashes)
& git -C $BaselineDirectory --no-pager diff "--output=$(Join-Path $evidence 'instrumentation-includes.patch')" -- @($includes.Keys)
if ($LASTEXITCODE -ne 0) {
	throw 'Could not record instrumentation-only includes'
}
& git -C $BaselineDirectory --no-pager diff --check
if ($LASTEXITCODE -ne 0) {
	throw 'Baseline instrumentation failed whitespace validation'
}

$previousToolchain = $env:RUSTUP_TOOLCHAIN
$previousTarget = $env:CARGO_TARGET_DIR
Push-Location (Join-Path $BaselineDirectory 'cli')
try {
	$env:RUSTUP_TOOLCHAIN = 'stable'
	if (-not $env:CARGO_TARGET_DIR) {
		$env:CARGO_TARGET_DIR = Join-Path $BaselineDirectory 'cli\target'
	}
	$auth = Invoke-CargoCapture -LogPath (Join-Path $evidence 'auth-cache-negative-control.log') -CargoArguments @(
		'test', '--lib', 'auth::storage_reload_regression::credential_reloads_external_login',
		'--', '--exact', '--nocapture', '--test-threads=1'
	)
	$expectedFailure = $auth.ExitCode -eq 101 -and
		$auth.Text -match 'auth-storage-reload-requires-external-credential' -and
		$auth.Text -match '(?m)^\s*left:\s*"synthetic-auth-reload-a"\s*$' -and
		$auth.Text -match '(?m)^\s*right:\s*"synthetic-auth-reload-b"\s*$' -and
		$auth.Text -match 'test result: FAILED\. 0 passed; 1 failed; 0 ignored;'
	if (-not $expectedFailure) {
		throw "Baseline Auth control did not fail exclusively with cached A versus B (exit=$($auth.ExitCode)); inspect $evidence"
	}
	Write-Output '[source=baseline-helper observed_expected_auth_failure=cached-A-instead-of-B]'

	$build = Invoke-CargoCapture -BuildJson -LogPath (Join-Path $evidence 'normal-cli-build.log') -CargoArguments @(
		'build', '--bin', 'code', '--message-format=json-render-diagnostics'
	)
	if ($build.ExitCode -ne 0) {
		throw "Baseline normal CLI build failed ($($build.ExitCode))"
	}
	$binary = $null
	foreach ($line in $build.Lines) {
		if (-not $line.StartsWith('{')) { continue }
		try { $artifact = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
		if ($artifact.reason -eq 'compiler-artifact' -and $artifact.target.name -eq 'code' -and $artifact.executable) {
			$binary = $artifact.executable
		}
	}
	if (-not $binary -or -not (Test-Path -LiteralPath $binary -PathType Leaf)) {
		throw 'Cargo did not identify a normal CLI executable artifact'
	}
	& .\scripts\test-native-recovery.ps1 -Binary $binary -Expectation Baseline |
		Tee-Object -FilePath (Join-Path $evidence 'native-cli-baseline.log')
	Write-Output "[source=baseline-helper complete=true baseline_commit=$actualCommit evidence=$evidence retained_worktree=$BaselineDirectory]"
}
finally {
	$env:RUSTUP_TOOLCHAIN = $previousToolchain
	$env:CARGO_TARGET_DIR = $previousTarget
	Pop-Location
	Write-Output "[source=baseline-helper retained_worktree=$BaselineDirectory evidence=$evidence]"
}
