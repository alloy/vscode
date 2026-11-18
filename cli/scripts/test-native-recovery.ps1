# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string] $Binary,
	[ValidateSet('Baseline', 'Fixed')]
	[string] $Expectation = 'Fixed'
)

$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$previousBinary = $env:VSCODE_CLI_TEST_BINARY
$previousExpectation = $env:VSCODE_CLI_TEST_EXPECT_RECOVERY
$previousToolchain = $env:RUSTUP_TOOLCHAIN
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
	$env:VSCODE_CLI_TEST_BINARY = $binaryPath
	$env:VSCODE_CLI_TEST_EXPECT_RECOVERY = if ($Expectation -eq 'Fixed') { '1' } else { '0' }
	$env:RUSTUP_TOOLCHAIN = 'stable'
	$source = & git --no-pager rev-parse HEAD
	if ($LASTEXITCODE -ne 0) {
		throw 'Cannot identify the checkout under test'
	}
	$hash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash
	Write-Output "[source=demo-runner commit=$source expectation=$Expectation binary=$binaryPath sha256=$hash]"
	& git --no-pager status --short -- src
	& cargo test --lib tunnels::dev_tunnels::native_recovery_cli_tests::native_recovery_cli_demo -- --exact --ignored --nocapture --test-threads=1
	if ($LASTEXITCODE -ne 0) {
		throw "Native recovery demonstration failed ($LASTEXITCODE)"
	}
}
finally {
	$env:VSCODE_CLI_TEST_BINARY = $previousBinary
	$env:VSCODE_CLI_TEST_EXPECT_RECOVERY = $previousExpectation
	$env:RUSTUP_TOOLCHAIN = $previousToolchain
	Pop-Location
}
