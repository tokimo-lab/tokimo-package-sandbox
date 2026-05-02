<#
.SYNOPSIS
  Run the sandbox_integration test suite end-to-end.

.DESCRIPTION
  Strategy: spawn `tokimo-sandbox-svc.exe --console` as an elevated child
  process so its eprintln! diagnostics are captured to a file (running
  the service under SCM throws those away). Then run `cargo test` against
  the same `\\.\pipe\tokimo-sandbox-svc` named pipe.

  Layout of artifacts (under target/integration/):
    svc.log    — service stdout+stderr (--console mode)
    test.log   — cargo test output
    build.log  — cargo build output (only if -SkipBuild not given)
    summary.txt — one-line PASS/FAIL marker for tooling

  Must be run from an elevated shell. UAC must allow elevation if not
  already admin. With UAC fully disabled, run an admin pwsh manually first.

.PARAMETER SkipBuild
  Skip cargo build (use existing target/debug binaries).

.PARAMETER KeepRunning
  Don't kill the svc.exe child after tests (useful for ad-hoc poking).
#>

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Admin check
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host '[!] not elevated — must run from an admin pwsh' -ForegroundColor Red
    Write-Host '    HCS / Hyper-V APIs require Administrator.' -ForegroundColor Red
    exit 87
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$Root      = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Exe       = Join-Path $Root 'target\debug\tokimo-sandbox-svc.exe'
$ArtDir    = Join-Path $Root 'target\integration'
$SvcLog    = Join-Path $ArtDir 'svc.log'
$TestLog   = Join-Path $ArtDir 'test.log'
$BuildLog  = Join-Path $ArtDir 'build.log'
$Summary   = Join-Path $ArtDir 'summary.txt'
$PipePath  = '\\.\pipe\tokimo-sandbox-svc'

New-Item -ItemType Directory -Force -Path $ArtDir | Out-Null
foreach ($f in @($SvcLog, $TestLog, $BuildLog, $Summary)) {
    if (Test-Path $f) { Remove-Item $f -Force }
}

function Write-Section([string]$Msg) {
    Write-Host ''
    Write-Host "=== $Msg ===" -ForegroundColor Cyan
}

function Stop-LeftoverSvc {
    Get-Process 'tokimo-sandbox-svc' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    # Give Windows a beat to release the named pipe.
    Start-Sleep -Milliseconds 500
}

function Wait-PipeReady([int]$timeoutSec = 30) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $PipePath) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

# ---------------------------------------------------------------------------
# 1. Cleanup
# ---------------------------------------------------------------------------
Write-Section 'cleanup'
Stop-LeftoverSvc

# Also uninstall any leftover SCM service from prior runs so it doesn't
# preempt our --console pipe.
if (Get-Service 'tokimo-sandbox-svc' -ErrorAction SilentlyContinue) {
    Write-Host '  ‣ removing leftover SCM service' -ForegroundColor DarkGray
    Stop-Service 'tokimo-sandbox-svc' -Force -ErrorAction SilentlyContinue
    if (Test-Path $Exe) { & $Exe --uninstall *>&1 | Out-Null }
    sc.exe delete 'tokimo-sandbox-svc' *>&1 | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Get-Service 'tokimo-sandbox-svc' -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
    }
}
Stop-LeftoverSvc

# ---------------------------------------------------------------------------
# 2. Build
# ---------------------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Section 'cargo build --tests'
    Push-Location $Root
    try {
        cargo build --tests *>&1 | Tee-Object -FilePath $BuildLog
        if ($LASTEXITCODE -ne 0) {
            'FAIL: build' | Out-File $Summary
            Write-Host "BUILD FAILED — see $BuildLog" -ForegroundColor Red
            exit 1
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host '[*] -SkipBuild: using existing target/debug binaries' -ForegroundColor DarkGray
}

if (-not (Test-Path $Exe)) {
    'FAIL: svc.exe missing' | Out-File $Summary
    Write-Host "missing $Exe" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 3. Spawn svc --console (logs to file)
# ---------------------------------------------------------------------------
Write-Section 'launch tokimo-sandbox-svc --console'
$svcProc = Start-Process -FilePath $Exe `
    -ArgumentList '--console' `
    -WorkingDirectory $Root `
    -RedirectStandardOutput $SvcLog `
    -RedirectStandardError "$SvcLog.err" `
    -PassThru `
    -WindowStyle Hidden

Write-Host "  ‣ pid=$($svcProc.Id), log=$SvcLog"

if (-not (Wait-PipeReady 20)) {
    'FAIL: pipe never appeared' | Out-File $Summary
    Write-Host 'pipe never appeared in 20s' -ForegroundColor Red
    if (-not $svcProc.HasExited) { $svcProc.Kill() }
    Write-Host '--- last 60 lines of svc.log ---' -ForegroundColor Yellow
    if (Test-Path $SvcLog) { Get-Content $SvcLog -Tail 60 }
    exit 1
}
Write-Host "  ‣ pipe ready: $PipePath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Run cargo test
# ---------------------------------------------------------------------------
Write-Section 'cargo test --test sandbox_integration'
$testExit = 1
Push-Location $Root
try {
    cargo test --test sandbox_integration -- --test-threads=1 --nocapture *>&1 |
        Tee-Object -FilePath $TestLog
    $testExit = $LASTEXITCODE
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# 5. Cleanup svc child
# ---------------------------------------------------------------------------
Write-Section 'shutdown'
if (-not $KeepRunning) {
    if (-not $svcProc.HasExited) {
        Write-Host "  ‣ killing svc pid=$($svcProc.Id)"
        $svcProc.Kill()
        try { $svcProc.WaitForExit(5000) | Out-Null } catch {}
    }
    Stop-LeftoverSvc
} else {
    Write-Host "  ‣ -KeepRunning: leaving svc pid=$($svcProc.Id) alive" -ForegroundColor DarkGray
}

# Merge stderr into svc.log if anything got captured separately.
if (Test-Path "$SvcLog.err") {
    Get-Content "$SvcLog.err" | Add-Content $SvcLog
    Remove-Item "$SvcLog.err" -Force
}

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
if ($testExit -eq 0) {
    'PASS' | Out-File $Summary
    Write-Host "`n=== PASS ===" -ForegroundColor Green
} else {
    'FAIL: cargo test' | Out-File $Summary
    Write-Host "`n=== FAIL (exit $testExit) ===" -ForegroundColor Red
    Write-Host '--- last 40 lines of svc.log ---' -ForegroundColor Yellow
    if (Test-Path $SvcLog) { Get-Content $SvcLog -Tail 40 }
}
Write-Host "logs: $ArtDir" -ForegroundColor Cyan
exit $testExit
