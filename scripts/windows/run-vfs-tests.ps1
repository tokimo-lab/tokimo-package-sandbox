# Run only vfs-related integration tests (fuse_chmod + neighbours) with the
# svc already built. Must be invoked from an elevated shell.

[CmdletBinding()]
param(
    [string[]]$Tests = @('fuse_chmod', 'fuse_mount', 'fuse_rename', 'fuse_symlink')
)

$ErrorActionPreference = 'Continue'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[!] not elevated' -ForegroundColor Red
    exit 87
}

$Root   = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Exe    = Join-Path $Root 'target\debug\tokimo-sandbox-svc.exe'
$ArtDir = Join-Path $Root 'target\integration'
$SvcLog = Join-Path $ArtDir 'svc.log'
$TestLog = Join-Path $ArtDir 'test-vfs.log'

New-Item -ItemType Directory -Force -Path $ArtDir | Out-Null
Set-Location $Root

Write-Host "==> Killing leftover svc + VMs" -ForegroundColor Cyan
Get-Process tokimo-sandbox-svc -ErrorAction SilentlyContinue | Stop-Process -Force
hcsdiag.exe list 2>$null | Select-String 'tokimo-sess' | ForEach-Object {
    if ($_ -match '(tokimo-sess-\S+)') { hcsdiag.exe kill $Matches[1] | Out-Null }
}
Start-Sleep 2

Write-Host "==> Launching svc --console" -ForegroundColor Cyan
$svcProc = Start-Process -FilePath $Exe -ArgumentList '--console' `
    -RedirectStandardOutput $SvcLog -RedirectStandardError "$SvcLog.err" `
    -NoNewWindow -PassThru
Start-Sleep 3

if ($svcProc.HasExited) {
    Write-Host "[!] svc exited immediately, see $SvcLog" -ForegroundColor Red
    Get-Content $SvcLog -Tail 30
    exit 1
}

$failed = $false
try {
    foreach ($t in $Tests) {
        Write-Host "==> cargo test --test $t" -ForegroundColor Cyan
        & cargo test --test $t -- --test-threads=1 --nocapture *>&1 |
            Tee-Object -FilePath $TestLog -Append
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[FAIL] $t exited with $LASTEXITCODE" -ForegroundColor Red
            $failed = $true
        }
    }
} finally {
    Write-Host "==> Stopping svc (pid $($svcProc.Id))" -ForegroundColor Cyan
    Stop-Process -Id $svcProc.Id -Force -ErrorAction SilentlyContinue
    hcsdiag.exe list 2>$null | Select-String 'tokimo-sess' | ForEach-Object {
        if ($_ -match '(tokimo-sess-\S+)') { hcsdiag.exe kill $Matches[1] | Out-Null }
    }
}

if ($failed) { exit 1 } else { Write-Host "ALL VFS TESTS PASSED" -ForegroundColor Green; exit 0 }
