#!/usr/bin/env pwsh
# rebake-initrd.ps1 — local dev convenience.
#
# Rebuilds vm/initrd.img after editing Rust sources for tokimo-sandbox-init,
# without touching debootstrap / kernel / rootfs (those come from the latest
# vm-v* release pulled by fetch-vm.ps1).
#
# Pipeline:
#   1. cargo build --release --target x86_64-unknown-linux-musl --bin tokimo-sandbox-init
#   2. WSL bash packaging/vm-image/scripts/rebake-initrd.sh \
#         --base   <BaseInitrd>      (default: vm/initrd.img — must already exist)
#         --init-bin target/x86_64-unknown-linux-musl/release/tokimo-sandbox-init
#         --out    target/vm-rebake/initrd.img
#   3. Optional: -InstallToVm copies the rebaked initrd over vm/initrd.img and
#      writes vm/.rebaked so the user knows this isn't a clean release artifact.
#
# Requires WSL with a Linux distro that has cpio, gzip, and bash.

param(
    [string]$BaseInitrd,
    [switch]$SkipBuild,
    [switch]$InstallToVm,
    [ValidateSet("amd64","arm64")]
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$rustTarget = if ($Arch -eq "amd64") { "x86_64-unknown-linux-musl" } else { "aarch64-unknown-linux-musl" }
$initBinPath = Join-Path $repoRoot "target\$rustTarget\release\tokimo-sandbox-init"
$tunPumpBinPath = Join-Path $repoRoot "target\$rustTarget\release\tokimo-tun-pump"

if (-not $BaseInitrd) {
    $BaseInitrd = Join-Path $repoRoot "vm\initrd.img"
}
if (-not (Test-Path $BaseInitrd)) {
    throw "Base initrd not found: $BaseInitrd. Run scripts/fetch-vm.ps1 first."
}

# Sanity: WSL available?
$wsl = Get-Command wsl -ErrorAction SilentlyContinue
if (-not $wsl) {
    throw "wsl.exe not found. Install WSL or run packaging/vm-image/scripts/rebake-initrd.sh from a Linux shell directly."
}

if (-not $SkipBuild) {
    Write-Host "==> cargo build --release --target $rustTarget --bins (init + tun-pump)" -ForegroundColor Cyan
    Push-Location $repoRoot
    try {
        & wsl bash -c "cd `"`$(wslpath -a '$($repoRoot -replace '\\','/')')`" && cargo build --release --target $rustTarget --bin tokimo-sandbox-init --bin tokimo-tun-pump"
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $initBinPath)) {
    throw "init binary not found after build: $initBinPath"
}
if (-not (Test-Path $tunPumpBinPath)) {
    throw "tun-pump binary not found after build: $tunPumpBinPath"
}

$outDir = Join-Path $repoRoot "target\vm-rebake"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outImg = Join-Path $outDir "initrd.img"

function To-Wsl([string]$p) {
    & wsl wslpath -a ($p -replace '\\','/')
}

$baseW = To-Wsl $BaseInitrd
$initW = To-Wsl $initBinPath
$tunW  = To-Wsl $tunPumpBinPath
$outW  = To-Wsl $outImg
$scriptW = To-Wsl (Join-Path $repoRoot "packaging\vm-image\scripts\rebake-initrd.sh")
$initShW = To-Wsl (Join-Path $repoRoot "packaging\vm-image\init.sh")
$extrasDir = Join-Path $repoRoot "packaging\vm-image\extras"
$extrasArgs = @()
if (Test-Path $extrasDir) {
    $extrasW = To-Wsl $extrasDir
    $extrasArgs = @("--extras-dir", $extrasW)
}

Write-Host "==> rebake-initrd.sh --base $baseW --init-bin $initW --tun-pump-bin $tunW --init-sh $initShW $($extrasArgs -join ' ') --out $outW" -ForegroundColor Cyan
& wsl bash $scriptW --base $baseW --init-bin $initW --tun-pump-bin $tunW --init-sh $initShW @extrasArgs --out $outW
if ($LASTEXITCODE -ne 0) { throw "rebake failed" }

Write-Host "==> rebaked initrd: $outImg ($([math]::Round((Get-Item $outImg).Length/1MB,2)) MB)" -ForegroundColor Green

if ($InstallToVm) {
    $target = Join-Path $repoRoot "vm\initrd.img"
    Copy-Item -Force $outImg $target
    Set-Content -Path (Join-Path $repoRoot "vm\.rebaked") -Value "rebaked from $($BaseInitrd) at $(Get-Date -Format o)"
    Write-Host "==> installed to $target (vm/.rebaked marker written)" -ForegroundColor Green
}
