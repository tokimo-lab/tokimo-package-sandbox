#!/usr/bin/env pwsh
# Build minimal Tokimo VM artifacts entirely on the local machine using Docker.
# This bypasses the sister CI / heavy debian rootfs and produces only what
# Windows session tests need: bash + coreutils + busybox.
#
# Steps:
#   1) docker run rust:1.95-slim-bookworm  → builds tokimo-sandbox-init (musl static)
#   2) docker run debian:13                → builds vmlinuz + initrd + rootfs.vhdx
#
# Output: <repo>/vm/{vmlinuz, initrd.img, rootfs.vhdx}

param(
    [switch]$Force,
    [switch]$SkipInitBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$vmDir = Join-Path $repoRoot "vm"
$pkgDir = Join-Path $repoRoot "packaging/vm-local"

# Detect docker (prefer docker.exe; fall back to docker on PATH).
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) { throw "docker not found on PATH" }

New-Item -ItemType Directory -Force -Path $vmDir | Out-Null

if ($Force -and (Test-Path "$vmDir/vmlinuz")) {
    Remove-Item -Force "$vmDir/vmlinuz","$vmDir/initrd.img","$vmDir/rootfs.vhdx" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 1) tokimo-sandbox-init (musl static)
# ---------------------------------------------------------------------------
$initBin = Join-Path $pkgDir "tokimo-sandbox-init"
if (-not $SkipInitBuild) {
    Write-Host "==> [1/2] Building tokimo-sandbox-init (musl static, in rust:1.95-slim-bookworm)" -ForegroundColor Cyan
    # Convert Windows path to docker-compatible (forward slashes, drive lower).
    $repoMount = $repoRoot -replace '\\','/'
    docker run --rm --platform linux/amd64 `
        -v "${repoMount}:/src" -w /src `
        rust:1.95-slim-bookworm bash /src/packaging/vm-local/build-init-bin.sh
    if ($LASTEXITCODE -ne 0) { throw "tokimo-sandbox-init build failed" }
} else {
    if (-not (Test-Path $initBin)) { throw "tokimo-sandbox-init not found at $initBin (drop -SkipInitBuild)" }
}

# ---------------------------------------------------------------------------
# 2) vmlinuz + initrd.img + rootfs.vhdx
# ---------------------------------------------------------------------------
Write-Host "==> [2/2] Building kernel + initrd + rootfs.vhdx (in debian:13)" -ForegroundColor Cyan
$pkgMount = $pkgDir -replace '\\','/'
$vmMount  = $vmDir  -replace '\\','/'

docker run --rm --platform linux/amd64 `
    -v "${pkgMount}:/work:ro" `
    -v "${vmMount}:/out" `
    debian:13 bash /work/build-in-docker.sh
if ($LASTEXITCODE -ne 0) { throw "VM build failed" }

Write-Host ""
Write-Host "==> All artifacts ready:" -ForegroundColor Green
Get-ChildItem $vmDir | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB, 2)}} | Format-Table -AutoSize
