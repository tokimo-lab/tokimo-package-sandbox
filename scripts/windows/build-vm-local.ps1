#!/usr/bin/env pwsh
# Build Tokimo VM artifacts on Windows using Docker, then install to vm/.
# Reuses CI's packaging/vm-base/build.sh for the full rootfs pipeline.
#
# Steps:
#   1) docker run rust:1.95-slim-bookworm  → builds guest binaries (musl static)
#   2) packaging/vm-base/build.sh          → builds vmlinuz + initrd + rootfs
#   3) Convert rootfs to vhdx (Windows-specific)
#   4) Copy artifacts to vm/
#
# Output: <repo>/vm/{vmlinuz, initrd.img, rootfs.vhdx}

param(
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",
    [switch]$Force,
    [switch]$SkipInitBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$vmDir = Join-Path $repoRoot "vm"
$pkgDir = Join-Path $repoRoot "packaging/vm-local"
$vmBaseDir = Join-Path $repoRoot "packaging/vm-base"

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) { throw "docker not found on PATH" }

New-Item -ItemType Directory -Force -Path $vmDir | Out-Null

if ($Force -and (Test-Path "$vmDir/vmlinuz")) {
    Remove-Item -Force "$vmDir/vmlinuz","$vmDir/initrd.img","$vmDir/rootfs.vhdx" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$vmDir/rootfs" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 1) Guest binaries (musl static, in Docker)
# ---------------------------------------------------------------------------
$guestBins = @("tokimo-sandbox-init", "tokimo-tun-pump", "tokimo-sandbox-fuse")
$binsExist = ($guestBins | ForEach-Object { Test-Path (Join-Path $pkgDir $_) }) -notcontains $false

if (-not $SkipInitBuild) {
    Write-Host "==> [1/3] Building guest binaries ($Arch, musl static, in rust:1.95-slim-bookworm)" -ForegroundColor Cyan
    $repoMount = $repoRoot -replace '\\','/'
    $linkerVar = if ($Arch -eq "arm64") { "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc" } else { "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc" }
    docker run --rm --platform "linux/$Arch" `
        -v "${repoMount}:/src" `
        -e "CARGO_TARGET_DIR=/tmp/target" `
        -e $linkerVar `
        -w /src `
        rust:1.95-slim-bookworm bash /src/packaging/vm-local/build-init-bin.sh $Arch
    if ($LASTEXITCODE -ne 0) { throw "Guest binary build failed" }
} else {
    if (-not $binsExist) { throw "Guest binaries not found in $pkgDir (drop -SkipInitBuild)" }
}

# ---------------------------------------------------------------------------
# 2) Full VM build using CI script
# ---------------------------------------------------------------------------
Write-Host "==> [2/3] Building VM artifacts (packaging/vm-base/build.sh $Arch)" -ForegroundColor Cyan
$env:TOKIMO_INIT_BIN = Join-Path $pkgDir "tokimo-sandbox-init"
$env:TOKIMO_TUN_PUMP_BIN = Join-Path $pkgDir "tokimo-tun-pump"
$env:TOKIMO_FUSE_BIN = Join-Path $pkgDir "tokimo-sandbox-fuse"
& bash (Join-Path $vmBaseDir "build.sh") $Arch
if ($LASTEXITCODE -ne 0) { throw "VM build failed" }

# ---------------------------------------------------------------------------
# 3) Convert rootfs to vhdx + copy to vm/
# ---------------------------------------------------------------------------
$outputDir = Join-Path $vmBaseDir "tokimo-os-$Arch"
Write-Host "==> [3/3] Converting rootfs to vhdx + copying to $vmDir" -ForegroundColor Cyan

$rootfsDir = Join-Path $outputDir "rootfs"
$rootfsSizeMB = [math]::Floor((Get-ChildItem $rootfsDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB)
$imgSizeMB = $rootfsSizeMB + 256

Write-Host "    rootfs: ${rootfsSizeMB}MB, image: ${imgSizeMB}MB"

# Create raw ext4 image from rootfs directory, then convert to vhdx
# This needs to run inside a docker container with qemu-utils + e2fsprogs
$outputMount = $outputDir -replace '\\','/'
$vmMount = $vmDir -replace '\\','/'
docker run --rm --platform "linux/$Arch" `
    -v "${outputMount}:/input:ro" `
    -v "${vmMount}:/out" `
    debian:13 bash -c "apt-get update -qq && apt-get install -y -qq e2fsprogs qemu-utils >/dev/null 2>&1 && qemu-img create -f raw /tmp/rootfs.img ${imgSizeMB}M >/dev/null && mkfs.ext4 -F -L tokimo-rootfs -d /input/rootfs /tmp/rootfs.img >/dev/null && qemu-img convert -f raw -O vhdx -o subformat=dynamic /tmp/rootfs.img /out/rootfs.vhdx"
if ($LASTEXITCODE -ne 0) { throw "rootfs vhdx conversion failed" }

Copy-Item (Join-Path $outputDir "vmlinuz") $vmDir -Force
Copy-Item (Join-Path $outputDir "initrd.img") $vmDir -Force

Write-Host ""
Write-Host "==> All artifacts ready:" -ForegroundColor Green
Get-ChildItem $vmDir | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB, 2)}} | Format-Table -AutoSize
