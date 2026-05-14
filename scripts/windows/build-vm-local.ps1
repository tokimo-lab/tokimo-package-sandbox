#!/usr/bin/env pwsh
# Build Tokimo VM artifacts on Windows using Docker, then install to .vm/base/.
# Reuses CI's packaging/vm-base/build.sh for the full rootfs pipeline.
#
# Steps:
#   1) docker run rust:1.95-slim-bookworm  → builds guest binaries (musl static)
#   2) packaging/vm-base/build.sh          → builds vmlinuz + initrd + rootfs
#   3) Convert rootfs to vhdx (Windows-specific)
#   4) Copy artifacts to .vm/base/
#
# Output: <repo>/.vm/base/{vmlinuz, initrd.img, rootfs.vhdx}

param(
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",
    [switch]$Force,
    [switch]$SkipInitBuild
)

$ErrorActionPreference = "Stop"
# $PSScriptRoot = .../packages/tokimo-package-sandbox/scripts/windows
# So $repoRoot here is actually the sandbox package root, not the workspace
# repo root. That's intentional: svc reads .vm/base relative to its cwd
# (set to the sandbox package by tests), so we output to <sandbox>/.vm/base/.
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$vmDir = Join-Path $repoRoot ".vm/base"
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
# 2) Full VM build using CI script. We invoke via WSL bash with absolute
#    /mnt/<drive>/ paths and TOKIMO_SKIP_LOCAL_EXTRACT=1 so the host-side
#    rootfs extraction (which needs root) is bypassed; Step 3 below does
#    the rootfs.tar -> vhdx conversion inside docker instead.
# ---------------------------------------------------------------------------
Write-Host "==> [2/3] Building VM artifacts (packaging/vm-base/build.sh $Arch via WSL)" -ForegroundColor Cyan
function ConvertTo-WslPath([string]$winPath) {
    $p = $winPath -replace '\\','/'
    if ($p -match '^([A-Za-z]):/(.*)$') {
        return "/mnt/$($Matches[1].ToLower())/$($Matches[2])"
    }
    return $p
}
$wslVmBase  = ConvertTo-WslPath $vmBaseDir
$wslInitBin = ConvertTo-WslPath (Join-Path $pkgDir "tokimo-sandbox-init")
$wslTunBin  = ConvertTo-WslPath (Join-Path $pkgDir "tokimo-tun-pump")
$wslFuseBin = ConvertTo-WslPath (Join-Path $pkgDir "tokimo-sandbox-fuse")
$bashCmd = "cd $wslVmBase && TOKIMO_SKIP_LOCAL_EXTRACT=1 TOKIMO_INIT_BIN=$wslInitBin TOKIMO_TUN_PUMP_BIN=$wslTunBin TOKIMO_FUSE_BIN=$wslFuseBin bash build.sh $Arch"
& bash -c $bashCmd
if ($LASTEXITCODE -ne 0) { throw "VM build failed" }

# ---------------------------------------------------------------------------
# 3) Convert rootfs.tar to vhdx + copy to .vm/base/
#    Everything happens inside docker so we don't need root on the host
#    (host extraction in build.sh would need passwordless sudo, which WSL
#    doesn't provide by default).
# ---------------------------------------------------------------------------
$outputDir = Join-Path $vmBaseDir "tokimo-os-$Arch"
$rootfsTar = Join-Path $vmBaseDir "rootfs.tar"
if (-not (Test-Path $rootfsTar)) { throw "rootfs.tar not found at $rootfsTar" }
Write-Host "==> [3/3] Converting rootfs.tar to vhdx + copying to $vmDir" -ForegroundColor Cyan

$tarSizeMB = [math]::Floor((Get-Item $rootfsTar).Length / 1MB)
# Virtual disk size for rootfs.vhdx (dynamic VHDX, so host file only
# grows as the guest writes). 256 GB gives plenty of headroom for apt /
# pip / model caches; mkfs.ext4 metadata occupies ~3 GB of that. Users
# can later grow it online with `Resize-VHD` + guest `resize2fs /dev/sda`
# (ext4 was created without 64bit feature → 16 TiB single-volume cap).
$imgSizeMB = 256 * 1024
Write-Host "    rootfs.tar: ${tarSizeMB}MB, image: ${imgSizeMB}MB (256 GB dynamic VHDX)"

$vmBaseMount = $vmBaseDir -replace '\\','/'
$vmMount = $vmDir -replace '\\','/'
New-Item -ItemType Directory -Force -Path $vmDir | Out-Null

docker run --rm --platform "linux/$Arch" `
    -v "${vmBaseMount}:/input:ro" `
    -v "${vmMount}:/out" `
    -v "${vmBaseMount}/mkvhdx.sh:/mkvhdx.sh:ro" `
    -e "IMG_MB=$imgSizeMB" `
    debian:13 bash /mkvhdx.sh
if ($LASTEXITCODE -ne 0) { throw "rootfs vhdx conversion failed" }

# vmlinuz + initrd are direct outputs of build.sh under tokimo-os-{arch}/
if (-not (Test-Path (Join-Path $outputDir "vmlinuz"))) {
    throw "vmlinuz not found at $outputDir/vmlinuz (build.sh did not run, or failed)"
}
Copy-Item (Join-Path $outputDir "vmlinuz") $vmDir -Force
Copy-Item (Join-Path $outputDir "initrd.img") $vmDir -Force

Write-Host ""
Write-Host "==> All artifacts ready:" -ForegroundColor Green
Get-ChildItem $vmDir | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB, 2)}} | Format-Table -AutoSize
