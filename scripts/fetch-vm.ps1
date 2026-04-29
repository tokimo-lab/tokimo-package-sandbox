#!/usr/bin/env pwsh
# Download VM artifacts (kernel + initrd + rootfs.vhdx) from
# tokimo-package-rootfs GitHub releases into <repo>/vm/.
#
# Usage:
#   pwsh scripts/fetch-vm.ps1                  # latest release, amd64
#   pwsh scripts/fetch-vm.ps1 -Tag v1.6.0      # specific tag
#   pwsh scripts/fetch-vm.ps1 -Arch arm64      # arm64 (less tested)
#
# Layout produced (all read-only at runtime):
#   vm/vmlinuz        — Linux kernel
#   vm/initrd.img     — initramfs (busybox + Hyper-V modules + tokimo-sandbox-init)
#   vm/rootfs.vhdx    — ext4 VHDX rootfs

param(
    [string]$Tag = "latest",
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$vmDir = Join-Path $repoRoot "vm"
$work  = Join-Path $env:TEMP "tokimo-fetch-vm"

$repo = "tokimo-lab/tokimo-package-rootfs"
# New artifact naming (v1.7.0+): tokimo-linux-<component>-<arch>.<ext>
# arch in the artifact filename is x86_64 / arm64.
$archName = if ($Arch -eq "amd64") { "x86_64" } else { "arm64" }
$kernelAsset = "tokimo-linux-kernel-$archName.tar.zst"
$vhdxAsset   = "tokimo-linux-rootfs-$archName.vhdx.zip"

if ($Tag -eq "latest") {
    $base = "https://github.com/$repo/releases/latest/download"
} else {
    $base = "https://github.com/$repo/releases/download/$Tag"
}

New-Item -ItemType Directory -Force -Path $vmDir, $work | Out-Null

$kernel = Join-Path $vmDir "vmlinuz"
$initrd = Join-Path $vmDir "initrd.img"
$rootfs = Join-Path $vmDir "rootfs.vhdx"

if (-not $Force -and (Test-Path $kernel) -and (Test-Path $initrd) -and (Test-Path $rootfs)) {
    Write-Host "vm/ already populated. Use -Force to re-download." -ForegroundColor Yellow
    Get-ChildItem $vmDir | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB, 2)}}
    return
}

function Download($url, $out) {
    Write-Host "==> $url" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
}

# 1) kernel bundle (vmlinuz + initrd.img, zstd-compressed tarball)
$bootZst = Join-Path $work $kernelAsset
$bootTar = $bootZst -replace '\.zst$', ''
Download "$base/$kernelAsset" $bootZst

# Need zstd. Try ambient, then fall back to MSYS / scoop / chocolatey.
$zstd = Get-Command zstd -ErrorAction SilentlyContinue
if (-not $zstd) {
    throw "zstd.exe not found. Install with: winget install Facebook.Zstd  (or: choco install zstandard)"
}
& zstd -d -f $bootZst -o $bootTar
if ($LASTEXITCODE -ne 0) { throw "zstd decompression failed" }

# Extract vmlinuz + initrd.img from the tar.
$tar = Get-Command tar -ErrorAction SilentlyContinue
if (-not $tar) {
    throw "tar.exe not found. Windows 10+ ships bsdtar in System32; check your PATH."
}
& tar -xf $bootTar -C $vmDir vmlinuz initrd.img
if ($LASTEXITCODE -ne 0) { throw "tar extraction failed" }

# 2) rootfs VHDX
$vhdxZip = Join-Path $work $vhdxAsset
Download "$base/$vhdxAsset" $vhdxZip
Expand-Archive -Path $vhdxZip -DestinationPath $work -Force
Move-Item -Force (Join-Path $work "rootfs.vhdx") $rootfs

Remove-Item -Recurse -Force $work

Write-Host ""
Write-Host "Done. vm/ contents:" -ForegroundColor Green
Get-ChildItem $vmDir | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB, 2)}} | Format-Table -AutoSize
