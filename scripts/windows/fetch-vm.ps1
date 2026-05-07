#!/usr/bin/env pwsh
# Download VM artifacts (kernel + initrd + rootfs.vhdx) from
# tokimo-package-sandbox GitHub releases into <repo>/.vm/base/.
#
# Kernel and rootfs are published under independent tag namespaces:
#   vm-kernel-*  → vmlinuz + initrd.img (tokimo guest bins baked in)
#   vm-rootfs-*  → rootfs.vhdx.zip (Debian, no tokimo bins)
#
# Usage:
#   pwsh scripts/windows/fetch-vm.ps1                         # latest of each
#   pwsh scripts/windows/fetch-vm.ps1 -KernelTag vm-kernel-1.0.0
#   pwsh scripts/windows/fetch-vm.ps1 -RootfsTag vm-rootfs-1.0.0
#   pwsh scripts/windows/fetch-vm.ps1 -Arch arm64
#
# Layout produced (all read-only at runtime):
#   .vm/base/vmlinuz        — Linux kernel (from vm-kernel-*)
#   .vm/base/initrd.img     — initramfs incl. tokimo-sandbox-init/fuse/tun-pump (from vm-kernel-*)
#   .vm/base/rootfs.vhdx    — ext4 VHDX rootfs, pure Debian (from vm-rootfs-*)

param(
    [string]$KernelTag = "latest",
    [string]$RootfsTag = "latest",
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$vmDir = Join-Path $repoRoot ".vm/base"
$work  = Join-Path $env:TEMP "tokimo-fetch-vm"

$repo = "tokimo-lab/tokimo-package-sandbox"
$archName = if ($Arch -eq "amd64") { "x86_64" } else { "arm64" }
$kernelAsset = "tokimo-linux-kernel-$archName.tar.zst"
$vhdxAsset   = "tokimo-linux-rootfs-$archName.vhdx.zip"

function Resolve-Base($tag, $prefix) {
    if ($tag -eq "latest") {
        # GitHub /releases/latest only returns the single newest release across
        # ALL tags; with two independent prefixes we have to query the API to
        # find the most recent matching one.
        $resp = Invoke-RestMethod -UseBasicParsing `
            -Uri "https://api.github.com/repos/$repo/releases?per_page=30"
        $hit = $resp | Where-Object { $_.tag_name -like "$prefix*" } | Select-Object -First 1
        if (-not $hit) { throw "no release found for tag prefix $prefix*" }
        return "https://github.com/$repo/releases/download/$($hit.tag_name)"
    }
    return "https://github.com/$repo/releases/download/$tag"
}

$kernelBase = Resolve-Base $KernelTag "vm-kernel-"
$rootfsBase = Resolve-Base $RootfsTag "vm-rootfs-"

New-Item -ItemType Directory -Force -Path $vmDir, $work | Out-Null

$kernel = Join-Path $vmDir "vmlinuz"
$initrd = Join-Path $vmDir "initrd.img"
$rootfs = Join-Path $vmDir "rootfs.vhdx"

if (-not $Force -and (Test-Path $kernel) -and (Test-Path $initrd) -and (Test-Path $rootfs)) {
    Write-Host ".vm/base already populated. Use -Force to re-download." -ForegroundColor Yellow
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
Download "$kernelBase/$kernelAsset" $bootZst

$zstd = Get-Command zstd -ErrorAction SilentlyContinue
if (-not $zstd) {
    throw "zstd.exe not found. Install with: winget install Facebook.Zstd  (or: choco install zstandard)"
}
& zstd -d -f $bootZst -o $bootTar
if ($LASTEXITCODE -ne 0) { throw "zstd decompression failed" }

$tar = Get-Command tar -ErrorAction SilentlyContinue
if (-not $tar) {
    throw "tar.exe not found. Windows 10+ ships bsdtar in System32; check your PATH."
}
& tar -xf $bootTar -C $vmDir vmlinuz initrd.img
if ($LASTEXITCODE -ne 0) { throw "tar extraction failed" }

# 2) rootfs VHDX
$vhdxZip = Join-Path $work $vhdxAsset
Download "$rootfsBase/$vhdxAsset" $vhdxZip
Expand-Archive -Path $vhdxZip -DestinationPath $work -Force
Move-Item -Force (Join-Path $work "rootfs.vhdx") $rootfs

Remove-Item -Recurse -Force $work

Write-Host ""
Write-Host "Done. .vm/base contents:" -ForegroundColor Green
Get-ChildItem $vmDir | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB, 2)}} | Format-Table -AutoSize

