#!/usr/bin/env pwsh
# rebake-initrd.ps1 — local dev convenience for rebuilding .vm/base/initrd.img
# on Windows. Thin wrapper that delegates to scripts/linux/rebake-initrd.sh
# inside WSL — that script in turn cross-compiles the three guest musl
# binaries and calls packaging/vm/scripts/rebake-initrd.sh to swap them
# (plus init.sh) into a copy of the base initrd.
#
# Pipeline: see scripts/linux/rebake-initrd.sh for the canonical flow.
#
# Usage:
#   pwsh scripts/windows/rebake-initrd.ps1                  # full rebake
#   pwsh scripts/windows/rebake-initrd.ps1 -SkipBuild       # use existing build
#   pwsh scripts/windows/rebake-initrd.ps1 -InstallToVm     # overwrite .vm/base/initrd.img
#   pwsh scripts/windows/rebake-initrd.ps1 -Arch arm64      # cross-target
#   pwsh scripts/windows/rebake-initrd.ps1 -BaseInitrd path # custom base
#
# Requires WSL with a Linux distro that has cargo (or rustup), bash, cpio,
# gzip and (for the vermagic self-check) kmod's modinfo.

param(
    [string]$BaseInitrd,
    [switch]$SkipBuild,
    [switch]$InstallToVm,
    [ValidateSet("amd64","arm64")]
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$wsl = Get-Command wsl -ErrorAction SilentlyContinue
if (-not $wsl) {
    throw "wsl.exe not found. Install WSL or run scripts/linux/rebake-initrd.sh from a Linux shell directly."
}

function To-Wsl([string]$p) {
    return (& wsl wslpath -a ($p -replace '\\','/')).Trim()
}

$repoRootW = To-Wsl $repoRoot
$scriptW = "$repoRootW/scripts/linux/rebake-initrd.sh"

$wslArgs = @("--arch", $Arch)
if ($SkipBuild)    { $wslArgs += "--skip-build" }
if ($InstallToVm)  { $wslArgs += "--install-to-vm" }
if ($BaseInitrd) {
    $wslArgs += "--base"
    $wslArgs += (To-Wsl $BaseInitrd)
}

Write-Host "==> wsl bash $scriptW $($wslArgs -join ' ')" -ForegroundColor Cyan
& wsl bash $scriptW @wslArgs
if ($LASTEXITCODE -ne 0) { throw "rebake failed (exit $LASTEXITCODE)" }
