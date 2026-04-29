<#
.SYNOPSIS
    Download and extract Windows sandbox artifacts (kernel, initrd, rootfs.vhdx).

.DESCRIPTION
    Downloads tokimo-os-amd64.tar.zst (kernel + initrd) and rootfs-amd64.vhdx.zip
    from GitHub releases and places them in %USERPROFILE%\.tokimo\.

    After running this script, the test suite will find the artifacts
    automatically. Set TOKIMO_KERNEL, TOKIMO_INITRD, or TOKIMO_ROOTFS_VHDX
    environment variables to override the default paths.

.EXAMPLE
    pwsh -ExecutionPolicy Bypass -File .\scripts\setup-windows-artifacts.ps1
#>

param(
    [string]$Version = "v1.4.2",
    [string]$Arch = "amd64",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repo = "https://github.com/tokimo-lab/tokimo-package-rootfs/releases/download/$Version"

if ($TargetDir -eq "") {
    $TargetDir = "$env:USERPROFILE\.tokimo"
}

Write-Host "=== Tokimo Windows Sandbox Artifact Setup ===" -ForegroundColor Cyan
Write-Host "  Version : $Version"
Write-Host "  Arch    : $Arch"
Write-Host "  Target  : $TargetDir"
Write-Host ""

# Create directories.
$null = New-Item -ItemType Directory -Force -Path "$TargetDir\kernel"

# ---------------------------------------------------------------------------
# 1. Download and extract kernel + initrd
# ---------------------------------------------------------------------------

$osArchive = "$env:TEMP\tokimo-os-$Arch.tar.zst"
$osUrl = "$repo/tokimo-os-$Arch.tar.zst"

Write-Host "[1/2] Downloading kernel + initrd..." -ForegroundColor Yellow
Write-Host "  $osUrl" -ForegroundColor DarkGray

curl.exe -sL -o "$osArchive" "$osUrl"
if (-not (Test-Path $osArchive)) {
    Write-Host "ERROR: Failed to download tokimo-os-$Arch.tar.zst" -ForegroundColor Red
    exit 1
}

Write-Host "  Extracting..." -ForegroundColor DarkGray

# Try tar --zstd first (available on Windows 10 21H2+).
$extracted = $false
$tarZstdOk = tar --zstd -xf "$osArchive" -C "$TargetDir" 2>&1
if ($LASTEXITCODE -eq 0) {
    $extracted = $true
} else {
    # Fallback: try piping through zstd if installed.
    $hasZstd = Get-Command zstd -ErrorAction SilentlyContinue
    if ($hasZstd) {
        zstd -d -c "$osArchive" | tar -xf - -C "$TargetDir"
        if ($LASTEXITCODE -eq 0) { $extracted = $true }
    }
}

if (-not $extracted) {
    Write-Host "ERROR: Could not extract .tar.zst archive." -ForegroundColor Red
    Write-Host "  Install zstd (winget install zstandard) or use a newer Windows build with tar --zstd support." -ForegroundColor Yellow
    Remove-Item "$osArchive" -Force -ErrorAction SilentlyContinue
    exit 1
}

Remove-Item "$osArchive" -Force -ErrorAction SilentlyContinue

# Verify the extracted files.
$kernel = "$TargetDir\kernel\vmlinuz"
$initrd = "$TargetDir\initrd.img"

# The tarball might have files at root or under a subdirectory — find them.
if (-not (Test-Path $kernel)) {
    $found = Get-ChildItem "$TargetDir" -Recurse -Filter "vmlinuz" -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $null = New-Item -ItemType Directory -Force -Path "$TargetDir\kernel"
        Move-Item $found.FullName $kernel -Force
    }
}
if (-not (Test-Path $initrd)) {
    $found = Get-ChildItem "$TargetDir" -Recurse -Filter "initrd.img" -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Move-Item $found.FullName $initrd -Force
    }
}

if (Test-Path $kernel) {
    $size = (Get-Item $kernel).Length
    Write-Host "  Kernel : $kernel ($('{0:N1}' -f ($size / 1MB)) MB)" -ForegroundColor Green
} else {
    Write-Host "  WARNING: kernel/vmlinuz not found after extraction." -ForegroundColor Red
}

if (Test-Path $initrd) {
    $size = (Get-Item $initrd).Length
    Write-Host "  Initrd : $initrd ($('{0:N1}' -f ($size / 1MB)) MB)" -ForegroundColor Green
} else {
    Write-Host "  WARNING: initrd.img not found after extraction." -ForegroundColor Red
}

# Clean up any leftover subdirectories from the tarball.
Get-ChildItem "$TargetDir" -Directory | Where-Object { $_.Name -notin @("kernel", "rootfs") } | ForEach-Object {
    Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 2. Download and extract VHDX
# ---------------------------------------------------------------------------

$vhdxZip = "$env:TEMP\rootfs-$Arch.vhdx.zip"
$vhdxUrl = "$repo/rootfs-$Arch.vhdx.zip"
$vhdxTarget = "$TargetDir\rootfs.vhdx"

if (Test-Path $vhdxTarget) {
    Write-Host ""
    Write-Host "[2/2] VHDX already present: $vhdxTarget" -ForegroundColor Green
    Write-Host ""
    Write-Host "=== Setup complete ===" -ForegroundColor Cyan
    exit 0
}

Write-Host ""
Write-Host "[2/2] Downloading rootfs VHDX..." -ForegroundColor Yellow
Write-Host "  $vhdxUrl" -ForegroundColor DarkGray

curl.exe -sL -o "$vhdxZip" "$vhdxUrl"
if (-not (Test-Path $vhdxZip)) {
    Write-Host "ERROR: Failed to download rootfs-$Arch.vhdx.zip" -ForegroundColor Red
    exit 1
}

Write-Host "  Extracting..." -ForegroundColor DarkGray

# Extract the zip.
$extractDir = "$env:TEMP\tokimo-vhdx-extract"
Remove-Item "$extractDir" -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -Path "$vhdxZip" -DestinationPath "$extractDir" -Force

# Find the .vhdx file.
$vhdxFile = Get-ChildItem "$extractDir" -Recurse -Filter "*.vhdx" -File -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $vhdxFile) {
    Write-Host "ERROR: No .vhdx file found in archive." -ForegroundColor Red
    Remove-Item "$extractDir" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$vhdxZip" -Force -ErrorAction SilentlyContinue
    exit 1
}

Move-Item $vhdxFile.FullName $vhdxTarget -Force
Remove-Item "$extractDir" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$vhdxZip" -Force -ErrorAction SilentlyContinue

$size = (Get-Item $vhdxTarget).Length
Write-Host "  VHDX   : $vhdxTarget ($('{0:N1}' -f ($size / 1GB)) GB)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Artifacts installed to $TargetDir"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Build:  cargo build --bin tokimo-sandbox-svc"
Write-Host "  2. Run service (as admin):  .\target\debug\tokimo-sandbox-svc.exe --console"
Write-Host "  3. Test:   cargo test --test windows_run -- --nocapture"
Write-Host ""
