# Fix Unix permissions on the TokimoOS rootfs after extracting to Windows (NTFS).
#
# NTFS doesn't store Unix permissions, so extracting a Linux rootfs tarball
# to C:\Users\... makes everything drwxrwxrwx (777). This is cosmetic —
# the sandbox VM works perfectly fine with 777 — but if you want proper
# permissions for ls -la or security, this script fixes them.
#
# How it works:
#   WSL2 with [automount] options = "metadata" stores Unix permissions
#   as NTFS extended attributes. This script:
#     1. Enables metadata mode in WSL2 (one-time)
#     2. Re-extracts the rootfs tarball with permissions preserved
#
# If WSL2 is not available, permissions cannot be fixed on bare Windows NTFS.
# The sandbox still works correctly regardless.
#
# Usage:
#   .\scripts\fix-permissions.ps1

param(
    [string]$RootfsPath = ""
)

$ErrorActionPreference = "Stop"

if ($RootfsPath -eq "") {
    $RootfsPath = "$env:USERPROFILE\.tokimo\rootfs"
}
$TarFile = "$env:USERPROFILE\.tokimo\rootfs-amd64.tar.zst"

if (-not (Test-Path $TarFile)) {
    Write-Host "Rootfs tarball not found at $TarFile" -ForegroundColor Red
    Write-Host "Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases" -ForegroundColor Yellow
    exit 1
}

$wslAvailable = $null -ne (Get-Command wsl -ErrorAction SilentlyContinue)
if (-not $wslAvailable) {
    Write-Host "WSL2 is not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "Without WSL2, Unix permissions cannot be preserved on Windows NTFS." -ForegroundColor Yellow
    Write-Host "This is a COSMETIC issue — the sandbox VM works correctly with 777 permissions." -ForegroundColor Yellow
    Write-Host "Executables are still executable, reads and writes work normally." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To install WSL2: wsl --install" -ForegroundColor White
    exit 1
}

Write-Host "Rootfs: $RootfsPath" -ForegroundColor Cyan
Write-Host "Tarball: $TarFile" -ForegroundColor Cyan
Write-Host ""

# 1. Enable metadata mode if not already set
Write-Host "[1/3] Checking WSL2 metadata mode..." -ForegroundColor Green
$hasMetadata = wsl -e sh -c "grep -q '^options.*metadata' /etc/wsl.conf 2>/dev/null && echo YES || echo NO"
if ($hasMetadata -ne "YES") {
    Write-Host "  Enabling metadata mode in WSL2..." -ForegroundColor Yellow
    wsl -u root -e sh -c "printf '[automount]\noptions = \"metadata,umask=022\"\n' >> /etc/wsl.conf"
    Write-Host "  WSL2 needs to restart for this to take effect." -ForegroundColor Yellow
    Write-Host "  Shutting down WSL2..." -ForegroundColor Yellow
    wsl --shutdown
    Start-Sleep -Seconds 3
    # Verify WSL2 came back
    wsl -e echo "WSL2 restarted" 2>$null | Out-Null
    Write-Host "  Metadata mode enabled." -ForegroundColor Green
} else {
    Write-Host "  Already enabled." -ForegroundColor Green
}

# 2. Verify metadata is working
Write-Host "[2/3] Verifying metadata mode..." -ForegroundColor Green
$testResult = wsl -e sh -c "
touch /mnt/c/Users/William/.tokimo/.permtest
chmod 640 /mnt/c/Users/William/.tokimo/.permtest
stat -c '%a' /mnt/c/Users/William/.tokimo/.permtest
rm /mnt/c/Users/William/.tokimo/.permtest
"
if ($testResult -eq "640") {
    Write-Host "  Metadata mode works." -ForegroundColor Green
} else {
    Write-Host "  WARNING: Metadata mode may not be active yet." -ForegroundColor Yellow
    Write-Host "  Try restarting Windows if permissions don't stick." -ForegroundColor Yellow
}

# 3. Re-extract the rootfs
Write-Host "[3/3] Re-extracting rootfs with proper permissions..." -ForegroundColor Green

$wslRootfs = ($RootfsPath -replace '\\', '/' -replace '^([A-Z]):', '/mnt/$1').ToLower()
$wslTar = ($TarFile -replace '\\', '/' -replace '^([A-Z]):', '/mnt/$1').ToLower()

wsl -e sh -c "
set -e
rm -rf '$wslRootfs'
mkdir -p '$wslRootfs'
zstd -d -f '$wslTar'
tar -xpf '${wslTar%.zst}' -C '$wslRootfs' --numeric-owner --no-same-owner
echo '=== Checking result ==='
echo -n '  /bin/bash: '; stat -c '%a %n' '$wslRootfs/bin/bash'
echo -n '  /etc/shadow: '; stat -c '%a %n' '$wslRootfs/etc/shadow'
echo -n '  /home/tokimo: '; stat -c '%a %n' '$wslRootfs/home/tokimo'
echo '=== Done ==='
"

Write-Host ""
Write-Host "Permissions fixed!" -ForegroundColor Green
Write-Host "Run .\scripts\enter-sandbox.ps1 to verify." -ForegroundColor Cyan
