# Enter the TokimoOS sandbox interactively.
#
# The HCS VM is single-shot (boot -> run command -> poweroff), so we can't
# attach a tty to it directly. Instead, this script uses WSL2 to chroot
# into the same rootfs that the VM uses, giving you an interactive shell
# inside the exact same filesystem.
#
# Usage:
#   .\scripts\enter-sandbox.ps1
#
# Or to run a single command and exit:
#   .\scripts\enter-sandbox.ps1 -Command "node -e 'console.log(1+2)'"

param(
    [string]$Command = "",
    [string]$RootfsPath = ""
)

$ErrorActionPreference = "Stop"

# --- Find rootfs ---
if ($RootfsPath -eq "") {
    $RootfsPath = "$env:USERPROFILE\.tokimo\rootfs"
}
if (-not (Test-Path "$RootfsPath\usr")) {
    Write-Host "Rootfs not found at $RootfsPath" -ForegroundColor Red
    Write-Host "Download: https://github.com/tokimo-lab/tokimo-package-rootfs/releases" -ForegroundColor Yellow
    exit 1
}

Write-Host "Rootfs: $RootfsPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "=== Filesystem layout ===" -ForegroundColor Green
Write-Host ""

# --- Show what's inside ---
$items = @(
    @{Label="OS";       Cmd={ Get-Content "$RootfsPath\etc\os-release" | Select-String "PRETTY_NAME" }},
    @{Label="Kernel";   Cmd={ Get-ChildItem "$env:USERPROFILE\.tokimo\kernel\vmlinuz" -ErrorAction SilentlyContinue | Select Name,Length }},
    @{Label="Initrd";   Cmd={ Get-ChildItem "$env:USERPROFILE\.tokimo\initrd.img" -ErrorAction SilentlyContinue | Select Name,Length }},
    @{Label="Shells";   Cmd={ Get-ChildItem "$RootfsPath\bin" -Name | Select-String "bash|sh" }},
    @{Label="Node.js";  Cmd={ Get-ChildItem "$RootfsPath\usr\bin\node" -ErrorAction SilentlyContinue; Get-ChildItem "$RootfsPath\home\tokimo\bin\pnpm*" -ErrorAction SilentlyContinue }},
    @{Label="Python";   Cmd={ Get-ChildItem "$RootfsPath\usr\bin\python*" -Name }},
    @{Label="Lua";      Cmd={ Get-ChildItem "$RootfsPath\usr\bin\lua*" -Name }},
    @{Label="Pandoc";   Cmd={ Get-ChildItem "$RootfsPath\usr\bin\pandoc" -ErrorAction SilentlyContinue }},
    @{Label="FFmpeg";   Cmd={ Get-ChildItem "$RootfsPath\usr\bin\ffmpeg" -ErrorAction SilentlyContinue }},
    @{Label="LibreOffice"; Cmd={ Get-ChildItem "$RootfsPath\usr\lib\libreoffice\program\soffice.bin" -ErrorAction SilentlyContinue }},
    @{Label="Git";      Cmd={ Get-ChildItem "$RootfsPath\usr\bin\git" -ErrorAction SilentlyContinue }},
    @{Label="Users";    Cmd={ Get-ChildItem "$RootfsPath\home" -Name }},
    @{Label="Pkgs";     Cmd={ Get-ChildItem "$RootfsPath\home\tokimo\python_packages" -Directory -Name 2>$null | Select-Object -First 15 }},
    @{Label="TotalSize";Cmd={ "{0:N0} MB" -f ((Get-ChildItem $RootfsPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB) }}
)

foreach ($item in $items) {
    Write-Host "  $($item.Label): " -NoNewline -ForegroundColor Yellow
    $result = & $item.Cmd 2>$null
    if ($result) {
        if ($result -is [array]) { Write-Host ($result -join ", ") } else { Write-Host $result }
    } else {
        Write-Host "(not found)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "===================================" -ForegroundColor Green
Write-Host ""

# --- Try WSL2 interactive mode ---
$wslAvailable = $null -ne (Get-Command wsl -ErrorAction SilentlyContinue)

if (-not $wslAvailable) {
    Write-Host "WSL2 not installed. Install it to get an interactive shell:" -ForegroundColor Yellow
    Write-Host "  wsl --install" -ForegroundColor White
    Write-Host ""
    Write-Host "You can still browse the rootfs in File Explorer:" -ForegroundColor White
    Write-Host "  start $RootfsPath" -ForegroundColor White
    exit 0
}

# Translate Windows path to WSL path
$wslRootfs = ($RootfsPath -replace '\\', '/' -replace '^([A-Z]):', '/mnt/$1').ToLower()
$wslHome = "/home/tokimo"

if ($Command -ne "") {
    # One-shot command mode
    Write-Host "Running inside sandbox:" -ForegroundColor Cyan
    Write-Host "  > $Command" -ForegroundColor White
    Write-Host ""
    wsl -e sudo /usr/sbin/chroot "$wslRootfs" /bin/bash -lc "$Command"
} else {
    # Interactive shell mode
    Write-Host "Entering interactive sandbox shell..." -ForegroundColor Cyan
    Write-Host "  Rootfs: $RootfsPath (inside VM: /)"
    Write-Host "  User:   tokimo (uid 1000)"
    Write-Host "  Home:   /home/tokimo"
    Write-Host ""
    Write-Host "  Type 'exit' or press Ctrl+D to leave." -ForegroundColor DarkGray
    Write-Host ""

    # The rootfs already has .bashrc/.bash_profile that set up env and PS1.
    wsl -e sudo /usr/sbin/chroot "$wslRootfs" /bin/bash --login
}

Write-Host ""
Write-Host "Session ended." -ForegroundColor Green
