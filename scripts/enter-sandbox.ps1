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

# --- Enter the sandbox ---
$wslAvailable = $null -ne (Get-Command wsl -ErrorAction SilentlyContinue)

if (-not $wslAvailable) {
    Write-Host "WSL2 not installed." -ForegroundColor Yellow
    Write-Host "  You can still browse the rootfs: start $RootfsPath" -ForegroundColor White
    Write-Host "  Or use the service: cargo run --example hv_smoke" -ForegroundColor White
    exit 0
}

# Translate Windows path to WSL path (C:\Users\... -> /mnt/c/Users/...)
$wslRootfs = ($RootfsPath -replace '\\', '/' -replace '^([A-Z]):', '/mnt/$1').ToLower()

# Check if bubblewrap is available (no sudo needed)
$hasBwrap = (wsl -e which bwrap 2>$null) -ne ""

if (-not $hasBwrap) {
    Write-Host "bubblewrap not installed in WSL2." -ForegroundColor Yellow
    Write-Host "  Run: wsl -e sudo apt install -y bubblewrap" -ForegroundColor White
    Write-Host "  Then re-run this script." -ForegroundColor White
    exit 1
}

# Full namespace isolation: --unshare-all gives user+mount+PID+IPC+UTS+cgroup+net,
# then --share-net opts back in so the sandbox has internet access for debugging.
$bwrapFlags = "--bind '$wslRootfs' / --bind /tmp /tmp --proc /proc --dev /dev --unshare-all --share-net --uid 1000 --gid 1000 --hostname TokimoOS"

if ($Command -ne "") {
    Write-Host "Running inside sandbox (full namespace isolation):" -ForegroundColor Cyan
    Write-Host "  > $Command" -ForegroundColor White
    Write-Host ""
    $cmd = "exec bwrap $bwrapFlags --clearenv --setenv HOME /home/tokimo --setenv USER tokimo --setenv LOGNAME tokimo --setenv PATH /home/tokimo/bin:/usr/local/bin:/usr/bin:/bin --setenv NPM_CONFIG_PREFIX /home/tokimo --setenv NODE_PATH /home/tokimo/lib/node_modules --setenv PYTHONPATH /home/tokimo/python_packages --setenv PIP_TARGET /home/tokimo/python_packages --setenv TERM xterm-256color -- /bin/bash -lc '$Command'"
    wsl -e sh -c $cmd
} else {
    Write-Host "Entering sandbox (full namespace isolation)..." -ForegroundColor Cyan
    Write-Host "  Rootfs : $RootfsPath"
    Write-Host "  Inside : /  (bwrap --unshare-all --share-net)"
    Write-Host "  User   : tokimo (uid 1000), Host: TokimoOS"
    Write-Host "  PID ns : isolated (ps shows only sandbox processes)"
    Write-Host ""
    Write-Host "  Type 'exit' or Ctrl+D to leave." -ForegroundColor DarkGray
    Write-Host ""

    $cmd = "exec bwrap $bwrapFlags --unsetenv LD_LIBRARY_PATH --setenv HOME /home/tokimo --setenv USER tokimo --setenv LOGNAME tokimo --setenv TERM xterm-256color -- /bin/bash --login"
    wsl -e sh -c $cmd
}

Write-Host ""
Write-Host "Session ended." -ForegroundColor Green
