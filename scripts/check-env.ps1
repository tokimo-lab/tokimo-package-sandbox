# 环境检查脚本 — 请用管理员 PowerShell 运行，并把全部输出贴回给我。
# Run-As-Admin: pwsh -ExecutionPolicy Bypass -File .\scripts\check-env.ps1 *>&1 | Tee-Object -FilePath .\scripts\check-env.log

$ErrorActionPreference = 'Continue'

function Section($name) {
    Write-Host ""
    Write-Host "===== $name =====" -ForegroundColor Cyan
}

Section "1. WSL2"
try { wsl --status } catch { Write-Host "wsl --status failed: $_" }
try { wsl -l -v } catch { Write-Host "wsl -l -v failed: $_" }

Section "2. Docker"
try {
    docker version --format '{{.Server.OS}} {{.Server.Version}}'
} catch { Write-Host "docker not available: $_" }

Section "3. Hyper-V"
try {
    Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All |
        Select-Object FeatureName, State | Format-List
} catch { Write-Host "Get-WindowsOptionalFeature failed: $_" }

try {
    Get-Service vmcompute, vmms -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType | Format-Table -AutoSize
} catch { Write-Host "Get-Service failed: $_" }

Section "4. Claude Desktop VM bundle"
$claudeBundle = "$env:LOCALAPPDATA\Claude-3p\vm_bundles\claudevm.bundle"
if (Test-Path $claudeBundle) {
    Get-ChildItem $claudeBundle -ErrorAction SilentlyContinue |
        Select-Object Name, Length, LastWriteTime |
        Format-Table -AutoSize
} else {
    Write-Host "NOT FOUND: $claudeBundle"
}

Section "5. Claude resources (smol-bin VHDX template)"
$apps = "C:\Program Files\WindowsApps"
if (Test-Path $apps) {
    Get-ChildItem $apps -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $r = Join-Path $_.FullName 'app\resources'
            if (Test-Path $r) {
                Write-Host "Resources: $r"
                Get-ChildItem $r -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '\.(vhdx|exe)$' -or $_.Name -eq 'cowork-svc.exe' } |
                    Select-Object Name, Length | Format-Table -AutoSize
            }
        }
} else {
    Write-Host "WindowsApps not accessible (need admin or takeown)"
}

Section "6. Architecture / OS"
[Environment]::Is64BitOperatingSystem
[Environment]::OSVersion
$PSVersionTable.PSVersion

Section "7. Workspace artifacts dir"
$tokimo = "$env:USERPROFILE\.tokimo"
if (Test-Path $tokimo) {
    Get-ChildItem $tokimo -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Length | Format-Table -AutoSize
} else {
    Write-Host "NOT FOUND: $tokimo (will be populated by build steps)"
}

Write-Host ""
Write-Host "===== DONE =====" -ForegroundColor Green
Write-Host "Log saved to: $PSScriptRoot\check-env.log (if you used Tee-Object)"
