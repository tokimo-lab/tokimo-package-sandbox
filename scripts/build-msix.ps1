<#
.SYNOPSIS
    Build and (optionally) sign the Tokimo Sandbox Service MSIX package.

.DESCRIPTION
    Mirrors Anthropic Claude Desktop's packaging model: the SYSTEM service
    is shipped as a signed MSIX so installation doesn't require a UAC
    prompt. The package's signature — not local admin elevation — is the
    trust anchor.

.PARAMETER Configuration
    "release" (default) or "debug".

.PARAMETER PfxPath
    Optional path to a .pfx code-signing certificate. If omitted, the
    package is built but not signed.

.PARAMETER PfxPassword
    Password for the .pfx file. Only used when PfxPath is provided.

.EXAMPLE
    pwsh ./scripts/build-msix.ps1
    pwsh ./scripts/build-msix.ps1 -PfxPath C:\certs\tokimo.pfx -PfxPassword $env:TOKIMO_PFX_PWD
#>
param(
    [ValidateSet("release", "debug")]
    [string]$Configuration = "release",
    [string]$PfxPath,
    [string]$PfxPassword
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$layout   = Join-Path $repoRoot "target\msix-layout"
$outDir   = Join-Path $repoRoot "target\msix"
$package  = Join-Path $outDir   "Tokimo.SandboxSvc.msix"

# 1. Build the service binary.
Push-Location $repoRoot
try {
    if ($Configuration -eq "release") {
        cargo build --release --bin tokimo-sandbox-svc
        $exe = Join-Path $repoRoot "target\release\tokimo-sandbox-svc.exe"
    } else {
        cargo build --bin tokimo-sandbox-svc
        $exe = Join-Path $repoRoot "target\debug\tokimo-sandbox-svc.exe"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $exe)) { throw "service binary not found: $exe" }

# 2. Stage the layout.
if (Test-Path $layout) { Remove-Item -Recurse -Force $layout }
New-Item -ItemType Directory -Path $layout                     | Out-Null
New-Item -ItemType Directory -Path (Join-Path $layout "assets") | Out-Null

Copy-Item (Join-Path $repoRoot "packaging\windows\AppxManifest.xml") $layout
Copy-Item $exe $layout

# Placeholder logos so MakeAppx doesn't reject the package. Replace with
# real artwork before publishing.
$logos = @("StoreLogo.png", "Square150x150Logo.png", "Square44x44Logo.png")
foreach ($name in $logos) {
    $dest = Join-Path $layout "assets\$name"
    if (-not (Test-Path $dest)) {
        # 1x1 transparent PNG — valid file, fails store certification but
        # passes MakeAppx schema validation.
        $bytes = [Convert]::FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4//8/AwAI/AL+XJ6jQwAAAABJRU5ErkJggg==")
        [IO.File]::WriteAllBytes($dest, $bytes)
    }
}

# 3. Locate MakeAppx.exe.
$kit = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Directory -ErrorAction SilentlyContinue |
       Sort-Object Name -Descending | Select-Object -First 1
if (-not $kit) { throw "Windows 10 SDK not found. Install one to get MakeAppx.exe." }
$makeAppx = Join-Path $kit.FullName "x64\MakeAppx.exe"
$signTool = Join-Path $kit.FullName "x64\SignTool.exe"
if (-not (Test-Path $makeAppx)) { throw "MakeAppx.exe not found at $makeAppx" }

# 4. Pack.
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
if (Test-Path $package)        { Remove-Item -Force $package }

& $makeAppx pack /d $layout /p $package /o
if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed ($LASTEXITCODE)" }

# 5. Optional sign.
if ($PfxPath) {
    if (-not (Test-Path $signTool)) { throw "SignTool.exe not found at $signTool" }
    & $signTool sign /fd SHA256 /a /f $PfxPath /p $PfxPassword $package
    if ($LASTEXITCODE -ne 0) { throw "SignTool failed ($LASTEXITCODE)" }
}

Write-Host ""
Write-Host "Built: $package" -ForegroundColor Green
if (-not $PfxPath) {
    Write-Host "Package is UNSIGNED. Install with:" -ForegroundColor Yellow
    Write-Host "  Add-AppxPackage -AllowUnsigned -Path '$package'" -ForegroundColor Yellow
}
