#!/usr/bin/env pwsh
# Tail the COM2 named pipe of the most recent Tokimo VM.
# Usage: scripts/tail-vm-console.ps1 [-Timeout 90]
param([int]$Timeout = 90)

$ErrorActionPreference = 'Continue'
$deadline = (Get-Date).AddSeconds($Timeout)
$found = $null

while ((Get-Date) -lt $deadline) {
    $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'tokimo-vm-com2-*' }
    if ($pipes) { $found = $pipes[0].FullName; break }
    Start-Sleep -Milliseconds 200
}

if (-not $found) { Write-Host "no com2 pipe seen within $Timeout s"; exit 1 }
Write-Host "=== attaching to $found ===" -ForegroundColor Cyan

# Open the pipe as a file. Hyper-V keeps it readable as a stream.
try {
    $stream = [System.IO.File]::Open("\\.\pipe\$($found.Substring(9))", 'Open', 'Read')
    $reader = New-Object System.IO.StreamReader($stream)
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line) { Start-Sleep -Milliseconds 50; continue }
        Write-Host $line
    }
} catch {
    Write-Host "tail error: $_"
}
