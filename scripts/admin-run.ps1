param([Parameter(Mandatory=$true)][string]$Cmd)
$log = "F:\tokimo-package-sandbox\admin-out.log"
Remove-Item $log -ErrorAction SilentlyContinue
$wrap = @"
`$ErrorActionPreference='Continue'
try { & {$Cmd} *>&1 | Tee-Object -FilePath '$log' } catch { `$_ | Out-File -Append '$log' }
`$LASTEXITCODE | Out-File -Append '$log'
"@
$tmp = [IO.Path]::GetTempFileName() + '.ps1'
Set-Content -Path $tmp -Value $wrap -Encoding UTF8
$p = Start-Process -FilePath powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$tmp `
  -Verb RunAs -Wait -PassThru -WindowStyle Hidden
Remove-Item $tmp -ErrorAction SilentlyContinue
Write-Host "ExitCode=$($p.ExitCode)"
if (Test-Path $log) { Get-Content $log }
