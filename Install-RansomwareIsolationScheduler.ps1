<#
Install script for Intune "Platform scripts" (Windows)
- Copies kit to C:\sec_reports\RansomwareIsolationKit
- Creates scheduled task: hourly Detect -> if needed run Remediate
- Runs as SYSTEM (recommended)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseDir = "C:\sec_reports\RansomwareIsolationKit"
$Detect  = Join-Path $BaseDir "Detect.ps1"
$Remed   = Join-Path $BaseDir "Remediate.ps1"
$Undo    = Join-Path $BaseDir "Undo.ps1"
$Settings= Join-Path $BaseDir "settings.json"
$Orchestrator = Join-Path $BaseDir "Run-Orchestrator.ps1"

# ====== YOU MUST PASTE YOUR ACTUAL SCRIPT CONTENTS HERE (one-time) ======
# If you want, I can generate a packaged ZIP + embedded contents version too.
$DetectContent = @'
# (PASTE Detect.ps1 CONTENT HERE)
'@

$RemediateContent = @'
# (PASTE Remediate.ps1 CONTENT HERE)
'@

$UndoContent = @'
# (PASTE PR-Undo-Remediate.ps1 CONTENT HERE)
'@

$SettingsContent = @'
{
  "WatchPaths": [
    { "Path": "C:\\Users", "Mode": "DesktopWildcard" },
    { "Path": "D:\\Work",  "Mode": "Direct" }
  ],
  "IncludeSubdirectories": true,
  "SuspiciousExtensions": [".locky",".encrypted",".crypt",".crypto",".ryk",".ryuk",".conti",".akira",".clop",".revil",".blackcat",".wannacry",".tesla",".stop"],
  "ExcludePathRegex": ["\\\\node_modules\\\\","\\\\bin\\\\","\\\\obj\\\\","\\\\target\\\\","\\\\dist\\\\","\\\\.git\\\\","\\\\venv\\\\","\\\\AppData\\\\","\\\\OneDriveTemp\\\\","\\\\Microsoft\\\\Office\\\\","\\\\Packages\\\\"],
  "Detection": {
    "LookbackMinutesForSuspiciousExt": 60,
    "BurstLookbackMinutes": 10,
    "BurstCountSoftThreshold": 800
  },
  "Logging": { "BaseDir": "C:\\sec_reports\\RansomwareIsolationKit" }
}
'@

function Ensure-Dir([string]$p) { if (-not (Test-Path $p)) { New-Item -Path $p -ItemType Directory -Force | Out-Null } }

function Write-File([string]$path, [string]$content) {
  $content | Out-File -FilePath $path -Encoding UTF8 -Force
}

# Orchestrator: run Detect; if exit 1 => run Remediate
$OrchestratorContent = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

`$base = '$BaseDir'
`$detect = Join-Path `$base 'Detect.ps1'
`$remed = Join-Path `$base 'Remediate.ps1'

# Ensure dir exists
if (-not (Test-Path `$base)) { exit 0 }

# Run detect
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$detect
`$code = `$LASTEXITCODE

if (`$code -eq 1) {
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$remed
  exit `$LASTEXITCODE
}

# 0=healthy, 2=detect error -> just exit with code
exit `$code
"@

# ====== MAIN ======
Ensure-Dir $BaseDir

# Permissions (SYSTEM full)
cmd.exe /c "icacls `"$BaseDir`" /grant `"SYSTEM:(OI)(CI)F`" /T" | Out-Null

Write-File $Detect $DetectContent
Write-File $Remed  $RemediateContent
Write-File $Undo   $UndoContent
Write-File $Settings $SettingsContent
Write-File $Orchestrator $OrchestratorContent

# Register scheduled task (Hourly)
$TaskName = "RansomwareIsolationKit-Orchestrator"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Orchestrator`""
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

$SettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Replace if exists
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $SettingsSet | Out-Null

# Start immediately once
Start-ScheduledTask -TaskName $TaskName

exit 0