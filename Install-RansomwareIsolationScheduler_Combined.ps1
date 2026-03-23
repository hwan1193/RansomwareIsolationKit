<#
.SYNOPSIS
  Intune 단일 설치 스크립트
  - Detect.ps1 / Remediate.ps1 / Undo.ps1 / settings.json / Run-Orchestrator.ps1 를
    C:\sec_reports\RansomwareIsolationKit 아래에 생성
  - SYSTEM 권한 예약 작업(RansomwareIsolationKit-Orchestrator) 등록
  - Detect 결과가 1이면 Remediate 실행
  - Intune PowerShell Script(플랫폼 스크립트)로 바로 배포 가능

.RECOMMENDED INTUNE OPTIONS
  - Run this script using the logged on credentials: No
  - Enforce script signature check: No
  - Run script in 64 bit PowerShell Host: Yes

.NOTES
  - 최초에는 반드시 테스트 그룹/테스트 VM 1~2대에 먼저 배포
  - 기본값은 "물리 NIC Disable" 방식으로 격리
  - 더 보수적으로 쓰려면 settings.json에서
    Isolation.LocalFirewallOutboundBlockInsteadOfAdapterDisable 값을 true 로 바꾸면
    방화벽 Outbound 차단 방식으로 동작
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BaseDir      = 'C:\sec_reports\RansomwareIsolationKit'
$DetectPath   = Join-Path $BaseDir 'Detect.ps1'
$RemedPath    = Join-Path $BaseDir 'Remediate.ps1'
$UndoPath     = Join-Path $BaseDir 'Undo.ps1'
$SettingsPath = Join-Path $BaseDir 'settings.json'
$OrchPath     = Join-Path $BaseDir 'Run-Orchestrator.ps1'
$InstallLog   = Join-Path $BaseDir ('install_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
$TaskName     = 'RansomwareIsolationKit-Orchestrator'

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Log([string]$Message) {
    $line = '[{0:yyyy-MM-dd HH:mm:ss}] {1}' -f (Get-Date), $Message
    Add-Content -Path $InstallLog -Value $line -Encoding UTF8
    Write-Host $line
}

function Write-FileUtf8([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if ($parent) { Ensure-Dir $parent }
    $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

$DetectContent = @'
<# 
Intune Proactive Remediation - Detection Script
- Exit 0: Healthy (no suspicious indicators)
- Exit 1: Issue detected (run remediation)
- Exit 2: Script error (Intune shows as error)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseDir      = "C:\sec_reports\RansomwareIsolationKit"
$SettingsPath = Join-Path $BaseDir "settings.json"
$DetectLog    = Join-Path $BaseDir ("detect_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Ensure-Dir([string]$dir) {
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
function Write-Log([string]$msg) {
  $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
  Add-Content -Path $DetectLog -Value $line -Encoding UTF8
}
function Load-Settings {
  if (-not (Test-Path -LiteralPath $SettingsPath)) {
    throw "settings.json not found: $SettingsPath"
  }
  return ((Get-Content -Raw -Path $SettingsPath -Encoding UTF8) | ConvertFrom-Json)
}
function Is-ExcludedPath([string]$fullPath, [string[]]$excludeRegex) {
  foreach ($rx in $excludeRegex) {
    if ($fullPath -match $rx) { return $true }
  }
  return $false
}
function Expand-WatchTargets($settings) {
  $targets = New-Object System.Collections.Generic.List[string]

  foreach ($wp in $settings.WatchPaths) {
    if ($wp.Mode -eq "Direct") {
      if (Test-Path -LiteralPath $wp.Path) { $targets.Add($wp.Path) | Out-Null }
      continue
    }

    if ($wp.Mode -eq "DesktopWildcard") {
      $usersRoot = $wp.Path
      if (-not (Test-Path -LiteralPath $usersRoot)) { continue }
      Get-ChildItem -Path $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $desktop = Join-Path $_.FullName "Desktop"
        if (Test-Path -LiteralPath $desktop) { $targets.Add($desktop) | Out-Null }
      }
    }
  }

  return $targets | Sort-Object -Unique
}
function Find-RecentSuspiciousExtensions([string[]]$targets, [datetime]$since, $settings) {
  $hits = New-Object System.Collections.Generic.List[string]
  $susSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($e in $settings.SuspiciousExtensions) { [void]$susSet.Add($e) }

  foreach ($t in $targets) {
    try {
      Get-ChildItem -Path $t -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $full = $_.FullName
        if (Is-ExcludedPath $full $settings.ExcludePathRegex) { return }
        if ($_.LastWriteTime -lt $since) { return }

        $ext = $_.Extension
        if ($ext -and $susSet.Contains($ext)) {
          $hits.Add($full) | Out-Null
        }
      }
    } catch {
      Write-Log ("WARN: Failed target scan: {0} => {1}" -f $t, $_.Exception.Message)
    }
  }
  return $hits
}
function Get-BurstCount([string[]]$targets, [datetime]$since, $settings) {
  $script:count = 0
  foreach ($t in $targets) {
    try {
      Get-ChildItem -Path $t -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $full = $_.FullName
        if (Is-ExcludedPath $full $settings.ExcludePathRegex) { return }
        if ($_.LastWriteTime -ge $since) { $script:count++ }
      }
    } catch {
      Write-Log ("WARN: Failed burst scan: {0} => {1}" -f $t, $_.Exception.Message)
    }
  }
  return $script:count
}

try {
  Ensure-Dir $BaseDir
  Write-Log "START Detect (Host=$env:COMPUTERNAME User=$env:USERNAME)"

  $settings = Load-Settings
  $targets  = Expand-WatchTargets $settings
  Write-Log ("WatchTargets: " + ($targets -join ", "))

  if (-not $targets -or $targets.Count -eq 0) {
    Write-Log "INFO: no watch targets found"
    exit 0
  }

  $lookbackMins = [int]$settings.Detection.LookbackMinutesForSuspiciousExt
  $sinceExt = (Get-Date).AddMinutes(-1 * $lookbackMins)
  $hits = Find-RecentSuspiciousExtensions -targets $targets -since $sinceExt -settings $settings

  if ($hits.Count -gt 0) {
    Write-Log "DETECTED: suspicious extensions within last ${lookbackMins} minutes. Count=$($hits.Count)"
    $hits | Select-Object -First 20 | ForEach-Object { Write-Log "HIT: $_" }
    exit 1
  }

  $burstMins = [int]$settings.Detection.BurstLookbackMinutes
  $sinceBurst = (Get-Date).AddMinutes(-1 * $burstMins)
  $burstCount = Get-BurstCount -targets $targets -since $sinceBurst -settings $settings
  Write-Log "INFO: file changes count in last ${burstMins} min = $burstCount"

  $soft = [int]$settings.Detection.BurstCountSoftThreshold
  if ($burstCount -ge $soft) {
    Write-Log "SOFT WARNING: burstCount >= softThreshold ($soft). Not triggering by default."
    if ($settings.Detection.TriggerOnBurstThreshold -eq $true) {
      Write-Log "TriggerOnBurstThreshold=true -> remediation trigger"
      exit 1
    }
  }

  Write-Log "END Detect => Healthy"
  exit 0
}
catch {
  try { Write-Log "ERROR: $($_.Exception.Message)" } catch {}
  exit 2
}
'@

$RemediateContent = @'
<#
Intune Proactive Remediation - Remediation Script
- Runs when Detect exits 1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseDir      = "C:\sec_reports\RansomwareIsolationKit"
$SettingsPath = Join-Path $BaseDir "settings.json"
$RemLog       = Join-Path $BaseDir ("remediate_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Ensure-Dir([string]$dir) {
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
function Write-Log([string]$msg) {
  $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
  Add-Content -Path $RemLog -Value $line -Encoding UTF8
  Write-Host $line
}
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Admin/System context required."
  }
}
function Load-Settings {
  if (-not (Test-Path -LiteralPath $SettingsPath)) { throw "settings.json not found: $SettingsPath" }
  return ((Get-Content -Raw -Path $SettingsPath -Encoding UTF8) | ConvertFrom-Json)
}
function Ensure-EventSource([string]$logName, [string]$source) {
  if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    New-EventLog -LogName $logName -Source $source
  }
}
function Write-Event([string]$logName, [string]$source, [int]$eventId, [string]$message, [string]$entryType="Error") {
  try { Write-EventLog -LogName $logName -Source $source -EventId $eventId -EntryType $entryType -Message $message } catch {}
}
function Get-TargetAdapters([bool]$onlyPhysical) {
  $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
  if ($onlyPhysical) {
    $adapters = $adapters | Where-Object {
      $_.HardwareInterface -eq $true -and
      $_.InterfaceDescription -notmatch "Hyper-V|Virtual|TAP|TUN|VPN|Loopback|VMware|vEthernet"
    }
  }
  return @($adapters)
}
function Apply-LocalIsolation([bool]$useFirewallBlock, [bool]$onlyPhysical) {
  if ($useFirewallBlock) {
    Write-Log "Local isolation = Firewall outbound block"
    foreach ($p in @("Domain","Private","Public")) {
      Set-NetFirewallProfile -Profile $p -DefaultOutboundAction Block | Out-Null
    }
    return
  }

  Write-Log "Local isolation = Disable-NetAdapter (onlyPhysical=$onlyPhysical)"
  $targets = Get-TargetAdapters -onlyPhysical:$onlyPhysical
  if ($targets.Count -eq 0) {
    Write-Log "No target adapters to disable."
    return
  }

  foreach ($a in $targets) {
    Write-Log ("Adapter target: {0} / {1}" -f $a.Name, $a.InterfaceDescription)
  }

  $targets | Disable-NetAdapter -Confirm:$false -ErrorAction Continue
  Write-Log "Adapters disabled."
}

Ensure-Dir $BaseDir
Assert-Admin
$settings = Load-Settings

Write-Log "START Remediate (Host=$env:COMPUTERNAME User=$env:USERNAME)"

$logName = [string]$settings.Logging.EventLog.LogName
$source  = [string]$settings.Logging.EventLog.Source
Ensure-EventSource $logName $source

$msg = "RansomwareIsolationKit remediation triggered. Host=$env:COMPUTERNAME User=$env:USERNAME"
Write-Event $logName $source 9411 $msg "Error"
Write-Log $msg

$useFirewallBlock = [bool]$settings.Isolation.LocalFirewallOutboundBlockInsteadOfAdapterDisable
$onlyPhysical     = [bool]$settings.Isolation.DisableOnlyPhysicalAdapters

Apply-LocalIsolation -useFirewallBlock:$useFirewallBlock -onlyPhysical:$onlyPhysical

Write-Event $logName $source 9414 "Local isolation applied." "Error"
Write-Log "Local isolation applied."
Write-Log "END Remediate"
exit 0
'@

$UndoContent = @'
<#
.SYNOPSIS
  Undo local isolation (Enable adapters OR revert firewall outbound rule)

.EXAMPLE
  powershell.exe -ExecutionPolicy Bypass -File C:\sec_reports\RansomwareIsolationKit\Undo.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseDir      = "C:\sec_reports\RansomwareIsolationKit"
$SettingsPath = Join-Path $BaseDir "settings.json"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "관리자 권한으로 실행해야 합니다."
  }
}
function Read-Settings([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { throw "settings.json not found: $path" }
  return ((Get-Content -Raw -Path $path -Encoding UTF8) | ConvertFrom-Json)
}
function Ensure-Dir([string]$dir) {
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
function New-RunLogFile([string]$baseDir) {
  Ensure-Dir $baseDir
  $name = "undo_isolation_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
  return (Join-Path $baseDir $name)
}
function Write-Log([string]$LogFile, [string]$msg) {
  $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
  Add-Content -Path $LogFile -Value $line -Encoding UTF8
  Write-Host $line
}
function Ensure-EventSource([string]$logName, [string]$source, [string]$LogFile) {
  if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    New-EventLog -LogName $logName -Source $source
    Write-Log $LogFile "EventLog source created: LogName=$logName Source=$source"
  }
}
function Write-Event([string]$logName, [string]$source, [int]$eventId, [string]$message, [string]$LogFile, [string]$entryType="Information") {
  try {
    Write-EventLog -LogName $logName -Source $source -EventId $eventId -EntryType $entryType -Message $message
  } catch {
    Write-Log $LogFile "WARN: Failed to write event log: $($_.Exception.Message)"
  }
}
function Get-TargetAdapters([bool]$onlyPhysical) {
  $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -ne "Up" }
  if ($onlyPhysical) {
    $adapters = $adapters | Where-Object {
      $_.HardwareInterface -eq $true -and
      $_.InterfaceDescription -notmatch "Hyper-V|Virtual|TAP|TUN|VPN|Loopback|VMware|vEthernet"
    }
  }
  return @($adapters)
}

Assert-Admin
$settings = Read-Settings $SettingsPath

$logDir  = [string]$settings.Logging.BaseDir
$LogFile = New-RunLogFile $logDir
Write-Log $LogFile "START Undo isolation"
Write-Log $LogFile "SettingsPath=$SettingsPath"

if ($settings.Logging.EventLog.Enabled) {
  Ensure-EventSource -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -LogFile $LogFile
}

$iso = $settings.Isolation
if ($iso.LocalFirewallOutboundBlockInsteadOfAdapterDisable) {
  Write-Log $LogFile "Reverting firewall outbound default action to ALLOW (Domain/Private/Public)"
  foreach ($p in @("Domain","Private","Public")) {
    Set-NetFirewallProfile -Profile $p -DefaultOutboundAction Allow | Out-Null
  }
  $msg = "Undo isolation: Firewall outbound default action restored to ALLOW."
  Write-Log $LogFile $msg
  if ($settings.Logging.EventLog.Enabled) {
    Write-Event -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -eventId 9211 -message $msg -LogFile $LogFile -entryType "Information"
  }
}
else {
  Write-Log $LogFile "Enabling network adapters (onlyPhysical=$($iso.DisableOnlyPhysicalAdapters))"
  $targets = Get-TargetAdapters -onlyPhysical:$iso.DisableOnlyPhysicalAdapters
  if ($targets.Count -eq 0) {
    Write-Log $LogFile "No adapters found to enable."
  }
  else {
    foreach ($a in $targets) {
      Write-Log $LogFile ("Adapter enable target: Name={0}, IfDesc={1}, Status={2}" -f $a.Name, $a.InterfaceDescription, $a.Status)
    }
    $targets | Enable-NetAdapter -Confirm:$false -ErrorAction Continue
    Write-Log $LogFile "Network adapters enabled."
  }

  $msg = "Undo isolation: Network adapters enabled (local)."
  if ($settings.Logging.EventLog.Enabled) {
    Write-Event -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -eventId 9212 -message $msg -LogFile $LogFile -entryType "Information"
  }
}

Write-Log $LogFile "END."
exit 0
'@

$SettingsContent = @'
{
  "WatchPaths": [
    { "Path": "C:\\Users", "Mode": "DesktopWildcard" },
    { "Path": "D:\\Work",  "Mode": "Direct" }
  ],
  "IncludeSubdirectories": true,
  "SuspiciousExtensions": [
    ".locky", ".encrypted", ".crypt", ".crypto", ".ryk", ".ryuk", ".conti",
    ".akira", ".clop", ".revil", ".blackcat", ".wannacry", ".tesla", ".stop"
  ],
  "ExcludePathRegex": [
    "\\\\node_modules\\\\", "\\\\bin\\\\", "\\\\obj\\\\", "\\\\target\\\\", "\\\\dist\\\\", "\\\\.git\\\\",
    "\\\\venv\\\\", "\\\\AppData\\\\", "\\\\OneDriveTemp\\\\", "\\\\Microsoft\\\\Office\\\\", "\\\\Packages\\\\"
  ],
  "Detection": {
    "LookbackMinutesForSuspiciousExt": 60,
    "BurstLookbackMinutes": 10,
    "BurstCountSoftThreshold": 800,
    "TriggerOnBurstThreshold": false
  },
  "Isolation": {
    "LocalFirewallOutboundBlockInsteadOfAdapterDisable": false,
    "DisableOnlyPhysicalAdapters": true
  },
  "Logging": {
    "BaseDir": "C:\\sec_reports\\RansomwareIsolationKit",
    "EventLog": {
      "Enabled": true,
      "LogName": "Application",
      "Source": "RansomwareIsolationKit"
    }
  }
}
'@

$OrchestratorContent = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

`$base   = '$BaseDir'
`$detect = Join-Path `$base 'Detect.ps1'
`$remed  = Join-Path `$base 'Remediate.ps1'

if (-not (Test-Path -LiteralPath `$base)) { exit 0 }
if (-not (Test-Path -LiteralPath `$detect)) { exit 0 }
if (-not (Test-Path -LiteralPath `$remed))  { exit 0 }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$detect
`$code = `$LASTEXITCODE

if (`$code -eq 1) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$remed
    exit `$LASTEXITCODE
}

exit `$code
"@

try {
    Ensure-Dir $BaseDir
    Write-Log "START install"

    cmd.exe /c "icacls `"$BaseDir`" /grant `"SYSTEM:(OI)(CI)F`" /T /C" | Out-Null

    Write-FileUtf8 -Path $DetectPath   -Content $DetectContent
    Write-FileUtf8 -Path $RemedPath    -Content $RemediateContent
    Write-FileUtf8 -Path $UndoPath     -Content $UndoContent
    Write-FileUtf8 -Path $SettingsPath -Content $SettingsContent
    Write-FileUtf8 -Path $OrchPath     -Content $OrchestratorContent

    Write-Log "Files written to $BaseDir"

    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>RansomwareIsolationKit hourly detect/remediate orchestrator</Description>
    <Author>Intune</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>$(Get-Date -Format s)</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$OrchPath"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    $xmlPath = Join-Path $BaseDir 'task.xml'
    $taskXml | Out-File -FilePath $xmlPath -Encoding Unicode -Force

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Existing task removed: $TaskName"
    }

    schtasks.exe /Create /TN $TaskName /XML $xmlPath /RU SYSTEM /F | Out-Null
    Write-Log "Scheduled task created: $TaskName"

    Start-ScheduledTask -TaskName $TaskName
    Write-Log "Scheduled task started once"

    Write-Log "END install => success"
    exit 0
}
catch {
    try { Write-Log ("ERROR: " + $_.Exception.Message) } catch {}
    throw
}
