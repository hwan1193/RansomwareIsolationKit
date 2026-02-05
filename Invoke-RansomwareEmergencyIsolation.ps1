<#
.SYNOPSIS
  Ransomware suspected -> Evidence + MDE Isolation + Local Fallback (Enterprise-ready template)

.REQUIREMENTS
  - Run as Administrator
  - PowerShell 5.1+ (Windows)
  - If using MDE API: Azure AD App registration w/ proper permissions (Device.Isolate, Machine.Read.All etc.)

.USAGE
  powershell -ExecutionPolicy Bypass -File .\Invoke-RansomwareEmergencyIsolation.ps1 -SettingsPath .\settings.json
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$SettingsPath = ".\settings.json",

  # If you want to include Changed events (more noisy), set true
  [Parameter(Mandatory=$false)]
  [bool]$EnableChangedEvent = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "관리자 권한으로 실행해야 합니다."
  }
}

function Read-Settings([string]$path) {
  if (-not (Test-Path $path)) { throw "settings.json not found: $path" }
  return (Get-Content -Raw -Path $path -Encoding UTF8) | ConvertFrom-Json
}

function Ensure-Dir([string]$dir) {
  if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

function New-RunLogFile([string]$logDir) {
  Ensure-Dir $logDir
  $name = "ransom_isolation_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
  return (Join-Path $logDir $name)
}

function Write-Log([string]$LogFile, [string]$msg) {
  $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
  Add-Content -Path $LogFile -Value $line -Encoding UTF8
  Write-Host $line
}

function Ensure-EventSource([string]$logName, [string]$source, [string]$LogFile) {
  if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    # requires admin
    New-EventLog -LogName $logName -Source $source
    Write-Log $LogFile "EventLog source created: LogName=$logName Source=$source"
  }
}

function Write-Event([string]$logName, [string]$source, [int]$eventId, [string]$message, [string]$LogFile, [string]$entryType="Warning") {
  try {
    Write-EventLog -LogName $logName -Source $source -EventId $eventId -EntryType $entryType -Message $message
  } catch {
    Write-Log $LogFile "WARN: Failed to write event log: $($_.Exception.Message)"
  }
}

function Is-ExcludedPath([string]$fullPath, [string[]]$excludeRegex) {
  foreach ($rx in $excludeRegex) {
    if ($fullPath -match $rx) { return $true }
  }
  return $false
}

function Get-ProcessNameSafely {
  # FileSystemWatcher doesn't reliably provide process. This is a heuristic placeholder.
  # In enterprise, replace with Sysmon (EventID 11/2 etc) correlation or MDE Advanced Hunting.
  return $null
}

function Is-AllowProcess([string]$procName, [string[]]$allowList) {
  if (-not $procName) { return $false }
  $pn = $procName.Trim().ToLowerInvariant()
  return $allowList | ForEach-Object { $_.ToLowerInvariant() } | Where-Object { $_ -eq $pn } | ForEach-Object { $true } | Select-Object -First 1
}

function Get-TargetAdapters([bool]$onlyPhysical) {
  $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
  if ($onlyPhysical) {
    $adapters = $adapters | Where-Object {
      $_.HardwareInterface -eq $true -and
      $_.InterfaceDescription -notmatch "Hyper-V|Virtual|TAP|TUN|VPN|Loopback|VMware|vEthernet"
    }
  }
  return $adapters
}

function Apply-LocalIsolation([pscustomobject]$settings, [string]$LogFile) {
  $iso = $settings.Isolation
  if ($iso.LocalFirewallOutboundBlockInsteadOfAdapterDisable) {
    Write-Log $LogFile "Local isolation mode: Windows Firewall outbound block (Domain/Private/Public)"
    if (-not $settings.DryRun) {
      foreach ($p in @("Domain","Private","Public")) {
        Set-NetFirewallProfile -Profile $p -DefaultOutboundAction Block | Out-Null
      }
    } else {
      Write-Log $LogFile "DryRun=true -> No firewall changes applied."
    }
    return
  }

  Write-Log $LogFile "Local isolation mode: Disable-NetAdapter (onlyPhysical=$($iso.DisableOnlyPhysicalAdapters))"
  $targets = Get-TargetAdapters -onlyPhysical:$iso.DisableOnlyPhysicalAdapters
  if ($targets.Count -eq 0) {
    Write-Log $LogFile "WARN: No target adapters found to disable."
    return
  }

  foreach ($a in $targets) {
    Write-Log $LogFile ("Adapter disable target: Name={0}, IfDesc={1}" -f $a.Name, $a.InterfaceDescription)
  }

  if (-not $settings.DryRun) {
    $targets | Disable-NetAdapter -Confirm:$false -ErrorAction Continue
    Write-Log $LogFile "Network adapters disabled."
  } else {
    Write-Log $LogFile "DryRun=true -> No adapter disabled."
  }
}

function Get-MDEToken([pscustomobject]$mde) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $tokenUri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $mde.TenantId
  $body = @{
    client_id     = $mde.ClientId
    client_secret = $mde.ClientSecret
    scope         = $mde.Scope
    grant_type    = "client_credentials"
  }
  $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
  return $resp.access_token
}

function Get-MDEMachineIdByHostname([string]$apiBase, [string]$token, [string]$hostname) {
  # NOTE: In real enterprise, caching + strict matching + device naming conventions needed.
  $uri = "$apiBase/api/machines?`$filter=computerDnsName eq '$hostname'"
  $hdr = @{ Authorization = "Bearer $token" }
  $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $hdr
  if ($resp.value -and $resp.value.Count -ge 1) { return $resp.value[0].id }
  return $null
}

function Invoke-MDEIsolation([pscustomobject]$settings, [string]$LogFile) {
  $mde = $settings.MDE
  $token = Get-MDEToken $mde
  $hostname = $env:COMPUTERNAME

  Write-Log $LogFile "MDE: resolving machine id for hostname=$hostname"
  $machineId = Get-MDEMachineIdByHostname -apiBase $mde.ApiBase -token $token -hostname $hostname
  if (-not $machineId) { throw "MDE: machine id not found for $hostname (check naming / permissions)" }

  $uri = "$($mde.ApiBase)/api/machines/$machineId/isolate"
  $hdr = @{ Authorization = "Bearer $token" }
  $payload = @{
    Comment       = $mde.IsolateComment
    IsolationType = $mde.IsolationType  # Full or Selective (depends on tenant support)
  } | ConvertTo-Json

  Write-Log $LogFile "MDE: calling isolate endpoint (machineId=$machineId)"
  if (-not $settings.DryRun) {
    $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $hdr -Body $payload -ContentType "application/json"
    Write-Log $LogFile ("MDE: isolate response: " + ($resp | ConvertTo-Json -Compress))
  } else {
    Write-Log $LogFile "DryRun=true -> MDE isolation not executed."
  }
}

# -------------------- MAIN --------------------
Assert-Admin
$settings = Read-Settings $SettingsPath

$logDir  = $settings.Logging.LogDir
$LogFile = New-RunLogFile $logDir
Write-Log $LogFile "START RansomwareIsolationKit"
Write-Log $LogFile "SettingsPath=$SettingsPath DryRun=$($settings.DryRun) EnableChangedEvent=$EnableChangedEvent"

# EventLog setup (optional)
if ($settings.Logging.EventLog.Enabled) {
  Ensure-EventSource -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -LogFile $LogFile
}

# Build concrete watch list
$watchTargets = New-Object System.Collections.Generic.List[pscustomobject]

foreach ($wp in $settings.WatchPaths) {
  if ($wp.Mode -eq "Direct") {
    if (-not (Test-Path $wp.Path)) {
      Write-Log $LogFile "WARN: WatchPath not found (skip): $($wp.Path)"
      continue
    }
    $watchTargets.Add([pscustomobject]@{
      Path = $wp.Path
      TimeWindowSeconds = [int]$wp.TimeWindowSeconds
      ThresholdCount = [int]$wp.ThresholdCount
    }) | Out-Null
  }
  elseif ($wp.Mode -eq "DesktopWildcard") {
    # Expand: C:\Users\*\Desktop
    $usersRoot = $wp.Path
    if (-not (Test-Path $usersRoot)) {
      Write-Log $LogFile "WARN: Users root not found (skip): $usersRoot"
      continue
    }
    Get-ChildItem -Path $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $desktop = Join-Path $_.FullName "Desktop"
      if (Test-Path $desktop) {
        $watchTargets.Add([pscustomobject]@{
          Path = $desktop
          TimeWindowSeconds = [int]$wp.TimeWindowSeconds
          ThresholdCount = [int]$wp.ThresholdCount
        }) | Out-Null
      }
    }
  }
}

if ($watchTargets.Count -eq 0) { throw "No valid watch targets found. Check settings.json WatchPaths." }

Write-Log $LogFile ("WatchTargets:`n" + ($watchTargets | ForEach-Object { " - {0} (Window={1}s, Threshold={2})" -f $_.Path, $_.TimeWindowSeconds, $_.ThresholdCount } | Out-String))

# Global trigger guard
$script:Triggered = $false

# Per-path sliding windows
$state = @{}
foreach ($t in $watchTargets) {
  $state[$t.Path] = @{
    Queue = New-Object System.Collections.Generic.Queue[DateTime]
    Lock  = New-Object object
    Window = $t.TimeWindowSeconds
    Threshold = $t.ThresholdCount
  }
}

# Suspicious ext lookup
$suspSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($e in $settings.SuspiciousExtensions) { [void]$suspSet.Add($e) }

function Trigger-Isolation([string]$reason, [string]$fullPath) {
  if ($script:Triggered) { return }
  $script:Triggered = $true

  $msg = "EMERGENCY ISOLATION TRIGGERED. Reason=$reason Path=$fullPath Host=$env:COMPUTERNAME User=$env:USERNAME"
  Write-Log $LogFile "!!! $msg"

  if ($settings.Logging.EventLog.Enabled) {
    Write-Event -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -eventId 9111 -message $msg -LogFile $LogFile -entryType "Error"
  }

  # 1) Try MDE isolation
  $mdeOk = $false
  if ($settings.Isolation.UseMDE) {
    try {
      Invoke-MDEIsolation -settings $settings -LogFile $LogFile
      $mdeOk = $true
      Write-Log $LogFile "MDE isolation SUCCESS."
      if ($settings.Logging.EventLog.Enabled) {
        Write-Event -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -eventId 9112 -message "MDE isolation succeeded." -LogFile $LogFile -entryType "Information"
      }
    } catch {
      Write-Log $LogFile "MDE isolation FAILED: $($_.Exception.Message)"
      if ($settings.Logging.EventLog.Enabled) {
        Write-Event -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -eventId 9113 -message ("MDE isolation failed: " + $_.Exception.Message) -LogFile $LogFile -entryType "Warning"
      }
    }
  }

  # 2) Local fallback
  if (-not $mdeOk -and $settings.Isolation.FallbackLocalAdapterDisable) {
    try {
      Apply-LocalIsolation -settings $settings -LogFile $LogFile
      if ($settings.Logging.EventLog.Enabled) {
        Write-Event -logName $settings.Logging.EventLog.LogName -source $settings.Logging.EventLog.Source -eventId 9114 -message "Local isolation applied." -LogFile $LogFile -entryType "Error"
      }
    } catch {
      Write-Log $LogFile "Local isolation FAILED: $($_.Exception.Message)"
    }
  }

  Write-Log $LogFile "Monitor will stop now."
}

# Watchers
$subscriptions = New-Object System.Collections.Generic.List[object]
$watchers = New-Object System.Collections.Generic.List[System.IO.FileSystemWatcher]

foreach ($t in $watchTargets) {
  $w = New-Object System.IO.FileSystemWatcher
  $w.Path = $t.Path
  $w.IncludeSubdirectories = [bool]$settings.IncludeSubdirectories
  $w.EnableRaisingEvents = $true
  $w.NotifyFilter = [IO.NotifyFilters]'FileName, DirectoryName, LastWrite'

  $handler = {
    if ($script:Triggered) { return }

    $chg  = $Event.SourceEventArgs.ChangeType.ToString()
    $name = $Event.SourceEventArgs.Name
    $full = $Event.SourceEventArgs.FullPath

    # Exclude noisy paths
    if (Is-ExcludedPath -fullPath $full -excludeRegex $using:settings.ExcludePathRegex) { return }

    # Skip office temp files
    if ($name -like "~$*") { return }

    # Suspicious extension immediate
    $ext = [System.IO.Path]::GetExtension($name)
    if ($ext -and $using:suspSet.Contains($ext)) {
      Write-Log $using:LogFile "EVENT $chg :: $full :: ext=$ext => suspicious ext trigger"
      Trigger-Isolation -reason ("SuspiciousExtension:" + $ext) -fullPath $full
      return
    }

    # Optional allow-process heuristic (placeholder)
    $proc = Get-ProcessNameSafely
    if (Is-AllowProcess -procName $proc -allowList $using:settings.AllowProcessNames) {
      return
    }

    # Sliding window count per watcher path
    $base = $Event.Sender.Path
    $st = $using:state[$base]

    [System.Threading.Monitor]::Enter($st.Lock)
    try {
      $now = Get-Date
      $st.Queue.Enqueue($now)
      $cutoff = $now.AddSeconds(-1 * [int]$st.Window)
      while ($st.Queue.Count -gt 0 -and $st.Queue.Peek() -lt $cutoff) {
        [void]$st.Queue.Dequeue()
      }
      $count = $st.Queue.Count
      $threshold = [int]$st.Threshold
      $window = [int]$st.Window
    } finally {
      [System.Threading.Monitor]::Exit($st.Lock)
    }

    Write-Log $using:LogFile "EVENT $chg :: $full :: count_in_${window}s=$count threshold=$threshold"

    if ($count -ge $threshold) {
      Trigger-Isolation -reason ("RateThreshold:${count}in${window}s") -fullPath $full
    }
  }

  # Register: Created/Renamed (less noisy)
  $subscriptions.Add((Register-ObjectEvent $w Created -Action $handler)) | Out-Null
  $subscriptions.Add((Register-ObjectEvent $w Renamed -Action $handler)) | Out-Null

  # Optional Changed
  if ($EnableChangedEvent) {
    $subscriptions.Add((Register-ObjectEvent $w Changed -Action $handler)) | Out-Null
  }

  $watchers.Add($w) | Out-Null
  Write-Log $LogFile "Watcher enabled: $($t.Path)"
}

Write-Log $LogFile "RUNNING... (Ctrl+C to stop)"
try {
  while (-not $script:Triggered) { Start-Sleep -Seconds 1 }
} finally {
  foreach ($s in $subscriptions) {
    try { Unregister-Event -SourceIdentifier $s.Name -ErrorAction SilentlyContinue } catch {}
  }
  foreach ($w in $watchers) { try { $w.Dispose() } catch {} }
  Write-Log $LogFile "END."
}