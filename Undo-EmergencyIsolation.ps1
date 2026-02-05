<#
.SYNOPSIS
  Undo local isolation (Enable adapters OR revert firewall outbound rule)

.USAGE
  powershell -ExecutionPolicy Bypass -File .\Undo-EmergencyIsolation.ps1 -SettingsPath .\settings.json
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$SettingsPath = ".\settings.json"
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
  $name = "undo_isolation_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
  return (Join-Path $logDir $name)
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
  $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -ne "Up" } # disabled / down
  if ($onlyPhysical) {
    $adapters = $adapters | Where-Object {
      $_.HardwareInterface -eq $true -and
      $_.InterfaceDescription -notmatch "Hyper-V|Virtual|TAP|TUN|VPN|Loopback|VMware|vEthernet"
    }
  }
  return $adapters
}

# -------------------- MAIN --------------------
Assert-Admin
$settings = Read-Settings $SettingsPath

$logDir  = $settings.Logging.LogDir
$LogFile = New-RunLogFile $logDir
Write-Log $LogFile "START Undo-EmergencyIsolation"
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
} else {
  Write-Log $LogFile "Enabling network adapters (onlyPhysical=$($iso.DisableOnlyPhysicalAdapters))"
  $targets = Get-TargetAdapters -onlyPhysical:$iso.DisableOnlyPhysicalAdapters
  if ($targets.Count -eq 0) {
    Write-Log $LogFile "No adapters found to enable (already up or filtered)."
  } else {
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