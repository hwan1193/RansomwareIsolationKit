<# 
Intune Proactive Remediation - Undo / Restore Script
- Use as a separate remediation package (manual trigger or scheduled)
- Run as SYSTEM (Intune default), 64-bit PowerShell = Yes
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseDir = "C:\sec_reports\RansomwareIsolationKit"
$SettingsPath = Join-Path $BaseDir "settings.json"
$LogFile = Join-Path $BaseDir ("undo_pr_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Ensure-Dir([string]$dir) {
  if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
function Write-Log([string]$msg) {
  $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
  Add-Content -Path $LogFile -Value $line -Encoding UTF8
  Write-Host $line
}
function Assert-AdminOrSystem {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Admin/System context required."
  }
}
function Load-Settings {
  if (-not (Test-Path $SettingsPath)) {
    throw "settings.json not found: $SettingsPath"
  }
  (Get-Content -Raw -Path $SettingsPath -Encoding UTF8) | ConvertFrom-Json
}
function Ensure-EventSource([string]$logName, [string]$source) {
  if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    New-EventLog -LogName $logName -Source $source
  }
}
function Write-Event([string]$logName, [string]$source, [int]$eventId, [string]$message, [string]$entryType="Information") {
  try { Write-EventLog -LogName $logName -Source $source -EventId $eventId -EntryType $entryType -Message $message } catch {}
}

function Get-AdaptersToEnable([bool]$onlyPhysical) {
  # Enable adapters that are NOT Up (Disabled/Down)
  $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -ne "Up" }
  if ($onlyPhysical) {
    $adapters = $adapters | Where-Object {
      $_.HardwareInterface -eq $true -and
      $_.InterfaceDescription -notmatch "Hyper-V|Virtual|TAP|TUN|VPN|Loopback|VMware|vEthernet"
    }
  }
  return $adapters
}

# ---- (Optional) MDE Unisolate API Template ----
function Invoke-MDEUnisolateTemplate {
  param(
    [Parameter(Mandatory=$false)][string]$TenantId,
    [Parameter(Mandatory=$false)][string]$ClientId,
    [Parameter(Mandatory=$false)][string]$ClientSecret
  )
  # 템플릿 자리만 유지 (운영 적용 시 구현)
  # - token: POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
  # - machine id: GET https://api.security.microsoft.com/api/machines?$filter=computerDnsName eq '{hostname}'
  # - unisolate: POST https://api.security.microsoft.com/api/machines/{id}/unisolate
  throw "MDE unisolate not configured (template only)."
}

# ---------------- MAIN ----------------
Ensure-Dir $BaseDir
Assert-AdminOrSystem
$settings = Load-Settings

Write-Log "START Undo (PR) Host=$env:COMPUTERNAME User=$env:USERNAME"

$logName = "Application"
$source  = "RansomwareIsolationKit"
Ensure-EventSource $logName $source

Write-Event $logName $source 9511 "Proactive Undo started." "Information"

# 1) (Optional) MDE unisolate (template)
#    NOTE: 로컬 격리만 쓴 환경이면 여기 스킵해도 됨.
try {
  # Invoke-MDEUnisolateTemplate -TenantId "..." -ClientId "..." -ClientSecret "..."
  Invoke-MDEUnisolateTemplate
  Write-Log "MDE unisolate success."
  Write-Event $logName $source 9512 "MDE unisolate success." "Information"
} catch {
  Write-Log ("MDE unisolate not used or failed: " + $_.Exception.Message)
  Write-Event $logName $source 9513 ("MDE unisolate not used/failed: " + $_.Exception.Message) "Warning"
}

# 2) Local undo (Firewall or Adapter)
# 너가 기존 Invoke에서 방화벽 모드 쓸 수도 있으니 둘 다 원복 처리
# 2-1) Firewall outbound default action -> Allow
try {
  foreach ($p in @("Domain","Private","Public")) {
    Set-NetFirewallProfile -Profile $p -DefaultOutboundAction Allow | Out-Null
  }
  Write-Log "Firewall outbound default action restored to ALLOW."
  Write-Event $logName $source 9514 "Firewall outbound restored to ALLOW." "Information"
} catch {
  Write-Log ("Firewall restore skipped/failed: " + $_.Exception.Message)
}

# 2-2) Enable adapters
try {
  $onlyPhysical = $true
  $targets = Get-AdaptersToEnable -onlyPhysical:$onlyPhysical
  if ($targets.Count -eq 0) {
    Write-Log "No adapters found to enable (already up or filtered)."
  } else {
    foreach ($a in $targets) {
      Write-Log ("Enable adapter: {0} / {1} / Status={2}" -f $a.Name, $a.InterfaceDescription, $a.Status)
    }
    $targets | Enable-NetAdapter -Confirm:$false -ErrorAction Continue
    Write-Log "Adapters enabled."
  }
  Write-Event $logName $source 9515 "Local adapters enabled (undo complete)." "Information"
} catch {
  Write-Log ("Enable adapter failed: " + $_.Exception.Message)
  Write-Event $logName $source 9516 ("Enable adapter failed: " + $_.Exception.Message) "Error"
}

Write-Log "END Undo (PR)"
exit 0