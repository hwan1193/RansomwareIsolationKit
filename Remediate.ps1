<#
Intune Proactive Remediation - Remediation Script
- Runs when Detect exits 1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseDir = "C:\sec_reports\RansomwareIsolationKit"
$SettingsPath = Join-Path $BaseDir "settings.json"
$RemLog = Join-Path $BaseDir ("remediate_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Ensure-Dir([string]$dir) {
  if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
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
  if (-not (Test-Path $SettingsPath)) { throw "settings.json not found: $SettingsPath (run Detect once or deploy settings)" }
  $raw = Get-Content -Raw -Path $SettingsPath -Encoding UTF8
  return ($raw | ConvertFrom-Json)
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
  return $adapters
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

# ---- (Optional) MDE Isolation API Template ----
function Invoke-MDEIsolationTemplate {
  param(
    [Parameter(Mandatory=$false)][string]$TenantId,
    [Parameter(Mandatory=$false)][string]$ClientId,
    [Parameter(Mandatory=$false)][string]$ClientSecret
  )

  # 템플릿 자리만 유지: 운영 적용 시 여기 구현
  # - 토큰 발급: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
  # - machine id 조회: GET https://api.security.microsoft.com/api/machines?$filter=computerDnsName eq '{hostname}'
  # - isolate: POST https://api.security.microsoft.com/api/machines/{id}/isolate
  #
  # 여기서 Secret 평문 저장은 금지(권장).
  throw "MDE isolation not configured (template only)."
}

# ---------------- MAIN ----------------
Ensure-Dir $BaseDir
Assert-Admin
$settings = Load-Settings

Write-Log "START Remediate (Host=$env:COMPUTERNAME User=$env:USERNAME)"

# Event Log (for SIEM / Defender custom collection)
$logName = "Application"
$source  = "RansomwareIsolationKit"
Ensure-EventSource $logName $source

$msg = "Proactive Remediation triggered isolation. Host=$env:COMPUTERNAME User=$env:USERNAME"
Write-Event $logName $source 9411 $msg "Error"
Write-Log $msg

# 1) Try MDE (template)
$mdeSucceeded = $false
try {
  # If you later configure secrets safely, pass them here.
  # Invoke-MDEIsolationTemplate -TenantId "..." -ClientId "..." -ClientSecret "..."
  # For now: template throws
  Invoke-MDEIsolationTemplate
  $mdeSucceeded = $true
  Write-Event $logName $source 9412 "MDE isolation success." "Information"
  Write-Log "MDE isolation success."
} catch {
  Write-Event $logName $source 9413 ("MDE isolation failed/template: " + $_.Exception.Message) "Warning"
  Write-Log ("MDE isolation not used or failed: " + $_.Exception.Message)
}

# 2) Local fallback (recommended to keep)
if (-not $mdeSucceeded) {
  # Choose local mode:
  # - Adapter disable: fastest, strongest
  # - Firewall outbound block: easier to revert, sometimes safer
  $useFirewallBlock = $false
  $onlyPhysical = $true

  Apply-LocalIsolation -useFirewallBlock:$useFirewallBlock -onlyPhysical:$onlyPhysical
  Write-Event $logName $source 9414 "Local isolation applied." "Error"
  Write-Log "Local isolation applied."
}

Write-Log "END Remediate"
exit 0