<# 
Intune Proactive Remediation - Detection Script
- Exit 0: Healthy (no suspicious indicators)
- Exit 1: Issue detected (run remediation)
- Exit 2: Script error (Intune shows as error)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Storage (shared) ----
$BaseDir    = "C:\sec_reports\RansomwareIsolationKit"
$SettingsPath = Join-Path $BaseDir "settings.json"
$DetectLog  = Join-Path $BaseDir ("detect_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Ensure-Dir([string]$dir) {
  if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
function Write-Log([string]$msg) {
  $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
  Add-Content -Path $DetectLog -Value $line -Encoding UTF8
}

# ---- Default settings (your environment) ----
$DefaultSettingsJson = @"
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
    "BurstCountSoftThreshold": 800
  },

  "Logging": {
    "BaseDir": "C:\\sec_reports\\RansomwareIsolationKit"
  }
}
"@

function Load-Settings {
  Ensure-Dir $BaseDir

  if (-not (Test-Path $SettingsPath)) {
    # auto-provision settings.json once
    $DefaultSettingsJson | Out-File -FilePath $SettingsPath -Encoding UTF8 -Force
  }
  $raw = Get-Content -Raw -Path $SettingsPath -Encoding UTF8
  return ($raw | ConvertFrom-Json)
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
      if (Test-Path $wp.Path) { $targets.Add($wp.Path) | Out-Null }
      continue
    }

    if ($wp.Mode -eq "DesktopWildcard") {
      $usersRoot = $wp.Path
      if (-not (Test-Path $usersRoot)) { continue }
      Get-ChildItem -Path $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $desktop = Join-Path $_.FullName "Desktop"
        if (Test-Path $desktop) { $targets.Add($desktop) | Out-Null }
      }
    }
  }

  # unique
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

        # 최근 변경/생성 기반
        if ($_.LastWriteTime -lt $since) { return }

        $ext = $_.Extension
        if ($ext -and $susSet.Contains($ext)) {
          $hits.Add($full) | Out-Null
        }
      }
    } catch {}
  }
  return $hits
}

function Get-BurstCount([string[]]$targets, [datetime]$since, $settings) {
  $count = 0
  foreach ($t in $targets) {
    try {
      Get-ChildItem -Path $t -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $full = $_.FullName
        if (Is-ExcludedPath $full $settings.ExcludePathRegex) { return }
        if ($_.LastWriteTime -ge $since) { $script:count++ }
      }
    } catch {}
  }
  return $count
}

# ---------------- MAIN ----------------
try {
  Ensure-Dir $BaseDir
  Write-Log "START Detect (Host=$env:COMPUTERNAME User=$env:USERNAME)"

  $settings = Load-Settings
  $targets  = Expand-WatchTargets $settings

  Write-Log ("WatchTargets: " + ($targets -join ", "))

  # 1) Suspicious extension (strong trigger)
  $lookbackMins = [int]$settings.Detection.LookbackMinutesForSuspiciousExt
  $sinceExt = (Get-Date).AddMinutes(-1 * $lookbackMins)
  $hits = Find-RecentSuspiciousExtensions -targets $targets -since $sinceExt -settings $settings

  if ($hits.Count -gt 0) {
    Write-Log "DETECTED: suspicious extensions within last ${lookbackMins} minutes. Count=$($hits.Count)"
    $hits | Select-Object -First 20 | ForEach-Object { Write-Log "HIT: $_" }
    exit 1
  }

  # 2) Burst count (soft signal; mainly for tuning / FP visibility)
  $burstMins = [int]$settings.Detection.BurstLookbackMinutes
  $sinceBurst = (Get-Date).AddMinutes(-1 * $burstMins)
  $burstCount = Get-BurstCount -targets $targets -since $sinceBurst -settings $settings
  Write-Log "INFO: file changes count (LastWriteTime) in last ${burstMins} min = $burstCount (soft)"

  # NOTE: default is "soft" → not triggering remediation unless you decide later
  $soft = [int]$settings.Detection.BurstCountSoftThreshold
  if ($burstCount -ge $soft) {
    Write-Log "SOFT WARNING: burstCount >= softThreshold ($soft). (Not triggering by default)"
    # 원하면 아래 주석 해제해서 burst도 트리거로 쓰면 됨.
    # exit 1
  }

  Write-Log "END Detect => Healthy"
  exit 0

} catch {
  try { Write-Log "ERROR: $($_.Exception.Message)" } catch {}
  exit 2
}