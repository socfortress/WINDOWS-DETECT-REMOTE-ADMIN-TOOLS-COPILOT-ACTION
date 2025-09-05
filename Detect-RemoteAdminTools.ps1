[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\Detect-Remote-Admin-Tools-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [int]   $MaxScanSeconds = 120,
  [int]   $MaxDetections  = 200
)

$ErrorActionPreference = 'Stop'
$ScriptName = "Detect-Remote-Admin-Tools"
$HostName   = $env:COMPUTERNAME
$LogMaxKB   = 100
$LogKeep    = 5
$RunStart   = Get-Date
$sw = [System.Diagnostics.Stopwatch]::StartNew()

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:sszzz"
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    default { Write-Host $line }
  }
  try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}
function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    $sizeKB = [math]::Floor((Get-Item $LogPath).Length / 1KB)
    if ($sizeKB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 1; $i--) {
        $src = "$LogPath.$i"; $dst = "$LogPath." + ($i + 1)
        if (Test-Path $src) { Move-Item -Force $src $dst -ErrorAction SilentlyContinue }
      }
      Move-Item -Force $LogPath "$LogPath.1" -ErrorAction SilentlyContinue
    }
  }
}
function New-ArJsonLine { param([hashtable]$Fields)
  $std = [ordered]@{
    timestamp      = (Get-Date).ToUniversalTime().ToString("o")
    host           = $HostName
    action         = $ScriptName
    copilot_action = $true
  }
  ($std + $Fields) | ConvertTo-Json -Compress
}
function Commit-NDJSON { param([string[]]$Lines,[string]$Path=$ARLog)
  if (-not $Lines -or $Lines.Count -eq 0) {
    $Lines = @( New-ArJsonLine @{ item="status"; status="no_results"; message="no detections" } )
  }
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  try {
    [System.IO.File]::WriteAllLines($tmp, $Lines, [System.Text.Encoding]::ASCII)
    try { Move-Item -Force -Path $tmp -Destination $Path }
    catch { Write-Log "Primary move to $Path failed; writing .new fallback" "WARN"; Move-Item -Force -Path $tmp -Destination ($Path + ".new") }
  } finally { if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue } }
  foreach ($p in @($Path, ($Path + ".new"))) {
    if (Test-Path $p) {
      $fi = Get-Item $p
      $head = Get-Content -Path $p -TotalCount 1 -ErrorAction SilentlyContinue
      if (-not $head) { $head = "<empty>" }
      Write-Log ("VERIFY: path={0} size={1}B first_line={2}" -f $fi.FullName, $fi.Length, $head) "INFO"
    }
  }
}

$ToolPatterns = @('TeamViewer','AnyDesk','Ammyy','RemoteUtilities','UltraViewer','AeroAdmin')
$RegPaths = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$SearchRoots = @("C:\Program Files","C:\Program Files (x86)","$env:ProgramData","$env:APPDATA","$env:LOCALAPPDATA","C:\Users\Public")

Rotate-Log
Write-Log "=== SCRIPT START : $ScriptName (host=$HostName) ===" "INFO"

try {
  $lines = @()
  $detections = New-Object System.Collections.Generic.List[object]
  $regKeysScanned = 0

  $lines += New-ArJsonLine @{ item="config"; patterns=$ToolPatterns; reg_paths=$RegPaths; search_roots=$SearchRoots }

  Write-Log "Scanning registry uninstall keys..." "INFO"
  foreach ($path in $RegPaths) {
    if ($sw.Elapsed.TotalSeconds -ge $MaxScanSeconds) { Write-Log "Time budget reached (registry phase)" "WARN"; break }
    $items = @(Get-ItemProperty $path -ErrorAction SilentlyContinue)
    foreach ($it in $items) {
      $regKeysScanned++
      $name = $it.DisplayName
      if ($name) {
        foreach ($pattern in $ToolPatterns) {
          if ($name -match [regex]::Escape($pattern)) {
            $detections.Add([pscustomobject]@{ source='Registry'; name=$name; version=$it.DisplayVersion; path=$it.PSPath })
            Write-Log "Flagged (Registry): $name" "WARN"
            break
          }
        }
      }
      if ($sw.Elapsed.TotalSeconds -ge $MaxScanSeconds -or $detections.Count -ge $MaxDetections) { break }
    }
  }

  Write-Log "Scanning filesystem roots (dir-name match only)..." "INFO"
  foreach ($root in $SearchRoots) {
    if ($sw.Elapsed.TotalSeconds -ge $MaxScanSeconds) { Write-Log "Time budget reached (filesystem phase)" "WARN"; break }
    foreach ($pattern in $ToolPatterns) {
      if ($sw.Elapsed.TotalSeconds -ge $MaxScanSeconds) { break }
      try {
        $candidateDirs = Get-ChildItem -LiteralPath $root -Directory -Recurse -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -match [regex]::Escape($pattern) }
        foreach ($dir in $candidateDirs) {
          if ($sw.Elapsed.TotalSeconds -ge $MaxScanSeconds -or $detections.Count -ge $MaxDetections) { break }
          try {
            Get-ChildItem -LiteralPath $dir.FullName -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
              $detections.Add([pscustomobject]@{ source='Filesystem'; name=$_.Name; version=$null; path=$_.FullName })
              Write-Log "Flagged (Filesystem): $($_.FullName)" "WARN"
            }
          } catch {}
        }
      } catch {}
      if ($detections.Count -ge $MaxDetections) { Write-Log "MaxDetections cap reached ($MaxDetections)" "WARN"; break }
    }
  }

  $detections = $detections | Sort-Object name, path -Unique
  $lines = @(
    New-ArJsonLine @{
      item             = "summary"
      total_found      = $detections.Count
      reg_keys_scanned = $regKeysScanned
      duration_s       = [math]::Round($sw.Elapsed.TotalSeconds,1)
      capped           = ($detections.Count -ge $MaxDetections)
      timed_out        = ($sw.Elapsed.TotalSeconds -ge $MaxScanSeconds)
    }
  ) + $lines

  foreach ($d in $detections) {
    $lines += New-ArJsonLine @{ item="detection"; source=$d.source; name=$d.name; version=$d.version; path=$d.path }
  }

  Commit-NDJSON -Lines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) "INFO"
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  Commit-NDJSON -Lines @( New-ArJsonLine @{ item="error"; status="error"; error="$($_.Exception.Message)" } ) -Path $ARLog
  Write-Log "Error NDJSON written" "INFO"
}
finally {
  $sw.Stop()
  $dur = [int]$sw.Elapsed.TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ===" "INFO"
}
