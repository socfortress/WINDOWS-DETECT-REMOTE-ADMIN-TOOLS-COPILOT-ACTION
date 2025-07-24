[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\Detect-RemoteAdminTools.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5
$runStart = Get-Date

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

Rotate-Log

try {
  if (Test-Path $ARLog) {
    Remove-Item -Path $ARLog -Force -ErrorAction Stop
  }
  New-Item -Path $ARLog -ItemType File -Force | Out-Null
  Write-Log "Active response log cleared for fresh run."
} catch {
  Write-Log "Failed to clear ${ARLog}: $($_.Exception.Message)" 'WARN'
}

Write-Log "=== SCRIPT START : Detect Remote Admin Tools (Registry + Filesystem) ==="

$ToolPatterns = @('TeamViewer','AnyDesk','Ammyy','RemoteUtilities','UltraViewer','AeroAdmin')
$RegPaths = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$Detections = @()

foreach ($path in $RegPaths) {
  $Detections += Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
    $name = $_.DisplayName
    if ($name) {
      foreach ($pattern in $ToolPatterns) {
        if ($name -match $pattern) {
          $Detections += [PSCustomObject]@{
            source  = 'Registry'
            name    = $name
            version = $_.DisplayVersion
            path    = $path
          }
          Write-Log "Flagged (Registry): $name" 'WARN'
        }
      }
    }
  }
}

$SearchRoots = @("C:\Program Files","C:\Program Files (x86)","$env:ProgramData","$env:APPDATA","$env:LOCALAPPDATA","C:\Users\Public")

foreach ($root in $SearchRoots) {
  foreach ($pattern in $ToolPatterns) {
    try {
      Get-ChildItem -Path $root -Filter "$pattern*.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $Detections += [PSCustomObject]@{
          source  = 'Filesystem'
          name    = $_.Name
          version = $null
          path    = $_.FullName
        }
        Write-Log "Flagged (Filesystem): $($_.FullName)" 'WARN'
      }
    } catch {}
  }
}

$Detections = $Detections | Sort-Object name, path -Unique
$timestamp = (Get-Date).ToString("o")

$FullReport = @{
  host = $HostName
  timestamp = $timestamp
  action = "detect_remote_admin_tools"
  item_count = $Detections.Count
  detections = $Detections
}

$FlaggedReport = @{
  host = $HostName
  timestamp = $timestamp
  action = "detect_remote_admin_tools_flagged"
  flagged_count = $Detections.Count
  flagged_detections = $Detections
}

$FullReport   | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
$FlaggedReport| ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000

Write-Log "JSON reports (full + flagged) written to $ARLog"
Write-Host "`n=== Remote Admin Tool Detection Report ==="
Write-Host "Host: $HostName"
Write-Host "Tools Found: $($Detections.Count)"

if ($Detections.Count -gt 0) {
  $Detections | Format-Table -AutoSize
} else {
  Write-Host "No remote admin tools detected."
}

$dur = [int]((Get-Date) - $runStart).TotalSeconds
Write-Log "=== SCRIPT END : duration ${dur}s ==="
