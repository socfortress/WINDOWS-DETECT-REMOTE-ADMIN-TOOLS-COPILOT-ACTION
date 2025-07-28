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
$Report = [PSCustomObject]@{
  host        = $HostName
  timestamp   = $timestamp
  action      = "detect_remote_admin_tools"
  total_found = $Detections.Count
  detections  = $Detections
  copilot_soar = $true
}
$json = $Report | ConvertTo-Json -Depth 5 -Compress
$tempFile = "$env:TEMP\arlog.tmp"
Set-Content -Path $tempFile -Value $json -Encoding ascii -Force

try {
  Move-Item -Path $tempFile -Destination $ARLog -Force
  Write-Log "Log file replaced at $ARLog"
} catch {
  Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
  Write-Log "Log locked, wrote results to $ARLog.new" 'WARN'
}
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
