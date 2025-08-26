[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\Detect-RemoteAdminTools.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function NowZ { (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz') }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Detect Remote Admin Tools (Registry + Filesystem) ==="

$ToolPatterns=@('TeamViewer','AnyDesk','Ammyy','RemoteUtilities','UltraViewer','AeroAdmin')
$RegPaths=@(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$SearchRoots=@("C:\Program Files","C:\Program Files (x86)","$env:ProgramData","$env:APPDATA","$env:LOCALAPPDATA","C:\Users\Public")

$Detections=@()
$ts = NowZ
$lines=@()

try{
  
  $regKeysScanned = 0
  foreach($path in $RegPaths){
    $items = @(Get-ItemProperty $path -ErrorAction SilentlyContinue)
    foreach($it in $items){
      $regKeysScanned++
      $name=$it.DisplayName
      if($name){
        foreach($pattern in $ToolPatterns){
          if($name -match [regex]::Escape($pattern)){
            $Detections += [pscustomobject]@{
              source='Registry'
              name=$name
              version=$it.DisplayVersion
              path=$it.PSPath
            }
            Write-Log "Flagged (Registry): $name" 'WARN'
            break
          }
        }
      }
    }
  }

  foreach($root in $SearchRoots){
    foreach($pattern in $ToolPatterns){
      try{
        $dirs = @(
          Get-ChildItem -LiteralPath $root -Directory -Recurse -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -match [regex]::Escape($pattern) }
        )
        foreach($dir in $dirs){
          try{
            Get-ChildItem -LiteralPath $dir.FullName -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object{
              $Detections += [pscustomobject]@{
                source='Filesystem'
                name=$_.Name
                version=$null
                path=$_.FullName
              }
              Write-Log "Flagged (Filesystem): $($_.FullName)" 'WARN'
            }
          }catch{}
        }

        Get-ChildItem -LiteralPath $root -Filter ("{0}*.exe" -f $pattern) -Recurse -ErrorAction SilentlyContinue | ForEach-Object{
          $Detections += [pscustomobject]@{
            source='Filesystem'
            name=$_.Name
            version=$null
            path=$_.FullName
          }
          Write-Log "Flagged (Filesystem): $($_.FullName)" 'WARN'
        }
      }catch{}
    }
  }

  $Detections = $Detections | Sort-Object name, path -Unique

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'detect_remote_admin_tools'
    copilot_action = $true
    type           = 'verify_source'
    reg_paths      = $RegPaths
    search_roots   = $SearchRoots
    patterns       = $ToolPatterns
    reg_keys_scanned = $regKeysScanned
    detections_count = $Detections.Count
  } | ConvertTo-Json -Compress -Depth 6)

  foreach($d in $Detections){
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'detect_remote_admin_tools'
      copilot_action = $true
      type           = 'detection'
      source         = $d.source
      name           = $d.name
      version        = $d.version
      path           = $d.path
    } | ConvertTo-Json -Compress -Depth 5)
  }

  $summary = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'detect_remote_admin_tools'
    copilot_action = $true
    type           = 'summary'
    total_found    = $Detections.Count
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 6 )) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'

  Write-Host "`n=== Remote Admin Tool Detection Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Tools Found: $($Detections.Count)"
  if($Detections.Count -gt 0){
    $Detections | Format-Table -AutoSize
  } else {
    Write-Host "No remote admin tools detected."
  }
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err = [pscustomobject]@{
    timestamp      = NowZ
    host           = $HostName
    action         = 'detect_remote_admin_tools'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(($err | ConvertTo-Json -Compress -Depth 6)) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
