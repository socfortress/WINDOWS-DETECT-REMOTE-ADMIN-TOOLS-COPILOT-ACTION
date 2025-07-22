# PowerShell Detect Remote Admin Tools Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for detecting remote administration tools (RATs) via registry and filesystem scans.

---

## Overview

The `Detect-RemoteAdminTools.ps1` script scans the Windows registry and common filesystem locations for known remote administration tools (such as TeamViewer, AnyDesk, Ammyy, RemoteUtilities, UltraViewer, AeroAdmin). It flags detections, logs all actions, results, and errors in both a script log and an active-response log, and outputs structured JSON for SOAR/SIEM integration.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Detection Logic**: Identifies remote admin tools in registry and filesystem
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\Detect-RemoteAdminTools.ps1 [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter | Type   | Default Value                                                    | Description                                  |
|-----------|--------|------------------------------------------------------------------|----------------------------------------------|
| `LogPath` | string | `$env:TEMP\Detect-RemoteAdminTools.log`                          | Path for execution logs                      |
| `ARLog`   | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\Detect-RemoteAdminTools.ps1

# Custom log path
.\Detect-RemoteAdminTools.ps1 -LogPath "C:\Logs\RemoteAdminTools.log"

# Integration with OSSEC/Wazuh active response
.\Detect-RemoteAdminTools.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Message` (string): The log message
- `Level` (ValidateSet): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

**Features**:
- Timestamped output
- Color-coded console output
- File logging
- Verbose/debug support

**Usage**:
```powershell
Write-Log "Flagged (Registry): $name" 'WARN'
Write-Log "Flagged (Filesystem): $($_.FullName)" 'WARN'
Write-Log "JSON reports (full + flagged) appended to $ARLog"
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation
   - Start time logging

2. **Execution**
   - Scans registry uninstall keys for known RATs
   - Scans common filesystem locations for RAT executables
   - Flags and logs detections

3. **Completion**
   - Outputs full inventory and flagged detections as JSON to the active response log
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details as JSON

---

## JSON Output Format

### Full Report Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "detect_remote_admin_tools",
  "item_count": 2,
  "detections": [
    {
      "source": "Registry",
      "name": "TeamViewer",
      "version": "15.42.4",
      "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\..."
    },
    {
      "source": "Filesystem",
      "name": "AnyDesk.exe",
      "version": null,
      "path": "C:\\Program Files\\AnyDesk\\AnyDesk.exe"
    }
  ]
}
```

### Flagged Detections Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "detect_remote_admin_tools_flagged",
  "flagged_count": 2,
  "flagged_detections": [
    {
      "source": "Registry",
      "name": "TeamViewer",
      "version": "15.42.4",
      "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\..."
    }
  ]
}
```

### Error Example

```json
{
  "timestamp": "2025-07-22T10:31:10.456Z",
  "host": "HOSTNAME",
  "action": "detect_remote_admin_tools",
  "status": "error",
  "error": "Access is denied"
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the detection logic as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **Registry/Filesystem Access Issues**: Ensure the script has access to all relevant locations.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation and incident response
