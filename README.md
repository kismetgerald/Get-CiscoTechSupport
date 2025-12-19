# Get-CiscoTechSupport

Automated collection of Cisco tech-support output from network devices with integrated STIG compliance checking.

## Overview

Get-CiscoTechSupport is a PowerShell-based automation tool designed for network administrators managing Cisco infrastructure. It automatically collects tech-support diagnostics from Cisco devices via SSH and optionally generates STIG (Security Technical Implementation Guide) compliance checklists, using Evaluate-STIG.

### Key Features

- **Automated Tech-Support Collection**: Schedule regular collection of diagnostic outputs from Cisco routers and switches
- **Two Collection Modes**:
  - **Device List Mode**: Collect from specific devices defined in a CSV file
  - **Discovery Mode**: Auto-discover devices using CDP, SNMP, or ARP
- **STIG Compliance Integration**: Automatic generation of STIG checklists using Evaluate-STIG
- **Air-Gapped Support**: Designed for secure, disconnected environments
- **Credential Security**: Uses Windows DPAPI for encrypted credential storage
- **Comprehensive Logging**: Detailed logs with rotation and retention policies
- **Windows Scheduled Tasks**: Fully automated execution with service account support

## System Requirements

### For Installation & Tech-Support Collection
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Network Access**: SSH connectivity to Cisco devices (port 22)
- **Permissions**: Administrator privileges for installation
- **Service Account**: Dedicated account for scheduled task execution

### For STIG Compliance Features (Optional)
- **PowerShell**: Version 7.x or higher
- **Evaluate-STIG**: External script (user-provided)

## Quick Start

### Installation

1. **Download the Latest Release**

   Visit the [Releases](../../releases) page and download the latest installer `Install-GetCiscoTechSupport_vX.X.X.ps1` and the full archive file `Get-CiscoTechSupport`.zip.

2. **Place both files in same folder**

   Save both the installer script and the archive file to a temporary location (e.g., `C:\Temp\Get-CiscoTechSupport`).

3. **Run the Installer**

   Open PowerShell as Administrator and run:

   ```powershell
   cd "C:\Temp\Get-CiscoTechSupport"
   .\Install-GetCiscotechSupport_vX.X.X.ps1 -ArchivePath .\Get-CiscoTechSupport.zip -InstallPath "C:\Admin\Scripts\Get-CiscoTechSupport"
   ```

4. **Follow the Interactive Prompts**

   The installer will guide you through:
   - Installation directory selection (default: `C:\Admin\Scripts\Get-CiscoTechSupport` | You can change this)
   - Service account credentials
   - Collection mode selection (Device List or Discovery)
   - Schedule configuration (Daily, Weekly, or Monthly)
   - Optional Evaluate-STIG integration

### Basic Usage

#### Device List Mode

1. **Create Device List**

   Edit `C:\Admin\Scripts\Get-CiscoTechSupport\Devices.txt`:

   ```txt
   10.0.0.1
   10.0.0.2
   10.0.1.1
   ```

2. **Configure Credentials**

   Run as the service account:

   ```powershell
   cd "C:\Admin\Scripts\Get-CiscoTechSupport"
   .\Python3\python.exe get-ciscotechsupport.py --save-credentials
   ```

   Follow the on-screen prompts to provide the credentials for the service account.

3. **Test Collection**

   ```powershell
   Get-ScheduledTask -TaskName "Cisco TechSupport*" | Start-ScheduledTask
   ```

4. **Verify Output**

   Check `C:\Admin\Scripts\Get-CiscoTechSupport\Results` for collected tech-support files.

#### Discovery Mode

Discovery mode automatically finds Cisco devices using network discovery protocols:

- **CDP Discovery**: Queries default gateway for network topology (recommended)
- **Hybrid**: Combines CDP and SNMP for thorough discovery
- **SNMP Scan**: Scans specific subnet via SNMP
- **ARP Discovery**: Parses local ARP table (limited to local subnet)

Configuration is completed during installation via interactive prompts.

## Installation Options

### Interactive Installation (Recommended)

```powershell
.\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\Get-CiscoTechSupport.zip"
```

The installer will prompt for all required configuration.

### Silent Installation

For automated deployments:

```powershell
.\Install-GetCiscoTechSupport.ps1 `
    -ArchivePath ".\Get-CiscoTechSupport.zip" `
    -InstallPath "C:\Admin\Scripts\Get-CiscoTechSupport" `
    -ServiceAccountCredential (Get-Credential) `
    -ScheduleType Weekly `
    -ScheduleTime "03:00" `
    -SkipTaskCreation:$false
```

### Installation with Evaluate-STIG Integration

```powershell
.\Install-GetCiscoTechSupport.ps1 `
    -ArchivePath ".\Get-CiscoTechSupport.zip" `
    -EnableEvaluateSTIG `
    -EvaluateSTIGPath "C:\Admin\STIGS\Evaluate-STIG\Evaluate-STIG.ps1" `
    -EvaluateSTIGScheduleDay 1 `
    -EvaluateSTIGScheduleTime "04:00"
```

## Multiple Collection Modes

You can run both Device List and Discovery modes simultaneously by installing the script twice with different collection mode selections. The installer will detect existing tasks and prompt appropriately:

- **Same mode**: Prompts to replace existing task
- **Different mode**: Proceeds without conflict, allowing coexistence

## Output Structure

```
C:\Admin\Scripts\Get-CiscoTechSupport\
├── Results\
│   ├── YYYY-MM-DD\
│   │   ├── DEVICE-NAME_tech-support_YYYY-MM-DD_HHmmss.txt
│   │   └── ...
│   └── STIG_Checklists\           (if Evaluate-STIG enabled)
│       ├── YYYY-MM-DD\
│       └── ...
├── Logs\
│   └── Get-CiscoTechSupport_YYYY-MM-DD.log
├── Devices.txt                     (Device List mode)
└── Get-CiscoTechSupport.ps1
```

## Scheduled Tasks

The installer creates Windows Scheduled Tasks for automation:

- **Tech-Support Collection**: Runs on configured schedule (Daily/Weekly/Monthly)
  - Task Name: `Cisco TechSupport Collector MODE DeviceList` or `MODE Discovery`
  - Default Time: 1st of month at 03:00 AM

- **STIG Checklist Generation** (if enabled): Runs monthly
  - Task Name: `Cisco STIG Checklist Generator`
  - Default Time: 1st of month at 04:00 AM

Both tasks run under the configured service account with elevated privileges.

## Uninstallation

```powershell
.\Install-GetCiscoTechSupport.ps1 -Uninstall
```

This removes:
- Installation directory and all scripts
- Scheduled tasks (all collection modes and STIG task)
- Python embedded distribution

**Note**: Saved credentials, device lists, and collected output files are NOT removed and must be manually deleted if needed.

## Security Considerations

### Credential Storage

- Credentials are encrypted using Windows DPAPI (Data Protection API)
- Credentials are user-specific and machine-specific
- Only the service account on the installation machine can decrypt credentials

### Network Security

- Uses SSH for device communication (encrypted)
- Supports SNMP v2c and v3 for discovery
- No credentials are logged or transmitted in clear text
- Follows principle of least privilege for service account

### Air-Gapped Environments

- No internet connectivity required
- All dependencies embedded in release archive
- PowerShell 7 detection supports offline scenarios
- Evaluate-STIG is not bundled and must be provided via external path

**IMPORTANT**: Store credential files securely and restrict access appropriately. Consider organizational security policies for credential management.

## Troubleshooting

### Installation Issues

**Problem**: "Administrator privileges required"
- **Solution**: Run PowerShell as Administrator

**Problem**: "Archive path not found"
- **Solution**: Verify the `-ArchivePath` parameter points to the correct `.zip` file

### Collection Issues

**Problem**: "No devices found in discovery mode"
- **Solution**: Check network connectivity, CDP/SNMP configuration on devices

**Problem**: "SSH connection timeout"
- **Solution**: Verify firewall rules, SSH enabled on devices, correct IP addresses

### STIG Task Issues

**Problem**: "PowerShell 7 not found"
- **Solution**: Install PowerShell 7.x from Microsoft or provide manual path during installation

**Problem**: "Evaluate-STIG.ps1 not found"
- **Solution**: Verify the path to Evaluate-STIG script is correct and accessible by service account

### Logs

Check detailed logs for troubleshooting:
- **Installation Log**: `C:\Logs\Get-CiscoTechSupport-Install_YYYYMMDD-HHMMSS.log`
- **Collection Log**: `C:\Admin\Scripts\Get-CiscoTechSupport\Logs\collection.log`

## Configuration Files

### Devices.csv (Device List Mode)

```csv
DeviceName,IPAddress
CORE-SWITCH-01,10.0.0.1
CORE-ROUTER-01,10.0.0.2
DISTRIBUTION-SW-01,10.0.1.1
```

### Script Parameters

The main script (`Get-CiscoTechSupport.ps1`) supports various parameters:

```powershell
# Setup credentials
.\Get-CiscoTechSupport.ps1 --setup-creds

# Discovery mode with specific method
.\Get-CiscoTechSupport.ps1 --discover --method cdp --gateway "10.0.0.1"

# Device list mode (default)
.\Get-CiscoTechSupport.ps1

# Custom device list location
.\Get-CiscoTechSupport.ps1 --device-list "C:\Custom\Path\Devices.csv"
```

## Advanced Features

### Log Rotation

Logs are automatically rotated:
- **Retention Period**: 30 days (configurable)
- **Location**: `Logs\` subdirectory
- **Format**: `Get-CiscoTechSupport_YYYY-MM-DD.log`

### Output Retention

Tech-support files are organized by date and can be managed manually or via organizational retention policies.

### Concurrent Collection Modes

Run both DeviceList and Discovery modes simultaneously by:
1. Complete first installation with one mode
2. Run installer again and select different mode
3. Both tasks will coexist and run on their respective schedules

## Support

For issues, questions, or feature requests:
- **Issues**: Submit via GitHub [Issues](../../issues)
- **Releases**: Check [Releases](../../releases) for latest version

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and release notes.

## License

MIT License
Copyright (c) 2025 KISMET AGBASI

## Contributing

Contributions are always welcome.  Just send me a Pull Request for review.

## Acknowledgments

- **Evaluate-STIG**: External STIG compliance tool integration support
- **Netmiko**: Python library for SSH device management
- **PySNMP**: Python SNMP library for network discovery

---

**Note**: This tool is designed for authorized network administration activities. Ensure you have proper authorization before scanning or collecting data from network devices.