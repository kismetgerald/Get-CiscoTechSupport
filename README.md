# Get-CiscoTechSupport

Automated collection of Cisco tech-support diagnostics with STIG compliance checking and email reporting for DoD network environments.

## Overview

Get-CiscoTechSupport automates the collection of diagnostic outputs from Cisco network devices via SSH, with optional STIG (Security Technical Implementation Guide) compliance checking and HTML email notifications. Designed for secure, air-gapped DoD environments.

### Key Features

- **Automated Tech-Support Collection** - Schedule regular diagnostic collection from Cisco routers and switches
- **Dual Collection Modes** - Device List mode (specific devices) or Discovery mode (auto-discover via CDP/SNMP/ARP)
- **Email Notifications** - Professional HTML reports with audit metadata and detailed attachments
- **STIG Compliance Integration** - Automatic checklist generation using Evaluate-STIG
- **Air-Gapped Ready** - All dependencies embedded, no internet connectivity required
- **Secure Credential Storage** - Windows DPAPI encryption for credentials and SMTP passwords
- **Service Account Execution** - Runs as dedicated service account with proper isolation
- **Comprehensive Audit Trail** - Detailed logging with DoD compliance metadata

## Quick Start

### 1. Download Release

Visit the [Releases](../../releases) page and download:
- `Install-GetCiscoTechSupport_vX.X.X.ps1` (installer)
- `Get-CiscoTechSupport.zip` (application archive)

### 2. Install

```powershell
# Open PowerShell as Administrator
cd "C:\Temp"
.\Install-GetCiscoTechSupport_vX.X.X.ps1 -ArchivePath .\Get-CiscoTechSupport.zip
```

### 3. Configure via Interactive Prompts

The installer guides you through:
- **Installation path** (default: `C:\Scripts\Get-CiscoTechSupport`)
- **Service account** credentials
- **Collection mode** (Device List or Discovery)
- **Schedule** (Daily, Weekly, or Monthly)
- **Email notifications** (optional)
- **Evaluate-STIG integration** (optional)

### 4. Setup Credentials

After installation, configure device credentials as the service account:

```powershell
cd "C:\Scripts\Get-CiscoTechSupport"
.\Python3\python.exe get-ciscotechsupport.py --save-credentials
```

### 5. Verify

Check the scheduled task was created:

```powershell
Get-ScheduledTask -TaskName "Cisco TechSupport*"
```

## System Requirements

### Core Requirements
- **OS**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: 5.1+ (for installation)
- **Network**: SSH access to Cisco devices (port 22)
- **Privileges**: Administrator (for installation only)
- **Service Account**: Dedicated account for scheduled execution

### Optional Features
- **STIG Compliance**: PowerShell 7.x + Evaluate-STIG script
- **Email Notifications**: SMTP server access (SSL/TLS/STARTTLS supported)

## Collection Modes

### Device List Mode
Collects from specific devices defined in `devices.txt`:

```txt
10.0.0.1
10.0.0.2
router.domain.com
```

### Discovery Mode
Auto-discovers Cisco devices using:
- **CDP Discovery** (recommended) - Queries gateway for network topology
- **Hybrid** - CDP + SNMP for thorough discovery
- **SNMP Scan** - Scans specific subnet
- **ARP Discovery** - Parses local ARP table

## Email Notifications

Professional HTML email reports include:
- **Executive Summary** - Success/failure counts with color-coded stats
- **Audit Metadata** - DoD compliance fields (user, timestamp, hostname, domain, etc.)
- **Device Details** - Status and results for each device
- **Detailed Attachment** - Full HTML report with complete audit trail

### Email Configuration
Configured during installation or via installer parameters:
- SMTP server and port
- Encryption (SSL/TLS/STARTTLS)
- From/To addresses
- Subject line (auto-dated)
- Optional authentication (credentials stored via DPAPI)

## Output Structure

```
C:\Scripts\Get-CiscoTechSupport\
├── Results\
│   ├── YYYY-MM-DD\
│   │   └── DEVICE_tech-support_YYYY-MM-DD_HHmmss.txt
│   └── STIG_Checklists\          (if Evaluate-STIG enabled)
├── Logs\
│   └── collection_YYYY-MM-DD.log
├── devices.txt                     (Device List mode)
├── .cisco_credentials              (encrypted)
└── .smtp_credentials               (encrypted, if email enabled)
```

## Advanced Installation

### Silent Installation

```powershell
$cred = Get-Credential  # Service account
.\Install-GetCiscoTechSupport.ps1 `
    -ArchivePath ".\Get-CiscoTechSupport.zip" `
    -InstallPath "C:\Scripts\Get-CiscoTechSupport" `
    -ServiceAccountCredential $cred `
    -ScheduleType Weekly `
    -ScheduleTime "03:00"
```

### With STIG Integration

```powershell
.\Install-GetCiscoTechSupport.ps1 `
    -ArchivePath ".\Get-CiscoTechSupport.zip" `
    -EnableEvaluateSTIG `
    -EvaluateSTIGPath "C:\STIGS\Evaluate-STIG\Evaluate-STIG.ps1" `
    -EvaluateSTIGScheduleDay 1 `
    -EvaluateSTIGScheduleTime "04:00"
```

### Multiple Collection Modes

Run both Device List and Discovery modes simultaneously by installing twice with different modes. The installer handles conflict detection automatically.

## Uninstallation

```powershell
.\Install-GetCiscoTechSupport.ps1 -Uninstall
```

Removes:
- Installation directory and scripts
- All scheduled tasks (collection + STIG)
- Embedded Python distribution

**Note**: Credentials, device lists, and collected outputs are preserved and must be manually deleted if needed.

## Security & Compliance

### Credential Security
- **Windows DPAPI encryption** - Machine and user-specific encryption
- **Service account isolation** - Credentials only accessible by service account
- **File ACL protection** - Hidden files with restricted permissions
- **No cleartext storage** - All passwords encrypted at rest

### Network Security
- **SSH encryption** - All device communication over SSH
- **SMTP TLS/SSL** - Encrypted email transport
- **SNMP v3 support** - Encrypted SNMP discovery
- **No credential logging** - Passwords never logged or transmitted in clear

### DoD Compliance
- **STIG V-253289** - Secondary Logon service properly managed
- **Audit trail** - Complete metadata in all outputs and emails
- **RMF requirements** - Logging, encryption, least privilege
- **Air-gapped deployment** - No internet connectivity required

**For detailed security documentation, see [ARCHITECTURE.md](ARCHITECTURE.md)**

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical architecture, security, and design details
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and release notes
- **[Wiki](../../wiki)** - Detailed guides and troubleshooting (coming soon)

### Planned Wiki Pages
- Installation Guide (detailed walkthrough)
- Configuration Reference (all parameters)
- Discovery Mode Setup
- Email Configuration Guide
- STIG Integration Guide
- Troubleshooting Guide
- Security Best Practices
- Development & Contributing

## Support & Contributing

- **Issues**: [GitHub Issues](../../issues)
- **Releases**: [Latest Releases](../../releases)
- **Contributing**: Pull requests welcome

## Troubleshooting

### Quick Diagnostics

**Installation Log**: `C:\Logs\Get-CiscoTechSupport-Install_YYYYMMDD-HHMMSS.log`
**Collection Log**: `C:\Scripts\Get-CiscoTechSupport\Logs\collection_YYYY-MM-DD.log`

### Common Issues

| Issue | Solution |
|-------|----------|
| "Administrator privileges required" | Run PowerShell as Administrator |
| "Archive path not found" | Verify .zip file location |
| "No devices found" (discovery) | Check CDP/SNMP configuration |
| "SSH timeout" | Verify firewall rules and device SSH access |
| "PowerShell 7 not found" (STIG) | Install PowerShell 7.x |
| "Email send failed" | Check SMTP server, port, credentials |

**For detailed troubleshooting, see the [Wiki](../../wiki)** (coming soon)

## Version History

**Current Version**: 0.0.5

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

## License

MIT License
Copyright (c) 2025 Kismet Agbasi

## Acknowledgments

- **Evaluate-STIG** - STIG compliance tool integration
- **Netmiko** - Python SSH library for Cisco devices
- **PySNMP** - SNMP library for network discovery
- **Jinja2** - HTML template engine for email reports

---

**IMPORTANT**: This tool is designed for authorized network administration only. Ensure proper authorization before scanning or collecting data from network devices.
