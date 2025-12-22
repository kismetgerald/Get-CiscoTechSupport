# Get-CiscoTechSupport - Architecture Documentation

## Document Information

**Project**: Get-CiscoTechSupport
**Version**: 0.0.6
**Date**: 2025-12-21
**Status**: Production Ready
**Target Environment**: Secure/Air-Gapped Windows Networks

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Architecture Design](#architecture-design)
4. [Component Specifications](#component-specifications)
5. [Security Architecture](#security-architecture)
6. [Data Flow](#data-flow)
7. [Deployment Architecture](#deployment-architecture)
8. [Compliance Considerations](#compliance-considerations)
9. [Operational Architecture](#operational-architecture)
10. [Error Handling and Logging](#error-handling-and-logging)
11. [Dependencies and External Integrations](#dependencies-and-external-integrations)
12. [Testing and Validation](#testing-and-validation)

---

## Executive Summary

Get-CiscoTechSupport is an enterprise-grade automation solution designed to collect diagnostic outputs from Cisco network infrastructure and optionally generate STIG compliance checklists. The system is architected for secure, air-gapped environments with emphasis on credential protection, audit logging, and unattended operation.

### Key Architectural Principles

- **Security First**: DPAPI credential encryption, no clear-text credential storage
- **Air-Gap Compatible**: No internet dependency, embedded runtime
- **Least Privilege**: Service account isolation, role-based execution
- **Audit Trail**: Comprehensive logging with retention policies
- **Fault Tolerance**: Graceful degradation, error recovery
- **Modularity**: Separation of concerns, pluggable components

---

## System Overview

### Purpose

Automate the collection and archival of Cisco device diagnostic outputs for:
- Troubleshooting and root cause analysis
- Compliance auditing and documentation
- Security posture assessment (STIG)
- Change management baselines

### Scope

**In Scope**:
- Cisco IOS/IOS-XE router and switch tech-support collection
- Network device discovery (CDP, SNMP, ARP)
- STIG checklist generation integration
- Email notification system with HTML reporting
- Windows Scheduled Task automation
- Credential management and encryption

**Out of Scope**:
- Non-Cisco device support
- Real-time monitoring or alerting
- Configuration management or deployment
- Network topology visualization

### Stakeholders

- **Network Administrators**: Primary users, configure and operate the system
- **Security Teams**: Review STIG compliance outputs
- **Compliance Auditors**: Verify security controls and audit trails
- **System Administrators**: Manage service accounts and scheduled tasks

---

## Architecture Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Server/Workstation                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │           Get-CiscoTechSupport Application                 │ │
│  │                                                            │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │ │
│  │  │  Installer   │  │ Main Script  │  │  Evaluate-STIG  │   │ │
│  │  │   (PS 5.1+)  │  │   (Python)   │  │    (PS 7.x)     │   │ │
│  │  └──────────────┘  └──────────────┘  └─────────────────┘   │ │
│  │         │                  │                    │          │ │
│  │  ┌──────▼──────────────────▼────────────────────▼───────┐  │ │
│  │  │         Embedded Python 3.14 Runtime                 │  │ │
│  │  │                                                      │  │ │
│  │  │  ┌─────────┐ ┌─────────┐ ┌──────────────┐ ┌──────┐ │  │ │
│  │  │  │ Netmiko │ │ PySNMP  │ │ Cryptography │ │Jinja2│ │  │ │
│  │  │  └─────────┘ └─────────┘ └──────────────┘ └──────┘ │  │ │
│  │  │  (SSH/CLI)   (Discovery)  (SSH Security)  (Email)   │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                                                            | │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │        Windows Scheduled Tasks (Service Account)     │  │ │
│  │  │  • Cisco TechSupport Collector MODE DeviceList       │  │ │
│  │  │  • Cisco TechSupport Collector MODE Discovery        │  │ │
│  │  │  • Cisco STIG Checklist Generator (optional)         │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                   Storage Subsystem                        │ │
│  │  • Encrypted Credentials (DPAPI - Cisco & SMTP)            │ │
│  │  • Configuration Files (CSV)                               │ │
│  │  • Output Archives (Tech-Support, STIG)                    │ │
│  │  • Audit Logs (30-day retention)                           │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ SSH (Port 22)
                              │ SNMP (Port 161)
                              │ SMTP (Ports 25/587/465)
                              ▼
        ┌────────────────────────────────────────┐
        │       Cisco Network Infrastructure     │
        │  • Routers (IOS/IOS-XE)                │
        │  • Switches (IOS/IOS-XE)               │
        │  • CDP-enabled devices                 │
        │  • SNMP-enabled devices                │
        └────────────────────────────────────────┘
                              │
                              │ SMTP/TLS
                              ▼
        ┌────────────────────────────────────────┐
        │          SMTP Mail Server              │
        │  • Email Relay                         │
        │  • TLS/SSL Encryption                  │
        │  • Authentication (optional)           │
        └────────────────────────────────────────┘
```

### Architectural Layers

#### 1. Presentation Layer
- **PowerShell Console Interface**: Interactive prompts during installation and credential setup
- **Logging Output**: Color-coded console messages for user feedback
- **Task Scheduler UI**: Native Windows interface for task management

#### 2. Application Layer
- **Installer Module**: Installation orchestration, validation, and task creation
- **Collection Engine**: Device discovery and tech-support retrieval
- **Email Notification Module**: HTML report generation and SMTP delivery
- **STIG Integration Module**: Checklist generation coordination
- **Credential Manager**: Secure credential storage and retrieval (Cisco & SMTP)

#### 3. Runtime Layer
- **PowerShell 5.1+**: Windows native scripting environment
- **PowerShell 7.x**: Cross-platform runtime for Evaluate-STIG (optional)
- **Embedded Python 3.14**: Self-contained runtime with pre-installed packages

#### 4. Data Layer
- **Encrypted Credential Store**: DPAPI-protected XML files
- **Configuration Store**: CSV device lists, schedule configurations
- **Output Repository**: Date-organized tech-support and STIG outputs
- **Audit Log Repository**: Structured log files with rotation

#### 5. Infrastructure Layer
- **Windows Task Scheduler**: Unattended execution framework
- **Service Account**: Dedicated identity for scheduled operations
- **File System ACLs**: Access control for sensitive files
- **Network Infrastructure**: SSH and SNMP connectivity to devices

---

## Component Specifications

### 1. Installation Component (`Install-GetCiscoTechSupport.ps1`)

**Purpose**: Orchestrate deployment, configuration, and scheduled task creation.

**Key Functions**:

| Function | Purpose | Security Impact |
|----------|---------|----------------|
| `Install-CiscoCollector` | Main installation orchestration | Creates service account tasks |
| `Test-Administrator` | Verify elevated privileges | Prevents privilege escalation |
| `Expand-ArchiveCompat` | Extract embedded Python | Validates archive integrity |
| `Get-ServiceAccountCredential` | Collect service account creds | Credential in-memory only |
| `New-CiscoCollectorTask` | Create scheduled task | Registers with service account |
| `Remove-CiscoCollectorTask` | Task removal with mode awareness | Supports multiple collection modes |
| `Get-PowerShell7Path` | Detect PowerShell 7 for STIG | Air-gap compatible detection |
| `New-EvaluateSTIGTask` | Create STIG task with monthly trigger | COM-based monthly scheduling |
| `Uninstall-CiscoCollector` | Clean removal of all components | Preserves credentials/outputs |

**Installation Flow**:
```
Start → Validate Admin → Extract Archive → Validate Python →
Setup Service Account → Configure Collection Mode →
Create Scheduled Task(s) → Optional: Setup Evaluate-STIG →
Configure Credentials → Completion
```

**State Transitions**:
- **Pre-Installation**: System validation, privilege check
- **Installation**: File extraction, directory creation
- **Configuration**: Credential setup, task creation
- **Post-Installation**: Validation, initial task run offer
- **Operational**: Scheduled execution

### 2. Collection Component (`get-ciscotechsupport.py`)

**Purpose**: Execute device discovery and tech-support collection.

**Execution Modes**:

#### Device List Mode
- **Input**: CSV file with DeviceName, IPAddress columns
- **Process**: Iterate devices, SSH to each, execute `show tech-support`
- **Output**: Individual tech-support files per device
- **Error Handling**: Skip failed devices, log errors, continue execution

#### Discovery Mode
- **Methods**:
  - **CDP Discovery**: Query default gateway neighbors recursively
  - **Hybrid**: CDP + SNMP subnet scan
  - **SNMP Scan**: Subnet-based device enumeration
  - **ARP Discovery**: Local ARP table parsing (limited scope)

- **Process**:
  1. Discover devices using selected method
  2. Deduplicate device list
  3. Attempt SSH connection to each device
  4. Execute `show tech-support` command
  5. Archive output with timestamp

**Python Integration**:
- **Netmiko**: SSH connection management, Cisco CLI interaction
- **PySNMP**: SNMP v2c/v3 queries for discovery
- **Cryptography**: Secure SSH key exchange
- **Jinja2**: HTML email template rendering
- **MarkupSafe**: Safe HTML escaping for email content

### 3. Email Notification Component

**Purpose**: Generate HTML reports and send email notifications after collection completes.

**Architecture**:
- **HTML Report Generation**: Jinja2 template-based rendering
- **Email Delivery**: Python `email` and `smtplib` libraries
- **Credential Security**: DPAPI-encrypted SMTP credentials (`.smtp_credentials`)
- **Graceful Failure**: Email failures don't abort collection process
- **DoD Compliance Metadata**: Full audit trail in email reports

**Email Report Structure**:

```
┌────────────────────────────────────────────────────────┐
│              Email Notification                        │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │         EXECUTIVE SUMMARY                        │  │
│  │  • Collection Date/Time (UTC)                    │  │
│  │  • Total Devices                                 │  │
│  │  • Success Count (Green)                         │  │
│  │  • Failure Count (Red)                           │  │
│  │  • Success Rate Percentage                       │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │         AUDIT METADATA (DoD Compliance)          │  │
│  │  • Executed By: <Service Account>               │  │
│  │  • Execution Time: <UTC Timestamp>              │  │
│  │  • Collection Server: <Hostname>                │  │
│  │  • Domain: <Domain Name>                        │  │
│  │  • Collection Mode: DeviceList/Discovery        │  │
│  │  • Output Directory: <Path>                     │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │         DEVICE COLLECTION RESULTS                │  │
│  │  Device Name   | IP Address  | Status           │  │
│  │  ────────────────────────────────────────────    │  │
│  │  DEVICE01      | 10.0.0.1    | ✓ Success        │  │
│  │  DEVICE02      | 10.0.0.2    | ✗ Timeout        │  │
│  │  ...                                             │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  📎 Attachment: detailed_report.html                  │
│     (Full audit trail with timestamps, errors, etc.)  │
└────────────────────────────────────────────────────────┘
```

**SMTP Configuration Options**:

| Parameter | Description | Default |
|-----------|-------------|---------|
| **Server** | SMTP server hostname/IP | (Required) |
| **Port** | SMTP port | 587 |
| **Encryption** | SSL (465), STARTTLS (587), or None (25) | STARTTLS |
| **Authentication** | Username/password (optional) | None |
| **From Address** | Sender email address | (Required) |
| **To Address(es)** | Recipient email(s), comma-separated | (Required) |
| **Subject** | Email subject line | "Cisco Tech-Support Collection Report - [Date]" |

**Security Implementation**:
- **SMTP Credentials**: Stored in `.smtp_credentials` file using Windows DPAPI
- **Service Account Binding**: Credentials only decryptable by service account on installation machine
- **File ACLs**: Hidden file with service account-only access
- **Transport Security**: Supports TLS/SSL encryption for SMTP communication
- **No Clear-Text Logging**: SMTP passwords never logged or displayed

**Integration with Installer**:
```powershell
# Installer function: Start-SMTPCredentialSetup
1. Prompt user for SMTP configuration
2. Validate SMTP server connectivity
3. Collect authentication credentials (if required)
4. Use RunAs pattern with service account
5. Export credentials via Export-Clixml (DPAPI)
6. Apply file ACLs and hidden attribute
7. Add email parameters to scheduled task arguments
```

**Email Flow**:
```
Collection Complete → Build Summary Dict →
Load SMTP Credentials (DPAPI) →
Render Jinja2 Template →
Create MIME Multipart Message →
  ├─ HTML Body (Executive Summary + Metadata + Results)
  └─ HTML Attachment (Detailed Report)
→ Connect to SMTP Server (TLS/SSL) →
Authenticate (if required) →
Send Email →
Log Result (Success/Failure) →
Continue Execution (Graceful Failure)
```

### 4. STIG Integration Component

**Purpose**: Generate STIG compliance checklists from collected tech-support files.

**Architecture**:
- **Separate Scheduled Task**: Independent from collection tasks
- **Monthly Execution**: Runs on configurable day (default: 1st) at 04:00
- **PowerShell 7 Requirement**: Uses external Evaluate-STIG.ps1 script
- **Input**: Tech-support files from Results directory
- **Output**: STIG checklists in multiple formats (CKLB, XCCDF, Summary)

**Task Trigger Implementation**:
```powershell
# PowerShell lacks native monthly day-of-month triggers
# Solution: COM object manipulation

1. Create initial daily trigger
2. Use Schedule.Service COM object
3. Clear triggers and create new MONTHLYDATE trigger (Type=4)
4. Set DaysOfMonth bit mask (e.g., day 1 = 1, day 15 = 16384)
5. Set MonthsOfYear = 0xFFF (all 12 months)
6. Re-register task with service account credentials
```

### 5. Credential Management Component

**Security Architecture**:

```
User Input (Interactive/Parameter)
         │
         ▼
PSCredential Object (In-Memory)
         │
         ▼
SecureString → Encrypted Standard String
         │
         ▼
Windows DPAPI Encryption
         │
         ▼
XML File (Machine + User Bound)
         │
         ▼
File System (Service Account Access Only)
         │
         ▼
Hidden File with ACLs (Service Account Only)
```

**Credential Types**:
- **Cisco Device Credentials**: SSH username/password for device access
- **SNMP Community Strings**: v2c read-only community for device discovery
- **SNMP v3 Credentials**: Username, auth/priv protocols and passphrases for secure SNMP
- **SMTP Credentials**: Username/password for authenticated email delivery (optional)

**Storage Locations**:
- **Cisco/SNMP**: `<InstallPath>\.cisco_credentials`
- **SMTP**: `<InstallPath>\.smtp_credentials`

**Access Control Matrix**:

| Credential Type | File | NTFS ACLs | Attributes | DPAPI Binding |
|-----------------|------|-----------|-----------|---------------|
| Cisco SSH | `.cisco_credentials` | Service Account: Full, Admins: Read | Hidden, System | Machine + Service Account |
| SMTP Auth | `.smtp_credentials` | Service Account: Full, Admins: Read | Hidden, System | Machine + Service Account |

**Security Properties**:
- Only the service account on the installation machine can decrypt
- NTFS permissions restrict file access to service account (Admins read-only for recovery)
- Credentials never logged or transmitted in clear text
- Files hidden from casual browsing
- DPAPI keys managed by Windows LSA, inaccessible to users

### 6. Logging and Audit Component

**Log Architecture**:

| Log Type | Location | Retention | Purpose |
|----------|----------|-----------|---------|
| Installation | `Logs\Install_YYYY-MM-DD.log` | Permanent | Audit trail of installations |
| Collection | `Logs\Get-CiscoTechSupport_YYYY-MM-DD.log` | 30 days | Operational logs |
| STIG Generation | Embedded in collection logs | 30 days | STIG task execution |

**Log Levels**:
- **INFO**: Normal operations, state transitions
- **SUCCESS**: Successful operations, milestones
- **WARNING**: Non-fatal issues, degraded functionality
- **ERROR**: Failures requiring attention
- **DEBUG**: Detailed troubleshooting information (conditional)

**Log Format**:
```
[YYYY-MM-DD HH:MM:SS] [LEVEL] Message text
```

**Logging Functions**:
- `Write-InstallLog`: Installation and configuration logging
- `-NoConsole` parameter: Suppresses console output for progress indicators
- Automatic log rotation based on date

---

## Security Architecture

### Threat Model

**Assets**:
- Network device credentials (HIGH value)
- SNMP community strings (MEDIUM value)
- Tech-support outputs (MEDIUM value - may contain sensitive config)
- Service account credentials (HIGH value)

**Threats**:
1. **Credential Theft**: Unauthorized access to stored credentials
2. **Privilege Escalation**: Misuse of service account
3. **Data Exfiltration**: Theft of tech-support outputs
4. **Man-in-the-Middle**: Interception of SSH/SNMP traffic
5. **Unauthorized Execution**: Malicious scheduled task modification

### Security Controls

#### 1. Credential Protection

**Control**: Windows DPAPI Encryption
- **Implementation**: `Export-Clixml` with DPAPI
- **Binding**: Machine + User (service account)
- **Key Storage**: Windows LSA Secrets (managed by OS)
- **Decryption**: Only possible by same user on same machine

**Control**: In-Memory Credential Handling
- **Implementation**: PSCredential and SecureString objects
- **Duration**: Exists only during execution, never persisted to disk in clear text
- **Garbage Collection**: Automatic cleanup by PowerShell runtime

**Control**: File System ACLs
- **Implementation**: NTFS permissions
- **Access**: Service account Read/Write, Administrators Read
- **Inheritance**: Disabled on credential files

#### 2. Network Security

**Control**: SSH Encryption
- **Protocol**: SSH v2
- **Cipher Suites**: AES-256-CTR, AES-128-CTR (Netmiko defaults)
- **Key Exchange**: Diffie-Hellman Group 14+
- **Authentication**: Username/Password (supports public key)
- **DoD Compliance**: Meets FIPS 140-2 encryption requirements

**Control**: SNMP Security
- **v2c**: Community string authentication (encrypted in storage)
- **v3**: AuthPriv mode with SHA-256/AES-256 support
- **Read-Only**: Uses read-only community/user
- **DoD Compliance**: SNMPv3 recommended for classified networks

**Control**: SMTP Security
- **TLS/SSL**: STARTTLS (587) or SSL (465) encryption
- **Cipher Suites**: TLS 1.2+ with AES-256
- **Certificate Validation**: Server certificate verification
- **Authentication**: SASL PLAIN over TLS (encrypted credentials)

#### 3. Execution Security

**Control**: Service Account Isolation
- **Principle**: Dedicated account, not shared with other services
- **Privileges**: Local admin on collection server only
- **Network Access**: SSH to devices, SNMP queries
- **Interactive Logon**: Denied

**Control**: Code Signing (Recommended)
- **Implementation**: Sign PowerShell scripts with organizational certificate
- **Enforcement**: Set-ExecutionPolicy AllSigned
- **Validation**: Scripts verified before execution

**Control**: Task Scheduler Security
- **RunLevel**: Highest (required for network operations)
- **User Context**: Service account only
- **Password Storage**: Encrypted by Task Scheduler
- **Task Modification**: Requires administrator privileges

#### 4. Audit and Compliance

**Control**: Comprehensive Logging
- **Events Logged**: All credential access, device connections, failures
- **Log Protection**: Append-only during execution
- **Retention**: 30 days automatic, longer via organizational policy
- **Review**: Manual or SIEM integration

**Control**: Installation Audit Trail
- **Events**: Installation, configuration changes, uninstallation
- **Details**: User, timestamp, parameters, outcome
- **Permanence**: Installation logs not auto-deleted

### DoD-Specific Security Compliance

This solution has been designed with DoD security requirements in mind. Below is a comprehensive mapping to DoD security frameworks:

#### STIG (Security Technical Implementation Guide) Compliance

**Applicable STIGs**:
- Windows Server STIG (Operating System)
- Application Security and Development STIG
- Network Device Management STIG

**Key STIG Controls Addressed**:

| STIG ID | Control | Implementation | Status |
|---------|---------|----------------|--------|
| **V-253289** | Secondary Logon Service | Temporarily enabled for RunAs, immediately disabled after credential setup | ✅ Compliant |
| **V-220857** | Password Storage | DPAPI encryption, no clear-text storage | ✅ Compliant |
| **V-220858** | Audit Logging | Comprehensive logging with UTC timestamps | ✅ Compliant |
| **V-220912** | Least Privilege | Service account with minimal required permissions | ✅ Compliant |
| **V-220725** | SSH Encryption | AES-256-CTR, DH Group 14+, SSH v2 only | ✅ Compliant |
| **V-220947** | File Permissions | NTFS ACLs on credential files | ✅ Compliant |

**STIG Checklist Integration**:
- Native integration with **Evaluate-STIG** tool
- Automated monthly checklist generation (CKLB, XCCDF formats)
- Output suitable for eMASS upload and review boards

#### JSIG (Joint Special Access Program Implementation Guide) Considerations

**Classification Handling**:
- ❌ **Not cleared for classified data** - Tech-support outputs may contain sensitive configurations
- ✅ **Suitable for FOUO/CUI** - With proper labeling and handling procedures
- ⚠️ **Special Access Programs**: Review tech-support outputs for SAP-sensitive data before storage

**Data Spillage Prevention**:
1. **Output Review**: Manually review tech-support files for classification markings
2. **Network Segmentation**: Deploy on appropriate classification network (NIPR/SIPR)
3. **Email Restrictions**: Only send emails within same classification domain
4. **Storage Controls**: Apply appropriate file system labels and access controls

**Recommended JSIG Enhancements** (for SAP environments):
- Disable email notifications (or use classified email system)
- Implement additional file encryption (e.g., NSA-approved tools)
- Add classification banners to all outputs
- Restrict service account to dedicated SAP system

#### RMF (Risk Management Framework) Compliance

**NIST SP 800-53 Control Mapping**:

| Control Family | Control ID | Control Name | Implementation |
|----------------|------------|--------------|----------------|
| **AC** | AC-2 | Account Management | Dedicated service account, documented purpose |
| **AC** | AC-3 | Access Enforcement | NTFS ACLs, DPAPI user binding |
| **AC** | AC-6 | Least Privilege | Service account minimal permissions |
| **AU** | AU-2 | Audit Events | Comprehensive logging of all operations |
| **AU** | AU-3 | Content of Audit Records | UTC timestamps, user, device, action, outcome |
| **AU** | AU-9 | Protection of Audit Info | Log file ACLs, append-only during execution |
| **AU** | AU-11 | Audit Retention | 30-day minimum, configurable |
| **IA** | IA-2 | Identification & Auth | Service account authentication |
| **IA** | IA-5 | Authenticator Mgmt | DPAPI credential protection, rotation support |
| **SC** | SC-8 | Transmission Confid. | SSH, SNMP v3, SMTP TLS/SSL |
| **SC** | SC-13 | Cryptographic Protection | AES-256, DPAPI, TLS 1.2+ |
| **SC** | SC-28 | Protection at Rest | DPAPI credential encryption, BitLocker support |
| **SI** | SI-4 | System Monitoring | Audit logging, error detection |

**RMF Assessment Evidence**:

**Assessment Objective**: Verify that Get-CiscoTechSupport implements security controls per RMF requirements.

| Evidence Type | Location | Purpose |
|---------------|----------|---------|
| **Installation Logs** | `Logs\Install_YYYY-MM-DD.log` | Prove secure installation |
| **Credential Files** | `.cisco_credentials`, `.smtp_credentials` | DPAPI encryption validation |
| **File ACLs** | `icacls` output | Access control verification |
| **Task Scheduler** | XML exports | Scheduled task security settings |
| **Operational Logs** | `Logs\Get-CiscoTechSupport_*.log` | Audit trail completeness |
| **Network Captures** | Wireshark PCAP | SSH/SNMP/SMTP encryption validation |

**ATO (Authority to Operate) Readiness**:
- ✅ **System Security Plan (SSP)**: Use this ARCHITECTURE.md as foundation
- ✅ **Security Control Traceability Matrix**: See NIST 800-53 mapping above
- ✅ **Configuration Baseline**: Installation parameters documented
- ✅ **Continuous Monitoring**: Audit log integration with SIEM
- ⚠️ **Residual Risk**: Review tech-support output content for sensitive data

#### FIPS 140-2 Cryptographic Compliance

**Encryption Modules**:
- **Windows DPAPI**: FIPS 140-2 validated (when Windows in FIPS mode)
- **SSH (Netmiko/Cryptography)**: Uses FIPS-approved algorithms (AES-256, SHA-256)
- **TLS (SMTP)**: TLS 1.2+ with FIPS-approved cipher suites

**FIPS Mode Activation** (if required):
```powershell
# Enable FIPS mode on Windows Server
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Value 1
Restart-Computer
```

**FIPS-Validated Algorithms Used**:
- **AES-256-CTR** (SSH encryption)
- **SHA-256** (SSH integrity, SNMP v3 auth)
- **RSA 2048+** (SSH key exchange)
- **TLS 1.2/1.3** (SMTP encryption)

### Security Best Practices

1. **Credential Rotation**: Regularly update device credentials, re-run `--save-credentials`
2. **Service Account Hygiene**: Dedicated account, complex password (15+ chars), monitor for anomalies
3. **Network Segmentation**: Collection server on management VLAN, isolated from user networks
4. **File Encryption**: Enable BitLocker on system drive for additional at-rest protection
5. **Least Privilege**: Grant minimal device permissions (e.g., privilege 1 for show commands)
6. **Audit Logs**: Integrate with centralized logging (SIEM, Splunk, ArcSight)
7. **Output Classification**: Review tech-support files for sensitive data before long-term storage
8. **Email Security**: Only send emails within appropriate classification domain
9. **FIPS Mode**: Enable Windows FIPS mode for DoD/IC environments
10. **Patch Management**: Keep Windows Server and PowerShell updated per DISA guidance

---

## Data Flow

### Installation Data Flow

```
User Input → Installer Validation → Archive Extraction →
Python Validation → Service Account Collection →
Credential Encryption → Task Registration → Credential Setup
```

**Data Elements**:
- Installation parameters (paths, schedules)
- Service account credentials (in-memory, encrypted for storage)
- Archive contents (extracted to file system)
- Task definitions (registered with Task Scheduler)

### Collection Data Flow (Device List Mode)

```
Scheduled Task Trigger → Python Execution →
Read devices.txt → Read Encrypted Credentials (DPAPI) →
For Each Device:
  └─ SSH Connect → Authenticate →
     Execute "show tech-support" →
     Capture Output → Write to File →
     SSH Disconnect
→ Collection Summary Generated →
If Email Configured:
  └─ Read SMTP Credentials (DPAPI) →
     Render HTML Report (Jinja2) →
     Connect to SMTP Server (TLS/SSL) →
     Send Email with Attachment →
     Log Email Result
→ Cleanup → Log Results → Exit
```

**Data Elements**:
- Device list (devices.txt, one IP/hostname per line)
- Cisco credentials (DPAPI, decrypted in-memory)
- SMTP credentials (DPAPI, decrypted in-memory, optional)
- SSH session data (encrypted in transit)
- Tech-support output (written to file system)
- Email report (HTML, generated dynamically)
- Audit logs (appended)

### Collection Data Flow (Discovery Mode)

```
Scheduled Task Trigger → Python Execution →
Read Encrypted Credentials (DPAPI) → Network Discovery:
  ├─ CDP: Query Gateway → Recursive Neighbor Discovery
  ├─ SNMP: Subnet Scan → Filter Cisco Devices
  └─ Hybrid: CDP + SNMP → Merge Results
→ Deduplicate Device List → For Each Device:
  └─ SSH Connect → Authenticate →
     Execute "show tech-support" →
     Capture Output → Write to File →
     SSH Disconnect
→ Collection Summary Generated →
If Email Configured:
  └─ Read SMTP Credentials (DPAPI) →
     Render HTML Report (Jinja2) →
     Connect to SMTP Server (TLS/SSL) →
     Send Email with Attachment →
     Log Email Result
→ Cleanup → Log Results → Exit
```

**Data Elements**:
- Discovery queries (CDP, SNMP)
- Device discovery results (in-memory)
- Cisco credentials (DPAPI, decrypted in-memory)
- SMTP credentials (DPAPI, decrypted in-memory, optional)
- SSH session data (encrypted in transit)
- Tech-support outputs (written to file system)
- Email report (HTML, generated dynamically)
- Audit logs (appended)

### STIG Generation Data Flow

```
Monthly Scheduled Task Trigger → PowerShell 7 Execution →
Read Tech-Support Files (Input Directory) →
Invoke Evaluate-STIG.ps1:
  └─ Parse Configurations →
     Apply STIG Rules →
     Generate Checklists (CKLB, XCCDF, Summary)
→ Write to STIG_Checklists Directory →
Log Results → Exit
```

**Data Elements**:
- Tech-support files (read-only)
- STIG rule definitions (Evaluate-STIG internal)
- Checklist outputs (CKLB, XCCDF, Summary formats)
- Execution logs

---

## Deployment Architecture

### Deployment Topology

```
┌───────────────────────────────────────────────────────────┐
│                    Management Network                     │
│                         (VLAN 100)                        │
│                                                           │
│  ┌──────────────────────────────────────────────────────┐ │
│  │       Collection Server (Windows Server 2022)        │ │
│  │  • Get-CiscoTechSupport Application                  │ │
│  │  • Service Account: svc_cisco_collect                │ │
│  │  • IP: 10.0.100.10                                   │ │
│  └──────────────────────────────────────────────────────┘ │
│                          │                                │
│                          │ SSH (22), SNMP (161)           │
│                          ▼                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │          Cisco Network Devices                       │ │
│  │  • Core Switches: 10.0.100.1-5                       │ │
│  │  • Distribution Switches: 10.0.101.1-10              │ │
│  │  • Core Routers: 10.0.100.250-254                    │ │
│  └──────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
                          │
                          │ Log Forwarding (Optional)
                          ▼
┌────────────────────────────────────────────────────────────┐
│                    Logging/SIEM Server                     │
│  • Centralized Log Collection                              │
│  • Alert Generation                                        │
│  • Compliance Reporting                                    │
└────────────────────────────────────────────────────────────┘
```

### Installation Scenarios

#### Scenario 1: Single Collection Server (Recommended)
- **Deployment**: One server, one or both collection modes
- **Use Case**: Small to medium networks (<500 devices)
- **Benefits**: Simplified management, single audit point

#### Scenario 2: Multi-Mode Collection Server
- **Deployment**: One server, both DeviceList and Discovery modes
- **Use Case**: Hybrid environments (static core, dynamic edge)
- **Configuration**:
  - DeviceList task collects core/critical devices (daily/weekly)
  - Discovery task collects edge devices (weekly/monthly)

#### Scenario 3: Distributed Collection (Advanced)
- **Deployment**: Multiple servers, geographic distribution
- **Use Case**: Large enterprise, geographically dispersed data centers
- **Considerations**: Separate service accounts, centralized storage replication

### Resource Requirements

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **CPU** | 2 cores | 4 cores | Python SSH sessions CPU-bound |
| **RAM** | 4 GB | 8 GB | Multiple concurrent SSH sessions |
| **Disk** | 10 GB | 50+ GB | Depends on device count, retention |
| **Network** | 100 Mbps | 1 Gbps | SSH throughput, large tech-support files |
| **OS** | Server 2016 | Server 2022 | PowerShell 5.1+ required |

### Scaling Considerations

| Devices | Concurrent Connections | Estimated Runtime | Server Resources |
|---------|------------------------|-------------------|------------------|
| 1-50 | 5 | 5-15 minutes | Minimum specs |
| 51-200 | 10 | 15-45 minutes | Recommended specs |
| 201-500 | 20 | 45-120 minutes | Recommended + SSD |
| 500+ | 20-30 | 2+ hours | Consider distributed |

---

## Compliance Considerations

### Regulatory Alignment

#### NIST Cybersecurity Framework
- **Identify**: Asset inventory via device discovery
- **Protect**: Credential encryption, access controls
- **Detect**: Audit logging, error detection
- **Respond**: Automated collection for incident response
- **Recover**: Historical tech-support baselines

#### STIG Compliance
- **Integration**: Native Evaluate-STIG integration
- **Automation**: Monthly automated checklist generation
- **Reporting**: CKLB, XCCDF, and summary formats
- **Audit Trail**: Complete logging of STIG assessments

#### SOC 2 Type II
- **Availability**: Scheduled, automated collection
- **Confidentiality**: Encrypted credential storage
- **Processing Integrity**: Comprehensive error handling and logging
- **Privacy**: No PII collected or stored

### Audit Controls

**AC-1: Access Control Policy**
- Service account with documented purpose
- NTFS ACLs on sensitive files
- Task Scheduler access restrictions

**AU-2: Audit Events**
- All credential access logged
- Device connection attempts logged
- Success/failure outcomes logged
- Timestamps in all log entries

**AU-9: Protection of Audit Information**
- Log files protected by NTFS ACLs
- Append-only during execution
- 30-day retention minimum
- Integration with centralized logging

**IA-5: Authenticator Management**
- DPAPI encryption of stored credentials
- No clear-text credential exposure
- Support for credential rotation
- Strong password requirements

**SC-8: Transmission Confidentiality**
- SSH encryption for device communication
- AES-256 cipher support
- Certificate-based authentication supported

**SC-28: Protection of Information at Rest**
- DPAPI credential encryption
- Optional BitLocker integration
- NTFS file system encryption

### Audit Evidence

**Installation Audit**:
- `Logs\Install_YYYY-MM-DD.log`: Complete installation record
- Task Scheduler XML exports: Task definitions
- File system snapshots: Installed components

**Operational Audit**:
- `Logs\Get-CiscoTechSupport_YYYY-MM-DD.log`: Daily operations
- Task Scheduler history: Execution records
- Output files with timestamps: Collection evidence

**Security Audit**:
- Credential files with ACLs: Access control evidence
- Event Viewer logs: Windows security events
- Network flow logs: SSH/SNMP communications

---

## Operational Architecture

### Operational States

```
┌─────────────┐
│  Installed  │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│  Credentials        │◄─── Manual: --setup-creds
│  Not Configured     │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│  Ready for          │◄─── Scheduled tasks created
│  Execution          │     Credentials configured
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│  Scheduled          │◄─── Task triggers on schedule
│  Execution          │
└──────┬──────────────┘
       │
       ├──► Success ──► Outputs Written ──► Logs Updated
       │
       └──► Failure ──► Error Logged ──► Manual Review
```

### Maintenance Operations

#### Credential Rotation
```powershell
# Run as service account
cd "C:\Scripts\Get-CiscoTechSupport"
.\Python3\python.exe get-ciscotechsupport.py --save-credentials
```

#### Manual Collection
```powershell
# Run as service account or administrator
cd "C:\Scripts\Get-CiscoTechSupport"
.\Python3\python.exe get-ciscotechsupport.py
```

#### Task Schedule Modification
```powershell
# Via Task Scheduler GUI or PowerShell cmdlets
Get-ScheduledTask -TaskName "Cisco TechSupport Collector*"
Set-ScheduledTask -TaskName "TaskName" -Trigger $newTrigger
```

#### Log Review
```powershell
# View today's log
Get-Content "C:\Scripts\Get-CiscoTechSupport\Logs\Get-CiscoTechSupport_$(Get-Date -Format yyyy-MM-dd).log"

# Search for errors
Select-String -Path "C:\Scripts\Get-CiscoTechSupport\Logs\*.log" -Pattern "ERROR"
```

### Monitoring and Alerting

**Recommended Monitoring**:
1. **Task Execution**: Monitor scheduled task completion status
2. **Log Errors**: Alert on ERROR level log entries
3. **Output File Age**: Alert if no new outputs in expected timeframe
4. **Disk Space**: Monitor Results directory growth
5. **Credential Access**: Audit credential file access patterns

**Integration Points**:
- **SIEM**: Forward logs via syslog or file-based ingestion
- **Monitoring Tools**: PowerShell-based health checks
- **Ticketing Systems**: Automated ticket creation on failures

---

## Error Handling and Logging

### Error Handling Strategy

**Principle**: Fail gracefully, log comprehensively, continue when possible

#### Error Categories

| Category | Handling | User Impact | Example |
|----------|----------|-------------|---------|
| **Fatal** | Stop execution, log, exit | Installation fails | Missing archive file |
| **Recoverable** | Log warning, skip, continue | Partial collection | Single device timeout |
| **Informational** | Log info, continue | None | Device already processed |

#### Error Handling Patterns

**Pattern 1: Try-Catch with Logging**
```powershell
try {
    # Risky operation
    $result = Invoke-RiskyOperation
    Write-InstallLog -Message "Operation succeeded" -Level SUCCESS
}
catch {
    Write-InstallLog -Message "Operation failed: $_" -Level ERROR
    # Determine if fatal or recoverable
    if ($IsFatal) {
        throw
    }
}
```

**Pattern 2: Validation Gates**
```powershell
if (-not (Test-Prerequisite)) {
    Write-InstallLog -Message "Prerequisite not met" -Level ERROR
    throw "Prerequisite validation failed"
}
# Continue with operation
```

**Pattern 3: Graceful Degradation**
```powershell
if (Test-OptionalFeature) {
    Enable-OptionalFeature
} else {
    Write-InstallLog -Message "Optional feature unavailable, continuing without" -Level WARNING
}
```

### Logging Architecture

**Logging Levels**:
- **DEBUG**: Verbose diagnostic information (opt-in)
- **INFO**: General informational messages, state changes
- **SUCCESS**: Successful operations, milestones
- **WARNING**: Non-fatal issues, degraded functionality
- **ERROR**: Fatal errors, operation failures

**Log Rotation**:
- **Strategy**: Daily log files, automatic rotation
- **Naming**: `Get-CiscoTechSupport_YYYY-MM-DD.log`
- **Retention**: 30 days (configurable)
- **Cleanup**: Automatic purge of logs older than retention period

**Console vs. File Logging**:
- **Console**: INFO, SUCCESS, WARNING, ERROR (color-coded)
- **File**: All levels including DEBUG
- **`-NoConsole` flag**: Suppresses console output for specific log entries

---

## Dependencies and External Integrations

### Internal Dependencies

| Component | Dependency | Version | Purpose |
|-----------|-----------|---------|---------|
| Installer | PowerShell | 5.1+ | Scripting runtime |
| Installer | .NET Framework | 4.5+ | Archive extraction |
| Collection | Embedded Python | 3.14.x | SSH/SNMP/email operations |
| STIG Task | PowerShell | 7.x | Evaluate-STIG runtime |
| All | Windows Task Scheduler | Built-in | Scheduled execution |

### Python Package Dependencies

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| netmiko | Latest | SSH connectivity, Cisco CLI | MIT |
| pysnmp | Latest | SNMP queries for discovery | BSD |
| cryptography | Latest | SSH key exchange, encryption | Apache 2.0 |
| jinja2 | Latest | HTML email template rendering | BSD |
| markupsafe | Latest | Safe HTML escaping | BSD |

**Email Libraries (Built-in)**:
- `email` - MIME message construction (Python standard library)
- `smtplib` - SMTP client implementation (Python standard library)

**Embedded Distribution**:
- Self-contained Python 3.14.x installation
- No external Python installation required
- Pre-installed packages, no pip dependency
- Isolated from system Python (if present)
- Air-gap compatible (all dependencies bundled)

### External Integrations

#### Evaluate-STIG (Optional)
- **Type**: External PowerShell script
- **Version**: User-provided (tested with 1.2510.0)
- **Integration**: Scheduled task invocation
- **Data Exchange**: File system (tech-support inputs, checklist outputs)
- **Dependency**: PowerShell 7.x runtime

#### Network Devices
- **Protocol**: SSH v2
- **Port**: 22 (default, configurable)
- **Authentication**: Username/Password (public key supported)
- **Commands**: `show tech-support`, `show cdp neighbors detail`

#### SNMP Agents (Discovery Mode)
- **Protocol**: SNMP v2c or v3
- **Port**: 161 (default)
- **Authentication**: Community string (v2c) or USM (v3)
- **MIBs**: sysDescr, sysObjectID for device identification

#### Windows Active Directory (Recommended)
- **Purpose**: Service account management
- **Integration**: Group Policy, password policies
- **Benefits**: Centralized credential management, audit

#### SIEM/Log Aggregation (Optional)
- **Integration**: File-based log ingestion or syslog forwarding
- **Formats**: Plain text, structured (JSON possible)
- **Benefits**: Centralized monitoring, correlation, alerting

---

## Testing and Validation

### Testing Strategy

**Unit Testing**: Individual functions tested in isolation
- Credential encryption/decryption
- Archive extraction
- Task creation/removal
- CSV parsing

**Integration Testing**: Component interaction testing
- Installer → Task Scheduler
- Collection script → Python runtime
- STIG task → Evaluate-STIG script

**System Testing**: End-to-end scenarios
- Fresh installation
- Credential setup and collection
- Scheduled task execution
- Uninstallation cleanup

**Security Testing**: Vulnerability and control validation
- Credential storage security
- File permission verification
- Network encryption validation
- Audit log completeness

### Test Cases (Sample)

#### TC-001: Fresh Installation
**Objective**: Verify successful installation on clean system
**Steps**:
1. Extract release archive
2. Run installer as Administrator
3. Follow interactive prompts
4. Verify scheduled task created
5. Verify files extracted correctly

**Expected**: Installation completes successfully, task visible in Task Scheduler

#### TC-002: Credential Setup
**Objective**: Verify credential encryption and storage
**Steps**:
1. Run `.\Get-CiscoTechSupport.ps1 --setup-creds` as service account
2. Enter credentials interactively
3. Verify `.cisco_credentials` created
4. Attempt to read file as different user

**Expected**: Credentials encrypted, file unreadable by unauthorized users

#### TC-003: Device List Collection
**Objective**: Verify successful tech-support collection
**Steps**:
1. Create `Devices.csv` with test devices
2. Configure credentials
3. Run `.\Get-CiscoTechSupport.ps1` manually
4. Verify output files created in Results directory

**Expected**: Tech-support files collected, named correctly, contain valid data

#### TC-004: Multiple Collection Mode Coexistence
**Objective**: Verify DeviceList and Discovery modes can coexist
**Steps**:
1. Install with DeviceList mode
2. Re-run installer, select Discovery mode
3. Verify both scheduled tasks exist
4. Verify no conflict during execution

**Expected**: Both tasks created, both execute successfully

#### TC-005: STIG Task Creation
**Objective**: Verify monthly STIG task configured correctly
**Steps**:
1. Install with `-EnableEvaluateSTIG`
2. Provide Evaluate-STIG script path
3. Verify task created in Task Scheduler
4. Export task XML, verify monthly trigger (Type=4, DaysOfMonth=1)

**Expected**: Task created with correct monthly schedule

#### TC-006: Uninstallation Cleanup
**Objective**: Verify complete removal of components
**Steps**:
1. Complete installation with all features
2. Run `.\Install-GetCiscoTechSupport.ps1 -Uninstall`
3. Verify scheduled tasks removed
4. Verify installation directory removed
5. Verify credentials and outputs NOT removed

**Expected**: Clean uninstallation, selective preservation of user data

### Validation Criteria

**Installation Success**:
- ✅ Scheduled task(s) created and enabled
- ✅ Python runtime extracted and functional
- ✅ Log file created with installation record
- ✅ No errors in installation log

**Operational Success**:
- ✅ Scheduled task executes on schedule
- ✅ Tech-support files collected and archived
- ✅ No authentication failures
- ✅ Logs written with appropriate detail

**Security Compliance**:
- ✅ Credentials encrypted with DPAPI
- ✅ File permissions restrict unauthorized access
- ✅ SSH encryption used for device communication
- ✅ Audit logs capture all credential access

---

## Appendices

### Appendix A: File System Layout

```
C:\Scripts\Get-CiscoTechSupport\
│
├── Python3\                             # Embedded Python runtime
│   ├── python.exe
│   ├── Lib\
│   └── site-packages\
│       ├── netmiko\
│       ├── pysnmp\
│       ├── cryptography\
│       ├── jinja2\
│       └── markupsafe\
│
├── get-ciscotechsupport.py              # Main collection script (Python)
├── Install-GetCiscoTechSupport.ps1      # Installer script (PowerShell)
├── devices.txt                          # Device list (DeviceList mode)
├── .cisco_credentials                   # Encrypted Cisco credentials (DPAPI)
├── .smtp_credentials                    # Encrypted SMTP credentials (DPAPI, optional)
│
├── Results\                             # Collection outputs
│   ├── DEVICE01_tech-support_2025-12-18_030001.txt
│   ├── DEVICE02_tech-support_2025-12-18_030245.txt
│   └── STIG_Checklists\                # STIG outputs (optional)
│       ├── DEVICE01.cklb
│       └── Combined_Summary.xlsx
│
└── Logs\                                # Audit and operational logs
    ├── Install_2025-12-18.log
    ├── Get-CiscoTechSupport_2025-12-18.log
    └── Get-CiscoTechSupport_2025-12-17.log
```

### Appendix B: Network Port Requirements

| Protocol | Port | Direction | Purpose | Encryption |
|----------|------|-----------|---------|------------|
| SSH | 22 | Outbound | Device tech-support collection | SSH v2 (AES-256) |
| SNMP | 161 | Outbound | Device discovery (Discovery mode) | SNMPv3 (optional) |
| SMTP | 25 | Outbound | Email delivery (unencrypted) | None |
| SMTP | 587 | Outbound | Email delivery (STARTTLS) | TLS 1.2+ |
| SMTP | 465 | Outbound | Email delivery (SSL) | SSL/TLS 1.2+ |
| SMB | 445 | Outbound | File share access (if applicable) | SMB3 encryption |

**Firewall Rules**:
- Collection server → Network devices: SSH (22), SNMP (161)
- Collection server → SMTP server: SMTP (25/587/465)
- No inbound connections required

**DoD Network Considerations**:
- **NIPR (Unclassified)**: All ports listed above
- **SIPR (Secret)**: Verify SMTP server on same classification network
- **Cross-Domain**: Do NOT send emails across classification boundaries

### Appendix C: Service Account Configuration

**Recommended Service Account Setup**:

```powershell
# Create dedicated service account
New-LocalUser -Name "svc_cisco_collect" -Description "Cisco Tech-Support Collection Service Account" -PasswordNeverExpires

# Add to local Administrators group (required for Task Scheduler RunLevel Highest)
Add-LocalGroupMember -Group "Administrators" -Member "svc_cisco_collect"

# Configure logon rights
# - Allow: Log on as a batch job
# - Deny: Log on locally, Log on through Remote Desktop

# Set strong password per organizational policy
Set-LocalUser -Name "svc_cisco_collect" -Password (Read-Host -AsSecureString "Enter Password")
```

**Security Considerations**:
- Use domain account in AD environments
- Apply least privilege principle
- Enforce password complexity and rotation
- Monitor account usage via audit logs

### Appendix D: Troubleshooting Decision Tree

```
Issue: Scheduled Task Not Executing
├─ Is task enabled?
│  ├─ No → Enable task in Task Scheduler
│  └─ Yes → Continue
│
├─ Check Last Run Result in Task Scheduler
│  ├─ 0x0 (Success) → Task ran, check logs for collection issues
│  ├─ 0x1 (Failure) → Check task credentials, service account permissions
│  └─ Task Never Ran → Check trigger configuration, service account login rights
│
├─ Review Execution Log
│  ├─ ERROR: Credential file not found → Run --setup-creds as service account
│  ├─ ERROR: Python not found → Verify python313\python.exe exists
│  └─ ERROR: Device authentication failed → Update credentials or check device SSH

Issue: No Tech-Support Files Collected
├─ Check Devices.csv file exists and formatted correctly
├─ Verify network connectivity (ping devices)
├─ Verify SSH enabled on devices
├─ Review collection log for per-device errors
└─ Test manual SSH connection from collection server

Issue: STIG Task Not Running
├─ Verify PowerShell 7 installed and accessible
├─ Verify Evaluate-STIG.ps1 path correct
├─ Check task trigger configuration (monthly on day 1)
├─ Review task execution history
└─ Manually run Evaluate-STIG.ps1 to test
```

---

## Revision History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0 | 2025-12-18 | Claude Code | Initial architecture documentation |
| 1.1 | 2025-12-20 | Claude Code | Added email notification system, enhanced DoD/STIG/JSIG/RMF compliance documentation |

---

## Approval Signatures

_This section to be completed by reviewing authorities_

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Security Architect | | | |
| Compliance Officer | | | |
| Network Architecture Lead | | | |
| IT Operations Manager | | | |

---

**End of Document**