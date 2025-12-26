# Security Policy

## Supported Versions

The following versions of Get-CiscoTechSupport receive security updates:

| Version | Supported          | Notes                                      |
| ------- | ------------------ | ------------------------------------------ |
| 0.0.7   | :white_check_mark: | Current release (2025-12-25)               |
| 0.0.6   | :white_check_mark: | Security updates provided                  |
| 0.0.5   | :white_check_mark: | Critical security fixes only               |
| < 0.0.5 | :x:                | No longer supported - please upgrade       |

**Recommendation:** Always use the latest version (0.0.7) for the most comprehensive security features, including STIG execution logging and enhanced credential handling.

---

## Reporting a Vulnerability

### What Qualifies as a Security Vulnerability?

**Please report these issues privately:**
- Credential exposure (clear-text passwords, unencrypted storage)
- Authentication bypass or weak authentication
- Privilege escalation vulnerabilities
- Cryptographic weaknesses (weak algorithms, implementation flaws)
- Command injection or code execution vulnerabilities
- Path traversal or file access vulnerabilities
- DoD compliance violations (STIG, RMF, FIPS 140-2)
- Sensitive data leakage in logs or outputs

**These are regular bugs, not security issues:**
- Performance problems
- Non-security feature requests
- Documentation errors
- UI/UX issues
- Third-party dependency vulnerabilities (we address these proactively)

### How to Report

**Email:** KismetG17@gmail.com
**Subject:** `[SECURITY] Get-CiscoTechSupport Vulnerability Report`

**Include in your report:**
1. **Description:** Clear explanation of the vulnerability
2. **Reproduction Steps:** Detailed steps to reproduce the issue
3. **Impact:** What an attacker could achieve
4. **Affected Versions:** Which versions are vulnerable
5. **Suggested Fix:** If you have one (optional but appreciated)
6. **Classification Considerations:** Any DoD classification implications

**DO NOT:**
- Open a public GitHub issue for security vulnerabilities
- Discuss the vulnerability publicly before coordinated disclosure
- Test vulnerabilities against production systems without authorization

### Response Timeline

| Timeline       | Action                                              |
| -------------- | --------------------------------------------------- |
| **48 hours**   | Initial acknowledgment of your report               |
| **7 days**     | Triage completed, severity assessment, remediation plan |
| **7-90 days**  | Fix development (based on severity - see below)     |
| **Post-fix**   | Coordinated public disclosure                       |

**Severity-Based Fix Timeline:**
- **Critical** (credential exposure, RCE): 7-14 days
- **High** (privilege escalation, auth bypass): 14-30 days
- **Medium** (DoD violations, crypto weaknesses): 30-60 days
- **Low** (info disclosure, hardening): 60-90 days

---

## Responsible Disclosure Policy

We follow responsible disclosure practices:

1. **Embargo Period:** We request 90 days from initial report to public disclosure
2. **Coordinated Disclosure:** We'll work with you to agree on disclosure timing
3. **Credit:** You'll be credited in CHANGELOG.md unless you prefer anonymity
4. **Notice:** We request 7 days notice before any public disclosure
5. **CVE Assignment:** For significant vulnerabilities, we'll request CVE assignment

**If we miss our response timeline:**
- Send a follow-up email after 7 days
- Escalate to GitHub issue after 14 days (mark as security-related, redact details)

---

## Security Best Practices for Users

### Service Account Security

**Create a Dedicated Service Account:**
```powershell
# Create dedicated account with strong password
$password = ConvertTo-SecureString "StrongP@ssw0rd123!" -AsPlainText -Force
New-LocalUser -Name "svc_cisco_collect" -Password $password -PasswordNeverExpires

# Add to Administrators group (required for scheduled tasks)
Add-LocalGroupMember -Group "Administrators" -Member "svc_cisco_collect"

# Deny interactive logon (security hardening)
$secPolicy = Get-Content "$env:TEMP\secpol.cfg"
$secPolicy += "SeDenyInteractiveLogonRight = svc_cisco_collect"
Set-Content "$env:TEMP\secpol.cfg" -Value $secPolicy
secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg"
```

**NEVER use SYSTEM account** - it has excessive privileges and breaks credential isolation.

### Credential Storage Validation

**Verify DPAPI Encryption and ACLs:**
```powershell
# Check credential file encryption and permissions
$credFile = "C:\Scripts\Get-CiscoTechSupport\.cisco_credentials"

# Verify ACLs - only service account should have full control
icacls $credFile
# Expected: svc_cisco_collect:(F), BUILTIN\Administrators:(R)

# Verify DPAPI encryption (file should not be plain text)
Get-Content $credFile | Select-Object -First 5
# Expected: XML with encrypted Base64 strings
```

**Rotate credentials regularly:**
- Cisco device passwords: Every 90 days
- SMTP credentials: Every 90 days
- Service account password: Every 180 days

### Network Security

**Deploy on Management VLAN:**
- Isolate collection server from user networks
- Use dedicated management VLAN for device access
- Apply firewall rules restricting outbound SSH (port 22) to device subnet only

**Secure Device Protocols:**
- **SSH:** Require SSH v2 only, disable Telnet on all devices
- **SNMP:** Use SNMPv3 with authPriv (AES-256, SHA-256)
- **SMTP:** Use TLS/SSL (port 587/465), never plain SMTP (port 25)

**Network Architecture:**
```
┌─────────────────┐
│ Collection      │  Management VLAN (10.0.0.0/24)
│ Server          │  - Firewall rules: SSH outbound to devices only
│ (WIN11-03)      │  - No internet access (air-gapped)
└────────┬────────┘
         │
    ┌────┴────┐
    │ Switch  │  Management VLAN
    │ (mgmt)  │
    └────┬────┘
         │
    ┌────┴────────────────┐
    │  Cisco Devices      │  Device Subnet (10.1.0.0/16)
    │  (routers/switches) │  - SSH enabled, Telnet disabled
    └─────────────────────┘
```

### File System Security

**Enable BitLocker:**
```powershell
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly
```

**Apply NTFS Permissions:**
```powershell
$installPath = "C:\Scripts\Get-CiscoTechSupport"

# Remove inheritance
icacls $installPath /inheritance:r

# Service account: Full control
icacls $installPath /grant "svc_cisco_collect:(OI)(CI)F"

# Administrators: Read
icacls $installPath /grant "BUILTIN\Administrators:(OI)(CI)R"

# SYSTEM: Read (required for scheduled tasks)
icacls $installPath /grant "NT AUTHORITY\SYSTEM:(OI)(CI)R"
```

**Audit Credential File Access:**
```powershell
# Enable file auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Add SACL to credential file
$credFile = "C:\Scripts\Get-CiscoTechSupport\.cisco_credentials"
$acl = Get-Acl $credFile
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Read,Write,Delete", "Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl $credFile $acl
```

---

## DoD-Specific Security Guidance

### Classification Handling

**⚠️ CRITICAL: Tech-support outputs may contain classified data**

**Classification Considerations:**
- Device configurations may include:
  - IP addresses (FOUO/CUI)
  - Network topology (CONFIDENTIAL)
  - Crypto keys (SECRET)
  - Access control lists (CONFIDENTIAL)

**Best Practices:**
1. **Review outputs** for classification markings before archiving
2. **Deploy on appropriate network:**
   - NIPRNET: Unclassified/FOUO/CUI only
   - SIPRNET: SECRET and below
   - JWICS: TOP SECRET and below
3. **DO NOT send emails** across classification boundaries
4. **Store outputs** on classified file servers with proper labeling
5. **Sanitize before** sharing with vendors or third parties

**Marking Outputs:**
```powershell
# Add classification marking to filenames
$output = "DEVICE01_10.0.1.1_20251225_030001_tech-support.txt"
$classified = "SECRET_DEVICE01_10.0.1.1_20251225_030001_tech-support.txt"
Rename-Item $output $classified
```

### STIG Compliance

This tool addresses the following STIG requirements:

| STIG ID    | Title                              | Compliance Status       |
| ---------- | ---------------------------------- | ----------------------- |
| V-253289   | Secondary Logon service management | ✅ Compliant (documented) |
| V-220857   | No clear-text password storage     | ✅ Compliant (DPAPI)      |
| V-220858   | Comprehensive audit logging        | ✅ Compliant (all logs)   |
| V-220859   | Least privilege service accounts   | ✅ Compliant (dedicated)  |

**STIG Documentation:** See [ARCHITECTURE.md](ARCHITECTURE.md) for complete STIG control mapping.

### RMF/ATO Requirements

**Using Get-CiscoTechSupport in an Authorization to Operate (ATO):**

1. **System Security Plan (SSP):**
   - Use ARCHITECTURE.md as foundation for SSP description
   - Map to NIST SP 800-53 controls (documented in ARCHITECTURE.md)
   - Include data flow diagrams (available in ARCHITECTURE.md)

2. **Security Controls Assessment:**
   - Assess IA-5 (Authenticator Management) - DPAPI credential protection
   - Assess AU-2 (Audit Events) - Comprehensive logging
   - Assess CM-7 (Least Functionality) - Service account isolation

3. **Continuous Monitoring:**
   - Include log review in CM plan
   - Monitor credential file access (Event ID 4663)
   - Track scheduled task modifications (Event ID 4698, 4702)

4. **Assessment Evidence:**
   - Provide installation logs
   - Provide sample collection logs
   - Provide STIG checklist results (Evaluate-STIG integration)

### FIPS 140-2 Compliance

**Enable FIPS Mode (Windows Server):**
```powershell
# Enable FIPS-approved algorithms
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" `
                 -Name "Enabled" -Value 1

# Restart required
Restart-Computer -Force
```

**FIPS-Approved Algorithms Used:**
- **Credential Encryption:** AES-256 (DPAPI)
- **SSH:** AES-256-GCM, SHA-256 HMAC
- **SMTP TLS:** TLS 1.2+ with AES-256-GCM
- **SNMP:** AES-256, SHA-256 (SNMPv3 authPriv)

**Non-FIPS Algorithms (Justification Required):**
- None - all cryptography uses FIPS-approved algorithms

---

## Audit and Monitoring

### Log Review

**Log Locations:**
- **Installation Logs:** `C:\Logs\Get-CiscoTechSupport-Install-YYYYMMDD-HHMMSS.log`
- **Collection Logs:** `<InstallPath>\Logs\collection.log`
- **Console Output:** `<InstallPath>\Logs\console-output.log`
- **Failed Connections:** `<InstallPath>\Logs\hosts_offline.log`
- **STIG Execution:** `<InstallPath>\Logs\Invoke-EvaluateSTIG-YYYYMMDD-HHMMSS.log`

**What to Monitor:**
1. **ERROR messages:** Device failures, authentication errors, file I/O errors
2. **WARNING messages:** Offline devices, timeout warnings
3. **Credential access:** File access to `.cisco_credentials`, `.smtp_credentials`
4. **Task modifications:** Changes to scheduled tasks (Event ID 4698, 4702)
5. **File deletions:** Deletion of outputs or logs (potential data destruction)

**Daily Review Checklist:**
- [ ] Review ERROR logs for authentication failures
- [ ] Check `hosts_offline.log` for unreachable devices
- [ ] Verify scheduled task execution (Event Viewer: Task Scheduler log)
- [ ] Confirm outputs created (`Results/` directory)
- [ ] Review credential file access (Security log, Event ID 4663)

### SIEM Integration

**Splunk/ArcSight/Elastic Integration:**
```powershell
# Forward logs to SIEM via Windows Event Forwarding
# Create custom event source
New-EventLog -LogName "CiscoCollection" -Source "Get-CiscoTechSupport"

# Write to event log (add to Python script)
$logMessage = Get-Content "C:\Scripts\Get-CiscoTechSupport\Logs\collection.log" -Tail 1
Write-EventLog -LogName "CiscoCollection" -Source "Get-CiscoTechSupport" `
               -EntryType Information -EventId 1000 -Message $logMessage
```

**Alerting Rules:**
1. **Alert on ERROR:** Send alert for any ERROR-level log entries
2. **Alert on credential access:** Alert if non-service-account accesses `.cisco_credentials`
3. **Alert on task modification:** Alert if scheduled task modified by non-admin
4. **Alert on repeated failures:** Alert if >5 devices fail in single run

---

## Known Security Limitations

**This section provides transparency about accepted security risks:**

### 1. Tech-Support Content May Contain Sensitive Data
**Risk:** Device configurations may include passwords, keys, topology data
**Mitigation:** Manual review required before external sharing
**Status:** Accepted risk (by design - this is the purpose of the tool)

### 2. Service Account Requires Local Administrator
**Risk:** Elevated privileges for scheduled task execution
**Mitigation:** Dedicated account, network isolation, deny interactive logon
**Status:** Accepted risk (Windows Task Scheduler requirement)

### 3. DPAPI Decryption by SYSTEM and Administrators
**Risk:** SYSTEM account and Administrators group can decrypt DPAPI files
**Mitigation:** NTFS ACLs restrict file access, file audit logging enabled
**Status:** Accepted risk (Windows DPAPI design limitation)

### 4. No MFA for Device Access
**Risk:** SSH uses password-only authentication
**Mitigation:** Strong passwords, 90-day rotation, network segmentation
**Status:** Accepted risk (most Cisco devices don't support SSH key auth)

### 5. Embedded Dependencies
**Risk:** Vulnerable to upstream CVEs in netmiko, pysnmp, cryptography, jinja2
**Mitigation:** Proactive monitoring of CVE databases, timely updates
**Status:** Active monitoring (see dependency graph for CVE alerts)

### 6. No Built-In Output Encryption
**Risk:** Tech-support files stored in plain text on disk
**Mitigation:** BitLocker encryption, NTFS permissions, classified storage
**Status:** Accepted risk (outputs require human review, encryption would hinder)

---

## Security Assumptions

This tool assumes the following security measures are in place:

1. **Physical Security:**
   - Collection server in locked server room or data center
   - No unauthorized physical access
   - Tamper-evident seals on servers

2. **Windows Security Hardening:**
   - STIG baseline applied (Windows 10/11 or Server 2016+ STIG)
   - Latest patches installed (monthly patching cycle)
   - Unnecessary services disabled

3. **Network Segmentation:**
   - Management VLAN isolated from user networks
   - Firewall rules restricting collection server outbound access
   - No internet access (air-gapped or DMZ)

4. **Endpoint Protection:**
   - Antivirus/EDR enabled and up-to-date
   - Host-based firewall configured
   - Application whitelisting (AppLocker) considered

5. **Access Control:**
   - Role-based access to collection server
   - Privilege escalation monitoring
   - Account lockout policies enforced

6. **Audit Logging:**
   - Windows Event Forwarding to SIEM
   - Security event log size ≥ 1GB
   - Log retention ≥ 90 days

**If these assumptions are violated, security posture may be compromised.**

---

## Security Audit History

| Date       | Auditor       | Scope                     | Findings | Status   |
| ---------- | ------------- | ------------------------- | -------- | -------- |
| 2025-12-18 | Internal      | Credential storage        | 0 High   | Resolved |
| 2025-12-25 | Internal      | STIG wrapper logging      | 0 High   | Resolved |
| TBD        | External      | Independent security test | TBD      | Planned  |

---

## Security Contact

**Report security vulnerabilities to:**

**Email:** KismetG17@gmail.com
**Subject:** `[SECURITY] Get-CiscoTechSupport Vulnerability Report`
**GitHub:** [@kismetgerald](https://github.com/kismetgerald)
**Response Time:** 48 hours (initial acknowledgment)

**For general security questions:**
- Open a GitHub Discussion
- Reference this SECURITY.md document
- Review [ARCHITECTURE.md](ARCHITECTURE.md) security sections

---

## Additional Resources

- **ARCHITECTURE.md:** Security architecture, STIG controls, data flow diagrams
- **CONTRIBUTING.md:** Secure development guidelines, testing requirements
- **CODE_OF_CONDUCT.md:** Community standards and expected behavior
- **CHANGELOG.md:** Security fixes and vulnerability remediation history

---

*This security policy was last updated on December 26, 2025.*

*For questions or concerns about this security policy, contact KismetG17@gmail.com.*
