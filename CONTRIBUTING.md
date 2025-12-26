# Contributing to Get-CiscoTechSupport

Thank you for your interest in contributing to Get-CiscoTechSupport! This project helps enterprise IT professionals automate Cisco device diagnostic collection with a security-first approach designed for DoD and air-gapped environments.

We welcome contributions from the community, but please note that this project has **strict security and compliance requirements** that all contributions must meet.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Environment Setup](#development-environment-setup)
4. [How to Contribute](#how-to-contribute)
5. [Coding Standards](#coding-standards)
6. [Testing Requirements](#testing-requirements)
7. [Security Considerations](#security-considerations)
8. [Documentation Requirements](#documentation-requirements)
9. [Commit Message Guidelines](#commit-message-guidelines)
10. [Pull Request Process](#pull-request-process)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to KismetG17@gmail.com.

---

## Getting Started

### Prerequisites

**Operating System:**
- Windows 10/11 (for desktop testing)
- Windows Server 2016+ (for server testing)
- **Both desktop and server testing required** for installer changes

**Software:**
- PowerShell 5.1+ (built into Windows)
- PowerShell 7.x (for Evaluate-STIG integration testing)
- Python 3.6+ (for development only - not required for users)
- Git 2.23+
- Visual Studio Code (recommended IDE)

**Knowledge:**
- PowerShell scripting
- Python programming (optional, for collection script changes)
- Windows administration (service accounts, scheduled tasks)
- Basic networking (SSH, SNMP, SMTP)

### Understanding the Project

Before contributing, please read:

1. **README.md** - User guide, features, installation instructions
2. **ARCHITECTURE.md** - System design, security controls, data flow diagrams
3. **CHANGELOG.md** - Version history, recent changes, breaking changes
4. **SECURITY.md** - Security vulnerability reporting, DoD compliance guidance

### Critical Context

```
⚠️ AIR-GAP COMPLIANCE REQUIRED

All contributions MUST maintain air-gap compatibility.
No external dependencies at runtime.
Security is not optional.

This tool is designed for secure, air-gapped DoD environments.
Breaking air-gap compatibility or weakening security will result in PR rejection.
```

---

## Development Environment Setup

### Windows Setup

**1. Verify PowerShell 5.1+:**
```powershell
$PSVersionTable.PSVersion
# Expected: Major = 5, Minor = 1 or higher
```

**2. Install PowerShell 7.x (for STIG testing):**
```powershell
winget install --id Microsoft.PowerShell
# Verify installation
pwsh -Version
# Expected: 7.x.x
```

**3. Install Git:**
```powershell
winget install --id Git.Git
# Verify installation
git --version
# Expected: git version 2.x.x
```

**4. Install Visual Studio Code:**
```powershell
winget install --id Microsoft.VisualStudioCode
# Install PowerShell extension
code --install-extension ms-vscode.PowerShell
```

**5. Install PSScriptAnalyzer (required for linting):**
```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
```

### Python Development (Optional)

**Only required if modifying get-ciscotechsupport.py:**

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install development dependencies
pip install netmiko pysnmp cryptography jinja2 markupsafe

# Install dev tools
pip install pylint black
```

### Fork and Clone

```powershell
# Fork the repository on GitHub first
# Then clone your fork
git clone https://github.com/YOUR-USERNAME/Get-CiscoTechSupport.git
cd Get-CiscoTechSupport

# Add upstream remote
git remote add upstream https://github.com/kismetgerald/Get-CiscoTechSupport.git

# Verify remotes
git remote -v
```

---

## How to Contribute

### Types of Contributions Welcome

**🐛 Bug Fixes:**
- Security vulnerabilities (report privately first - see SECURITY.md)
- Installation errors or failures
- Collection script errors
- Logging issues
- Scheduled task creation failures

**✨ Features:**
- New collection modes or discovery methods
- Additional integrations (new STIG tools, monitoring systems)
- Enhanced reporting (email templates, formats)
- Performance optimizations

**📚 Documentation:**
- README.md improvements (clarity, examples, troubleshooting)
- ARCHITECTURE.md enhancements (diagrams, security details)
- Code comments and docstrings
- Usage examples and tutorials

**🧪 Testing:**
- Air-gap environment validation
- DoD environment testing
- Performance testing and metrics
- Edge case testing

**🔐 Security:**
- Credential handling improvements
- Encryption enhancements
- Audit logging features
- STIG compliance improvements

### What NOT to Contribute

**❌ These will be rejected:**

1. **Internet-Dependent Features** - Breaks air-gap compatibility
   - External API calls
   - Online package downloads
   - Cloud integrations

2. **Security Weakening** - Compromises security posture
   - Clear-text credential storage
   - DPAPI bypasses
   - Reduced audit logging
   - Weak encryption algorithms

3. **Out of Scope** - Not aligned with project goals
   - Non-Cisco device support (Juniper, Arista, etc.)
   - GUI implementations (this is a CLI/automated tool)
   - Monitoring/alerting systems (use SIEM integration instead)

4. **Breaking Changes Without Migration** - Impacts existing users
   - Parameter renames without aliases
   - File format changes without conversion tools
   - Backwards-incompatible changes

---

## Coding Standards

### PowerShell Style Guide

**Naming Conventions:**
- **Functions:** PascalCase with approved verbs (`Get-ServiceAccountCredential`, `New-ScheduledCollectionTask`)
- **Variables:** camelCase (`$serviceAccount`, `$installPath`, `$pythonExe`)
- **Constants:** SCREAMING_SNAKE_CASE (`$STIG_V253289`, `$DEFAULT_TIMEOUT`)
- **Parameters:** PascalCase (`-InstallPath`, `-ServiceAccountCredential`)

**Formatting:**
- **Indentation:** 4 spaces (no tabs)
- **Line Length:** 120 characters maximum
- **Braces:** Opening brace on same line (K&R style)
- **Spacing:** Space after keywords, around operators

**Function Template:**
```powershell
function Verb-Noun {
    <#
    .SYNOPSIS
        Brief description of function

    .DESCRIPTION
        Detailed description of what this function does

    .PARAMETER ParameterName
        Description of parameter

    .EXAMPLE
        Verb-Noun -ParameterName "value"
        Description of what this example does
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RequiredParam,

        [Parameter(Mandatory = $false)]
        [int]$OptionalParam = 10
    )

    try {
        Write-InstallLog -Message "Starting operation" -Level INFO

        # Logic here
        $result = Do-Something -Parameter $RequiredParam

        Write-InstallLog -Message "Operation successful" -Level SUCCESS
        return $result
    }
    catch {
        Write-InstallLog -Message "Error: $_" -Level ERROR
        throw
    }
}
```

**Best Practices:**
- Use `[CmdletBinding()]` for advanced functions
- Add parameter validation (`ValidateNotNull`, `ValidateSet`, `ValidateScript`)
- Use `try-catch` for error handling
- Log with `Write-InstallLog` at appropriate levels
- Return objects, not formatted text
- Use approved verbs (Get, Set, New, Remove, etc.)

**PSScriptAnalyzer:**
All PowerShell code must pass PSScriptAnalyzer with default rules:

```powershell
Invoke-ScriptAnalyzer -Path .\Install-GetCiscoTechSupport.ps1
# Expected: No errors or warnings
```

### Python Style Guide

**Follow PEP 8:**
- **Naming:** snake_case for functions/variables, UPPER_SNAKE_CASE for constants
- **Indentation:** 4 spaces (no tabs)
- **Line Length:** 100 characters maximum
- **Imports:** Grouped (standard library, third-party, local), alphabetically sorted

**Docstring Template:**
```python
def function_name(param1: str, param2: int = 10) -> bool:
    """
    Brief description of function.

    Detailed description of what this function does,
    including any important notes or caveats.

    Args:
        param1 (str): Description of param1
        param2 (int, optional): Description of param2. Defaults to 10.

    Returns:
        bool: True if successful, False otherwise

    Raises:
        ValueError: If param1 is empty
        ConnectionError: If device unreachable

    Example:
        >>> result = function_name("test", 20)
        >>> print(result)
        True
    """
    if not param1:
        raise ValueError("param1 cannot be empty")

    try:
        # Logic here
        return True
    except Exception as e:
        logger.error(f"Error: {e}")
        return False
```

**Best Practices:**
- Type hints for function signatures
- Comprehensive docstrings (Google style)
- Use `logging` module (not `print()`)
- Graceful error handling (try-except)
- Avoid global variables
- Use context managers (`with` statements)

---

## Testing Requirements

### Comprehensive Testing Checklist

**All PRs must complete applicable testing sections.**

### Installer Testing (PowerShell)

**Required for `Install-GetCiscoTechSupport.ps1` changes:**

#### Static Analysis:
- [ ] PSScriptAnalyzer passes with no errors
- [ ] No hard-coded credentials in code
- [ ] No relative paths (use absolute only)

#### Fresh Installation:
- [ ] Install on clean Windows 10/11 system
- [ ] Install on clean Windows Server 2016+ system
- [ ] All prompts work correctly
- [ ] Scheduled tasks created successfully
- [ ] Credential ACLs set correctly (`icacls` verification)
- [ ] Service account RunAs windows appear
- [ ] Python distribution extracted
- [ ] Required packages validated

#### Collection Modes:
- [ ] DeviceList mode tested (devices.txt)
- [ ] Discovery mode tested (CDP, SNMP, ARP, or Hybrid)
- [ ] Both modes can coexist (install twice with different modes)

#### Integrations:
- [ ] Evaluate-STIG integration tested (if modified)
- [ ] Email notifications tested (if modified)
- [ ] SMTP credential storage tested (if modified)

#### Uninstallation:
- [ ] Uninstall completes cleanly
- [ ] All scheduled tasks removed
- [ ] Installation directory removed
- [ ] Credentials preserved (expected behavior)

#### Logs:
- [ ] Installation log created in `C:\Logs\`
- [ ] All log entries have timestamps
- [ ] No credentials in logs (search for passwords)

### Collection Script Testing (Python)

**Required for `get-ciscotechsupport.py` changes:**

#### Core Functionality:
- [ ] DeviceList mode collects from all devices
- [ ] Discovery modes work (CDP/SNMP/ARP/Hybrid)
- [ ] Tech-support files created correctly
- [ ] File naming format correct (`HOSTNAME_IP_YYYYMMDD_HHMMSS_tech-support.txt`)

#### Credential Handling:
- [ ] DPAPI encryption works (`.cisco_credentials` file)
- [ ] DPAPI decryption works (load credentials)
- [ ] SMTP credentials work (if email enabled)
- [ ] Cross-machine DPAPI fails (expected - test on different PC)

#### Error Handling:
- [ ] Offline devices logged to `hosts_offline.log`
- [ ] Authentication failures logged properly
- [ ] Timeout errors handled gracefully
- [ ] SSH connection errors logged

#### Logging:
- [ ] `collection.log` created
- [ ] `console-output.log` created
- [ ] `hosts_offline.log` created (if failures)
- [ ] UTC timestamps in all logs
- [ ] **NO credentials in any log files** (critical)

#### Email Notifications:
- [ ] HTML email generated correctly
- [ ] Audit metadata included
- [ ] Attachment created
- [ ] Email delivered successfully
- [ ] SMTP TLS/SSL works (if enabled)

### Security Testing (CRITICAL)

**Required for ALL changes involving credentials, encryption, or sensitive data:**

#### Credential Protection:
- [ ] **NO credentials in logs** (search all log files for passwords)
- [ ] Credential files encrypted (`.cisco_credentials`, `.smtp_credentials`)
- [ ] Credential file ACLs correct (service account only)
- [ ] DPAPI prevents cross-machine access (test on different PC - should fail)

#### Service Account Isolation:
- [ ] Credential setup uses RunAs (not current user context)
- [ ] Task runs as service account (verify in Task Scheduler)
- [ ] Service account has minimum required permissions

#### Audit Logging:
- [ ] All actions logged with UTC timestamps
- [ ] User/computer/domain captured in logs
- [ ] Exit codes logged correctly
- [ ] Duration calculated correctly

#### Network Security:
- [ ] SSH connections encrypted (verify with Wireshark)
- [ ] SNMP v3 encryption works (if using SNMPv3)
- [ ] SMTP TLS/SSL negotiated (if email enabled - verify with Wireshark)

#### Code Security:
- [ ] No hard-coded credentials
- [ ] No clear-text passwords in memory dumps
- [ ] Input validation for paths (prevent injection)
- [ ] Absolute paths only (prevent relative path exploits)

### Air-Gap Testing

**Optional for contributors (maintainer validates during review):**

#### Installation:
- [ ] Install without internet connection
- [ ] All Python dependencies embedded (no pip install needed)
- [ ] No external URL calls during installation

#### Credential Setup:
- [ ] Credential setup works offline
- [ ] DPAPI encryption works offline
- [ ] No external dependencies for encryption

#### Collection:
- [ ] Collection runs without internet
- [ ] SSH to devices works (local network only)
- [ ] SNMP discovery works (local network only)

#### Email:
- [ ] Email to local relay (no external DNS)
- [ ] SMTP to internal server (no internet)

### Performance Testing (Optional for Significant Changes)

**Recommended for changes affecting collection speed or scale:**

#### Metrics to Capture:
- **Device Count:** Number of devices tested
- **Average Time:** Average time per device
- **Total Time:** End-to-end collection time
- **Success Rate:** Percentage of successful collections
- **Memory Usage:** Peak memory during collection

**Example:**
```
Test Results:
- Devices: 10
- Average Time: 1m 17s per device
- Total Time: 13m 45s
- Success Rate: 100% (10/10)
- Memory: 245 MB peak
```

See `.Performance_Metrics/` folder for examples.

### Credential Handling Example

**✅ CORRECT - Secure credential handling:**

```powershell
# Use SecureString for passwords
$password = Read-Host "Enter password" -AsSecureString
$credential = New-Object PSCredential("username", $password)

# Store with DPAPI encryption
$credential | Export-Clixml -Path ".\.credentials" -Force

# Set ACLs (service account only)
icacls ".\.credentials" /inheritance:r
icacls ".\.credentials" /grant "$serviceAccount:(F)"

# Load credentials
$credential = Import-Clixml -Path ".\.credentials"

# Use credentials (NEVER log)
try {
    $session = New-SSHSession -ComputerName $device -Credential $credential
}
catch {
    Write-Log "Connection failed" # NO credential details
}
```

**❌ INCORRECT - Insecure credential handling:**

```powershell
# NEVER do this:
$password = "PlainTextPassword123!"  # Hard-coded
$password = Read-Host "Enter password"  # Not SecureString
Write-Log "Password: $password"  # Logged in clear-text
$credential | ConvertTo-Json | Out-File "creds.json"  # Not encrypted

# NEVER store credentials in:
- Environment variables
- Plain text files
- Registry (without encryption)
- Source code or config files
```

---

## Security Considerations

### Credential Handling Rules

**MUST follow these rules for ALL credential-related code:**

1. **NEVER log credentials in clear-text**
   - Not in `Write-InstallLog`, `logger.info()`, `print()`, or any output
   - Not in exception messages
   - Not in debug output

2. **ALWAYS use DPAPI for storage**
   - PowerShell: `Export-Clixml` (uses DPAPI automatically)
   - Python: Windows DPAPI via `cryptography` library

3. **ALWAYS use SecureString/PSCredential in-memory**
   - PowerShell: `Read-Host -AsPlainText` converts to SecureString
   - Python: Don't store passwords in regular strings

4. **ALWAYS verify credential file ACLs**
   - Only service account should have Full Control
   - Administrators should have Read only (for debugging)
   - SYSTEM should have Read (for scheduled tasks)

5. **NEVER transmit over unencrypted channels**
   - SSH: Use SSH v2 with strong ciphers
   - SNMP: Use SNMPv3 with authPriv
   - SMTP: Use TLS/SSL (port 587/465)

### Code Review Security Checklist

**Before submitting PR, review your code for:**

- [ ] No hard-coded credentials (search for "password", "secret", "key")
- [ ] No credential logging (search log statements for credential variables)
- [ ] SSH/SNMP/SMTP use encryption (verify protocol versions)
- [ ] Input validation for file paths (prevent injection)
- [ ] Absolute paths only (search for `Join-Path` with relative paths)
- [ ] Error messages don't leak sensitive info
- [ ] Temporary files deleted after use
- [ ] Exceptions don't expose credentials

### DoD Compliance

**Reference STIG IDs in code comments:**

```powershell
# STIG V-253289: Secondary Logon service properly managed
# This service account isolation prevents privilege escalation
$credential = Get-ServiceAccountCredential
```

**Map to NIST 800-53 controls:**

```python
# NIST 800-53 IA-5 (Authenticator Management)
# Credentials encrypted with FIPS-approved AES-256 via DPAPI
encrypted_creds = encrypt_credentials(username, password)
```

**Use FIPS-approved algorithms:**
- **Encryption:** AES-256 (DPAPI)
- **Hashing:** SHA-256, SHA-384, SHA-512
- **Key Exchange:** RSA 2048+ or ECDH P-256+
- **Random:** OS-provided CSPRNG

### Vulnerability Disclosure

**DO NOT open public issue for security vulnerabilities.**

**Instead:**
1. Email KismetG17@gmail.com privately
2. Subject: `[SECURITY] Get-CiscoTechSupport Vulnerability Report`
3. Include: Description, reproduction, impact, affected versions
4. Wait for response (48 hours acknowledgment, 7-90 day fix)

See [SECURITY.md](SECURITY.md) for full responsible disclosure policy.

---

## Documentation Requirements

### When to Update Documentation

**README.md:**
- New features or capabilities
- Installation changes or new requirements
- Usage examples or parameters
- Troubleshooting new issues

**ARCHITECTURE.md:**
- Design changes or new components
- Security control additions or changes
- Data flow diagram updates
- STIG/RMF control mapping updates
- DoD compliance changes

**CHANGELOG.md:**
- **EVERY pull request** (no exceptions)
- Follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format
- Categorize: Added, Changed, Fixed, Deprecated, Removed, Security

### Documentation Style

**Tone:**
- Professional and concise
- Security-conscious (mention security implications)
- Actionable (provide examples, not just theory)

**Audience:**
- Enterprise IT professionals
- Windows administrators
- Network engineers
- DoD security personnel

**Formatting:**
- Use tables for comparisons
- Use code blocks with syntax highlighting
- Use headings and subheadings for scanability
- Include examples for complex procedures

**Security Sections:**
- Mark sensitive information clearly
- Include DoD classification guidance where applicable
- Reference STIG IDs and NIST controls
- Explain security trade-offs

---

## Commit Message Guidelines

### Format

```
<type>: <subject>

<body (optional)>

<footer (optional)>
```

### Type Prefixes

- **feat:** New feature or enhancement
- **fix:** Bug fix
- **docs:** Documentation changes only
- **refactor:** Code restructuring (no functionality change)
- **perf:** Performance improvements
- **test:** Adding or updating tests
- **chore:** Maintenance (version bumps, dependencies, etc.)
- **security:** Security fixes or improvements

### Subject Rules

1. **Imperative mood:** "Add feature" not "Added" or "Adds"
2. **Lowercase first word:** "add feature" not "Add feature"
3. **No period at end:** "Add feature" not "Add feature."
4. **50 characters max:** Be concise
5. **Be specific:** Describe WHAT and WHY, not HOW

### Examples

**✅ GOOD:**
```
feat: Add SMTP TLS support for email notifications

fix: Prevent PowerShell array unwrapping in task detection

docs: Update ARCHITECTURE.md with STIG logging wrapper flow

security: Validate credential file ACLs during setup

refactor: Extract credential handling into separate function

chore: Bump version to 0.0.8 in README and ARCHITECTURE
```

**❌ BAD:**
```
Added some stuff
fixed it
Update
Made changes to the installer
WIP
asdf
```

### Body (Optional)

Use body for detailed explanation if needed:

```
feat: Add CDP-based device discovery mode

Implements Cisco Discovery Protocol (CDP) neighbor parsing
for automated device discovery. Queries default gateway
for CDP neighbors recursively to build device list.

Benefits:
- No manual device list maintenance
- Discovers new devices automatically
- Maps network topology

Tested with 25-device lab environment.
```

### Footer (Optional)

Use footer for:
- Breaking changes: `BREAKING CHANGE: Parameter renamed`
- Issue references: `Closes #123`, `Fixes #456`, `Related to #789`
- Co-authors: `Co-authored-by: Name <email@example.com>`

---

## Pull Request Process

### Before Creating PR

**1. Sync with Upstream:**
```powershell
git fetch upstream
git checkout main
git merge upstream/main
```

**2. Create Feature Branch:**
```powershell
git checkout -b feature/descriptive-name
# Examples:
# feature/smtp-tls-support
# fix/credential-acl-validation
# docs/stig-compliance-guide
```

**3. Make Changes:**
- Follow coding standards
- Complete all applicable testing
- Update documentation
- Commit with semantic messages

**4. Run Final Checks:**
```powershell
# PowerShell: PSScriptAnalyzer
Invoke-ScriptAnalyzer -Path .\Install-GetCiscoTechSupport.ps1

# Python: pylint (if modified Python)
pylint get-ciscotechsupport.py

# Search for credentials in logs
Get-ChildItem -Path Logs\*.log -Recurse | Select-String "password|secret|key" -CaseSensitive
```

**5. Push to Your Fork:**
```powershell
git push origin feature/descriptive-name
```

**6. Create Pull Request:**
- Go to GitHub repository
- Click "New Pull Request"
- Fill out PR template completely
- Link related issues

### PR Review Process

**Timeline:**
- **Initial Review:** Within 7 business days
- **Follow-Up:** Within 3 business days

**Review Focus:**
1. **Security:** Credential handling, encryption, logging
2. **Testing:** Evidence of comprehensive testing
3. **Air-Gap:** No internet dependencies introduced
4. **Documentation:** README, ARCHITECTURE, CHANGELOG updated
5. **Code Quality:** Follows style guide, PSScriptAnalyzer passes
6. **Commit Messages:** Follow semantic commit convention

**Addressing Feedback:**
- Respond to all comments (agree, explain, or ask for clarification)
- Make requested changes in new commits (don't force-push)
- Request re-review when ready

**DO NOT:**
- Force-push after review starts (rebasing destroys review context)
- Argue without technical justification
- Ignore feedback or leave comments unresolved

### After Merge

**1. Update Local Repository:**
```powershell
git checkout main
git pull upstream main
```

**2. Delete Feature Branch:**
```powershell
git branch -d feature/descriptive-name
git push origin --delete feature/descriptive-name
```

**3. Celebrate!**
- Your contribution is now part of the project
- You'll be credited in CHANGELOG.md
- Thank you for making this project better!

---

## Quick Reference Checklist

**Before submitting PR:**

- [ ] Code follows PowerShell/Python style guidelines
- [ ] PSScriptAnalyzer passes (PowerShell)
- [ ] All applicable tests completed
- [ ] **NO credentials in code, logs, or commits**
- [ ] Documentation updated (README, ARCHITECTURE, CHANGELOG)
- [ ] Commit messages follow semantic convention
- [ ] Tested with service account (not current user)
- [ ] Air-gap compatibility maintained
- [ ] Security impact assessed
- [ ] PR template filled out completely

---

## Community Support

**Response Times:**
- **Security vulnerabilities:** 48 hours (email KismetG17@gmail.com)
- **Bug reports:** 7 business days
- **Feature requests:** 14 business days
- **Pull requests:** 7 business days (initial review)

**Contact:**
- **Email:** KismetG17@gmail.com
- **GitHub Issues:** https://github.com/kismetgerald/Get-CiscoTechSupport/issues
- **GitHub Discussions:** https://github.com/kismetgerald/Get-CiscoTechSupport/discussions

---

## Additional Resources

- **README.md** - User guide and quick start
- **ARCHITECTURE.md** - Technical architecture and security details
- **SECURITY.md** - Vulnerability reporting and DoD security guidance
- **CHANGELOG.md** - Version history and release notes
- **CODE_OF_CONDUCT.md** - Community standards

---

**Thank you for contributing to Get-CiscoTechSupport!**

*Your contributions help enterprise IT professionals automate Cisco device management securely.*

*Last updated: December 26, 2025*
