## Description

### Summary
<!-- Provide a clear, concise description of what this PR accomplishes -->

### Changes Made
<!-- List the key changes in bullet format -->
-
-

### Motivation and Context
<!-- Why is this change necessary? What problem does it solve? -->

### Related Issues
<!-- Link related issues. Use "Closes #123" to auto-close issues when merged -->
Closes #
Related to #

---

## Type of Change

**Select all that apply:**
- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that breaks existing functionality)
- [ ] 📚 Documentation update
- [ ] 🔐 Security improvement
- [ ] 🧪 Test improvement
- [ ] ♻️ Refactoring (code restructuring, no functionality change)
- [ ] ⚡ Performance improvement
- [ ] 🔧 Chore (dependency updates, version bumps, etc.)

---

## Testing Checklist

### Installer Testing (PowerShell)
**Required for `Install-GetCiscoTechSupport.ps1` changes:**

#### Static Analysis:
- [ ] PSScriptAnalyzer passes with no errors
- [ ] No hard-coded credentials in code
- [ ] No relative paths used

#### Installation Testing:
- [ ] Fresh install on clean Windows 10/11 system
- [ ] Fresh install on clean Windows Server 2016+ system
- [ ] All prompts work correctly
- [ ] Scheduled tasks created successfully
- [ ] Credential ACLs verified (icacls)
- [ ] Service account RunAs tested
- [ ] Python distribution extracted
- [ ] Required packages validated

#### Collection Modes:
- [ ] DeviceList mode tested
- [ ] Discovery mode tested (CDP/SNMP/ARP/Hybrid)
- [ ] Both modes coexist (if applicable)

#### Integrations:
- [ ] Evaluate-STIG integration tested (if modified)
- [ ] Email notifications tested (if modified)
- [ ] SMTP credentials tested (if modified)

#### Uninstallation:
- [ ] Uninstall completes cleanly
- [ ] All scheduled tasks removed
- [ ] Installation directory removed
- [ ] Credentials preserved (expected)

#### Logs:
- [ ] Installation log created in C:\Logs\
- [ ] All log entries have UTC timestamps
- [ ] **NO credentials in logs** (verified)

---

### Collection Script Testing (Python)
**Required for `get-ciscotechsupport.py` changes:**

#### Core Functionality:
- [ ] DeviceList mode collects from all devices
- [ ] Discovery modes work
- [ ] Tech-support files created correctly
- [ ] File naming format correct

#### Credential Handling:
- [ ] DPAPI encryption works
- [ ] DPAPI decryption works
- [ ] SMTP credentials work (if email enabled)
- [ ] Cross-machine DPAPI fails (expected)

#### Error Handling:
- [ ] Offline devices logged to hosts_offline.log
- [ ] Authentication failures logged
- [ ] Timeout errors handled gracefully
- [ ] SSH connection errors logged

#### Logging:
- [ ] collection.log created
- [ ] console-output.log created
- [ ] hosts_offline.log created (if failures)
- [ ] UTC timestamps in all logs
- [ ] **NO credentials in any logs** (verified)

#### Email Notifications:
- [ ] HTML email generated correctly
- [ ] Audit metadata included
- [ ] Attachment created
- [ ] Email delivered successfully
- [ ] SMTP TLS/SSL works (if enabled)

---

### Security Testing
**Required for ALL credential/encryption changes:**

#### Credential Protection:
- [ ] **NO credentials in logs** (searched all log files)
- [ ] Credential files encrypted
- [ ] Credential file ACLs correct
- [ ] DPAPI prevents cross-machine access (tested)

#### Service Account Isolation:
- [ ] Credential setup uses RunAs
- [ ] Task runs as service account
- [ ] Service account has minimum permissions

#### Audit Logging:
- [ ] All actions logged with UTC timestamps
- [ ] User/computer/domain captured
- [ ] Exit codes logged correctly
- [ ] Duration calculated correctly

#### Network Security:
- [ ] SSH connections encrypted (Wireshark verified)
- [ ] SNMP v3 encryption works (if applicable)
- [ ] SMTP TLS/SSL negotiated (if email - Wireshark verified)

#### Code Security:
- [ ] No hard-coded credentials
- [ ] Input validation for paths
- [ ] Absolute paths only
- [ ] Error messages don't leak sensitive data

---

### Air-Gap Testing
**Optional for contributors (maintainer validates):**

- [ ] Install without internet connection
- [ ] All Python dependencies embedded
- [ ] No external URL calls
- [ ] Credential setup works offline
- [ ] Collection runs offline
- [ ] Email to local relay (no internet)

---

### Performance Testing (Optional)
**Recommended for significant changes:**

- [ ] Tested with [X] devices
- [ ] Average time: [X] minutes per device
- [ ] Total time: [X] minutes
- [ ] Success rate: [X]%
- [ ] Memory usage: [X] MB peak

---

## Documentation Updates

**Required for features or behavior changes:**

- [ ] Updated README.md
- [ ] Updated ARCHITECTURE.md
- [ ] Updated CHANGELOG.md
- [ ] Updated code comments
- [ ] Updated docstrings (Python)

**Documentation summary:**
<!-- Briefly describe what documentation was updated and why -->

---

## Security Impact Assessment

### Credential Handling
**Does this PR modify credential storage/retrieval/transmission?**
- [ ] Yes (describe security measures below)
- [ ] No

**If Yes, security measures implemented:**
<!-- Example: "Used SecureString for in-memory handling, verified DPAPI encryption, tested ACLs" -->

---

### Encryption/Cryptography
**Does this PR change encryption methods or algorithms?**
- [ ] Yes (describe algorithms and FIPS compliance below)
- [ ] No

**If Yes, cryptographic changes:**
<!-- Example: "Upgraded to TLS 1.2+ only, disabled TLS 1.0/1.1, uses AES-256-GCM cipher" -->

---

### Audit Logging
**Does this PR affect audit logging?**
- [ ] Yes - Enhances logging (describe below)
- [ ] Yes - Reduces logging ⚠️ (justify below)
- [ ] No change to logging

**Logging changes:**
<!-- Example: "Added UTC timestamps to all STIG execution logs, includes user/computer/domain metadata" -->

---

### DoD Compliance
**Does this PR affect STIG/RMF/FIPS compliance?**
- [ ] Yes - Improves compliance (describe below)
- [ ] Yes - Potentially impacts compliance ⚠️ (explain below)
- [ ] No impact on compliance

**Compliance changes:**
<!-- Example: "Addresses STIG V-253289 by documenting Secondary Logon service isolation" -->

---

## Breaking Changes

**Does this PR introduce breaking changes?**
- [ ] Yes ⚠️ (describe migration path below)
- [ ] No

**If Yes, describe migration path for existing users:**
<!-- Example: "Parameter '-OldName' renamed to '-NewName'. Alias '-OldName' preserved for backwards compatibility. Update scripts to use '-NewName' in future versions." -->

---

## Screenshots / Logs (Optional)

**If applicable, add screenshots or log excerpts to demonstrate changes:**

<!--
Example:
- Installation log showing successful setup
- Email screenshot showing new HTML template
- Performance metrics showing improvement
-->

---

## Additional Context

**Any other context about this PR:**
<!-- Example: "Tested in air-gapped lab environment on Windows Server 2022 Standard" -->

---

## Checklist (PR Submitter)

**Before submitting this PR:**

- [ ] Read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Completed all applicable testing sections above
- [ ] Updated all relevant documentation
- [ ] Reviewed code for security issues
- [ ] Commit messages follow semantic convention
- [ ] Code follows PowerShell/Python style guidelines
- [ ] Targets `main` branch
- [ ] Linked related issues
- [ ] Tested with service account (not current user)
- [ ] Air-gap compatibility maintained
- [ ] No credentials in code, logs, or commits

---

## Reviewer Checklist (Maintainer Use)

**Before merging:**

- [ ] Code follows project style guidelines
- [ ] Security checklist items validated
- [ ] Air-gap testing completed
- [ ] Documentation updates verified
- [ ] Commit messages follow convention
- [ ] No credentials exposed in code/logs/commits
- [ ] Tests cover new functionality
- [ ] Breaking changes properly documented
- [ ] CHANGELOG.md entry present

**Post-merge tasks:**

- [ ] Close related issues
- [ ] Tag release (if version bump)
- [ ] Update project board (if applicable)

---

**Thank you for your contribution to Get-CiscoTechSupport!**
