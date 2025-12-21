# Changelog

All notable changes to the Get-CiscoTechSupport project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Email notification system with HTML reports and SMTP delivery
  - Professional HTML email templates with Jinja2
  - DoD compliance audit metadata in all email reports
  - Support for SSL/TLS, STARTTLS, and unauthenticated SMTP
  - DPAPI-encrypted SMTP credential storage
  - Detailed attachment with complete collection results
- Jinja2 3.1.6 and MarkupSafe 3.0.3 dependencies for email templating

### Changed
- Refactored SMTP credential setup to accept PSCredential parameter

### Fixed
- SMTP credential setup function parameter alignment
- Email configuration ordering bug - moved email config before task creation to ensure parameters are included in scheduled task
- Missing instance variables in CiscoCollector class causing AttributeError during email notifications
- -EnableEmail parameter not being honored in non-interactive mode (installer now checks $script:ScriptBoundParameters)

## [0.0.5] - 2025-12-21

### Added
- **Evaluate-STIG Integration** - Automated STIG checklist generation
  - 19 new installer parameters for Evaluate-STIG configuration
  - PowerShell 7.x detection with three-tier fallback
  - Separate monthly scheduled task for STIG checklist generation
  - Support for multiple output formats (CKLB, XCCDF, CSV, Summary, OQE)
  - Interactive and parameter-based configuration options
  - Air-gapped environment support with embedded dependencies
  - Directory structure for STIG checklist outputs

### Fixed
- Log output formatting issue during archive extraction
- False "multiple tasks" detection with single scheduled task
- PowerShell array unwrapping behavior in task detection function
- Multiple collection mode support with conflict detection
- Monthly scheduled task trigger creation for Evaluate-STIG
- Task settings cmdlet name correction
- Parameter set conflict in STIG task registration
- Monthly trigger COM object configuration

### Changed
- Enhanced scheduled task management to support multiple collection modes
- Improved conflict detection during installation of different modes
- Better diagnostic logging for troubleshooting

## [0.0.4] - 2025-12-18

### Added
- Service account credential setup automation
- Automated device credential configuration during installation
- Interactive prompts for credential setup
- Support for pre-captured credentials via PSCredential parameter

### Fixed
- Credential file permissions and ACL handling
- DPAPI encryption for secure credential storage
- Secondary Logon service STIG V-253289 compliance handling

### Changed
- Improved installation workflow with automatic credential setup
- Enhanced user experience with better prompts and feedback

## [0.0.3] - 2025-12-15

### Added
- Installation logging with timestamp-based log files
- Comprehensive error handling and validation
- Support for both DeviceList and Discovery collection modes
- Interactive installation prompts for configuration

### Fixed
- Archive extraction compatibility on Windows
- Python package validation improvements
- Scheduled task creation reliability

### Changed
- Improved installation script structure and organization
- Better user feedback during installation process

## [0.0.2] - 2025-12-10

### Added
- Embedded Python 3.14.x distribution
- Device discovery modes (CDP, SNMP, Hybrid, ARP)
- Scheduled task automation
- Windows DPAPI credential encryption

### Changed
- Simplified deployment with single .zip archive
- Air-gapped environment compatibility

## [0.0.1] - 2025-12-04

### Added
- Initial release of Get-CiscoTechSupport
- Basic tech-support collection from Cisco devices via SSH
- Device list mode for specific device targeting
- Output file organization by date
- PowerShell installation script
- Basic logging functionality

---

## Version History Legend

### Change Categories
- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon-to-be-removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security vulnerability fixes

### Release Types
- **Major (X.0.0)**: Breaking changes or major new features
- **Minor (0.X.0)**: New features, backward-compatible
- **Patch (0.0.X)**: Bug fixes and minor improvements

---

## Planned Features (Future Releases)

### v0.1.0 (Planned)
- Complete email notification system integration
- Email configuration parameters for silent installation
- Production-ready email delivery with all authentication methods
- Comprehensive testing and documentation

### v0.2.0 (Planned)
- Enhanced discovery mode features
- Custom SNMP community string support
- SNMPv3 authentication improvements
- Discovery caching and optimization

### v1.0.0 (Planned)
- Production release with full feature set
- Complete documentation (Wiki pages)
- Comprehensive testing in DoD environments
- Final security audit and STIG compliance verification

---

**Note**: This project is designed for authorized network administration in DoD and enterprise environments. Always ensure proper authorization before deployment.
