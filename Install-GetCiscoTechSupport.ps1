#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installation script for Cisco Tech-Support Collector

.DESCRIPTION
    Extracts the Cisco Tech-Support Collector archive, validates embedded Python
    distribution, and creates a scheduled task for automated collection runs. 
    Designed for offline deployment with embedded Python distribution.
    
    IMPORTANT: This solution REQUIRES a dedicated service account. The SYSTEM
    account should NOT be used for production deployments due to credential
    management and security audit limitations.

.PARAMETER ArchivePath
    Path to the downloaded .zip archive from GitHub

.PARAMETER InstallPath
    Target installation directory (default: C:\Scripts\Get-CiscoTechSupport)

.PARAMETER ScheduleType
    Schedule frequency: Daily, Weekly, Monthly, or None (default: Monthly)

.PARAMETER ScheduleTime
    Time to run the scheduled task (default: 03:00)

.PARAMETER ServiceAccountCredential
    PSCredential object for the dedicated service account that will run the scheduled task.
    This account should have appropriate permissions for the installation and output directories.
    
    NOTE: Device authentication credentials are configured separately using --save-credentials.
    These can be:
    - Different credentials (local device accounts, TACACS+, or RADIUS)
    - The same as the service account (if RADIUS/TACACS+ AAA is configured for this account)
    
    Credentials are stored encrypted in .cisco_credentials file using Windows DPAPI.

.PARAMETER DeviceListFile
    Path to devices.txt file for the collector

.PARAMETER OutputDirectory
    Directory where tech-support files will be saved

.PARAMETER LogPath
    Base path for installation log files. Actual log files will be timestamped.
    (default: C:\Logs\Get-CiscoTechSupport-Install.log)
    Example output: Get-CiscoTechSupport-Install-20251216-143052.log

.PARAMETER Force
    Force reinstallation if already installed

.PARAMETER SkipTaskCreation
    Skip scheduled task creation

.PARAMETER Uninstall
    Uninstall the Cisco Tech-Support Collector and remove all components

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\Get-CiscoTechSupport.zip"
    
    Installs the collector and prompts for service account credentials interactively

.EXAMPLE
    $cred = Get-Credential -Message "Enter service account credentials"
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\Get-CiscoTechSupport.zip" -ServiceAccountCredential $cred

    Installs the collector using pre-captured credentials

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\Get-CiscoTechSupport.zip" -ScheduleType Weekly -ScheduleTime "03:00"

    Installs with weekly schedule at 3:00 AM

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -Uninstall

    Completely removes the Cisco Tech-Support Collector installation

.NOTES
    Author: Kismet Agbasi (Github: kismetgerald Email: KismetG17@gmail.com)
    Version: 0.0.5
    Date: December 18, 2025
    Requires: PowerShell 5.1+ with Administrator privileges
    
    IMPORTANT: This script is designed for embedded Python distributions.
    The archive should contain Python at the root level, not inside a .venv folder.
    
    SECURITY NOTE: A dedicated service account is REQUIRED for production use.
    The SYSTEM account should only be used for testing/development purposes.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='Install')]
param(
    [Parameter(Mandatory = $true, ParameterSetName='Install', HelpMessage = "Path to the .zip archive")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ArchivePath,

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [Parameter(Mandatory = $false, ParameterSetName='Uninstall')]
    [string]$InstallPath = "C:\Scripts\Get-CiscoTechSupport",

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [ValidateSet('Daily', 'Weekly', 'Monthly', 'None')]
    [string]$ScheduleType = 'Monthly',

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$ScheduleTime = '03:00',

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [PSCredential]$ServiceAccountCredential,

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [string]$DeviceListFile,

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [Parameter(Mandatory = $false, ParameterSetName='Uninstall')]
    [string]$LogPath = "C:\Logs\Get-CiscoTechSupport-Install.log",

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [switch]$Force,

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [switch]$SkipTaskCreation,

    [Parameter(Mandatory = $true, ParameterSetName='Uninstall')]
    [switch]$Uninstall
)

#region Configuration
$ErrorActionPreference = 'Stop'
# Generate timestamped log filename
$logDirectory = Split-Path -Path $LogPath -Parent
$logBaseName = [System.IO.Path]::GetFileNameWithoutExtension($LogPath)
$logExtension = [System.IO.Path]::GetExtension($LogPath)
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogFile = Join-Path $logDirectory "$logBaseName-$timestamp$logExtension"
$script:TaskName = "Cisco Tech-Support Collector"
$script:PythonSubfolder = "Python3"
$script:RequiredPackages = @('netmiko', 'pysnmp', 'cryptography')
$script:PythonScriptName = 'get-ciscotechsupport.py'
#endregion

#region Logging Functions
function Write-InstallLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $syslogTimestamp = Get-Date -Format 'MMM dd HH:mm:ss'
    $hostname = $env:COMPUTERNAME
    
    $syslogMessage = "$syslogTimestamp $hostname GetCiscoTechSupportInstall[$PID]: $Level - $Message"
    $consoleMessage = "[$timestamp] [$Level] $Message"
    
    $logDir = Split-Path -Path $script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    Add-Content -Path $script:LogFile -Value $syslogMessage -ErrorAction SilentlyContinue
    
    if (-not $NoConsole) {
        $color = switch ($Level) {
            'ERROR'   { 'Red' }
            'WARNING' { 'Yellow' }
            'SUCCESS' { 'Green' }
            'DEBUG'   { 'Gray' }
            default   { 'White' }
        }
        Write-Host $consoleMessage -ForegroundColor $color
    }
}

function Write-LogSection {
    param([string]$Title)
    $separator = "=" * 80
    Write-InstallLog -Message $separator -Level INFO
    Write-InstallLog -Message $Title -Level INFO
    Write-InstallLog -Message $separator -Level INFO
}
#endregion

#region Log Management Functions
function Get-InstallationLogs {
    <#
    .SYNOPSIS
        Finds all installation log files
    
    .PARAMETER LogPath
        The base log path (without timestamp)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    try {
        $logDirectory = Split-Path -Path $LogPath -Parent
        $logBaseName = [System.IO.Path]::GetFileNameWithoutExtension($LogPath)
        $logExtension = [System.IO.Path]::GetExtension($LogPath)
        
        if (-not (Test-Path $logDirectory)) {
            return @()
        }
        
        # Pattern: Get-CiscoTechSupport-Install-*.log
        $pattern = "$logBaseName-*$logExtension"
        $logFiles = Get-ChildItem -Path $logDirectory -Filter $pattern -File -ErrorAction SilentlyContinue
        
        return $logFiles | Sort-Object LastWriteTime -Descending
    }
    catch {
        Write-InstallLog -Message "Error finding log files: $_" -Level WARNING
        return @()
    }
}

function Show-LogManagementMenu {
    <#
    .SYNOPSIS
        Displays log management menu during uninstallation
    
    .PARAMETER LogPath
        The base log path (without timestamp)
    
    .RETURNS
        'preserve' or 'purge'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    $logFiles = Get-InstallationLogs -LogPath $LogPath
    
    if ($logFiles.Count -eq 0) {
        Write-Host "No installation log files found to manage" -ForegroundColor Gray
        return 'preserve'
    }
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "LOG FILE MANAGEMENT" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Found $($logFiles.Count) installation log file(s):" -ForegroundColor White
    Write-Host ""
    
    $totalSize = 0
    $currentLogFile = $script:LogFile
    
    foreach ($log in $logFiles) {
        $sizeKB = [math]::Round($log.Length / 1KB, 2)
        $totalSize += $log.Length
        
        $isActive = ($log.FullName -eq $currentLogFile)
        $marker = if ($isActive) { " [ACTIVE - Will be preserved]" } else { "" }
        
        Write-Host "  $($log.Name)$marker" -ForegroundColor $(if ($isActive) { 'Cyan' } else { 'Gray' })
        Write-Host "    Last Modified: $($log.LastWriteTime)" -ForegroundColor DarkGray
        Write-Host "    Size: $sizeKB KB" -ForegroundColor DarkGray
    }
    
    $totalSizeKB = [math]::Round($totalSize / 1KB, 2)
    Write-Host ""
    Write-Host "Total Size: $totalSizeKB KB" -ForegroundColor White
    Write-Host ""
    Write-Host "What would you like to do with these log files?" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [P] Preserve - Keep all log files (default)" -ForegroundColor Green
    Write-Host "  [D] Delete - Remove all installation log files" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Selection [P]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'P' }
    
    if ($choice -eq 'D' -or $choice -eq 'd') {
        Write-Host ""
        Write-Host "WARNING: This will permanently delete all installation logs!" -ForegroundColor Red
        $confirm = Read-Host "Type YES in UPPERCASE to confirm deletion"
        
        if ($confirm -cne 'YES') {
            Write-Host "Log deletion cancelled - logs will be preserved" -ForegroundColor Yellow
            Write-InstallLog -Message "Log deletion cancelled by user" -Level INFO
            return 'preserve'
        }
        
        Write-InstallLog -Message "User confirmed deletion of all log files" -Level INFO
        return 'purge'
    }
    else {
        Write-Host "Log files will be preserved" -ForegroundColor Green
        Write-InstallLog -Message "Log files will be preserved" -Level INFO
        return 'preserve'
    }
}

function Remove-InstallationLogs {
    <#
    .SYNOPSIS
        Removes all installation log files
    
    .PARAMETER LogPath
        The base log path (without timestamp)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    try {
        $logFiles = Get-InstallationLogs -LogPath $LogPath
        
        if ($logFiles.Count -eq 0) {
            Write-InstallLog -Message "No log files found to remove" -Level INFO
            return $true
        }
        
        Write-InstallLog -Message "Removing $($logFiles.Count) log file(s)..." -Level INFO
        
        $successCount = 0
        $failCount = 0
        
        $currentLogFile = $script:LogFile
        
        foreach ($log in $logFiles) {
            # Skip the currently active log file
            if ($log.FullName -eq $currentLogFile) {
                Write-InstallLog -Message "Skipped (active): $($log.Name)" -Level INFO
                Write-Host "  Skipping active log file: $($log.Name)" -ForegroundColor Yellow
                $successCount++  # Count as success since we intentionally skipped it
                continue
            }
            
            try {
                Remove-Item -Path $log.FullName -Force -ErrorAction Stop
                Write-InstallLog -Message "Deleted: $($log.Name)" -Level SUCCESS
                $successCount++
            }
            catch {
                Write-InstallLog -Message "Failed to delete: $($log.Name) - $_" -Level ERROR
                $failCount++
            }
        }
        
        Write-Host ""
        Write-Host "Log File Deletion Summary:" -ForegroundColor Cyan
        Write-Host "  Successfully deleted: $successCount" -ForegroundColor Green
        if ($failCount -gt 0) {
            Write-Host "  Failed to delete: $failCount" -ForegroundColor Red
        }
        
        return ($failCount -eq 0)
    }
    catch {
        Write-InstallLog -Message "Error during log file removal: $_" -Level ERROR
        return $false
    }
}
#endregion

#region Utility Functions
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PowerShellVersion {
    $version = $PSVersionTable.PSVersion
    Write-InstallLog -Message "PowerShell Version: $($version.Major).$($version.Minor).$($version.Build)" -Level INFO
    
    if ($version.Major -ge 7) {
        Write-InstallLog -Message "PowerShell 7+ detected - using modern cmdlets" -Level SUCCESS
        return $version
    }
    elseif ($version.Major -eq 5 -and $version.Minor -ge 1) {
        Write-InstallLog -Message "PowerShell 5.1 detected - compatible" -Level SUCCESS
        return $version
    }
    else {
        Write-InstallLog -Message "PowerShell version too old. Requires 5.1 or higher." -Level ERROR
        throw "Unsupported PowerShell version"
    }
}

function Expand-ArchiveCompat {
    param(
        [string]$Path,
        [string]$DestinationPath
    )
    
    Write-InstallLog -Message "Extracting archive: $Path" -Level INFO
    Write-InstallLog -Message "Destination: $DestinationPath" -Level INFO
    
    # Try .NET ZipFile first (fastest method)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        Write-InstallLog -Message "Using .NET ZipFile for extraction (fast method)" -Level INFO
        
        # Check PowerShell version to determine extraction method
        $psVersion = $PSVersionTable.PSVersion.Major
        
        Write-Host "Extracting archive (this may take a moment)..." -ForegroundColor Cyan -NoNewline
        
        if ($psVersion -ge 7) {
            # PowerShell 7+ supports overwrite parameter directly
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath, $true)
            Write-Host " Done!" -ForegroundColor Green
            Write-InstallLog -Message "Archive extracted successfully (PS7+ with overwrite)" -Level SUCCESS
        }
        else {
            # PowerShell 5.1: Check if destination exists and handle manually
            if (Test-Path $DestinationPath) {
                Write-InstallLog -Message "Destination exists, removing before extraction" -Level INFO
                Remove-Item -Path $DestinationPath -Recurse -Force -ErrorAction Stop
            }
            
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath)
            Write-Host " Done!" -ForegroundColor Green
            Write-InstallLog -Message "Archive extracted successfully (.NET ZipFile)" -Level SUCCESS
        }
        return
    }
    catch {
        Write-Host " Failed!" -ForegroundColor Red
        Write-InstallLog -Message ".NET ZipFile extraction failed: $_" -Level WARNING
        Write-InstallLog -Message "Falling back to Expand-Archive cmdlet" -Level INFO
    }
    
    # Fallback to Expand-Archive (slower but more compatible)
    try {
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -Path $Path -DestinationPath $DestinationPath -Force
            Write-InstallLog -Message "Archive extracted successfully (Expand-Archive fallback)" -Level SUCCESS
        }
        else {
            Write-InstallLog -Message "Neither .NET ZipFile nor Expand-Archive are available" -Level ERROR
            throw "No compatible archive extraction method available"
        }
    }
    catch {
        Write-InstallLog -Message "Failed to extract archive: $_" -Level ERROR
        throw
    }
}

function Get-ServiceAccountCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    
    if ($Credential) {
        Write-InstallLog -Message "Using provided service account credential" -Level INFO
        return $Credential
    }
    
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "SERVICE ACCOUNT CONFIGURATION" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IMPORTANT: " -ForegroundColor Yellow -NoNewline
    Write-Host "This scheduled task MUST run under a dedicated service account." -ForegroundColor White
    Write-Host ""
    Write-Host "NOTE: " -ForegroundColor Cyan -NoNewline
    Write-Host "Service account purpose:" -ForegroundColor White
    Write-Host "  - Runs the scheduled task" -ForegroundColor Gray
    Write-Host "  - Stores device credentials in encrypted file" -ForegroundColor Gray
    Write-Host "  - Can optionally be used for RADIUS/TACACS+ authentication to devices" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The service account must have:" -ForegroundColor White
    Write-Host "  - Read/Execute permissions on: $InstallPath" -ForegroundColor Gray
    Write-Host "  - Modify permissions on output directory" -ForegroundColor Gray
    Write-Host "  - Network connectivity to reach Cisco devices" -ForegroundColor Gray
    Write-Host "  - (Optional) RADIUS/TACACS+ access if used for device authentication" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Example service account names:" -ForegroundColor White
    Write-Host "  - DOMAIN\svc_cisco_collector" -ForegroundColor Gray
    Write-Host "  - .\ServiceAccount (local account)" -ForegroundColor Gray
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    $cred = Get-Credential -Message "Enter credentials for the service account that will run the scheduled task"
    
    if (-not $cred) {
        Write-InstallLog -Message "No credentials provided - installation cancelled" -Level ERROR
        throw "Service account credentials are required"
    }
    
    Write-InstallLog -Message "Service account configured: $($cred.UserName)" -Level SUCCESS
    return $cred
}
#endregion

#region Service Account Credential Setup Functions
function Test-SecondaryLogonService {
    try {
        $service = Get-Service -Name "seclogon" -ErrorAction Stop
        return @{
            Exists = $true
            Status = $service.Status
            StartType = $service.StartType
        }
    }
    catch {
        return @{
            Exists = $false
            Status = "NotFound"
            StartType = "NotFound"
        }
    }
}

function Set-SecondaryLogonService {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Manual','Disabled')]
        [string]$StartType,
        
        [Parameter(Mandatory=$false)]
        [switch]$StopService
    )
    
    try {
        if ($StopService) {
            Write-InstallLog -Message "Stopping Secondary Logon service" -Level INFO
            Stop-Service -Name "seclogon" -Force -ErrorAction Stop
            
            # Wait for service to stop (max 10 seconds)
            $timeout = 10
            $elapsed = 0
            while ((Get-Service -Name "seclogon").Status -ne 'Stopped' -and $elapsed -lt $timeout) {
                Start-Sleep -Seconds 1
                $elapsed++
            }
            
            $service = Get-Service -Name "seclogon"
            if ($service.Status -eq 'Stopped') {
                Write-InstallLog -Message "Secondary Logon service stopped successfully" -Level SUCCESS
            }
            else {
                Write-InstallLog -Message "Secondary Logon service did not stop within timeout" -Level WARNING
                return $false
            }
        }
        
        Set-Service -Name "seclogon" -StartupType $StartType -ErrorAction Stop
        Write-InstallLog -Message "Secondary Logon service startup type set to: $StartType" -Level INFO
        
        # Validate the change
        $service = Get-Service -Name "seclogon"
        if ($service.StartType -eq $StartType) {
            Write-InstallLog -Message "Verified: Secondary Logon service is $StartType" -Level SUCCESS
            
            if ($StopService -and $service.Status -eq 'Stopped') {
                Write-InstallLog -Message "Verified: Secondary Logon service is Stopped" -Level SUCCESS
            }
            
            return $true
        }
        else {
            Write-InstallLog -Message "Failed to set Secondary Logon service to $StartType" -Level ERROR
            return $false
        }
    }
    catch {
        Write-InstallLog -Message "Failed to modify Secondary Logon service: $_" -Level ERROR
        return $false
    }
}

#region Credential File Security Functions

function Set-CredentialFilePermissions {
    <#
    .SYNOPSIS
        Secures the credential file with restricted permissions and hidden attribute
    
    .DESCRIPTION
        Sets the credential file to hidden and configures ACLs so only the service
        account has Read/Write access. All other users are denied access.
    
    .PARAMETER FilePath
        Path to the credential file
    
    .PARAMETER ServiceAccountName
        Username of the service account (e.g., DOMAIN\svc_account)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$ServiceAccountName
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-InstallLog -Message "Credential file not found: $FilePath" -Level WARNING
            return $false
        }
        
        Write-InstallLog -Message "Securing credential file: $FilePath" -Level INFO
        
        # Set the hidden attribute
        $file = Get-Item $FilePath -Force
        $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::Hidden
        Write-InstallLog -Message "Set hidden attribute on credential file" -Level SUCCESS
        
        # Get the current ACL
        $acl = Get-Acl -Path $FilePath
        
        # Disable inheritance and remove inherited permissions
        $acl.SetAccessRuleProtection($true, $false)
        
        # Remove all existing access rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        
        # Create access rule for service account (Read, Write)
        $serviceAccountIdentity = New-Object System.Security.Principal.NTAccount($ServiceAccountName)
        $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::Read -bor `
                           [System.Security.AccessControl.FileSystemRights]::Write
        $accessType = [System.Security.AccessControl.AccessControlType]::Allow
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $serviceAccountIdentity,
            $fileSystemRights,
            $inheritanceFlags,
            $propagationFlags,
            $accessType
        )
        
        $acl.AddAccessRule($accessRule)
        
        # Apply the modified ACL
        Set-Acl -Path $FilePath -AclObject $acl
        
        Write-InstallLog -Message "Credential file permissions configured:" -Level SUCCESS
        Write-InstallLog -Message "  - Service Account ($ServiceAccountName): Read, Write" -Level INFO
        Write-InstallLog -Message "  - All Others: Denied (no inherited permissions)" -Level INFO
        Write-InstallLog -Message "  - File Attribute: Hidden" -Level INFO
        
        # Verify the permissions
        $verifyAcl = Get-Acl -Path $FilePath
        $serviceAccountAccess = $verifyAcl.Access | Where-Object { $_.IdentityReference -eq $ServiceAccountName }
        
        if ($serviceAccountAccess) {
            Write-InstallLog -Message "Verified: Service account has access to credential file" -Level SUCCESS
            return $true
        }
        else {
            Write-InstallLog -Message "WARNING: Could not verify service account permissions" -Level WARNING
            return $false
        }
    }
    catch {
        Write-InstallLog -Message "Failed to secure credential file: $_" -Level ERROR
        return $false
    }
}

#endregion

function Start-ServiceAccountCredentialSetup {
    param(
        [Parameter(Mandatory=$true)]
        [PSCredential]$ServiceAccountCred,
        
        [Parameter(Mandatory=$true)]
        [string]$InstallPath,
        
        [Parameter(Mandatory=$true)]
        [string]$PythonScript
    )
    
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "CISCO DEVICE CREDENTIAL SETUP" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    $serviceInfo = Test-SecondaryLogonService
    
    if (-not $serviceInfo.Exists) {
        Write-Host "WARNING: Secondary Logon service not found" -ForegroundColor Red
        Write-Host "Cannot automatically launch credential setup" -ForegroundColor Yellow
        Write-InstallLog -Message "Secondary Logon service not found" -Level ERROR
        return $false
    }
    
    $needsRestore = $false
    $wasStoppedAndDisabled = ($serviceInfo.Status -eq 'Stopped' -and $serviceInfo.StartType -eq 'Disabled')
    
    Write-Host "Secondary Logon Service Status:" -ForegroundColor White
    Write-Host "  Current Status: $($serviceInfo.Status)" -ForegroundColor Gray
    Write-Host "  Startup Type: $($serviceInfo.StartType)" -ForegroundColor Gray
    Write-Host ""
    
    if ($wasStoppedAndDisabled) {
        Write-Host "NOTICE: " -ForegroundColor Yellow -NoNewline
        Write-Host "Secondary Logon service is STOPPED and DISABLED (STIG V-253289 compliant)" -ForegroundColor White
        Write-Host ""
        Write-Host "STIG V-253289 requires this service to be disabled for security." -ForegroundColor Gray
        Write-Host "To configure device credentials, we need to TEMPORARILY enable it." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Automated Setup Process:" -ForegroundColor Cyan
        Write-Host "  1. Set Secondary Logon to 'Manual' startup" -ForegroundColor Gray
        Write-Host "  2. Launch PowerShell as service account: $($ServiceAccountCred.UserName)" -ForegroundColor Gray
        Write-Host "  3. Run credential setup script (you'll be prompted for device credentials)" -ForegroundColor Gray
        Write-Host "  4. Verify credential file creation" -ForegroundColor Gray
        Write-Host "  5. Stop service and restore to 'Disabled' (STIG compliance)" -ForegroundColor Gray
        Write-Host ""
        
        $response = Read-Host "Proceed with automated credential setup? (yes/no) [yes]"
        if ([string]::IsNullOrWhiteSpace($response)) { $response = 'yes' }

        if ($response -notmatch '^y(es)?$|^Y(ES)?$') {
            Write-Host ""
            Write-Host "Credential setup skipped - you'll need to configure manually" -ForegroundColor Yellow
            Write-InstallLog -Message "Automated credential setup declined by user" -Level WARNING
            return $false
        }
        
        Write-Host ""
        Write-InstallLog -Message "Temporarily enabling Secondary Logon service for credential setup" -Level INFO
        Write-Host "Enabling Secondary Logon service..." -ForegroundColor Cyan
        
        if (-not (Set-SecondaryLogonService -StartType Manual)) {
            Write-Host "Failed to enable Secondary Logon service" -ForegroundColor Red
            Write-Host "You'll need to configure credentials manually" -ForegroundColor Yellow
            return $false
        }
        
        Write-Host "Secondary Logon service enabled" -ForegroundColor Green
        $needsRestore = $true
        Start-Sleep -Seconds 2
    }
    elseif ($serviceInfo.Status -eq 'Running') {
        Write-Host "Secondary Logon service is RUNNING - proceeding with credential setup" -ForegroundColor Green
        Write-Host ""
        Write-InstallLog -Message "Secondary Logon service is running - no changes needed" -Level INFO
    }
    else {
        Write-Host "Secondary Logon service is available - proceeding with credential setup" -ForegroundColor Green
        Write-Host ""
        Write-InstallLog -Message "Secondary Logon service status: $($serviceInfo.Status), StartType: $($serviceInfo.StartType)" -Level INFO
    }
    
    Write-Host ""
    Write-Host "Launching credential setup as: $($ServiceAccountCred.UserName)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IMPORTANT: A new PowerShell window will open where you'll enter:" -ForegroundColor Yellow
    Write-Host "  - Device username (for authenticating to Cisco devices)" -ForegroundColor White
    Write-Host "  - Device password" -ForegroundColor White
    Write-Host "  - Enable password (if required for privilege 15 access)" -ForegroundColor White
    Write-Host ""
    Write-Host "NOTE: These can be different from OR the same as the service account" -ForegroundColor Cyan
    Write-Host "      depending on your RADIUS/TACACS+ configuration." -ForegroundColor Cyan
    Write-Host ""
    
    $maxAttempts = 3
    $attempt = 0
    $launchSuccess = $false
    
    while ($attempt -lt $maxAttempts -and -not $launchSuccess) {
        $attempt++
        
        if ($attempt -gt 1) {
            Write-Host ""
            Write-Host "Attempt $attempt of $maxAttempts" -ForegroundColor Yellow
        }
        
        Write-Host "Enter password for service account: $($ServiceAccountCred.UserName)" -ForegroundColor Cyan
        $userPassword = Read-Host -AsSecureString
        
        if ($userPassword.Length -eq 0) {
            Write-Host "Password cannot be empty. Please try again." -ForegroundColor Red
            continue
        }
        
        $tempCred = New-Object System.Management.Automation.PSCredential($ServiceAccountCred.UserName, $userPassword)
        
        $credSetupScript = @"
`$ErrorActionPreference = 'Continue'

try {
    Set-Location '$InstallPath'
    Write-Host ''
    Write-Host 'Cisco Device Credential Setup' -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Service Account: $($ServiceAccountCred.UserName)' -ForegroundColor White
    Write-Host 'Install Path: $InstallPath' -ForegroundColor White
    Write-Host ''
    
    # Verify python.exe exists
    if (-not (Test-Path '$($script:PythonSubfolder)\python.exe')) {
        Write-Host 'ERROR: python.exe not found in current directory' -ForegroundColor Red
        Write-Host "Current directory: `$(Get-Location)" -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Press Enter to close...' -ForegroundColor Yellow
        Read-Host
        exit 1
    }
    
    # Verify Python script exists
    if (-not (Test-Path '.\$PythonScript')) {
        Write-Host 'ERROR: $PythonScript not found in current directory' -ForegroundColor Red
        Write-Host "Current directory: `$(Get-Location)" -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Press Enter to close...' -ForegroundColor Yellow
        Read-Host
        exit 1
    }
    
    Write-Host 'You will now be prompted for Cisco device credentials.' -ForegroundColor Yellow
    Write-Host 'These credentials will be encrypted and saved to .cisco_credentials' -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Enter the following:' -ForegroundColor White
    Write-Host '  1. Device Username (for SSH/Telnet authentication)' -ForegroundColor Gray
    Write-Host '  2. Device Password' -ForegroundColor Gray
    Write-Host '  3. Enable Password (for privilege 15 access)' -ForegroundColor Gray
    Write-Host ''
    
    # Run the Python script
    & '$($script:PythonSubfolder)\python.exe' '$PythonScript' --save-credentials
    
    `$pythonExitCode = `$LASTEXITCODE
    
    Write-Host ''
    Write-Host "Python script exit code: `$pythonExitCode" -ForegroundColor Gray
    Write-Host ''
    
    # Check if credential file was created
    if (Test-Path '.cisco_credentials') {
        `$fileSize = (Get-Item '.cisco_credentials').Length
        if (`$fileSize -gt 0) {
            Write-Host 'SUCCESS: Credential file created' -ForegroundColor Green
            Write-Host "Location: $InstallPath\.cisco_credentials" -ForegroundColor Gray
            Write-Host "Size: `$fileSize bytes" -ForegroundColor Gray
        }
        else {
            Write-Host 'WARNING: Credential file is empty' -ForegroundColor Yellow
            Write-Host "Location: $InstallPath\.cisco_credentials" -ForegroundColor Gray
        }
    }
    else {
        Write-Host 'WARNING: Credential file was not created' -ForegroundColor Yellow
        Write-Host "Expected location: $InstallPath\.cisco_credentials" -ForegroundColor Gray
        
        if (`$pythonExitCode -ne 0) {
            Write-Host "Python script exited with error code: `$pythonExitCode" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host ''
    Write-Host 'ERROR: An exception occurred' -ForegroundColor Red
    Write-Host "Error: `$_" -ForegroundColor Red
    Write-Host "Location: `$(Get-Location)" -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Press Enter to close this window and return to installation...' -ForegroundColor Cyan
Read-Host
"@
        
        # Use SystemDrive\Temp (shared system directory) instead of $env:TEMP (user-specific)
        # because the service account running under Start-Process -Credential cannot access 
        # the interactive user's AppData\Local\Temp directory
        $tempScriptPath = Join-Path $env:SystemDrive\Temp "cisco-cred-setup-$(Get-Random).ps1"

        # Ensure SystemDrive\Temp exists
        $systemTempDir = Join-Path $env:SystemDrive "Temp"
        if (-not (Test-Path $systemTempDir)) {
            New-Item -Path $systemTempDir -ItemType Directory -Force | Out-Null
        }
        
        try {
            Set-Content -Path $tempScriptPath -Value $credSetupScript -Force
            Write-InstallLog -Message "Launching credential setup window (attempt $attempt)" -Level INFO
            Write-Host ""
            Write-Host "Launching credential setup window..." -ForegroundColor Cyan
            
            $processParams = @{
                FilePath = "powershell.exe"
                ArgumentList = @(
                    "-NoProfile"
                    "-ExecutionPolicy", "Bypass"
                    "-File", "`"$tempScriptPath`""
                )
                Credential = $tempCred
                Wait = $true
                WindowStyle = "Normal"
                ErrorAction = "Stop"
            }
            
            Start-Process @processParams
            
            Write-Host ""
            Write-Host "Credential setup window closed" -ForegroundColor Green
            Write-InstallLog -Message "Credential setup completed successfully" -Level SUCCESS
            $launchSuccess = $true
            
        }
        catch {
            if ($_.Exception.Message -like "*password*" -or $_.Exception.Message -like "*1326*") {
                Write-Host ""
                Write-Host "ERROR: Incorrect password for $($ServiceAccountCred.UserName)" -ForegroundColor Red
                Write-InstallLog -Message "Password authentication failed (attempt $attempt)" -Level WARNING
                
                if ($attempt -lt $maxAttempts) {
                    Write-Host "Please try again..." -ForegroundColor Yellow
                }
                else {
                    Write-Host ""
                    Write-Host "Maximum password attempts reached" -ForegroundColor Red
                    Write-InstallLog -Message "Max password attempts reached - credential setup failed" -Level ERROR
                }
            }
            else {
                Write-Host ""
                Write-Host "ERROR: Failed to launch credential setup: $($_.Exception.Message)" -ForegroundColor Red
                Write-InstallLog -Message "Credential setup launch failed: $_" -Level ERROR
                break
            }
        }
        finally {
            if (Test-Path $tempScriptPath) {
                Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    if (-not $launchSuccess) {
        Write-Host ""
        Write-Host "Automated credential setup could not be completed" -ForegroundColor Yellow
        Write-Host "Please use the manual method in the NEXT STEPS section" -ForegroundColor Yellow
        Write-InstallLog -Message "Automated credential setup failed after $attempt attempts" -Level ERROR
    }
    
    # Only restore if we changed it (was stopped AND disabled)
    if ($needsRestore) {
        Write-Host ""
        Write-Host "Restoring STIG compliance..." -ForegroundColor Cyan
        Write-InstallLog -Message "Stopping and disabling Secondary Logon service" -Level INFO
        
        if (Set-SecondaryLogonService -StartType Disabled -StopService) {
            Write-Host "Secondary Logon service stopped and disabled (STIG compliant)" -ForegroundColor Green
            
            $finalCheck = Get-Service -Name "seclogon"
            Write-Host "  Status: $($finalCheck.Status)" -ForegroundColor Gray
            Write-Host "  Startup Type: $($finalCheck.StartType)" -ForegroundColor Gray
            Write-InstallLog -Message "Secondary Logon service restored: Status=$($finalCheck.Status), StartType=$($finalCheck.StartType)" -Level SUCCESS
        }
        else {
            Write-Host "WARNING: Failed to restore Secondary Logon service" -ForegroundColor Red
            Write-Host "MANUAL ACTION REQUIRED to maintain STIG compliance:" -ForegroundColor Yellow
            Write-Host "  Stop-Service -Name seclogon -Force" -ForegroundColor Yellow
            Write-Host "  Set-Service -Name seclogon -StartupType Disabled" -ForegroundColor Yellow
            Write-InstallLog -Message "Failed to restore Secondary Logon service - manual intervention required" -Level ERROR
        }
    }
    
    Start-Sleep -Seconds 2
    
    $credFile = Join-Path $InstallPath ".cisco_credentials"
    Write-Host ""
    Write-Host "Verifying credential file..." -ForegroundColor Cyan
    
    if (Test-Path $credFile) {
        $fileInfo = Get-Item $credFile
        if ($fileInfo.Length -gt 0) {
            Write-Host "SUCCESS: Credential file created and verified" -ForegroundColor Green
            Write-Host "  Location: $credFile" -ForegroundColor Gray
            Write-Host "  Size: $($fileInfo.Length) bytes" -ForegroundColor Gray
            Write-Host "  Created: $($fileInfo.CreationTime)" -ForegroundColor Gray
            Write-InstallLog -Message "Credential file verified: $credFile ($($fileInfo.Length) bytes)" -Level SUCCESS
            
            # Secure the credential file
            Write-Host ""
            Write-Host "Securing credential file..." -ForegroundColor Cyan
            $secureResult = Set-CredentialFilePermissions -FilePath $credFile -ServiceAccountName $ServiceAccountCred.UserName
            if ($secureResult) {
                Write-Host "Credential file secured successfully" -ForegroundColor Green
            }
            else {
                Write-Host "WARNING: Could not fully secure credential file" -ForegroundColor Yellow
                Write-Host "Manual verification recommended" -ForegroundColor Yellow
            }
            
            return $true
        }
        else {
            Write-Host "WARNING: Credential file exists but is EMPTY" -ForegroundColor Yellow
            Write-Host "The credential setup may not have completed successfully" -ForegroundColor Yellow
            Write-InstallLog -Message "Credential file is empty - setup may have failed" -Level WARNING
            return $false
        }
    }
    else {
        Write-Host "WARNING: Credential file was NOT created" -ForegroundColor Yellow
        Write-Host "The credential setup did not complete successfully" -ForegroundColor Yellow
        Write-InstallLog -Message "Credential file not found after setup attempt" -Level WARNING
        return $false
    }
}
#endregion

#region Python Validation Functions
function Test-EmbeddedPython {
    param([string]$InstallPath)
    
    Write-InstallLog -Message "Validating embedded Python distribution..." -Level INFO
    
    $pythonExe = "$InstallPath\$($script:PythonSubfolder)\python.exe"
    $libDir = "$InstallPath\$($script:PythonSubfolder)\Lib"
    $sitePackages = "$InstallPath\$($script:PythonSubfolder)\Lib\site-packages"
    
    if (-not (Test-Path $pythonExe)) {
        Write-InstallLog -Message "Missing python.exe at root level" -Level ERROR
        return $false
    }
    
    if (-not (Test-Path $libDir)) {
        Write-InstallLog -Message "Missing Lib directory" -Level ERROR
        return $false
    }
    
    if (-not (Test-Path $sitePackages)) {
        Write-InstallLog -Message "Missing Lib\site-packages directory" -Level ERROR
        return $false
    }
    
    Write-InstallLog -Message "Embedded Python structure validated" -Level SUCCESS
    
    try {
        $originalLocation = Get-Location
        Set-Location $InstallPath
        
        $pythonVersion = & $pythonExe --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-InstallLog -Message "Python version: $pythonVersion" -Level INFO
        }
        else {
            Write-InstallLog -Message "Failed to execute Python" -Level ERROR
            return $false
        }
    }
    catch {
        Write-InstallLog -Message "Failed to execute Python: $_" -Level ERROR
        return $false
    }
    finally {
        Set-Location $originalLocation
    }
    
    return $true
}

function Test-RequiredPackages {
    param(
        [string]$PythonExe,
        [string[]]$Packages
    )
    
    Write-InstallLog -Message "Validating required Python packages..." -Level INFO
    
    $pythonDir = Split-Path $PythonExe -Parent
    $originalLocation = Get-Location
    
    try {
        Set-Location $pythonDir
        
        $allInstalled = $true
        foreach ($package in $Packages) {
            try {
                $importTest = "import $package"
                & $PythonExe -c $importTest 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    $versionResult = & $PythonExe -m pip show $package 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        $versionLine = $versionResult | Select-String -Pattern '^Version:'
                        $version = if ($versionLine) { ($versionLine -split ':')[1].Trim() } else { 'unknown' }
                        Write-InstallLog -Message "Package '$package' (v$version) - OK" -Level SUCCESS
                    }
                    else {
                        Write-InstallLog -Message "Package '$package' - OK" -Level SUCCESS
                    }
                }
                else {
                    Write-InstallLog -Message "Package '$package' - MISSING" -Level ERROR
                    $allInstalled = $false
                }
            }
            catch {
                Write-InstallLog -Message "Failed to check package '$package': $_" -Level ERROR
                $allInstalled = $false
            }
        }
        
        return $allInstalled
    }
    finally {
        Set-Location $originalLocation
    }
}
#endregion

#region Scheduled Task Functions
function New-CiscoCollectorTask {
    <#
    .SYNOPSIS
        Creates a scheduled task for Cisco Tech-Support Collector
    
    .PARAMETER CollectionMode
        The collection mode: 'DeviceList' or 'Discovery'
    #>
    param(
        [string]$InstallPath,
        [string]$ScheduleType,
        [string]$ScheduleTime,
        [PSCredential]$Credential,
        [string]$TaskArguments,
        [Parameter(Mandatory = $true)]
        [ValidateSet('DeviceList', 'Discovery')]
        [string]$CollectionMode
    )
    
    # Generate dynamic task name based on collection mode
    $taskName = Get-CollectionModeTaskName -Mode $CollectionMode
    
    Write-InstallLog -Message "Creating scheduled task: $taskName" -Level INFO
    
    $pythonExe = "$InstallPath\$($script:PythonSubfolder)\python.exe"
    $scriptPath = Join-Path $InstallPath $script:PythonScriptName
    
    $fullArguments = "`"$scriptPath`" --non-interactive $TaskArguments"
    
    Write-InstallLog -Message "Task will execute: $pythonExe $fullArguments" -Level DEBUG
    
    $action = New-ScheduledTaskAction -Execute $pythonExe -Argument $fullArguments -WorkingDirectory $InstallPath
    
    $trigger = switch ($ScheduleType) {
        'Daily' {
            New-ScheduledTaskTrigger -Daily -At $ScheduleTime
        }
        'Weekly' {
            New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $ScheduleTime
        }
        'Monthly' {
            # PowerShell scheduled task cmdlets don't support "1st of month" directly
            # We'll create it and then modify via COM object
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $ScheduleTime -WeeksInterval 4
            $trigger
        }
        default {
            Write-InstallLog -Message "No schedule specified - task will be created without trigger" -Level WARNING
            $null
        }
    }
    
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
    
    $description = "Automated collection of Cisco tech-support output from network devices. Collection Mode: $CollectionMode. Configured to run $ScheduleType at $ScheduleTime. IMPORTANT: This task must NOT be run as SYSTEM - use a dedicated service account."
    
    try {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        
        if ($trigger) {
            Register-ScheduledTask -TaskName $taskName `
                                   -Description $description `
                                   -Action $action `
                                   -Trigger $trigger `
                                   -User $username `
                                   -Password $password `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -Force | Out-Null
        }
        else {
            Register-ScheduledTask -TaskName $taskName `
                                   -Description $description `
                                   -Action $action `
                                   -User $username `
                                   -Password $password `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -Force | Out-Null
        }
        
        # Adjust Monthly trigger to run on 1st day of month
        if ($ScheduleType -eq 'Monthly') {
            try {
                $taskScheduler = New-Object -ComObject Schedule.Service
                $taskScheduler.Connect()
                $taskFolder = $taskScheduler.GetFolder("\")
                $task = $taskFolder.GetTask($taskName)
                $taskDefinition = $task.Definition
                
                # Clear existing triggers and create new monthly trigger
                $taskDefinition.Triggers.Clear()
                $monthlyTrigger = $taskDefinition.Triggers.Create(4) # 4 = TASK_TRIGGER_MONTHLY
                $monthlyTrigger.StartBoundary = (Get-Date).ToString("yyyy-MM-01T$ScheduleTime`:00")
                $monthlyTrigger.MonthsOfYear = 0xFFF # All months (bits 1-12)
                $monthlyTrigger.DaysOfMonth = 1 # 1st day
                $monthlyTrigger.Enabled = $true
                
                # Save the modified task
                $taskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 4, $username, $password, 1) | Out-Null
                
                Write-InstallLog -Message "Monthly trigger configured for 1st day of month" -Level SUCCESS
            }
            catch {
                Write-InstallLog -Message "Warning: Could not set monthly trigger to 1st day: $_" -Level WARNING
                Write-InstallLog -Message "Task will run every 4 weeks instead" -Level INFO
            }
        }

        Write-InstallLog -Message "Scheduled task created successfully" -Level SUCCESS
        Write-InstallLog -Message "Task: $taskName" -Level INFO
        Write-InstallLog -Message "Collection Mode: $CollectionMode" -Level INFO
        Write-InstallLog -Message "Schedule: $ScheduleType at $ScheduleTime" -Level INFO
        Write-InstallLog -Message "User: $username" -Level INFO
        
        $task = Get-ScheduledTask -TaskName $taskName
        $principal = $task.Principal
        if ($principal.UserId -like "*SYSTEM*") {
            Write-InstallLog -Message "WARNING: Task is configured to run as SYSTEM - this is not supported!" -Level ERROR
            Write-InstallLog -Message "The Python script will fail if executed as SYSTEM." -Level ERROR
        }
        
        # Return the task name for use in later functions
        return $taskName
    }
    catch {
        Write-InstallLog -Message "Failed to create scheduled task: $_" -Level ERROR
        throw
    }
}

function Remove-CiscoCollectorTask {
    <#
    .SYNOPSIS
        Removes Cisco Tech-Support Collector scheduled task(s)
    
    .PARAMETER TaskName
        Specific task name to remove. If not provided, prompts user to select.
    
    .PARAMETER Force
        Remove all collector tasks without prompting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TaskName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        $existingTasks = Get-ExistingCollectorTasks
        
        if ($existingTasks.Count -eq 0) {
            Write-InstallLog -Message "No Cisco Tech-Support Collector tasks found" -Level INFO
            return $false
        }
        
        # If specific task name provided, remove only that task
        if ($TaskName) {
            $taskToRemove = $existingTasks | Where-Object { $_.TaskName -eq $TaskName }
            if ($taskToRemove) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
                Write-InstallLog -Message "Removed scheduled task: $TaskName" -Level SUCCESS
                return $true
            }
            else {
                Write-InstallLog -Message "Task not found: $TaskName" -Level WARNING
                return $false
            }
        }
        
        # If Force flag, remove all tasks without prompting
        if ($Force) {
            foreach ($task in $existingTasks) {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                Write-InstallLog -Message "Removed scheduled task: $($task.TaskName)" -Level SUCCESS
            }
            return $true
        }
        
        # Single task found - remove without prompting during uninstall
        if ($existingTasks.Count -eq 1) {
            $taskToRemove = $existingTasks[0]
            Write-Host "`nFound scheduled task: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($taskToRemove.TaskName)" -ForegroundColor White
            
            Unregister-ScheduledTask -TaskName $taskToRemove.TaskName -Confirm:$false -ErrorAction Stop
            Write-InstallLog -Message "Removed scheduled task: $($taskToRemove.TaskName)" -Level SUCCESS
            return $true
        }
        else {
            # Multiple tasks - let user choose
            Write-Host "`nFound multiple Cisco Tech-Support Collector tasks:" -ForegroundColor Yellow
            Write-Host ""
            
            for ($i = 0; $i -lt $existingTasks.Count; $i++) {
                $task = $existingTasks[$i]
                Write-Host "  [$($i + 1)] $($task.TaskName)" -ForegroundColor White
                Write-Host "      State: $($task.State)" -ForegroundColor Gray
                
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
                if ($taskInfo -and $taskInfo.LastRunTime) {
                    Write-Host "      Last Run: $($taskInfo.LastRunTime)" -ForegroundColor Gray
                }
            }
            
            Write-Host "  [A] Remove ALL tasks" -ForegroundColor Cyan
            Write-Host "  [N] Don't remove any tasks" -ForegroundColor Cyan
            Write-Host ""
            
            $selection = Read-Host "Select task(s) to remove [N]"
            if ([string]::IsNullOrWhiteSpace($selection)) { $selection = 'N' }
            
            if ($selection -eq 'A' -or $selection -eq 'a') {
                # Remove all tasks
                foreach ($task in $existingTasks) {
                    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                    Write-InstallLog -Message "Removed scheduled task: $($task.TaskName)" -Level SUCCESS
                }
                return $true
            }
            elseif ($selection -eq 'N' -or $selection -eq 'n') {
                Write-InstallLog -Message "Task removal cancelled by user" -Level INFO
                return $false
            }
            elseif ([int]::TryParse($selection, [ref]$null)) {
                # Remove specific task by number
                $index = [int]$selection - 1
                if ($index -ge 0 -and $index -lt $existingTasks.Count) {
                    $taskToRemove = $existingTasks[$index]
                    Unregister-ScheduledTask -TaskName $taskToRemove.TaskName -Confirm:$false -ErrorAction Stop
                    Write-InstallLog -Message "Removed scheduled task: $($taskToRemove.TaskName)" -Level SUCCESS
                    return $true
                }
                else {
                    Write-Host "Invalid selection" -ForegroundColor Red
                    Write-InstallLog -Message "Invalid task selection: $selection" -Level WARNING
                    return $false
                }
            }
            else {
                Write-Host "Invalid selection" -ForegroundColor Red
                Write-InstallLog -Message "Invalid task selection: $selection" -Level WARNING
                return $false
            }
        }
    }
    catch {
        Write-InstallLog -Message "Failed to remove scheduled task: $_" -Level ERROR
        return $false
    }
}

function Get-SanitizedTaskName {
    <#
    .SYNOPSIS
        Sanitizes a task name for Windows Task Scheduler compatibility
    
    .PARAMETER TaskName
        The proposed task name
    
    .DESCRIPTION
        Windows Task Scheduler has issues with certain characters, particularly
        hyphens in specific positions. This function creates a safe task name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )
    
    # Replace problematic characters
    # Hyphens can cause issues, replace with underscore
    # Keep spaces and alphanumeric characters
    $sanitized = $TaskName -replace '-', '_' -replace '[^\w\s]', ''
    
    return $sanitized.Trim()
}

function Get-CollectionModeTaskName {
    <#
    .SYNOPSIS
        Generates a task name with the collection mode appended
    
    .PARAMETER Mode
        The collection mode: 'DeviceList' or 'Discovery'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DeviceList', 'Discovery')]
        [string]$Mode
    )
    
    $baseTaskName = "Cisco TechSupport Collector"
    
    $taskName = switch ($Mode) {
        'DeviceList' { "$baseTaskName MODE DeviceList" }
        'Discovery'  { "$baseTaskName MODE Discovery" }
    }
    
    # Sanitize the task name for Task Scheduler compatibility
    return Get-SanitizedTaskName -TaskName $taskName
}

function Get-ExistingCollectorTasks {
    <#
    .SYNOPSIS
        Finds all Cisco Tech-Support Collector scheduled tasks
    
    .DESCRIPTION
        Searches for all scheduled tasks that match the collector naming pattern
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Match both old and new naming patterns for backward compatibility
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | 
                    Where-Object { 
                        $_.TaskName -like "Cisco Tech-Support Collector*" -or
                        $_.TaskName -like "Cisco TechSupport Collector*"
                    }
        
        return $allTasks
    }
    catch {
        Write-InstallLog -Message "Error searching for existing tasks: $_" -Level ERROR
        return @()
    }
}

function Start-InitialTaskRun {
    <#
    .SYNOPSIS
        Prompts user to run the scheduled task immediately
    
    .PARAMETER TaskName
        The name of the scheduled task to run
    
    .PARAMETER ServiceAccountName
        The service account username for context
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,
        
        [Parameter(Mandatory = $true)]
        [string]$ServiceAccountName
    )
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "INITIAL TASK RUN" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Would you like to run the scheduled task now for an initial test?" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This will:" -ForegroundColor White
    Write-Host "  - Execute the task immediately as $ServiceAccountName" -ForegroundColor Gray
    Write-Host "  - Collect tech-support output from configured devices" -ForegroundColor Gray
    Write-Host "  - Verify that credentials and configuration are working correctly" -ForegroundColor Gray
    Write-Host "  - Run in the background (you can check Task Scheduler for status)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "NOTE: " -ForegroundColor Cyan -NoNewline
    Write-Host "Device credentials must be configured for this to succeed." -ForegroundColor White
    Write-Host ""
    
    $response = Read-Host "Run task now? (yes/no) [no]"
    if ([string]::IsNullOrWhiteSpace($response)) { $response = 'no' }
    
    if ($response -match '^y(es)?$|^Y(ES)?$') {
        Write-Host ""
        Write-Host "Starting scheduled task..." -ForegroundColor Cyan
        Write-InstallLog -Message "User requested initial task run" -Level INFO
        
        try {
            # Start the scheduled task
            Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            
            Write-Host "Task started successfully!" -ForegroundColor Green
            Write-InstallLog -Message "Scheduled task started: $TaskName" -Level SUCCESS
            
            # Wait a moment and check task state
            Start-Sleep -Seconds 2
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            
            if ($task) {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
                Write-Host ""
                Write-Host "Task Status:" -ForegroundColor Cyan
                Write-Host "  State: $($task.State)" -ForegroundColor Gray
                
                if ($taskInfo) {
                    Write-Host "  Last Run Time: $($taskInfo.LastRunTime)" -ForegroundColor Gray
                    Write-Host "  Last Result: $($taskInfo.LastTaskResult)" -ForegroundColor Gray
                }
                
                Write-Host ""
                Write-Host "You can monitor the task in Task Scheduler or check the output directory." -ForegroundColor White
                Write-InstallLog -Message "Task state: $($task.State)" -Level INFO
            }
            
            return $true
        }
        catch {
            Write-Host "Failed to start task: $_" -ForegroundColor Red
            Write-InstallLog -Message "Failed to start scheduled task: $_" -Level ERROR
            Write-Host ""
            Write-Host "You can manually run the task from Task Scheduler or using:" -ForegroundColor Yellow
            Write-Host "  Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
            return $false
        }
    }
    else {
        Write-Host ""
        Write-Host "Initial task run skipped" -ForegroundColor Yellow
        Write-InstallLog -Message "User declined initial task run" -Level INFO
        return $false
    }
}

#endregion

#region Uninstallation Functions
function Uninstall-CiscoCollector {
    try {
        Write-LogSection "CISCO TECH-SUPPORT COLLECTOR UNINSTALLATION"
        Write-InstallLog -Message "Uninstallation started at $(Get-Date)" -Level INFO
        Write-InstallLog -Message "User: $env:USERNAME on $env:COMPUTERNAME" -Level INFO
        
        if (-not (Test-Administrator)) {
            Write-InstallLog -Message "This script requires Administrator privileges" -Level ERROR
            throw "Administrator privileges required"
        }
        Write-InstallLog -Message "Administrator privileges confirmed" -Level SUCCESS
        
        $componentsRemoved = @()
        $componentsFailed = @()
        
        if (-not (Test-Path $InstallPath)) {
            Write-InstallLog -Message "Installation directory not found: $InstallPath" -Level WARNING
            Write-InstallLog -Message "Nothing to uninstall" -Level INFO
            return
        }
        
        Write-InstallLog -Message "Found installation at: $InstallPath" -Level INFO
        
        Write-Host "`n" -NoNewline
        Write-Host "WARNING: " -ForegroundColor Red -NoNewline
        Write-Host "This will completely remove the Cisco Tech-Support Collector" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "The following will be removed:" -ForegroundColor White
        Write-Host "  - Installation directory: $InstallPath" -ForegroundColor Gray
        Write-Host "  - Scheduled task: $script:TaskName" -ForegroundColor Gray
        Write-Host "  - All Python scripts and dependencies" -ForegroundColor Gray
        Write-Host ""
        Write-Host "NOTE: " -ForegroundColor Yellow -NoNewline
        Write-Host "Saved credentials and output files will NOT be removed" -ForegroundColor White
        Write-Host "      (These must be manually deleted if needed)" -ForegroundColor Gray
        Write-Host ""

        $confirmation = Read-Host "Type YES in UPPERCASE to confirm uninstallation"

        if ($confirmation -cne 'YES') {
            if ($confirmation -eq 'yes') {
                Write-Host "`nUninstallation cancelled - 'YES' must be in UPPERCASE" -ForegroundColor Red
                Write-InstallLog -Message "Uninstallation cancelled - incorrect case" -Level WARNING
            }
            else {
                Write-Host "`nUninstallation cancelled" -ForegroundColor Yellow
                Write-InstallLog -Message "Uninstallation cancelled by user" -Level WARNING
            }
            return
        }
        
        Write-Host ""
        Write-LogSection "REMOVING COMPONENTS"
        
        Write-InstallLog -Message "Removing scheduled task..." -Level INFO
        if (Remove-CiscoCollectorTask) {
            Write-InstallLog -Message "Scheduled task removed successfully" -Level SUCCESS
            $componentsRemoved += "Scheduled Task"
        }
        else {
            Write-InstallLog -Message "No scheduled task found to remove" -Level INFO
        }
        
        Write-InstallLog -Message "Removing installation directory..." -Level INFO
        try {
            $pythonExe = "$InstallPath\$($script:PythonSubfolder)\python.exe"
            if (Test-Path $pythonExe) {
                $runningProcesses = Get-Process | Where-Object { $_.Path -like "$InstallPath*" }
                if ($runningProcesses) {
                    Write-InstallLog -Message "Found running processes from installation directory" -Level WARNING
                    foreach ($proc in $runningProcesses) {
                        Write-InstallLog -Message "  Stopping process: $($proc.Name) (PID: $($proc.Id))" -Level INFO
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    }
                    Start-Sleep -Seconds 2
                }
            }
            
            Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction Stop
            Write-InstallLog -Message "Installation directory removed successfully" -Level SUCCESS
            $componentsRemoved += "Installation Directory"
        }
        catch {
            Write-InstallLog -Message "Failed to remove installation directory: $_" -Level ERROR
            $componentsFailed += "Installation Directory"
        }
        
        # Log file management
        Write-LogSection "LOG FILE MANAGEMENT"
        $logAction = Show-LogManagementMenu -LogPath $LogPath
        
        if ($logAction -eq 'purge') {
            Write-Host ""
            Write-Host "Removing installation log files..." -ForegroundColor Cyan
            $logRemovalSuccess = Remove-InstallationLogs -LogPath $LogPath
            
            if ($logRemovalSuccess) {
                Write-Host "All log files removed successfully" -ForegroundColor Green
            }
            else {
                Write-Host "Some log files could not be removed" -ForegroundColor Yellow
            }
        }    

        Write-LogSection "UNINSTALLATION SUMMARY"
        
        if ($componentsRemoved.Count -gt 0) {
            Write-InstallLog -Message "Successfully removed:" -Level SUCCESS
            foreach ($component in $componentsRemoved) {
                Write-InstallLog -Message "  - $component" -Level SUCCESS
            }
        }
        
        if ($componentsFailed.Count -gt 0) {
            Write-InstallLog -Message "Failed to remove:" -Level ERROR
            foreach ($component in $componentsFailed) {
                Write-InstallLog -Message "  - $component" -Level ERROR
            }
        }
        
        Write-Host "`n" -NoNewline
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "MANUAL CLEANUP REQUIRED" -ForegroundColor Cyan
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "The following items were NOT automatically removed and may require manual cleanup:" -ForegroundColor Yellow
        Write-Host ""

        $itemNumber = 1

        if ($componentsFailed -contains "Installation Directory") {
            Write-Host "$itemNumber. Saved Credentials:" -ForegroundColor White
            Write-Host "   Location: $InstallPath\.cisco_credentials" -ForegroundColor Gray
            Write-Host "   (Encrypted credentials file - can only be read by service account)" -ForegroundColor Gray
            Write-Host "   NOTE: Installation directory removal failed, so credentials file still exists" -ForegroundColor Yellow
            Write-Host ""
            $itemNumber++
        }

        Write-Host "$itemNumber. Output Files:" -ForegroundColor White
        Write-Host "   Location: Previously configured output directory" -ForegroundColor Gray
        Write-Host "   Contains: Collected tech-support files" -ForegroundColor Gray
        Write-Host ""
        $itemNumber++

        # Log file management is now handled earlier in the uninstall process
        # No need to mention in manual cleanup section

        Write-Host "$itemNumber. Service Account:" -ForegroundColor White
        Write-Host "   If a dedicated service account was created, it can be disabled/removed" -ForegroundColor Gray
        Write-Host "   from Active Directory or local user accounts" -ForegroundColor Gray
        Write-Host ""

        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
        
        if ($componentsFailed.Count -eq 0) {
            Write-Host "Uninstallation completed successfully!" -ForegroundColor Green
        }
        else {
            Write-Host "Uninstallation completed with errors. Check log file: $script:LogFile" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-InstallLog -Message "Uninstallation failed: $_" -Level ERROR
        Write-InstallLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        throw
    }
}
#endregion

#region Main Installation Logic
function Install-CiscoCollector {
    try {
        Write-LogSection "CISCO TECH-SUPPORT COLLECTOR INSTALLATION"
        Write-InstallLog -Message "Installation started at $(Get-Date)" -Level INFO
        Write-InstallLog -Message "User: $env:USERNAME on $env:COMPUTERNAME" -Level INFO
        
        if (-not (Test-Administrator)) {
            Write-InstallLog -Message "This script requires Administrator privileges" -Level ERROR
            throw "Administrator privileges required"
        }
        Write-InstallLog -Message "Administrator privileges confirmed" -Level SUCCESS
        
        Write-LogSection "SYSTEM VALIDATION"
        Get-PowerShellVersion | Out-Null
        
        $serviceAccountCred = $null
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            $serviceAccountCred = Get-ServiceAccountCredential -Credential $ServiceAccountCredential
        }
        
        $resolvedArchive = Resolve-Path $ArchivePath
        Write-InstallLog -Message "Archive path: $resolvedArchive" -Level INFO
        
        if ((Test-Path $InstallPath) -and -not $Force) {
            Write-InstallLog -Message "Installation directory already exists: $InstallPath" -Level WARNING
            $response = Read-Host "Overwrite existing installation? (yes/no)"
            if ($response -notmatch '^y(es)?$|^Y(ES)?$') {
                Write-InstallLog -Message "Installation cancelled by user" -Level WARNING
                return
            }
        }
        
        Write-LogSection "EXTRACTION"
        if (Test-Path $InstallPath) {
            Write-InstallLog -Message "Removing existing installation..." -Level INFO
            Remove-Item -Path $InstallPath -Recurse -Force
        }
        
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-InstallLog -Message "Created installation directory: $InstallPath" -Level SUCCESS
        
        Expand-ArchiveCompat -Path $resolvedArchive -DestinationPath $InstallPath
        
        Write-LogSection "VALIDATION"
        $pythonExe = "$InstallPath\$($script:PythonSubfolder)\python.exe"
        $scriptPath = Join-Path $InstallPath $script:PythonScriptName

        if (-not (Test-Path $pythonExe)) {
            Write-InstallLog -Message "Python executable not found in $($script:PythonSubfolder) subfolder: $pythonExe" -Level ERROR
            Write-InstallLog -Message "Archive must contain embedded Python in $($script:PythonSubfolder)\ subfolder" -Level ERROR
        }
        
        if (-not (Test-Path $scriptPath)) {
            Write-InstallLog -Message "Python script not found: $scriptPath" -Level ERROR
            throw "Invalid archive structure - missing $script:PythonScriptName"
        }
        
        if (-not (Test-EmbeddedPython -InstallPath $InstallPath)) {
            Write-InstallLog -Message "Embedded Python validation failed" -Level ERROR
            throw "Invalid embedded Python distribution"
        }
        
        if (-not (Test-RequiredPackages -PythonExe $pythonExe -Packages $script:RequiredPackages)) {
            Write-InstallLog -Message "Required packages missing from embedded Python" -Level ERROR
            Write-InstallLog -Message "Required: $($script:RequiredPackages -join ', ')" -Level INFO
            throw "Missing required Python packages"
        }

        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            Write-LogSection "SCHEDULED TASK CREATION"
            
            Remove-CiscoCollectorTask
            
            Write-Host "`nCollection Mode Configuration" -ForegroundColor Cyan
            Write-Host "=========================================" -ForegroundColor Cyan
            Write-Host "  1. Device List - Collect from specific devices" -ForegroundColor White
            Write-Host "  2. Discovery - Auto-discover devices on network" -ForegroundColor White
            $modeChoice = Read-Host "`nSelection [1]"
            if ([string]::IsNullOrWhiteSpace($modeChoice)) { $modeChoice = '1' }
            
            $taskArguments = ""
            $collectionMode = 'DeviceList'  # Default to DeviceList mode
            
            if ($modeChoice -eq '2') {
                $collectionMode = 'Discovery'  # Set to Discovery mode
                Write-Host "`nDiscovery Method" -ForegroundColor Cyan
                Write-Host "=========================================" -ForegroundColor Cyan
                Write-Host "  1. CDP Discovery - Query default gateway for network topology (Recommended)" -ForegroundColor White
                Write-Host "  2. Hybrid - CDP + SNMP (most thorough)" -ForegroundColor White
                Write-Host "  3. SNMP Subnet Scan - Scan specific subnet via SNMP" -ForegroundColor White
                Write-Host "  4. ARP Discovery - Parse local ARP table (least reliable, but a last resort)" -ForegroundColor White
                $discoveryMethod = Read-Host "`nSelection [1]"
                if ([string]::IsNullOrWhiteSpace($discoveryMethod)) { $discoveryMethod = '1' }
                
                switch ($discoveryMethod) {
                    '1' {
                        # CDP Discovery
                        Write-Host "`nCDP Discovery Configuration" -ForegroundColor Cyan
                        Write-Host "This method queries your default gateway via CDP to discover" -ForegroundColor Gray
                        Write-Host "the network topology. This is the most reliable method for" -ForegroundColor Gray
                        Write-Host "discovering Cisco devices across VLANs." -ForegroundColor Gray
                        Write-Host ""
                        
                        $gatewayIP = Read-Host "Default gateway IP (leave blank to auto-detect)"
                        
                        if ([string]::IsNullOrWhiteSpace($gatewayIP)) {
                            $taskArguments = "--discover --method cdp"
                            Write-InstallLog -Message "CDP discovery configured with auto-detect gateway" -Level INFO
                        }
                        else {
                            $taskArguments = "--discover --method cdp --gateway `"$gatewayIP`""
                            Write-InstallLog -Message "CDP discovery configured with gateway: $gatewayIP" -Level INFO
                        }
                    }

                    '2' {
                        # Hybrid Discovery
                        Write-Host "`nHybrid Discovery Configuration" -ForegroundColor Cyan
                        Write-Host "This combines CDP and SNMP for the most thorough discovery." -ForegroundColor Gray
                        Write-Host ""
                        
                        $gatewayIP = Read-Host "Default gateway IP (leave blank to auto-detect)"
                        $subnet = Read-Host "Subnet for SNMP scan (e.g., 192.168.1.0/24)"
                        
                        if ([string]::IsNullOrWhiteSpace($gatewayIP)) {
                            $taskArguments = "--discover --method hybrid"
                        }
                        else {
                            $taskArguments = "--discover --method hybrid --gateway `"$gatewayIP`""
                        }
                        
                        if (-not [string]::IsNullOrWhiteSpace($subnet)) {
                            $taskArguments += " --subnet `"$subnet`""
                        }
                        
                        Write-InstallLog -Message "Hybrid discovery configured (CDP + SNMP)" -Level INFO
                    }
                    
                    '3' {
                        # SNMP Subnet Scan
                        Write-Host "`nSNMP Subnet Scan Configuration" -ForegroundColor Cyan
                        $subnet = Read-Host "Enter subnet for discovery (e.g., 192.168.1.0/24)"
                        
                        if ([string]::IsNullOrWhiteSpace($subnet)) {
                            Write-InstallLog -Message "No subnet provided for SNMP scan" -Level ERROR
                            throw "Subnet is required for SNMP discovery method"
                        }
                        
                        $taskArguments = "--discover --method snmp --subnet `"$subnet`""
                        Write-InstallLog -Message "SNMP discovery configured for subnet: $subnet" -Level INFO
                    }
                    
                    '4' {
                        # ARP Discovery
                        Write-Host "`nARP Discovery Configuration" -ForegroundColor Cyan
                        Write-Host "This method parses the local ARP table to find devices." -ForegroundColor Gray
                        Write-Host "Note: Only discovers devices on the local subnet." -ForegroundColor Yellow
                        Write-Host ""
                        
                        $taskArguments = "--discover --method arp"
                        Write-InstallLog -Message "ARP discovery configured" -Level INFO
                    }
                    
                }
                
                # SNMP Configuration (only for methods that use SNMP)
                if ($discoveryMethod -in @('2', '3')) {
                    Write-Host "`nSNMP Configuration" -ForegroundColor Cyan
                    Write-Host "  1. SNMP v2c (community string)" -ForegroundColor White
                    Write-Host "  2. SNMP v3 (username/auth)" -ForegroundColor White
                    Write-Host "  3. Skip SNMP configuration (use defaults)" -ForegroundColor White
                    $snmpChoice = Read-Host "`nSelection [1]"
                    if ([string]::IsNullOrWhiteSpace($snmpChoice)) { $snmpChoice = '1' }

                    if ($snmpChoice -eq '1') {
                        $snmpCommunity = Read-Host "SNMP community string [public]"
                        if ([string]::IsNullOrWhiteSpace($snmpCommunity)) { $snmpCommunity = 'public' }
                        $taskArguments += " --snmp-version 2c --snmp-community `"$snmpCommunity`""
                        Write-InstallLog -Message "SNMP v2c configured with community: $snmpCommunity" -Level INFO
                    }
                    elseif ($snmpChoice -eq '2') {
                        Write-Host "`nSNMP v3 Configuration" -ForegroundColor Cyan
                        
                        $snmpUser = Read-Host "SNMPv3 username"
                        if ([string]::IsNullOrWhiteSpace($snmpUser)) {
                            Write-InstallLog -Message "SNMPv3 username required" -Level ERROR
                            throw "SNMPv3 username is required"
                        }
                        
                        Write-Host "`nSecurity Level:" -ForegroundColor Cyan
                        Write-Host "  1. noAuthNoPriv - No authentication, no encryption" -ForegroundColor White
                        Write-Host "  2. authNoPriv - Authentication only, no encryption" -ForegroundColor White
                        Write-Host "  3. authPriv - Authentication and encryption" -ForegroundColor White
                        $secLevel = Read-Host "Selection [3]"
                        if ([string]::IsNullOrWhiteSpace($secLevel)) { $secLevel = '3' }
                        
                        if ($secLevel -eq '1') {
                            $taskArguments += " --snmp-version 3 --snmpv3-user `"$snmpUser`" --snmpv3-level noAuthNoPriv"
                            Write-InstallLog -Message "SNMPv3 configured (noAuthNoPriv): user=$snmpUser" -Level INFO
                        }

                        elseif ($secLevel -eq '2') {
                            Write-Host "`nAuthentication Protocol:" -ForegroundColor Cyan
                            Write-Host "  1. MD5" -ForegroundColor White
                            Write-Host "  2. SHA" -ForegroundColor White
                            $authProto = Read-Host "Selection [2]"
                            if ([string]::IsNullOrWhiteSpace($authProto)) { $authProto = '2' }
                            $authProtocol = if ($authProto -eq '1') { 'MD5' } else { 'SHA' }
                            
                            $authPassword = Read-Host "Authentication password" -AsSecureString
                            $authPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($authPassword))
                            
                            $taskArguments += " --snmp-version 3 --snmpv3-user `"$snmpUser`" --snmpv3-level authNoPriv --snmpv3-auth-protocol `"$authProtocol`" --snmpv3-auth-password `"$authPasswordPlain`""
                            Write-InstallLog -Message "SNMPv3 configured (authNoPriv): user=$snmpUser, auth=$authProtocol" -Level INFO
                        }

                        else {
                            Write-Host "`nAuthentication Protocol:" -ForegroundColor Cyan
                            Write-Host "  1. MD5" -ForegroundColor White
                            Write-Host "  2. SHA" -ForegroundColor White
                            $authProto = Read-Host "Selection [2]"
                            if ([string]::IsNullOrWhiteSpace($authProto)) { $authProto = '2' }
                            $authProtocol = if ($authProto -eq '1') { 'MD5' } else { 'SHA' }
                            
                            $authPassword = Read-Host "Authentication password" -AsSecureString
                            $authPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($authPassword))
                            
                            Write-Host "`nPrivacy Protocol:" -ForegroundColor Cyan
                            Write-Host "  1. DES" -ForegroundColor White
                            Write-Host "  2. AES" -ForegroundColor White
                            $privProto = Read-Host "Selection [2]"
                            if ([string]::IsNullOrWhiteSpace($privProto)) { $privProto = '2' }
                            $privProtocol = if ($privProto -eq '1') { 'DES' } else { 'AES' }
                            
                            $privPassword = Read-Host "Privacy password" -AsSecureString
                            $privPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($privPassword))
                            
                            $taskArguments += " --snmp-version 3 --snmpv3-user `"$snmpUser`" --snmpv3-level authPriv --snmpv3-auth-protocol `"$authProtocol`" --snmpv3-auth-password `"$authPasswordPlain`" --snmpv3-priv-protocol `"$privProtocol`" --snmpv3-priv-password `"$privPasswordPlain`""
                            Write-InstallLog -Message "SNMPv3 configured (authPriv): user=$snmpUser, auth=$authProtocol, priv=$privProtocol" -Level INFO
                        }
                    }
                    else {
                        Write-InstallLog -Message "SNMP configuration skipped, will use defaults" -Level INFO
                    }
                }
            } 
            else {
                Write-Host "`nDevice List Configuration" -ForegroundColor Cyan
                
                if ($DeviceListFile) {
                    Write-InstallLog -Message "Using provided device list file: $DeviceListFile" -Level INFO
                    $taskArguments = "-f `"$DeviceListFile`""
                }
                else {
                    Write-Host "Enter devices (comma-separated IPs or hostnames):" -ForegroundColor White
                    Write-Host "Example: 192.168.1.1,192.168.1.2,switch01.domain.com" -ForegroundColor Gray
                    $devicesInput = Read-Host "`nDevices"
                    
                    if ([string]::IsNullOrWhiteSpace($devicesInput)) {
                        Write-InstallLog -Message "No devices provided" -Level ERROR
                        throw "Device list is required for device list mode"
                    }
                    
                    $deviceList = $devicesInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
                    $devicesFile = Join-Path $InstallPath "devices.txt"
                    
                    $deviceList | Set-Content -Path $devicesFile -Force
                    Write-InstallLog -Message "Created device list file with $($deviceList.Count) device(s): $devicesFile" -Level SUCCESS
                    
                    foreach ($device in $deviceList) {
                        Write-InstallLog -Message "  - $device" -Level DEBUG
                    }
                    
                    $taskArguments = "-f `"$devicesFile`""
                }
            }
            
            if (-not $OutputDirectory) {
                Write-Host "`nOutput Directory Configuration" -ForegroundColor Cyan
                $defaultOutput = Join-Path $InstallPath "Results"
                $response = Read-Host "Output directory [$defaultOutput]"
                $OutputDirectory = if ([string]::IsNullOrWhiteSpace($response)) { $defaultOutput } else { $response }
            }
            
            if (-not (Test-Path $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
                Write-InstallLog -Message "Created output directory: $OutputDirectory" -Level SUCCESS
            }
            
            $taskArguments += " -o `"$OutputDirectory`""
            
            $createdTaskName = New-CiscoCollectorTask -InstallPath $InstallPath `
                                                       -ScheduleType $ScheduleType `
                                                       -ScheduleTime $ScheduleTime `
                                                       -Credential $serviceAccountCred `
                                                       -TaskArguments $taskArguments `
                                                       -CollectionMode $collectionMode
        }
        else {
            Write-InstallLog -Message "Scheduled task creation skipped" -Level INFO
        }

        # Automated credential setup
        $credSetupSuccess = $false
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            $credSetupSuccess = Start-ServiceAccountCredentialSetup -ServiceAccountCred $serviceAccountCred `
                                                                     -InstallPath $InstallPath `
                                                                     -PythonScript $script:PythonScriptName
            
            if (-not $credSetupSuccess) {
                Write-Host ""
                Write-Host ("=" * 80) -ForegroundColor Yellow
                Write-Host "MANUAL CREDENTIAL SETUP REQUIRED" -ForegroundColor Yellow
                Write-Host ("=" * 80) -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Automated credential setup failed or was skipped." -ForegroundColor White
                Write-Host "You'll need to follow the manual instructions in the NEXT STEPS section." -ForegroundColor White
                Write-Host ""
            }
        }

        Write-LogSection "INSTALLATION COMPLETE"
        Write-InstallLog -Message "Installation Path: $InstallPath" -Level SUCCESS
        Write-InstallLog -Message "Python Script: $scriptPath" -Level SUCCESS
        Write-InstallLog -Message "Log File: $script:LogFile" -Level SUCCESS
        
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            Write-InstallLog -Message "Scheduled Task: $createdTaskName" -Level SUCCESS
            Write-InstallLog -Message "Schedule: $ScheduleType at $ScheduleTime" -Level SUCCESS
            Write-InstallLog -Message "Service Account: $($serviceAccountCred.UserName)" -Level SUCCESS
            
            if ($credSetupSuccess) {
                Write-InstallLog -Message "Device Credentials: Configured" -Level SUCCESS
            }
            else {
                Write-InstallLog -Message "Device Credentials: Manual setup required" -Level WARNING
            }
        }
        
        Write-Host "`n" -NoNewline
        Write-Host "Installation successful! " -ForegroundColor Green -NoNewline
        Write-Host "Check log file for details: $script:LogFile" -ForegroundColor White

        # Offer initial task run if credentials were configured successfully
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None' -and $credSetupSuccess) {
            Start-InitialTaskRun -TaskName $createdTaskName -ServiceAccountName $serviceAccountCred.UserName
        }

        # Only show NEXT STEPS if credential setup failed
        if (-not $credSetupSuccess) {
            Write-Host "`n" -NoNewline
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host "NEXT STEPS" -ForegroundColor Cyan
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host ""

            $devicesFilePath = Join-Path $InstallPath "devices.txt"
            $credFilePath = Join-Path $InstallPath ".cisco_credentials"

            $stepNumber = 1

            Write-Host "$stepNumber. Configure Cisco device credentials (REQUIRED):" -ForegroundColor White
            Write-Host ""
            Write-Host "   The service account ($($serviceAccountCred.UserName)) runs the scheduled task." -ForegroundColor White
            Write-Host ""
            Write-Host "   Device authentication options:" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "   a) Use DIFFERENT credentials for device access (local/TACACS+/RADIUS)" -ForegroundColor Gray
            Write-Host "      - You'll configure separate username/password for Cisco devices" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   b) Use the SAME service account (if RADIUS/TACACS+ is configured)" -ForegroundColor Gray
            Write-Host "      - The service account credentials will authenticate to devices" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   Credentials will be encrypted and saved to:" -ForegroundColor White
            Write-Host "   $credFilePath" -ForegroundColor Gray
            Write-Host ""
            Write-Host "   Choose ONE method to save credentials:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "   METHOD 1 - Using runas (recommended):" -ForegroundColor Cyan
            Write-Host "   ----------------------------------------" -ForegroundColor Cyan
            Write-Host "   # Enable Secondary Logon if disabled (STIG compliance)" -ForegroundColor DarkGray
            Write-Host "   Set-Service -Name seclogon -StartupType Manual" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   runas /user:$($serviceAccountCred.UserName) powershell.exe" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   Then in the new PowerShell window:" -ForegroundColor Gray
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   # Restore STIG compliance after credential setup" -ForegroundColor DarkGray
            Write-Host "   Set-Service -Name seclogon -StartupType Disabled" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   METHOD 2 - Using PsExec (if runas is unavailable):" -ForegroundColor Cyan
            Write-Host "   --------------------------------------------------" -ForegroundColor Cyan
            Write-Host "   # Enable Secondary Logon if disabled (STIG compliance)" -ForegroundColor DarkGray
            Write-Host "   Set-Service -Name seclogon -StartupType Manual" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   cd `"$InstallPath\Utils\PsTools`"" -ForegroundColor DarkGray
            Write-Host "   .\PsExec.exe -accepteula -u $($serviceAccountCred.UserName) -p * -i powershell.exe" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   Then in the new PowerShell window:" -ForegroundColor Gray
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   # Restore STIG compliance after credential setup" -ForegroundColor DarkGray
            Write-Host "   Set-Service -Name seclogon -StartupType Disabled" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "   You will be prompted to enter:" -ForegroundColor White
            Write-Host ""
            Write-Host "   - Username for Cisco device authentication" -ForegroundColor Gray
            Write-Host "   - Password for Cisco device authentication" -ForegroundColor Gray
            Write-Host "   - Enable password (if required for privilege level 15)" -ForegroundColor Gray
            Write-Host ""
            $stepNumber++

            # Next step: Device list or test
            if ($isDiscoveryMode) {
                Write-Host "$stepNumber. Test the collection manually (as the service account):" -ForegroundColor White
                Write-Host "   Using the same runas/PsExec method from step 1:" -ForegroundColor Gray
                Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray

                # Provide appropriate test command based on discovery method
                if ($taskArguments -like "*--method cdp*") {
                    Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName --discover --method cdp" -ForegroundColor DarkGray
                }
                elseif ($taskArguments -like "*--method snmp*") {
                    Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName --discover --method snmp --subnet <your_subnet>" -ForegroundColor DarkGray
                }
                elseif ($taskArguments -like "*--method arp*") {
                    Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName --discover --method arp" -ForegroundColor DarkGray
                }
                elseif ($taskArguments -like "*--method hybrid*") {
                    Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName --discover --method hybrid" -ForegroundColor DarkGray
                }
                else {
                    # Fallback to generic discover command
                    Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName --discover" -ForegroundColor DarkGray
                }
            }
            elseif (Test-Path $devicesFilePath) {
                Write-Host "$stepNumber. Verify the device list file was created correctly:" -ForegroundColor White
                Write-Host "   type `"$devicesFilePath`"" -ForegroundColor Gray
                Write-Host "   (Should contain the device IPs/hostnames you specified)" -ForegroundColor DarkGray
                Write-Host ""
                $stepNumber++
                Write-Host "$stepNumber. Test the collection manually (as the service account):" -ForegroundColor White
                Write-Host "   Using the same runas/PsExec method:" -ForegroundColor Gray
                Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
                Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName -f devices.txt" -ForegroundColor DarkGray
            }
            else {
                Write-Host "$stepNumber. Verify your device list file contains the correct devices" -ForegroundColor White
                Write-Host ""
                $stepNumber++
                Write-Host "$stepNumber. Test the collection manually (as the service account):" -ForegroundColor White
                Write-Host "   Using the same runas/PsExec method:" -ForegroundColor Gray
                Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
                Write-Host "   $($script:PythonSubfolder)\python.exe $script:PythonScriptName -f <your_device_file>" -ForegroundColor DarkGray
            }
            Write-Host ""
            $stepNumber++

            # Final step: Verify task
            if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
                Write-Host "$stepNumber. Verify scheduled task configuration:" -ForegroundColor White
                Write-Host "   Get-ScheduledTask -TaskName '$createdTaskName' | Select-Object TaskName,State" -ForegroundColor Gray
                Write-Host "   Get-ScheduledTask -TaskName '$createdTaskName' | Select-Object -ExpandProperty Principal" -ForegroundColor Gray
                Write-Host ""
            }
        }

        # Always show IMPORTANT SECURITY NOTES
        $devicesFilePath = Join-Path $InstallPath "devices.txt"
        $credFilePath = Join-Path $InstallPath ".cisco_credentials"

        Write-Host ("=" * 80) -ForegroundColor Yellow
        Write-Host "IMPORTANT SECURITY NOTES" -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Yellow
        Write-Host ""
        Write-Host "SERVICE ACCOUNT USAGE:" -ForegroundColor Cyan
        Write-Host "  - Service Account ($($serviceAccountCred.UserName)): Runs the scheduled task" -ForegroundColor White
        Write-Host "  - Device Credentials: Can be different OR the same as service account" -ForegroundColor White
        Write-Host "    * Different: Configure separate local/TACACS+/RADIUS credentials" -ForegroundColor Gray
        Write-Host "    * Same: Use service account if RADIUS/TACACS+ AAA is configured" -ForegroundColor Gray
        Write-Host ""
        Write-Host "CREDENTIAL STORAGE:" -ForegroundColor Cyan
        Write-Host "  - Encrypted credentials file: $credFilePath" -ForegroundColor White
        Write-Host "  - Only readable by the service account that created it" -ForegroundColor White
        Write-Host "  - Encrypted using Windows DPAPI (user-specific)" -ForegroundColor White
        Write-Host ""
        Write-Host "STIG COMPLIANCE (V-253289):" -ForegroundColor Cyan
        Write-Host "  - Secondary Logon service should remain DISABLED except during credential setup" -ForegroundColor White
        Write-Host "  - If automated setup was used, service has been restored to Disabled" -ForegroundColor White
        Write-Host "  - If manual setup is needed, remember to disable service after completing setup" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "REQUIREMENTS:" -ForegroundColor Cyan
        Write-Host "  - The Python script will FAIL if task is changed to run as SYSTEM" -ForegroundColor Red
        Write-Host "  - Always use service account: $($serviceAccountCred.UserName)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Yellow
        Write-Host ""

    }
    catch {
        Write-InstallLog -Message "Installation failed: $_" -Level ERROR
        Write-InstallLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        throw
    }
}
#endregion

#region Script Execution
try {
    if ($Uninstall) {
        Uninstall-CiscoCollector
    }
    else {
        Install-CiscoCollector
    }
}
catch {
    Write-Host "`nOperation failed. Check log file for details: $script:LogFile" -ForegroundColor Red
    exit 1
}
#endregion