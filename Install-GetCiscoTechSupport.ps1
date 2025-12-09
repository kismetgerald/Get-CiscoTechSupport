#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installation script for Cisco Tech-Support Collector

.DESCRIPTION
    Extracts the Cisco Tech-Support Collector archive, validates embedded Python
    distribution, and creates a scheduled task for automated collection runs. 
    Designed for offline deployment with embedded Python distribution.

.PARAMETER ArchivePath
    Path to the downloaded .zip archive from GitHub

.PARAMETER InstallPath
    Target installation directory (default: C:\Scripts\Get-CiscoTechSupport)

.PARAMETER ScheduleType
    Schedule frequency: Daily, Weekly, Monthly, or None (default: Daily)

.PARAMETER ScheduleTime
    Time to run the scheduled task (default: 02:00)

.PARAMETER TaskUsername
    Username for scheduled task execution (default: SYSTEM)

.PARAMETER TaskPassword
    Password for scheduled task user (only if not using SYSTEM)

.PARAMETER DeviceListFile
    Path to devices.txt file for the collector

.PARAMETER OutputDirectory
    Directory where tech-support files will be saved

.PARAMETER LogPath
    Installation log file path (default: C:\Logs\Get-CiscoTechSupport-Install.log)

.PARAMETER Force
    Force reinstallation if already installed

.PARAMETER SkipTaskCreation
    Skip scheduled task creation

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip"

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip" -ScheduleType Weekly -ScheduleTime "03:00"

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip" -SkipTaskCreation

.NOTES
    Author: Kismet Agbasi (Github: kismetgerald Email: KismetG17@gmail.com)
    Version: 1.0.0-alpha
    Date: December 7, 2025
    Requires: PowerShell 5.1+ with Administrator privileges
    
    IMPORTANT: This script is designed for embedded Python distributions.
    The archive should contain Python at the root level, not inside a .venv folder.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the .zip archive")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ArchivePath,

    [Parameter(Mandatory = $false)]
    [string]$InstallPath = "C:\Scripts\Get-CiscoTechSupport",

    [Parameter(Mandatory = $false)]
    [ValidateSet('Daily', 'Weekly', 'Monthly', 'None')]
    [string]$ScheduleType = 'Daily',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$ScheduleTime = '02:00',

    [Parameter(Mandatory = $false)]
    [string]$TaskUsername = 'SYSTEM',

    [Parameter(Mandatory = $false)]
    [SecureString]$TaskPassword,

    [Parameter(Mandatory = $false)]
    [string]$DeviceListFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\Get-CiscoTechSupport-Install.log",

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$SkipTaskCreation
)

#region Configuration
$ErrorActionPreference = 'Stop'
$script:LogFile = $LogPath
$script:TaskName = "Cisco Tech-Support Collector"
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
    
    try {
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -Path $Path -DestinationPath $DestinationPath -Force
            Write-InstallLog -Message "Archive extracted successfully" -Level SUCCESS
        }
        else {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath)
            Write-InstallLog -Message "Archive extracted successfully" -Level SUCCESS
        }
    }
    catch {
        Write-InstallLog -Message "Failed to extract archive: $_" -Level ERROR
        throw
    }
}
#endregion

#region Python Validation Functions
function Test-EmbeddedPython {
    param([string]$InstallPath)
    
    Write-InstallLog -Message "Validating embedded Python distribution..." -Level INFO
    
    # Check for required Python files at root level
    $pythonExe = Join-Path $InstallPath "python.exe"
    $libDir = Join-Path $InstallPath "Lib"
    $sitePackages = Join-Path $InstallPath "Lib\site-packages"
    
    # Check for required files
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
    
    # Test Python execution
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
    
    # Change to Python directory for embedded Python
    $pythonDir = Split-Path $PythonExe -Parent
    $originalLocation = Get-Location
    
    try {
        Set-Location $pythonDir
        
        $allInstalled = $true
        foreach ($package in $Packages) {
            try {
                # Use simple import test instead of pip show
                $importTest = "import $package"
                & $PythonExe -c $importTest 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    # Try to get version using pip
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
    param(
        [string]$InstallPath,
        [string]$ScheduleType,
        [string]$ScheduleTime,
        [string]$Username,
        [SecureString]$Password,
        [string]$TaskArguments
    )
    
    Write-InstallLog -Message "Creating scheduled task: $script:TaskName" -Level INFO
    
    $pythonExe = Join-Path $InstallPath "python.exe"
    $scriptPath = Join-Path $InstallPath $script:PythonScriptName
    
    # Build complete arguments
    $fullArguments = "`"$scriptPath`" $TaskArguments"
    
    Write-InstallLog -Message "Task will execute: $pythonExe $fullArguments" -Level DEBUG
    
    # Create action - working directory is the install path (where python.exe is)
    $action = New-ScheduledTaskAction -Execute $pythonExe -Argument $fullArguments -WorkingDirectory $InstallPath
    
    # Create trigger based on schedule type
    $trigger = switch ($ScheduleType) {
        'Daily' {
            New-ScheduledTaskTrigger -Daily -At $ScheduleTime
        }
        'Weekly' {
            New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $ScheduleTime
        }
        'Monthly' {
            New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Monday -At $ScheduleTime
        }
        default {
            Write-InstallLog -Message "No schedule specified - task will be created without trigger" -Level WARNING
            $null
        }
    }
    
    # Create principal (user context)
    if ($Username -eq 'SYSTEM') {
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    }
    else {
        if (-not $Password) {
            Write-InstallLog -Message "Password required for non-SYSTEM accounts" -Level ERROR
            throw "Password required"
        }
        $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        $principal = New-ScheduledTaskPrincipal -UserId $Username -LogonType Password -RunLevel Highest
    }
    
    # Create settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
    
    # Create description
    $description = "Automated collection of Cisco tech-support output from network devices. Configured to run $ScheduleType at $ScheduleTime."
    
    # Register task
    try {
        if ($Username -eq 'SYSTEM') {
            if ($trigger) {
                Register-ScheduledTask -TaskName $script:TaskName -Description $description -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            }
            else {
                Register-ScheduledTask -TaskName $script:TaskName -Description $description -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            }
        }
        else {
            $plainPassword = $credential.GetNetworkCredential().Password
            if ($trigger) {
                Register-ScheduledTask -TaskName $script:TaskName -Description $description -Action $action -Trigger $trigger -User $Username -Password $plainPassword -Settings $settings -RunLevel Highest -Force | Out-Null
            }
            else {
                Register-ScheduledTask -TaskName $script:TaskName -Description $description -Action $action -User $Username -Password $plainPassword -Settings $settings -RunLevel Highest -Force | Out-Null
            }
        }
        
        Write-InstallLog -Message "Scheduled task created successfully" -Level SUCCESS
        Write-InstallLog -Message "Task: $script:TaskName" -Level INFO
        Write-InstallLog -Message "Schedule: $ScheduleType at $ScheduleTime" -Level INFO
        Write-InstallLog -Message "User: $Username" -Level INFO
    }
    catch {
        Write-InstallLog -Message "Failed to create scheduled task: $_" -Level ERROR
        throw
    }
}

function Remove-CiscoCollectorTask {
    try {
        $existingTask = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
            Write-InstallLog -Message "Removed existing scheduled task" -Level INFO
        }
    }
    catch {
        Write-InstallLog -Message "Warning: Could not remove existing task: $_" -Level WARNING
    }
}
#endregion

#region Main Installation Logic - Part 1
function Install-CiscoCollector {
    try {
        Write-LogSection "CISCO TECH-SUPPORT COLLECTOR INSTALLATION"
        Write-InstallLog -Message "Installation started at $(Get-Date)" -Level INFO
        Write-InstallLog -Message "User: $env:USERNAME on $env:COMPUTERNAME" -Level INFO
        
        # Check administrator privileges
        if (-not (Test-Administrator)) {
            Write-InstallLog -Message "This script requires Administrator privileges" -Level ERROR
            throw "Administrator privileges required"
        }
        Write-InstallLog -Message "Administrator privileges confirmed" -Level SUCCESS
        
        # Check PowerShell version
        Write-LogSection "SYSTEM VALIDATION"
        Get-PowerShellVersion | Out-Null
        
        # Resolve archive path
        $resolvedArchive = Resolve-Path $ArchivePath
        Write-InstallLog -Message "Archive path: $resolvedArchive" -Level INFO
        
        # Check if already installed
        if ((Test-Path $InstallPath) -and -not $Force) {
            Write-InstallLog -Message "Installation directory already exists: $InstallPath" -Level WARNING
            $response = Read-Host "Overwrite existing installation? (yes/no)"
            if ($response -notmatch '^y(es)?$') {
                Write-InstallLog -Message "Installation cancelled by user" -Level WARNING
                return
            }
        }
        
        # Create installation directory
        Write-LogSection "EXTRACTION"
        if (Test-Path $InstallPath) {
            Write-InstallLog -Message "Removing existing installation..." -Level INFO
            Remove-Item -Path $InstallPath -Recurse -Force
        }
        
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-InstallLog -Message "Created installation directory: $InstallPath" -Level SUCCESS
        
        # Extract archive
        Expand-ArchiveCompat -Path $resolvedArchive -DestinationPath $InstallPath
        
        # Validate extracted structure
        Write-LogSection "VALIDATION"
        $pythonExe = Join-Path $InstallPath "python.exe"
        $scriptPath = Join-Path $InstallPath $script:PythonScriptName
        
        if (-not (Test-Path $pythonExe)) {
            Write-InstallLog -Message "Python executable not found at root level: $pythonExe" -Level ERROR
            Write-InstallLog -Message "Archive must contain embedded Python at root level" -Level ERROR
            throw "Invalid archive structure - python.exe not found at root"
        }
        
        if (-not (Test-Path $scriptPath)) {
            Write-InstallLog -Message "Python script not found: $scriptPath" -Level ERROR
            throw "Invalid archive structure - missing $script:PythonScriptName"
        }
        
        # Validate embedded Python distribution
        if (-not (Test-EmbeddedPython -InstallPath $InstallPath)) {
            Write-InstallLog -Message "Embedded Python validation failed" -Level ERROR
            throw "Invalid embedded Python distribution"
        }
        
        # Validate required packages
        if (-not (Test-RequiredPackages -PythonExe $pythonExe -Packages $script:RequiredPackages)) {
            Write-InstallLog -Message "Required packages missing from embedded Python" -Level ERROR
            Write-InstallLog -Message "Required: $($script:RequiredPackages -join ', ')" -Level INFO
            throw "Missing required Python packages"
        }

        # Create scheduled task
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
            $isDiscoveryMode = $false
            
            if ($modeChoice -eq '2') {
                $isDiscoveryMode = $true
                Write-Host "`nDiscovery Configuration" -ForegroundColor Cyan
                $subnet = Read-Host "Enter subnet for discovery (e.g., 192.168.1.0/24)"
                
                if ([string]::IsNullOrWhiteSpace($subnet)) {
                    Write-InstallLog -Message "No subnet provided, using ARP discovery" -Level WARNING
                    $taskArguments = "--discover"
                } else {
                    $taskArguments = "--discover --subnet `"$subnet`""
                    Write-InstallLog -Message "Discovery mode configured for subnet: $subnet" -Level INFO
                }
                
                # SNMP Configuration
                Write-Host "`nSNMP Configuration" -ForegroundColor Cyan
                Write-Host "  1. SNMP v2c (community string)" -ForegroundColor White
                Write-Host "  2. SNMP v3 (username/auth)" -ForegroundColor White
                Write-Host "  3. Skip SNMP (ARP only)" -ForegroundColor White
                $snmpChoice = Read-Host "`nSelection [1]"
                if ([string]::IsNullOrWhiteSpace($snmpChoice)) { $snmpChoice = '1' }
                
                if ($snmpChoice -eq '1') {
                    # SNMP v2c
                    $snmpCommunity = Read-Host "SNMP community string [public]"
                    if ([string]::IsNullOrWhiteSpace($snmpCommunity)) { $snmpCommunity = 'public' }
                    $taskArguments += " --snmp-version 2c --snmp-community `"$snmpCommunity`""
                    Write-InstallLog -Message "SNMP v2c configured with community: $snmpCommunity" -Level INFO
                }
                elseif ($snmpChoice -eq '2') {
                    # SNMP v3
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
                        # noAuthNoPriv
                        $taskArguments += " --snmp-version 3 --snmpv3-user `"$snmpUser`" --snmpv3-level noAuthNoPriv"
                        Write-InstallLog -Message "SNMPv3 configured (noAuthNoPriv): user=$snmpUser" -Level INFO
                    }
                    elseif ($secLevel -eq '2') {
                        # authNoPriv
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
                        # authPriv
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
                    # Skip SNMP
                    Write-InstallLog -Message "SNMP configuration skipped, will use defaults" -Level INFO
                }
            }
            else {
                # Device list mode
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
                    
                    # Parse and create devices.txt
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
            
            # Prompt for output directory if not provided
            if (-not $OutputDirectory) {
                Write-Host "`nOutput Directory Configuration" -ForegroundColor Cyan
                $defaultOutput = Join-Path $InstallPath "Results"
                $response = Read-Host "Output directory [$defaultOutput]"
                $OutputDirectory = if ([string]::IsNullOrWhiteSpace($response)) { $defaultOutput } else { $response }
            }
            
            # Create output directory if it doesn't exist
            if (-not (Test-Path $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
                Write-InstallLog -Message "Created output directory: $OutputDirectory" -Level SUCCESS
            }
            
            # Add output directory to arguments
            $taskArguments += " -o `"$OutputDirectory`""
            
            # Create scheduled task with configured arguments
            New-CiscoCollectorTask -InstallPath $InstallPath `
                                   -ScheduleType $ScheduleType `
                                   -ScheduleTime $ScheduleTime `
                                   -Username $TaskUsername `
                                   -Password $TaskPassword `
                                   -TaskArguments $taskArguments
        }
        else {
            Write-InstallLog -Message "Scheduled task creation skipped" -Level INFO
        }

        # Installation complete
        Write-LogSection "INSTALLATION COMPLETE"
        Write-InstallLog -Message "Installation Path: $InstallPath" -Level SUCCESS
        Write-InstallLog -Message "Python Script: $scriptPath" -Level SUCCESS
        Write-InstallLog -Message "Log File: $script:LogFile" -Level SUCCESS
        
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            Write-InstallLog -Message "Scheduled Task: $script:TaskName" -Level SUCCESS
            Write-InstallLog -Message "Schedule: $ScheduleType at $ScheduleTime" -Level SUCCESS
        }
        
        Write-Host "`n" -NoNewline
        Write-Host "Installation successful! " -ForegroundColor Green -NoNewline
        Write-Host "Check log file for details: $script:LogFile" -ForegroundColor White
        
        # Show next steps
        Write-Host "`nNext Steps:" -ForegroundColor Cyan
        
        # Step 1: Service Account Configuration (if using SYSTEM)
        if ($TaskUsername -eq 'SYSTEM') {
            Write-Host "`n  1. Configure a dedicated service account (RECOMMENDED):" -ForegroundColor Yellow
            Write-Host "     a. Create a dedicated AD service account (e.g., svc_cisco_collector)" -ForegroundColor Gray
            Write-Host "     b. Grant the service account:" -ForegroundColor Gray
            Write-Host "        - Read/Execute on: $InstallPath" -ForegroundColor DarkGray
            Write-Host "        - Modify on: $(Join-Path $InstallPath 'Results')" -ForegroundColor DarkGray
            if (-not $isDiscoveryMode) {
                $devicesFilePath = Join-Path $InstallPath "devices.txt"
                if (Test-Path $devicesFilePath) {
                    Write-Host "        - Read on: $devicesFilePath" -ForegroundColor DarkGray
                }
            }
            Write-Host "     c. Update the scheduled task to use the service account:" -ForegroundColor Gray
            Write-Host "        `$cred = Get-Credential" -ForegroundColor DarkGray
            Write-Host "        Set-ScheduledTask -TaskName '$script:TaskName' ``" -ForegroundColor DarkGray
            Write-Host "            -User `$cred.UserName ``" -ForegroundColor DarkGray
            Write-Host "            -Password `$cred.GetNetworkCredential().Password" -ForegroundColor DarkGray
            Write-Host "`n     NOTE: Using SYSTEM account is not recommended for production!" -ForegroundColor Yellow
            Write-Host "           Credentials saved as SYSTEM cannot be easily managed or audited." -ForegroundColor Yellow
        }
        else {
            Write-Host "`n  1. Service account configured: $TaskUsername" -ForegroundColor Green
        }
        
        # Step 2: Configure credentials
        $stepNum = 2
        Write-Host "`n  $stepNum. Configure Cisco device credentials:" -ForegroundColor White
        if ($TaskUsername -eq 'SYSTEM') {
            Write-Host "`n     Option A: Using service account (RECOMMENDED - complete Step 1 first):" -ForegroundColor Gray
            Write-Host "     - Run: runas /user:DOMAIN\svc_cisco_collector powershell.exe" -ForegroundColor DarkGray
            Write-Host "     - In the service account PowerShell window:" -ForegroundColor DarkGray
            Write-Host "       cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "       .\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
            Write-Host "`n     Option B: Using SYSTEM account (not recommended):" -ForegroundColor Gray
            Write-Host "     - Run: .\Utils\PsTools\PsExec.exe -i -s powershell.exe" -ForegroundColor DarkGray
            Write-Host "     - In the SYSTEM PowerShell window:" -ForegroundColor DarkGray
            Write-Host "       cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "       .\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
        }
        else {
            Write-Host "     Run as the service account ($TaskUsername):" -ForegroundColor Gray
            Write-Host "     - Run: runas /user:$TaskUsername powershell.exe" -ForegroundColor DarkGray
            Write-Host "     - In the service account PowerShell window:" -ForegroundColor DarkGray
            Write-Host "       cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "       .\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
        }
        
        # Step 3: Verify/Test
        $stepNum++
        
        # Check if we're in discovery mode or device list mode
        $devicesFilePath = Join-Path $InstallPath "devices.txt"
        if ($isDiscoveryMode) {
            # Discovery mode - no mention of devices.txt
            Write-Host "`n  $stepNum. Test the collection manually (as the service account):" -ForegroundColor White
            Write-Host "     cd `"$InstallPath`"" -ForegroundColor Gray
            Write-Host "     .\python.exe $script:PythonScriptName --discover" -ForegroundColor Gray
        }
        elseif (Test-Path $devicesFilePath) {
            # Device list mode - file was created during installation
            Write-Host "`n  $stepNum. Verify the device list file was created correctly:" -ForegroundColor White
            Write-Host "     type `"$devicesFilePath`"" -ForegroundColor Gray
            Write-Host "     (Should contain the device IPs/hostnames you specified)" -ForegroundColor DarkGray
            $stepNum++
            Write-Host "`n  $stepNum. Test the collection manually (as the service account):" -ForegroundColor White
            Write-Host "     cd `"$InstallPath`"" -ForegroundColor Gray
            Write-Host "     .\python.exe $script:PythonScriptName -f devices.txt" -ForegroundColor Gray
        }
        else {
            # Device list mode - but file was provided externally
            Write-Host "`n  $stepNum. Verify your device list file contains the correct devices" -ForegroundColor White
            $stepNum++
            Write-Host "`n  $stepNum. Test the collection manually (as the service account):" -ForegroundColor White
            Write-Host "     cd `"$InstallPath`"" -ForegroundColor Gray
            Write-Host "     .\python.exe $script:PythonScriptName -f <your_device_file>" -ForegroundColor Gray
        }
        
        # Final step: View task
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            $stepNum++
            Write-Host "`n  $stepNum. Verify scheduled task configuration:" -ForegroundColor White
            Write-Host "     Get-ScheduledTask -TaskName '$script:TaskName' | Select-Object TaskName,State" -ForegroundColor Gray
            Write-Host "     Get-ScheduledTask -TaskName '$script:TaskName' | Select-Object -ExpandProperty Principal" -ForegroundColor Gray
            Write-Host ""
        }
        else {
            Write-Host ""
        }
        
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
    Install-CiscoCollector
}
catch {
    Write-Host "`nInstallation failed. Check log file for details: $script:LogFile" -ForegroundColor Red
    exit 1
}
#endregion