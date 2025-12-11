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
    Schedule frequency: Daily, Weekly, Monthly, or None (default: Daily)

.PARAMETER ScheduleTime
    Time to run the scheduled task (default: 02:00)

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
    Installation log file path (default: C:\Logs\Get-CiscoTechSupport-Install.log)

.PARAMETER Force
    Force reinstallation if already installed

.PARAMETER SkipTaskCreation
    Skip scheduled task creation

.PARAMETER Uninstall
    Uninstall the Cisco Tech-Support Collector and remove all components

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip"
    
    Installs the collector and prompts for service account credentials interactively

.EXAMPLE
    $cred = Get-Credential -Message "Enter service account credentials"
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip" -ServiceAccountCredential $cred

    Installs the collector using pre-captured credentials

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip" -ScheduleType Weekly -ScheduleTime "03:00"

    Installs with weekly schedule at 3:00 AM

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -Uninstall

    Completely removes the Cisco Tech-Support Collector installation

.NOTES
    Author: Kismet Agbasi (Github: kismetgerald Email: KismetG17@gmail.com)
    Version: 2.0.0
    Date: December 10, 2025
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
    [string]$ScheduleType = 'Daily',

    [Parameter(Mandatory = $false, ParameterSetName='Install')]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$ScheduleTime = '02:00',

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

#region Python Validation Functions
function Test-EmbeddedPython {
    param([string]$InstallPath)
    
    Write-InstallLog -Message "Validating embedded Python distribution..." -Level INFO
    
    $pythonExe = Join-Path $InstallPath "python.exe"
    $libDir = Join-Path $InstallPath "Lib"
    $sitePackages = Join-Path $InstallPath "Lib\site-packages"
    
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
    param(
        [string]$InstallPath,
        [string]$ScheduleType,
        [string]$ScheduleTime,
        [PSCredential]$Credential,
        [string]$TaskArguments
    )
    
    Write-InstallLog -Message "Creating scheduled task: $script:TaskName" -Level INFO
    
    $pythonExe = Join-Path $InstallPath "python.exe"
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
            New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Monday -At $ScheduleTime
        }
        default {
            Write-InstallLog -Message "No schedule specified - task will be created without trigger" -Level WARNING
            $null
        }
    }
    
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
    
    $description = "Automated collection of Cisco tech-support output from network devices. Configured to run $ScheduleType at $ScheduleTime. IMPORTANT: This task must NOT be run as SYSTEM - use a dedicated service account."
    
    try {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        
        if ($trigger) {
            Register-ScheduledTask -TaskName $script:TaskName `
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
            Register-ScheduledTask -TaskName $script:TaskName `
                                   -Description $description `
                                   -Action $action `
                                   -User $username `
                                   -Password $password `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -Force | Out-Null
        }
        
        Write-InstallLog -Message "Scheduled task created successfully" -Level SUCCESS
        Write-InstallLog -Message "Task: $script:TaskName" -Level INFO
        Write-InstallLog -Message "Schedule: $ScheduleType at $ScheduleTime" -Level INFO
        Write-InstallLog -Message "User: $username" -Level INFO
        
        $task = Get-ScheduledTask -TaskName $script:TaskName
        $principal = $task.Principal
        if ($principal.UserId -like "*SYSTEM*") {
            Write-InstallLog -Message "WARNING: Task is configured to run as SYSTEM - this is not supported!" -Level ERROR
            Write-InstallLog -Message "The Python script will fail if executed as SYSTEM." -Level ERROR
        }
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
            return $true
        }
        return $false
    }
    catch {
        Write-InstallLog -Message "Warning: Could not remove existing task: $_" -Level WARNING
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
        
        $confirmation = Read-Host "Type 'YES' to confirm uninstallation"
        
        if ($confirmation -cne 'YES') {
            Write-InstallLog -Message "Uninstallation cancelled by user" -Level WARNING
            Write-Host "`nUninstallation cancelled" -ForegroundColor Yellow
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
            $pythonExe = Join-Path $InstallPath "python.exe"
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

        Write-Host "$itemNumber. Log Files:" -ForegroundColor White
        Write-Host "   Location: $script:LogFile" -ForegroundColor Gray
        Write-Host ""
        $itemNumber++

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
            if ($response -notmatch '^y(es)?$') {
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
                
                Write-Host "`nSNMP Configuration" -ForegroundColor Cyan
                Write-Host "  1. SNMP v2c (community string)" -ForegroundColor White
                Write-Host "  2. SNMP v3 (username/auth)" -ForegroundColor White
                Write-Host "  3. Skip SNMP (ARP only)" -ForegroundColor White
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
            
            New-CiscoCollectorTask -InstallPath $InstallPath `
                                   -ScheduleType $ScheduleType `
                                   -ScheduleTime $ScheduleTime `
                                   -Credential $serviceAccountCred `
                                   -TaskArguments $taskArguments
        }
        else {
            Write-InstallLog -Message "Scheduled task creation skipped" -Level INFO
        }

        Write-LogSection "INSTALLATION COMPLETE"
        Write-InstallLog -Message "Installation Path: $InstallPath" -Level SUCCESS
        Write-InstallLog -Message "Python Script: $scriptPath" -Level SUCCESS
        Write-InstallLog -Message "Log File: $script:LogFile" -Level SUCCESS
        
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            Write-InstallLog -Message "Scheduled Task: $script:TaskName" -Level SUCCESS
            Write-InstallLog -Message "Schedule: $ScheduleType at $ScheduleTime" -Level SUCCESS
            Write-InstallLog -Message "Service Account: $($serviceAccountCred.UserName)" -Level SUCCESS
        }
        
        Write-Host "`n" -NoNewline
        Write-Host "Installation successful! " -ForegroundColor Green -NoNewline
        Write-Host "Check log file for details: $script:LogFile" -ForegroundColor White
        
        Write-Host "`n" -NoNewline
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "NEXT STEPS" -ForegroundColor Cyan
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "1. Configure Cisco device credentials:" -ForegroundColor White
        Write-Host ""
        Write-Host "   The service account ($($serviceAccountCred.UserName)) runs the scheduled task." -ForegroundColor White
        Write-Host ""
        Write-Host "   Device authentication options:" -ForegroundColor Cyan
        Write-Host "   a) Use DIFFERENT credentials for device access (local/TACACS+/RADIUS)" -ForegroundColor Gray
        Write-Host "      - You'll configure separate username/password for Cisco devices" -ForegroundColor DarkGray
        Write-Host "   b) Use the SAME service account (if RADIUS/TACACS+ is configured)" -ForegroundColor Gray
        Write-Host "      - The service account credentials will authenticate to devices" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   Credentials will be encrypted and saved to:" -ForegroundColor White
        Write-Host "   $InstallPath\.cisco_credentials" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Choose ONE method to save credentials:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   METHOD 1 - Using runas (recommended):" -ForegroundColor Cyan
        Write-Host "   ----------------------------------------" -ForegroundColor Cyan
        Write-Host "   runas /user:$($serviceAccountCred.UserName) powershell.exe" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   Then in the new PowerShell window:" -ForegroundColor Gray
        Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
        Write-Host "   .\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   METHOD 2 - Using PsExec (if runas is restricted):" -ForegroundColor Cyan
        Write-Host "   --------------------------------------------------" -ForegroundColor Cyan
        Write-Host "   cd `"$InstallPath\Utils\PsTools`"" -ForegroundColor DarkGray
        Write-Host "   .\PsExec.exe -u $($serviceAccountCred.UserName) -p * -i powershell.exe" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   Then in the new PowerShell window:" -ForegroundColor Gray
        Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
        Write-Host "   .\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   You will be prompted to enter:" -ForegroundColor White
        Write-Host "   - Username for Cisco device authentication" -ForegroundColor Gray
        Write-Host "   - Password for Cisco device authentication" -ForegroundColor Gray
        Write-Host "   - Enable password (if required for privilege level 15)" -ForegroundColor Gray
        Write-Host ""
        
        $devicesFilePath = Join-Path $InstallPath "devices.txt"
        $credFilePath = Join-Path $InstallPath ".cisco_credentials"
        
        Write-Host "2. Verify credentials were saved:" -ForegroundColor White
        Write-Host "   Test-Path `"$credFilePath`"" -ForegroundColor Gray
        Write-Host "   (Should return: True)" -ForegroundColor DarkGray
        Write-Host ""
        
        if ($isDiscoveryMode) {
            Write-Host "3. Test the collection manually (as the service account):" -ForegroundColor White
            Write-Host "   Using the same runas/PsExec method from step 1:" -ForegroundColor Gray
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "   .\python.exe $script:PythonScriptName --discover" -ForegroundColor DarkGray
        }
        elseif (Test-Path $devicesFilePath) {
            Write-Host "3. Verify the device list file was created correctly:" -ForegroundColor White
            Write-Host "   type `"$devicesFilePath`"" -ForegroundColor Gray
            Write-Host "   (Should contain the device IPs/hostnames you specified)" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "4. Test the collection manually (as the service account):" -ForegroundColor White
            Write-Host "   Using the same runas/PsExec method from step 1:" -ForegroundColor Gray
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "   .\python.exe $script:PythonScriptName -f devices.txt" -ForegroundColor DarkGray
        }
        else {
            Write-Host "3. Verify your device list file contains the correct devices" -ForegroundColor White
            Write-Host ""
            Write-Host "4. Test the collection manually (as the service account):" -ForegroundColor White
            Write-Host "   Using the same runas/PsExec method from step 1:" -ForegroundColor Gray
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
            Write-Host "   .\python.exe $script:PythonScriptName -f <your_device_file>" -ForegroundColor DarkGray
        }
        Write-Host ""
        
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            $lastStep = if ($isDiscoveryMode) { "4" } else { "5" }
            Write-Host "$lastStep. Verify scheduled task configuration:" -ForegroundColor White
            Write-Host "   Get-ScheduledTask -TaskName '$script:TaskName' | Select-Object TaskName,State" -ForegroundColor Gray
            Write-Host "   Get-ScheduledTask -TaskName '$script:TaskName' | Select-Object -ExpandProperty Principal" -ForegroundColor Gray
            Write-Host ""
        }
        
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
        Write-Host "  - Encrypted credentials file: $InstallPath\.cisco_credentials" -ForegroundColor White
        Write-Host "  - Only readable by the service account that created it" -ForegroundColor White
        Write-Host "  - Must be created using runas or PsExec as the service account" -ForegroundColor White
        Write-Host ""
        Write-Host "REQUIREMENTS:" -ForegroundColor Cyan
        Write-Host "  - The Python script will FAIL if task is changed to run as SYSTEM" -ForegroundColor Red
        Write-Host "  - Always use service account: $($serviceAccountCred.UserName)" -ForegroundColor Yellow
        Write-Host "  - Credentials encrypted with Windows DPAPI (user-specific)" -ForegroundColor White
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