#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installation script for Cisco Tech-Support Collector

.DESCRIPTION
    Extracts archive, validates Python, creates scheduled task with service account.
    REQUIRES dedicated service account - SYSTEM account not supported.

.PARAMETER ArchivePath
    Path to the .zip archive

.PARAMETER InstallPath
    Installation directory (default: C:\Scripts\Get-CiscoTechSupport)

.PARAMETER ScheduleType
    Schedule: Daily, Weekly, Monthly, or None (default: Daily)

.PARAMETER ScheduleTime
    Time to run (default: 02:00)

.PARAMETER ServiceAccountCredential
    PSCredential for service account

.PARAMETER DeviceListFile
    Path to devices.txt file

.PARAMETER OutputDirectory
    Output directory for tech-support files

.PARAMETER LogPath
    Log file path (default: C:\Logs\Get-CiscoTechSupport-Install.log)

.PARAMETER Force
    Force reinstallation

.PARAMETER SkipTaskCreation
    Skip scheduled task creation

.PARAMETER Uninstall
    Uninstall the solution

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip"

.EXAMPLE
    $cred = Get-Credential
    .\Install-GetCiscoTechSupport.ps1 -ArchivePath ".\cisco-collector.zip" -ServiceAccountCredential $cred

.EXAMPLE
    .\Install-GetCiscoTechSupport.ps1 -Uninstall

.NOTES
    Author: Kismet Agbasi (Github: kismetgerald Email: KismetG17@gmail.com)
    Version: 1.0.0-alpha2
    Date Created: December 7, 2025
    Last Updated: December 9, 2025
    Requires: PowerShell 5.1+ with Administrator privileges
    
    IMPORTANT: This script is designed for embedded Python distributions.
    The archive should contain Python at the root level, not inside a .venv folder.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='Install')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Install')]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ArchivePath,

    [Parameter(ParameterSetName='Install')]
    [Parameter(ParameterSetName='Uninstall')]
    [string]$InstallPath = "C:\Scripts\Get-CiscoTechSupport",

    [Parameter(ParameterSetName='Install')]
    [ValidateSet('Daily','Weekly','Monthly','None')]
    [string]$ScheduleType = 'Daily',

    [Parameter(ParameterSetName='Install')]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$ScheduleTime = '02:00',

    [Parameter(ParameterSetName='Install')]
    [PSCredential]$ServiceAccountCredential,

    [Parameter(ParameterSetName='Install')]
    [string]$DeviceListFile,

    [Parameter(ParameterSetName='Install')]
    [string]$OutputDirectory,

    [Parameter(ParameterSetName='Install')]
    [Parameter(ParameterSetName='Uninstall')]
    [string]$LogPath = "C:\Logs\Get-CiscoTechSupport-Install.log",

    [Parameter(ParameterSetName='Install')]
    [switch]$Force,

    [Parameter(ParameterSetName='Install')]
    [switch]$SkipTaskCreation,

    [Parameter(Mandatory=$true, ParameterSetName='Uninstall')]
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$script:LogFile = $LogPath
$script:TaskName = "Cisco Tech-Support Collector"
$script:RequiredPackages = @('netmiko','pysnmp','cryptography')
$script:PythonScriptName = 'get-ciscotechsupport.py'

function Write-InstallLog {
    param([string]$Message, [string]$Level='INFO', [switch]$NoConsole)
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $syslogTime = Get-Date -Format 'MMM dd HH:mm:ss'
    $hostname = $env:COMPUTERNAME
    $syslogMsg = "$syslogTime $hostname GetCiscoTechSupportInstall[$PID]: $Level - $Message"
    $consoleMsg = "[$timestamp] [$Level] $Message"
    
    $logDir = Split-Path -Path $script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    Add-Content -Path $script:LogFile -Value $syslogMsg -ErrorAction SilentlyContinue
    
    if (-not $NoConsole) {
        $color = switch ($Level) {
            'ERROR'{'Red'} 'WARNING'{'Yellow'} 'SUCCESS'{'Green'} 'DEBUG'{'Gray'} default{'White'}
        }
        Write-Host $consoleMsg -ForegroundColor $color
    }
}

function Write-LogSection {
    param([string]$Title)
    $sep = "=" * 80
    Write-InstallLog -Message $sep -Level INFO
    Write-InstallLog -Message $Title -Level INFO
    Write-InstallLog -Message $sep -Level INFO
}

function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PowerShellVersion {
    $ver = $PSVersionTable.PSVersion
    Write-InstallLog "PowerShell Version: $($ver.Major).$($ver.Minor).$($ver.Build)" -Level INFO
    
    if ($ver.Major -ge 7) {
        Write-InstallLog "PowerShell 7+ detected" -Level SUCCESS
        return $ver
    }
    elseif ($ver.Major -eq 5 -and $ver.Minor -ge 1) {
        Write-InstallLog "PowerShell 5.1 detected" -Level SUCCESS
        return $ver
    }
    else {
        Write-InstallLog "PowerShell version too old. Requires 5.1+" -Level ERROR
        throw "Unsupported PowerShell version"
    }
}

function Expand-ArchiveCompat {
    param([string]$Path, [string]$DestinationPath)
    
    Write-InstallLog "Extracting archive: $Path" -Level INFO
    Write-InstallLog "Destination: $DestinationPath" -Level INFO
    
    try {
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -Path $Path -DestinationPath $DestinationPath -Force
        }
        else {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath)
        }
        Write-InstallLog "Archive extracted successfully" -Level SUCCESS
    }
    catch {
        Write-InstallLog "Failed to extract archive: $_" -Level ERROR
        throw
    }
}

function Get-ServiceAccountCredential {
    param([PSCredential]$Credential)
    
    if ($Credential) {
        Write-InstallLog "Using provided service account credential" -Level INFO
        return $Credential
    }
    
    Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
    Write-Host "SERVICE ACCOUNT CONFIGURATION" -ForegroundColor Cyan
    Write-Host $('=' * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IMPORTANT: " -ForegroundColor Yellow -NoNewline
    Write-Host "This task MUST run under a dedicated service account." -ForegroundColor White
    Write-Host ""
    Write-Host "The service account must have:" -ForegroundColor White
    Write-Host "  • Read/Execute on installation directory" -ForegroundColor Gray
    Write-Host "  • Modify on output directory" -ForegroundColor Gray
    Write-Host "  • Network access to Cisco devices" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor White
    Write-Host "  • DOMAIN\svc_cisco_collector" -ForegroundColor Gray
    Write-Host "  • .\ServiceAccount (local)" -ForegroundColor Gray
    Write-Host ""
    Write-Host $('=' * 80) -ForegroundColor Cyan
    Write-Host ""
    
    $cred = Get-Credential -Message "Enter service account credentials"
    
    if (-not $cred) {
        Write-InstallLog "No credentials provided" -Level ERROR
        throw "Service account credentials required"
    }
    
    Write-InstallLog "Service account: $($cred.UserName)" -Level SUCCESS
    return $cred
}

function Test-EmbeddedPython {
    param([string]$InstallPath)
    
    Write-InstallLog "Validating embedded Python..." -Level INFO
    
    $pythonExe = Join-Path $InstallPath "python.exe"
    $libDir = Join-Path $InstallPath "Lib"
    $sitePackages = Join-Path $InstallPath "Lib\site-packages"
    
    if (-not (Test-Path $pythonExe)) {
        Write-InstallLog "Missing python.exe" -Level ERROR
        return $false
    }
    if (-not (Test-Path $libDir)) {
        Write-InstallLog "Missing Lib directory" -Level ERROR
        return $false
    }
    if (-not (Test-Path $sitePackages)) {
        Write-InstallLog "Missing Lib\site-packages" -Level ERROR
        return $false
    }
    
    Write-InstallLog "Python structure validated" -Level SUCCESS
    
    try {
        $origLoc = Get-Location
        Set-Location $InstallPath
        $pyVer = & $pythonExe --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-InstallLog "Python version: $pyVer" -Level INFO
        }
        else {
            Write-InstallLog "Failed to execute Python" -Level ERROR
            return $false
        }
    }
    catch {
        Write-InstallLog "Python execution failed: $_" -Level ERROR
        return $false
    }
    finally {
        Set-Location $origLoc
    }
    
    return $true
}

function Test-RequiredPackages {
    param([string]$PythonExe, [string[]]$Packages)
    
    Write-InstallLog "Validating Python packages..." -Level INFO
    
    $pyDir = Split-Path $PythonExe -Parent
    $origLoc = Get-Location
    
    try {
        Set-Location $pyDir
        $allInstalled = $true
        
        foreach ($pkg in $Packages) {
            try {
                & $PythonExe -c "import $pkg" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $verResult = & $PythonExe -m pip show $pkg 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        $verLine = $verResult | Select-String -Pattern '^Version:'
                        $ver = if ($verLine) {($verLine -split ':')[1].Trim()} else {'unknown'}
                        Write-InstallLog "Package '$pkg' (v$ver) - OK" -Level SUCCESS
                    }
                    else {
                        Write-InstallLog "Package '$pkg' - OK" -Level SUCCESS
                    }
                }
                else {
                    Write-InstallLog "Package '$pkg' - MISSING" -Level ERROR
                    $allInstalled = $false
                }
            }
            catch {
                Write-InstallLog "Failed to check '$pkg': $_" -Level ERROR
                $allInstalled = $false
            }
        }
        return $allInstalled
    }
    finally {
        Set-Location $origLoc
    }
}

function New-CiscoCollectorTask {
    param([string]$InstallPath, [string]$ScheduleType, [string]$ScheduleTime, [PSCredential]$Credential, [string]$TaskArguments)
    
    Write-InstallLog "Creating scheduled task: $script:TaskName" -Level INFO
    
    $pythonExe = Join-Path $InstallPath "python.exe"
    $scriptPath = Join-Path $InstallPath $script:PythonScriptName
    $fullArgs = "`"$scriptPath`" $TaskArguments"
    
    Write-InstallLog "Execute: $pythonExe $fullArgs" -Level DEBUG
    
    $action = New-ScheduledTaskAction -Execute $pythonExe -Argument $fullArgs -WorkingDirectory $InstallPath
    
    $trigger = switch ($ScheduleType) {
        'Daily' {New-ScheduledTaskTrigger -Daily -At $ScheduleTime}
        'Weekly' {New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $ScheduleTime}
        'Monthly' {New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Monday -At $ScheduleTime}
        default {
            Write-InstallLog "No schedule - task without trigger" -Level WARNING
            $null
        }
    }
    
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
    $desc = "Automated Cisco tech-support collection. Runs $ScheduleType at $ScheduleTime. WARNING: Must NOT run as SYSTEM!"
    
    try {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        
        if ($trigger) {
            Register-ScheduledTask -TaskName $script:TaskName -Description $desc -Action $action -Trigger $trigger -User $username -Password $password -Settings $settings -RunLevel Highest -Force | Out-Null
        }
        else {
            Register-ScheduledTask -TaskName $script:TaskName -Description $desc -Action $action -User $username -Password $password -Settings $settings -RunLevel Highest -Force | Out-Null
        }
        
        Write-InstallLog "Task created successfully" -Level SUCCESS
        Write-InstallLog "Task: $script:TaskName" -Level INFO
        Write-InstallLog "Schedule: $ScheduleType at $ScheduleTime" -Level INFO
        Write-InstallLog "User: $username" -Level INFO
        
        $task = Get-ScheduledTask -TaskName $script:TaskName
        if ($task.Principal.UserId -like "*SYSTEM*") {
            Write-InstallLog "WARNING: Task as SYSTEM - NOT SUPPORTED!" -Level ERROR
            Write-InstallLog "Python script will FAIL as SYSTEM" -Level ERROR
        }
    }
    catch {
        Write-InstallLog "Failed to create task: $_" -Level ERROR
        throw
    }
}

function Remove-CiscoCollectorTask {
    try {
        $task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
            Write-InstallLog "Removed existing task" -Level INFO
            return $true
        }
        return $false
    }
    catch {
        Write-InstallLog "Could not remove task: $_" -Level WARNING
        return $false
    }
}

function Uninstall-CiscoCollector {
    try {
        Write-LogSection "CISCO TECH-SUPPORT COLLECTOR UNINSTALLATION"
        Write-InstallLog "Uninstall started: $(Get-Date)" -Level INFO
        Write-InstallLog "User: $env:USERNAME on $env:COMPUTERNAME" -Level INFO
        
        if (-not (Test-Administrator)) {
            Write-InstallLog "Administrator privileges required" -Level ERROR
            throw "Administrator required"
        }
        Write-InstallLog "Administrator confirmed" -Level SUCCESS
        
        $removed = @()
        $failed = @()
        
        if (-not (Test-Path $InstallPath)) {
            Write-InstallLog "Installation not found: $InstallPath" -Level WARNING
            Write-InstallLog "Nothing to uninstall" -Level INFO
            return
        }
        
        Write-InstallLog "Found installation: $InstallPath" -Level INFO
        
        Write-Host "`nWARNING: " -ForegroundColor Red -NoNewline
        Write-Host "Complete removal of Cisco Tech-Support Collector" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Will remove:" -ForegroundColor White
        Write-Host "  • $InstallPath" -ForegroundColor Gray
        Write-Host "  • $script:TaskName" -ForegroundColor Gray
        Write-Host ""
        Write-Host "NOTE: " -ForegroundColor Yellow -NoNewline
        Write-Host "Credentials and output files NOT removed" -ForegroundColor White
        Write-Host ""
        
        $confirm = Read-Host "Type 'YES' to confirm"
        
        if ($confirm -ne 'YES') {
            Write-InstallLog "Cancelled by user" -Level WARNING
            Write-Host "`nCancelled" -ForegroundColor Yellow
            return
        }
        
        Write-Host ""
        Write-LogSection "REMOVING COMPONENTS"
        
        Write-InstallLog "Removing task..." -Level INFO
        if (Remove-CiscoCollectorTask) {
            Write-InstallLog "Task removed" -Level SUCCESS
            $removed += "Scheduled Task"
        }
        else {
            Write-InstallLog "No task found" -Level INFO
        }
        
        Write-InstallLog "Removing directory..." -Level INFO
        try {
            $pythonExe = Join-Path $InstallPath "python.exe"
            if (Test-Path $pythonExe) {
                $procs = Get-Process | Where-Object {$_.Path -like "$InstallPath*"}
                if ($procs) {
                    Write-InstallLog "Stopping running processes" -Level WARNING
                    foreach ($p in $procs) {
                        Write-InstallLog "  Stopping: $($p.Name) (PID: $($p.Id))" -Level INFO
                        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                    }
                    Start-Sleep -Seconds 2
                }
            }
            
            Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction Stop
            Write-InstallLog "Directory removed" -Level SUCCESS
            $removed += "Installation Directory"
        }
        catch {
            Write-InstallLog "Failed to remove directory: $_" -Level ERROR
            $failed += "Installation Directory"
        }
        
        Write-LogSection "SUMMARY"
        
        if ($removed.Count -gt 0) {
            Write-InstallLog "Removed:" -Level SUCCESS
            foreach ($c in $removed) {Write-InstallLog "  • $c" -Level SUCCESS}
        }
        
        if ($failed.Count -gt 0) {
            Write-InstallLog "Failed:" -Level ERROR
            foreach ($c in $failed) {Write-InstallLog "  • $c" -Level ERROR}
        }
        
        Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
        Write-Host "MANUAL CLEANUP" -ForegroundColor Cyan
        Write-Host $('=' * 80) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "NOT automatically removed:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "1. Saved Credentials (Credential Manager)" -ForegroundColor White
        Write-Host "2. Output Files (configured directory)" -ForegroundColor White
        Write-Host "3. Log Files: $script:LogFile" -ForegroundColor White
        Write-Host "4. Service Account (AD/local)" -ForegroundColor White
        Write-Host ""
        Write-Host $('=' * 80) -ForegroundColor Cyan
        Write-Host ""
        
        if ($failed.Count -eq 0) {
            Write-Host "Uninstall successful!" -ForegroundColor Green
        }
        else {
            Write-Host "Uninstall with errors. Check: $script:LogFile" -ForegroundColor Yellow
        }
    }
    catch {
        Write-InstallLog "Uninstall failed: $_" -Level ERROR
        Write-InstallLog "Stack: $($_.ScriptStackTrace)" -Level DEBUG
        throw
    }
}

function Install-CiscoCollector {
    try {
        Write-LogSection "CISCO TECH-SUPPORT COLLECTOR INSTALLATION"
        Write-InstallLog "Install started: $(Get-Date)" -Level INFO
        Write-InstallLog "User: $env:USERNAME on $env:COMPUTERNAME" -Level INFO
        
        if (-not (Test-Administrator)) {
            Write-InstallLog "Administrator required" -Level ERROR
            throw "Administrator required"
        }
        Write-InstallLog "Administrator confirmed" -Level SUCCESS
        
        Write-LogSection "SYSTEM VALIDATION"
        Get-PowerShellVersion | Out-Null
        
        $svcCred = $null
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            $svcCred = Get-ServiceAccountCredential -Credential $ServiceAccountCredential
        }
        
        $archiveResolved = Resolve-Path $ArchivePath
        Write-InstallLog "Archive: $archiveResolved" -Level INFO
        
        if ((Test-Path $InstallPath) -and -not $Force) {
            Write-InstallLog "Already exists: $InstallPath" -Level WARNING
            $resp = Read-Host "Overwrite? (yes/no)"
            if ($resp -notmatch '^y(es)?$') {
                Write-InstallLog "Cancelled by user" -Level WARNING
                return
            }
        }
        
        Write-LogSection "EXTRACTION"
        if (Test-Path $InstallPath) {
            Write-InstallLog "Removing existing..." -Level INFO
            Remove-Item -Path $InstallPath -Recurse -Force
        }
        
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-InstallLog "Created: $InstallPath" -Level SUCCESS
        
        Expand-ArchiveCompat -Path $archiveResolved -DestinationPath $InstallPath
        
        Write-LogSection "VALIDATION"
        $pythonExe = Join-Path $InstallPath "python.exe"
        $scriptPath = Join-Path $InstallPath $script:PythonScriptName
        
        if (-not (Test-Path $pythonExe)) {
            Write-InstallLog "python.exe not found: $pythonExe" -Level ERROR
            throw "Invalid archive - python.exe missing"
        }
        
        if (-not (Test-Path $scriptPath)) {
            Write-InstallLog "Script not found: $scriptPath" -Level ERROR
            throw "Invalid archive - $script:PythonScriptName missing"
        }
        
        if (-not (Test-EmbeddedPython -InstallPath $InstallPath)) {
            Write-InstallLog "Python validation failed" -Level ERROR
            throw "Invalid Python distribution"
        }
        
        if (-not (Test-RequiredPackages -PythonExe $pythonExe -Packages $script:RequiredPackages)) {
            Write-InstallLog "Missing packages" -Level ERROR
            Write-InstallLog "Required: $($script:RequiredPackages -join ', ')" -Level INFO
            throw "Missing Python packages"
        }

        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            Write-LogSection "SCHEDULED TASK CREATION"
            Remove-CiscoCollectorTask
            
            Write-Host "`nCollection Mode" -ForegroundColor Cyan
            Write-Host $('=' * 40) -ForegroundColor Cyan
            Write-Host "  1. Device List" -ForegroundColor White
            Write-Host "  2. Discovery" -ForegroundColor White
            $mode = Read-Host "`nSelection [1]"
            if ([string]::IsNullOrWhiteSpace($mode)) {$mode = '1'}
            
            $taskArgs = ""
            $isDiscovery = $false
            
            if ($mode -eq '2') {
                $isDiscovery = $true
                Write-Host "`nDiscovery Config" -ForegroundColor Cyan
                $subnet = Read-Host "Subnet (e.g., 192.168.1.0/24)"
                
                if ([string]::IsNullOrWhiteSpace($subnet)) {
                    Write-InstallLog "No subnet, using ARP" -Level WARNING
                    $taskArgs = "--discover"
                }
                else {
                    $taskArgs = "--discover --subnet `"$subnet`""
                    Write-InstallLog "Discovery subnet: $subnet" -Level INFO
                }
                
                Write-Host "`nSNMP Config" -ForegroundColor Cyan
                Write-Host "  1. SNMP v2c" -ForegroundColor White
                Write-Host "  2. SNMP v3" -ForegroundColor White
                Write-Host "  3. Skip SNMP" -ForegroundColor White
                $snmp = Read-Host "`nSelection [1]"
                if ([string]::IsNullOrWhiteSpace($snmp)) {$snmp = '1'}
                
                if ($snmp -eq '1') {
                    $community = Read-Host "Community [public]"
                    if ([string]::IsNullOrWhiteSpace($community)) {$community = 'public'}
                    $taskArgs += " --snmp-version 2c --snmp-community `"$community`""
                    Write-InstallLog "SNMP v2c: $community" -Level INFO
                }
                elseif ($snmp -eq '2') {
                    $snmpUser = Read-Host "SNMPv3 username"
                    if ([string]::IsNullOrWhiteSpace($snmpUser)) {
                        Write-InstallLog "SNMPv3 username required" -Level ERROR
                        throw "SNMPv3 username required"
                    }
                    
                    Write-Host "`nSecurity Level:" -ForegroundColor Cyan
                    Write-Host "  1. noAuthNoPriv" -ForegroundColor White
                    Write-Host "  2. authNoPriv" -ForegroundColor White
                    Write-Host "  3. authPriv" -ForegroundColor White
                    $secLvl = Read-Host "Selection [3]"
                    if ([string]::IsNullOrWhiteSpace($secLvl)) {$secLvl = '3'}
                    
                    if ($secLvl -eq '1') {
                        $taskArgs += " --snmp-version 3 --snmpv3-user `"$snmpUser`" --snmpv3-level noAuthNoPriv"
                        Write-InstallLog "SNMPv3 noAuthNoPriv: $snmpUser" -Level INFO
                    }
                    elseif ($secLvl -eq '2') {
                        Write-Host "`nAuth Protocol:" -ForegroundColor Cyan
                        Write-Host "  1. MD5" -ForegroundColor White
                        Write-Host "  2. SHA" -ForegroundColor White
                        $authProto = Read-Host "Selection [2]"
                        if ([string]::IsNullOrWhiteSpace($authProto)) {$authProto = '2'}
                        $authProtocol = if ($authProto -eq '1') {'MD5'} else {'SHA'}
                        
                        $authPass = Read-Host "Auth password" -AsSecureString
                        $authPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($authPass))
                        
                        $taskArgs += " --snmp-version 3 --snmpv3-user `"$snmpUser`" --snmpv3-level authNoPriv --snmpv3-auth-protocol `"$authProtocol`" --snmpv3-auth-password `"$authPlain`""
                        Write-InstallLog "SNMPv3 authNoPriv: $snmpUser, $authProtocol" -Level INFO
                    }
                    else {
                        Write-Host "`nAuth Protocol:" -ForegroundColor Cyan
                        Write-Host "  1. MD5" -ForegroundColor White
                        Write-Host "  2. SHA" -ForegroundColor White
                        $authProto = Read-Host "Selection [2]"
                        if ([string]::IsNullOrWhiteSpace($authProto)) {$authProto = '2'}
                        $authProtocol = if ($authProto -eq '1') {'MD5'} else {'SHA'}
                        
                        $authPass = Read-Host "Auth password" -AsSecureString
                        $authPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($authPass))
                        
                        Write-Host "`nPrivacy Protocol:" -ForegroundColor Cyan
                        Write-Host "  1. DES" -ForegroundColor White
                        Write-Host "  2. AES" -ForegroundColor White
                        $privProto = Read-Host "Selection [2]"
                        if ([string]::IsNullOrWhiteSpace($privProto)) {$privProto = '2'}
                        $privProtocol = if ($privProto -eq '1') {'DES'} else {'AES'}
                        
                        $privPass = Read-Host "Privacy password" -AsSecureString
                        $privPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($privPass))
                        
                        $taskArgs += " --snmp-version 3 --snmpv3-user `"$snmpUser`" --snmpv3-level authPriv --snmpv3-auth-protocol `"$authProtocol`" --snmpv3-auth-password `"$authPlain`" --snmpv3-priv-protocol `"$privProtocol`" --snmpv3-priv-password `"$privPlain`""
                        Write-InstallLog "SNMPv3 authPriv: $snmpUser, $authProtocol, $privProtocol" -Level INFO
                    }
                }
                else {
                    Write-InstallLog "SNMP skipped" -Level INFO
                }
            }
            else {
                Write-Host "`nDevice List Config" -ForegroundColor Cyan
                
                if ($DeviceListFile) {
                    Write-InstallLog "Using: $DeviceListFile" -Level INFO
                    $taskArgs = "-f `"$DeviceListFile`""
                }
                else {
                    Write-Host "Enter devices (comma-separated):" -ForegroundColor White
                    Write-Host "Example: 192.168.1.1,192.168.1.2,switch01" -ForegroundColor Gray
                    $devInput = Read-Host "`nDevices"
                    
                    if ([string]::IsNullOrWhiteSpace($devInput)) {
                        Write-InstallLog "No devices provided" -Level ERROR
                        throw "Device list required"
                    }
                    
                    $devList = $devInput -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_ -ne ''}
                    $devFile = Join-Path $InstallPath "devices.txt"
                    
                    $devList | Set-Content -Path $devFile -Force
                    Write-InstallLog "Created devices.txt with $($devList.Count) device(s)" -Level SUCCESS
                    foreach ($d in $devList) {Write-InstallLog "  - $d" -Level DEBUG}
                    
                    $taskArgs = "-f `"$devFile`""
                }
            }
            
            if (-not $OutputDirectory) {
                Write-Host "`nOutput Directory" -ForegroundColor Cyan
                $defOut = Join-Path $InstallPath "Results"
                $resp = Read-Host "Output directory [$defOut]"
                $OutputDirectory = if ([string]::IsNullOrWhiteSpace($resp)) {$defOut} else {$resp}
            }
            
            if (-not (Test-Path $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
                Write-InstallLog "Created output: $OutputDirectory" -Level SUCCESS
            }
            
            $taskArgs += " -o `"$OutputDirectory`""
            
            New-CiscoCollectorTask -InstallPath $InstallPath -ScheduleType $ScheduleType -ScheduleTime $ScheduleTime -Credential $svcCred -TaskArguments $taskArgs
        }
        else {
            Write-InstallLog "Task creation skipped" -Level INFO
        }

        Write-LogSection "INSTALLATION COMPLETE"
        Write-InstallLog "Path: $InstallPath" -Level SUCCESS
        Write-InstallLog "Script: $scriptPath" -Level SUCCESS
        Write-InstallLog "Log: $script:LogFile" -Level SUCCESS
        
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            Write-InstallLog "Task: $script:TaskName" -Level SUCCESS
            Write-InstallLog "Schedule: $ScheduleType at $ScheduleTime" -Level SUCCESS
            Write-InstallLog "Account: $($svcCred.UserName)" -Level SUCCESS
        }
        
        Write-Host "`nInstallation successful! " -ForegroundColor Green -NoNewline
        Write-Host "Log: $script:LogFile" -ForegroundColor White
        
        Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
        Write-Host "NEXT STEPS" -ForegroundColor Cyan
        Write-Host $('=' * 80) -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "1. Configure Cisco credentials:" -ForegroundColor White
        Write-Host "   As service account ($($svcCred.UserName)):" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   runas /user:$($svcCred.UserName) powershell.exe" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   Then:" -ForegroundColor Gray
        Write-Host "   cd `"$InstallPath`"" -ForegroundColor DarkGray
        Write-Host "   .\python.exe $script:PythonScriptName --save-credentials" -ForegroundColor DarkGray
        Write-Host ""
        
        $devFile = Join-Path $InstallPath "devices.txt"
        if ($isDiscovery) {
            Write-Host "2. Test collection:" -ForegroundColor White
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor Gray
            Write-Host "   .\python.exe $script:PythonScriptName --discover" -ForegroundColor Gray
        }
        elseif (Test-Path $devFile) {
            Write-Host "2. Verify devices.txt:" -ForegroundColor White
            Write-Host "   type `"$devFile`"" -ForegroundColor Gray
            Write-Host ""
            Write-Host "3. Test collection:" -ForegroundColor White
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor Gray
            Write-Host "   .\python.exe $script:PythonScriptName -f devices.txt" -ForegroundColor Gray
        }
        else {
            Write-Host "2. Test collection:" -ForegroundColor White
            Write-Host "   cd `"$InstallPath`"" -ForegroundColor Gray
            Write-Host "   .\python.exe $script:PythonScriptName -f <device_file>" -ForegroundColor Gray
        }
        Write-Host ""
        
        if (-not $SkipTaskCreation -and $ScheduleType -ne 'None') {
            $step = if ($isDiscovery) {"3"} else {"4"}
            Write-Host "$step. Verify task:" -ForegroundColor White
            Write-Host "   Get-ScheduledTask -TaskName '$script:TaskName'" -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host $('=' * 80) -ForegroundColor Yellow
        Write-Host "SECURITY NOTES" -ForegroundColor Yellow
        Write-Host $('=' * 80) -ForegroundColor Yellow
        Write-Host ""
        Write-Host "• Python script FAILS if task changed to SYSTEM" -ForegroundColor Red
        Write-Host "• Always use: $($svcCred.UserName)" -ForegroundColor Yellow
        Write-Host "• Credentials stored in Windows Credential Manager" -ForegroundColor White
        Write-Host "• Only service account can access credentials" -ForegroundColor White
        Write-Host ""
        Write-Host $('=' * 80) -ForegroundColor Yellow
        Write-Host ""
        
    }
    catch {
        Write-InstallLog "Installation failed: $_" -Level ERROR
        Write-InstallLog "Stack: $($_.ScriptStackTrace)" -Level DEBUG
        throw
    }
}

try {
    if ($Uninstall) {
        Uninstall-CiscoCollector
    }
    else {
        Install-CiscoCollector
    }
}
catch {
    Write-Host "`nFailed. Check log: $script:LogFile" -ForegroundColor Red
    exit 1
}