#Requires -Version 7.0

<#
.SYNOPSIS
    Test script to diagnose Invoke-EvaluateSTIG.ps1 wrapper issues

.DESCRIPTION
    This script tests the wrapper script with minimal parameters to identify
    what might be causing the scheduled task to fail.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$InstallPath = "C:\Admin\Scripts\Get-CiscoTechSupport",

    [Parameter(Mandatory = $false)]
    [string]$EvaluateSTIGPath = "C:\Admin\Evaluate-STIG_1.2510.0\Evaluate-STIG\Evaluate-STIG.ps1"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Wrapper Script Diagnostic Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check PowerShell version
Write-Host "[Test 1] Checking PowerShell version..." -ForegroundColor Yellow
Write-Host "  Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "  ERROR: PowerShell 7+ required!" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: PowerShell 7+ detected" -ForegroundColor Green
Write-Host ""

# Test 2: Check if wrapper script exists
Write-Host "[Test 2] Checking if wrapper script exists..." -ForegroundColor Yellow
$wrapperPath = Join-Path $InstallPath "Invoke-EvaluateSTIG.ps1"
Write-Host "  Path: $wrapperPath" -ForegroundColor Gray
if (-not (Test-Path $wrapperPath)) {
    Write-Host "  ERROR: Wrapper script not found!" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: Wrapper script found" -ForegroundColor Green
Write-Host ""

# Test 3: Check if Evaluate-STIG.ps1 exists
Write-Host "[Test 3] Checking if Evaluate-STIG.ps1 exists..." -ForegroundColor Yellow
Write-Host "  Path: $EvaluateSTIGPath" -ForegroundColor Gray
if (-not (Test-Path $EvaluateSTIGPath)) {
    Write-Host "  ERROR: Evaluate-STIG.ps1 not found!" -ForegroundColor Red
    Write-Host "  Please provide correct path with -EvaluateSTIGPath parameter" -ForegroundColor Yellow
    exit 1
}
Write-Host "  OK: Evaluate-STIG.ps1 found" -ForegroundColor Green
Write-Host ""

# Test 4: Check if Logs directory exists
Write-Host "[Test 4] Checking if Logs directory exists..." -ForegroundColor Yellow
$logsPath = Join-Path $InstallPath "Logs"
Write-Host "  Path: $logsPath" -ForegroundColor Gray
if (-not (Test-Path $logsPath)) {
    Write-Host "  WARNING: Logs directory not found - will be created by wrapper" -ForegroundColor Yellow
} else {
    Write-Host "  OK: Logs directory found" -ForegroundColor Green
}
Write-Host ""

# Test 5: Check wrapper script syntax
Write-Host "[Test 5] Checking wrapper script syntax..." -ForegroundColor Yellow
try {
    $null = Get-Command $wrapperPath -ErrorAction Stop
    Write-Host "  OK: Wrapper script syntax is valid" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Wrapper script has syntax errors!" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 6: Attempt dry-run with help parameter
Write-Host "[Test 6] Testing wrapper script execution (help)..." -ForegroundColor Yellow
try {
    & $wrapperPath -? 2>&1 | Out-Null
    Write-Host "  OK: Wrapper script can be invoked" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Failed to invoke wrapper script!" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 7: Show what parameters would be passed
Write-Host "[Test 7] Simulated scheduled task parameters..." -ForegroundColor Yellow
Write-Host "  -EvaluateSTIGScriptPath: $EvaluateSTIGPath" -ForegroundColor Gray
Write-Host "  -LogDirectory: $logsPath" -ForegroundColor Gray
Write-Host "  -CiscoConfig: $(Join-Path $InstallPath 'Results')" -ForegroundColor Gray
Write-Host "  -SelectDeviceType: Router,Switch" -ForegroundColor Gray
Write-Host "  -ScanType: Classified" -ForegroundColor Gray
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "All diagnostic tests passed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To test actual execution, run:" -ForegroundColor Yellow
Write-Host "  & '$wrapperPath' ``" -ForegroundColor White
Write-Host "    -EvaluateSTIGScriptPath '$EvaluateSTIGPath' ``" -ForegroundColor White
Write-Host "    -LogDirectory '$logsPath' ``" -ForegroundColor White
Write-Host "    -CiscoConfig '$(Join-Path $InstallPath 'Results')' ``" -ForegroundColor White
Write-Host "    -SelectDeviceType 'Router','Switch' ``" -ForegroundColor White
Write-Host "    -ScanType 'Classified'" -ForegroundColor White
Write-Host ""
