<#
.SYNOPSIS
    Validates that the system meets requirements for running Document-WinServer.ps1

.DESCRIPTION
    This script checks:
    - PowerShell version
    - Administrator privileges
    - Required modules availability
    - WinRM configuration (for remote execution)

.EXAMPLE
    .\Validate-Requirements.ps1
#>

[CmdletBinding()]
param()

Write-Host "`n=== Document-WinServer.ps1 - Requirements Validation ===" -ForegroundColor Cyan
Write-Host ""

$allPassed = $true

# Check PowerShell Version
Write-Host "Checking PowerShell Version..." -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -ge 5) {
    Write-Host "  ✓ PowerShell $($psVersion.ToString()) detected (>= 5.0 required)" -ForegroundColor Green
} else {
    Write-Host "  ✗ PowerShell $($psVersion.ToString()) detected (5.0+ required)" -ForegroundColor Red
    $allPassed = $false
}

# Check if running as Administrator
Write-Host "`nChecking Administrator Privileges..." -ForegroundColor Yellow
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "  ✓ Running with Administrator privileges" -ForegroundColor Green
} else {
    Write-Host "  ⚠ NOT running as Administrator (some data collection may be limited)" -ForegroundColor Yellow
}

# Check OS Type
Write-Host "`nChecking Operating System..." -ForegroundColor Yellow
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Host "  • OS: $($os.Caption)" -ForegroundColor Gray
    Write-Host "  • Version: $($os.Version)" -ForegroundColor Gray
    Write-Host "  • Build: $($os.BuildNumber)" -ForegroundColor Gray
    
    if ($os.Caption -match "Server") {
        Write-Host "  ✓ Windows Server detected" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Not a Windows Server OS (script designed for Server OS)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ✗ Could not determine OS information" -ForegroundColor Red
}

# Check for ServerManager module (for Features and Roles)
Write-Host "`nChecking ServerManager Module..." -ForegroundColor Yellow
if (Get-Module -ListAvailable -Name ServerManager) {
    Write-Host "  ✓ ServerManager module available (for Features and Roles)" -ForegroundColor Green
    try {
        Import-Module ServerManager -ErrorAction Stop
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            Write-Host "  ✓ Get-WindowsFeature cmdlet available" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ⚠ ServerManager module found but could not import" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠ ServerManager module not available (Features/Roles collection will be limited)" -ForegroundColor Yellow
}

# Check for NetSecurity module (for detailed firewall info)
Write-Host "`nChecking NetSecurity Module..." -ForegroundColor Yellow
if (Get-Module -ListAvailable -Name NetSecurity) {
    Write-Host "  ✓ NetSecurity module available (for detailed firewall info)" -ForegroundColor Green
    try {
        Import-Module NetSecurity -ErrorAction Stop
        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
            Write-Host "  ✓ Get-NetFirewallRule cmdlet available" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ⚠ NetSecurity module found but could not import" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠ NetSecurity module not available (will use netsh fallback)" -ForegroundColor Yellow
}

# Check for SmbShare cmdlets
Write-Host "`nChecking SMB Cmdlets..." -ForegroundColor Yellow
if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
    Write-Host "  ✓ Get-SmbShare cmdlet available" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Get-SmbShare not available (will use WMI fallback)" -ForegroundColor Yellow
}

# Check WinRM for remote execution
Write-Host "`nChecking WinRM Configuration (for remote execution)..." -ForegroundColor Yellow
try {
    $winrmStatus = Get-Service WinRM -ErrorAction Stop
    if ($winrmStatus.Status -eq 'Running') {
        Write-Host "  ✓ WinRM service is running" -ForegroundColor Green
        
        # Check if remoting is enabled
        try {
            $psRemoting = Test-WSMan -ErrorAction Stop
            Write-Host "  ✓ PowerShell remoting is enabled" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠ WinRM running but PowerShell remoting may not be configured" -ForegroundColor Yellow
            Write-Host "    Run 'Enable-PSRemoting -Force' to enable" -ForegroundColor Gray
        }
    } else {
        Write-Host "  ⚠ WinRM service is not running (required for remote execution)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠ Could not check WinRM status" -ForegroundColor Yellow
}

# Check common tools
Write-Host "`nChecking System Tools..." -ForegroundColor Yellow
$tools = @{
    'secedit.exe' = 'Security policy export'
    'auditpol.exe' = 'Audit policy information'
    'w32tm.exe' = 'Windows Time service'
}

foreach ($tool in $tools.GetEnumerator()) {
    $cmd = Get-Command $tool.Key -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host "  ✓ $($tool.Key) available ($($tool.Value))" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ $($tool.Key) not found ($($tool.Value))" -ForegroundColor Yellow
    }
}

# Check output directory
Write-Host "`nChecking Output Capabilities..." -ForegroundColor Yellow
$testDir = $env:TEMP
$testFile = Join-Path $testDir "test-write-$(Get-Random).txt"
try {
    "test" | Out-File -FilePath $testFile -ErrorAction Stop
    Remove-Item $testFile -ErrorAction SilentlyContinue
    Write-Host "  ✓ File system write access confirmed" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Cannot write to file system" -ForegroundColor Red
    $allPassed = $false
}

# Final summary
Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
if ($allPassed -and $isAdmin) {
    Write-Host "✓ System meets all requirements for Document-WinServer.ps1" -ForegroundColor Green
    Write-Host "`nYou can now run:" -ForegroundColor White
    Write-Host "  .\Document-WinServer.ps1" -ForegroundColor Cyan
} elseif ($allPassed -and !$isAdmin) {
    Write-Host "⚠ System meets basic requirements but not running as Administrator" -ForegroundColor Yellow
    Write-Host "`nFor complete data collection, run as Administrator:" -ForegroundColor White
    Write-Host "  Right-click PowerShell → Run as Administrator" -ForegroundColor Cyan
    Write-Host "  Then: .\Document-WinServer.ps1" -ForegroundColor Cyan
} else {
    Write-Host "✗ Some requirements are not met" -ForegroundColor Red
    Write-Host "`nThe script may still work with reduced functionality." -ForegroundColor Yellow
}
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host ""
