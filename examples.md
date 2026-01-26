# Document-WinServer.ps1 Usage Examples

This document provides practical examples for using the `Document-WinServer.ps1` script to document Windows Server configurations.

## Basic Usage

### Example 1: Document Local Server (Default - Both Formats)
```powershell
.\Document-WinServer.ps1
```
**Output:**
- `%COMPUTERNAME%-system-report.md`
- `%COMPUTERNAME%-system-report.html`

### Example 2: Generate Only Markdown Report
```powershell
.\Document-WinServer.ps1 -OutputFormat Markdown
```
**Output:**
- `%COMPUTERNAME%-system-report.md`

### Example 3: Generate Only HTML Report
```powershell
.\Document-WinServer.ps1 -OutputFormat HTML
```
**Output:**
- `%COMPUTERNAME%-system-report.html`

## Remote Server Documentation

### Example 4: Document Remote Server
```powershell
$cred = Get-Credential
.\Document-WinServer.ps1 -ComputerName SRV-APP-01 -Credential $cred
```

### Example 5: Document Multiple Remote Servers
```powershell
$cred = Get-Credential
$servers = @('SRV-APP-01', 'SRV-DB-01', 'SRV-WEB-01')

foreach ($server in $servers) {
    Write-Host "Documenting $server..." -ForegroundColor Cyan
    .\Document-WinServer.ps1 -ComputerName $server -Credential $cred -Verbose
}
```

## Advanced Usage

### Example 6: Include Missing Updates Scan
Download `wsusscn2.cab` from Microsoft Update Catalog and place it on the target server, then:

```powershell
.\Document-WinServer.ps1 -WsusCabPath 'C:\Temp\wsusscn2.cab'
```

### Example 7: Include Administrative Shares
```powershell
.\Document-WinServer.ps1 -IncludeAdminShares
```

### Example 8: Custom Output Directory
```powershell
.\Document-WinServer.ps1 -OutputDir 'C:\Reports\Servers'
```

### Example 9: Full Configuration (All Options)
```powershell
$cred = Get-Credential
.\Document-WinServer.ps1 `
    -ComputerName SRV-FNB-01 `
    -Credential $cred `
    -WsusCabPath 'C:\Temp\wsusscn2.cab' `
    -OutputDir 'C:\ServerDocs' `
    -IncludeAdminShares `
    -OutputFormat Both `
    -Verbose
```

## Batch Processing with Error Handling

### Example 10: Document All Domain Controllers
```powershell
$cred = Get-Credential
$outputPath = 'C:\ServerDocs\DomainControllers'

# Ensure output directory exists
if (!(Test-Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory -Force
}

# Get all domain controllers
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

foreach ($dc in $dcs) {
    try {
        Write-Host "`nDocumenting $dc..." -ForegroundColor Cyan
        .\Document-WinServer.ps1 `
            -ComputerName $dc `
            -Credential $cred `
            -OutputDir $outputPath `
            -OutputFormat Both `
            -Verbose
        Write-Host "✓ $dc completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Error documenting $dc : $_" -ForegroundColor Red
    }
}

Write-Host "`nAll reports saved to: $outputPath" -ForegroundColor Green
```

## Scheduled Documentation

### Example 11: Create Scheduled Task for Weekly Documentation
```powershell
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-ExecutionPolicy Bypass -File "C:\Scripts\Document-WinServer.ps1" -OutputDir "C:\Reports\Weekly" -OutputFormat Both'

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am

$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "Weekly Server Documentation" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -User "SYSTEM" `
    -Description "Generates weekly server documentation reports"
```

## Output Examples

### Markdown Output
The Markdown output includes:
- System information tables
- Features and roles with dependencies
- Security settings in various formats
- Firewall rules (enabled and disabled)
- Service accounts and configurations
- Software inventory
- Update history

### HTML Output
The HTML output provides:
- Professional styling with color-coded sections
- Responsive tables
- Easy-to-read formatting
- Printable layout
- Can be viewed in any web browser

## Tips and Best Practices

1. **Run with Administrator Privileges**: For complete data collection, always run the script with administrator rights.

2. **Remote Execution**: When documenting remote servers, ensure:
   - PowerShell remoting is enabled on target servers
   - You have appropriate credentials
   - Firewall allows WinRM traffic (TCP 5985/5986)

3. **Large Environments**: For many servers, consider:
   - Running in parallel with `Start-Job` or `Invoke-Command` with multiple computers
   - Scheduling during off-hours
   - Using a central shared storage for outputs

4. **Security**: 
   - Store credentials securely (don't hardcode in scripts)
   - Review firewall rules output before sharing externally
   - Protect generated reports as they contain sensitive configuration data

5. **Offline Updates Scan**:
   - Download latest `wsusscn2.cab` from [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/)
   - Place it on target server or accessible network share
   - File size is typically 200-400 MB

## Troubleshooting

### Common Issues

**Issue**: "Access Denied" errors
- **Solution**: Ensure you're running as Administrator and have proper permissions on remote servers

**Issue**: "Get-WindowsFeature" not found
- **Solution**: This cmdlet requires ServerManager module, which is only available on Windows Server with Desktop Experience

**Issue**: Remote execution fails
- **Solution**: Enable PowerShell remoting: `Enable-PSRemoting -Force`

**Issue**: Missing firewall information
- **Solution**: NetSecurity module required. Script will fallback to netsh if unavailable.
