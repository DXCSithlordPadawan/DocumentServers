# Document Servers

This repository contains scripts to document server configurations for both Windows and RHEL systems.

## Windows Server Documentation

### Document-WinServer.ps1

A comprehensive PowerShell script for documenting Windows Server 2016, 2019, and above configurations.

#### Features

The script collects detailed information about:
- **OS and Kernel Version** - Operating system details and kernel version
- **Windows Server Features and Roles** - Installed features, roles, and their dependencies
- **Installed Software** - Registry-based software inventory
- **Local Users & Groups** - Local users, groups, and service logon accounts
- **SMB Shares & ACLs** - File shares and access control lists
- **Security Settings**:
  - Local Security Policy (System Access, Event Audit, Privilege Rights, Registry Values)
  - Audit Policy (auditpol)
  - Network Security Settings (LAN Manager authentication, NTLM settings)
  - Account Lockout Settings
  - Password Policy
- **Firewall Configuration**:
  - Firewall Profiles (Domain/Private/Public)
  - Enabled and disabled firewall rules with detailed settings
  - Protocol, ports, and address information
- **Windows Updates**:
  - Installed security updates (HotFixes)
  - Missing security patches (offline scan via wsusscn2.cab)
  - Windows Update history
- **Windows Time (NTP)** - NTP configuration, peers, and status

#### Output Formats

The script supports multiple output formats:
- **Markdown** - Human-readable Markdown format
- **HTML** - Styled HTML report with tables and sections
- **Both** - Generate both Markdown and HTML (default)

#### Usage

```powershell
# Local server with both Markdown and HTML output (default)
.\Document-WinServer.ps1

# Local server with HTML output only
.\Document-WinServer.ps1 -OutputFormat HTML

# Remote server with credentials
.\Document-WinServer.ps1 -ComputerName SRV-FNB-01 -Credential (Get-Credential)

# Remote server with offline missing updates scan
.\Document-WinServer.ps1 -ComputerName SRV-FNB-01 -Credential (Get-Credential) -WsusCabPath 'C:\Temp\wsusscn2.cab' -Verbose

# Include administrative shares (C$, ADMIN$, etc.)
.\Document-WinServer.ps1 -IncludeAdminShares

# Specify custom output directory
.\Document-WinServer.ps1 -OutputDir "C:\Reports"
```

#### Parameters

- **ComputerName** - Target computer (defaults to local host)
- **Credential** - Optional PSCredential for remote connection
- **WsusCabPath** - Optional path to wsusscn2.cab for offline missing update scan
- **OutputDir** - Directory to save reports (defaults to current directory)
- **IncludeAdminShares** - Include administrative shares in SMB section
- **OutputFormat** - Output format: 'Markdown', 'HTML', or 'Both' (default: 'Both')

#### Requirements

- Windows Server 2016, 2019, or later
- PowerShell 5.1 or later
- Administrator privileges recommended for complete data collection
- ServerManager module for Features and Roles collection
- NetSecurity module for detailed firewall information (fallback to netsh if unavailable)

#### Output Files

- `<ComputerName>-system-report.md` - Markdown report
- `<ComputerName>-system-report.html` - HTML report

---

### Collect-ServerInfo.ps1 (SERVERINVENTORY)

Located in `powershell/SERVERINVENTORY/Collect-ServerInfo.ps1`, this is a comprehensive server inventory script with pipeline support for bulk operations. Enhanced to support Windows Server 2016, 2019, 2022, and above with dual output formats.

#### Features

The script collects detailed information about:
- **Computer System Information** - Name, manufacturer, model, processors, memory
- **Operating System Information** - OS version, architecture, install date
- **Physical Memory Information** - Memory banks, capacity, speed
- **PageFile Information** - Pagefile configuration
- **BIOS Information** - BIOS version, manufacturer, serial number
- **Logical Disk Information** - Disks, file systems, capacity
- **Volume Information** - Volume details and space
- **Network Interface Information** - NICs, IP addresses, MAC addresses
- **Software Information** - Installed software via WMI
- **HotFix Information** - Installed Windows updates
- **Services Information** - Auto-start services
- **Shares Information** - SMB shares
- **Windows Server Features and Roles** - Installed features, roles, and role services with dependencies
- **Local Security Policy** - Security settings via secedit export:
  - System Access settings
  - Event Audit settings
  - Privilege Rights (User Rights Assignments)
  - Registry Values
- **Firewall Configuration**:
  - Firewall Profiles (Domain/Private/Public)
  - Enabled firewall rules with protocol, ports, and addresses
  - Disabled firewall rules (for reference)

#### Output Formats

- **Markdown** - Human-readable Markdown format
- **HTML** - Styled HTML report with tables
- **Both** - Generate both Markdown and HTML (default)

#### Usage

```powershell
# Single server with both HTML and Markdown output (default)
.\Collect-ServerInfo.ps1 SERVER1

# Single server with HTML output only
.\Collect-ServerInfo.ps1 SERVER1 -OutputFormat HTML

# Single server with Markdown output only
.\Collect-ServerInfo.ps1 SERVER1 -OutputFormat Markdown

# Multiple servers via pipeline
"SERVER1","SERVER2","SERVER3" | .\Collect-ServerInfo.ps1

# All Windows Servers from Active Directory
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | 
    ForEach-Object { .\Collect-ServerInfo.ps1 $_.DNSHostName }

# With verbose output
.\Collect-ServerInfo.ps1 SERVER1 -Verbose
```

#### Parameters

- **ComputerName** - Target computer(s). Supports pipeline input.
- **OutputFormat** - Output format: 'Markdown', 'HTML', or 'Both' (default: 'Both')

#### Output Files

- `<ComputerName>.html` - HTML report (if HTML or Both selected)
- `<ComputerName>.md` - Markdown report (if Markdown or Both selected)

#### Requirements

- Windows Server 2016, 2019, 2022, or later
- PowerShell 5.1 or later
- Administrator privileges recommended for complete data collection
- ServerManager module for Features and Roles collection
- NetSecurity module for detailed firewall information (fallback to netsh if unavailable)

#### Usage Examples Script

See `powershell/SERVERINVENTORY/GetITCM.ps1` for comprehensive usage examples including:
- Single server documentation
- Bulk collection from Active Directory
- Different output format options
- OU-specific collection

---

## RHEL Server Documentation

### rhel_inventory.sh

A bash script for documenting RHEL server configurations.

#### Usage

```bash
# Make executable (already set, but if re-copied):
chmod +x ./rhel_inventory.sh

# Run with root (recommended for RAID tools, dmidecode, sosreport, firewall):
sudo ./rhel_inventory.sh
```

#### Output

- `./<hostname>_system_inventory.md` - Markdown report
- Optional: sosreport archive path is noted in the report if 'sos' is installed
