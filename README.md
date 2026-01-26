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
