<#
.SYNOPSIS
GetITCM.ps1 - Examples for using Collect-ServerInfo.ps1 script

.DESCRIPTION
This script provides example usage patterns for the Collect-ServerInfo.ps1 script,
demonstrating various ways to collect server information with different output formats.

.NOTES
The Collect-ServerInfo.ps1 script now supports:
- Dual output formats (HTML, Markdown, or Both)
- Windows Server Features and Roles collection
- Firewall settings (profiles and rules)
- Local security settings (via secedit)
- Enhanced compatibility with Windows Server 2016, 2019, and above

.EXAMPLES
See the example commands below
#>

# Import Active Directory module (required for AD queries)
Import-Module ActiveDirectory

# Example 1: Single server with both HTML and Markdown output (default)
.\Collect-ServerInfo.ps1 -ComputerName wwww.xxx.yyy.uk

# Example 2: Single server with HTML output only
.\Collect-ServerInfo.ps1 -ComputerName wwww.xxx.yyy.uk -OutputFormat HTML

# Example 3: Single server with Markdown output only
.\Collect-ServerInfo.ps1 -ComputerName wwww.xxx.yyy.uk -OutputFormat Markdown

# Example 4: All Windows Servers in Active Directory (both HTML and Markdown)
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | ForEach-Object { .\Collect-ServerInfo.ps1 $_.DNSHostName }

# Example 5: All Windows Servers with HTML output only
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | ForEach-Object { .\Collect-ServerInfo.ps1 $_.DNSHostName -OutputFormat HTML }

# Example 6: All Windows Servers with Markdown output only (for documentation systems)
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | ForEach-Object { .\Collect-ServerInfo.ps1 $_.DNSHostName -OutputFormat Markdown }

# Example 7: Specific OU with verbose output
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} -SearchBase "OU=Servers,DC=contoso,DC=com" | ForEach-Object { .\Collect-ServerInfo.ps1 $_.DNSHostName -Verbose }

# Example 8: Multiple specific servers
$servers = @("SERVER1", "SERVER2", "SERVER3")
$servers | ForEach-Object { .\Collect-ServerInfo.ps1 $_ }

# Optional: Windows 11 workstations (uncomment to use)
## Get-ADComputer -Filter {OperatingSystem -Like "Windows 11*"} | ForEach-Object { .\Collect-ServerInfo.ps1 $_.DNSHostName }

# Optional: Windows 10 workstations (uncomment to use)
## Get-ADComputer -Filter {OperatingSystem -Like "Windows 10*"} | ForEach-Object { .\Collect-ServerInfo.ps1 $_.DNSHostName }
