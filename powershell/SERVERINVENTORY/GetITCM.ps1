import-module ActiveDirectory
.\Collect-ServerInfo.ps1 -ComputerName wwww.xxx.yyy.uk
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | %{.\Collect-ServerInfo.ps1 $_.DNSHostName}
## Get-ADComputer -Filter {OperatingSystem -Like "Windows 11*"} | %{.\Collect-ServerInfo.ps1 $_.DNSHostName}
## Get-ADComputer -Filter {OperatingSystem -Like "Windows 10*"} | %{.\Collect-ServerInfo.ps1 $_.DNSHostName}
