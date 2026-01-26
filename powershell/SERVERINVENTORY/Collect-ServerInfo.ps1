<#
.SYNOPSIS
Collect-ServerInfo.ps1 - PowerShell script to collect information about Windows servers
.DESCRIPTION 
This PowerShell script runs a series of WMI and other queries to collect information
about Windows servers.
.OUTPUTS
Each server's results are output to HTML and/or Markdown.
.PARAMETER ComputerName
Target computer(s) to collect information from.
.PARAMETER OutputFormat
Output format: 'Markdown', 'HTML', or 'Both'. Defaults to 'Both'.
.PARAMETER -Verbose
See more detailed progress as the script is running.
.EXAMPLE
.\Collect-ServerInfo.ps1 SERVER1
Collect information about a single server.
.EXAMPLE
"SERVER1","SERVER2","SERVER3" | .\Collect-ServerInfo.ps1
Collect information about multiple servers.
.EXAMPLE
Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | %{.\Collect-ServerInfo.ps1 $_.DNSHostName}
Collects information about all servers in Active Directory.
.EXAMPLE
.\Collect-ServerInfo.ps1 SERVER1 -OutputFormat Markdown
Collect information and output only Markdown format.
.NOTES
Written by Paul Cunningham
Technical Consultant/Director at LockLAN Systems Pty Ltd - https://www.locklan.com.au
Microsoft MVP, Office Servers and Services - http://exchangeserverpro.com
You can also find me on:
* Twitter: https://twitter.com/paulcunningham
* Twitter: https://twitter.com/ExchServPro
* LinkedIn: http://au.linkedin.com/in/cunninghamp/
* Github: https://github.com/cunninghamp
License:
The MIT License (MIT)
Copyright (c) 2016 Paul Cunningham
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
Change Log:
V1.00, 20/04/2015 - First release
V1.01, 01/05/2015 - Updated with better error handling
#>


[CmdletBinding()]

Param (

    [parameter(ValueFromPipeline=$True)]
    [string[]]$ComputerName,

    [ValidateSet('Markdown','HTML','Both')]
    [string]$OutputFormat = 'Both'

)

Begin
{
    #Initialize
    Write-Verbose "Initializing"

    # Markdown helpers
    function Add-MDLine([string]$s, [System.Text.StringBuilder]$builder){ [void]$builder.AppendLine($s) }
    function Add-MDSection([string]$Title, [System.Text.StringBuilder]$builder){ Add-MDLine "" $builder; Add-MDLine "## $Title" $builder; Add-MDLine "" $builder }

    function Emit-MDTable([object[]]$Data,[string[]]$Cols, [System.Text.StringBuilder]$builder){
      if(-not $Data -or $Data.Count -eq 0){ Add-MDLine "> _No data found_" $builder; Add-MDLine "" $builder; return }
      Add-MDLine ('| ' + ($Cols -join ' | ') + ' |') $builder
      Add-MDLine ('| ' + (($Cols | ForEach-Object{'---'}) -join ' | ') + ' |') $builder
      foreach($row in $Data){
        $cells = foreach($c in $Cols){
          $v = $row.$c
          if($v -is [DateTime]){ $v = $v.ToString('yyyy-MM-dd HH:mm') }
          ($v -as [string]).Replace('|','`\|').Replace("`r`n",' ').Replace("`n",' ')
        }
        Add-MDLine ('| ' + ($cells -join ' | ') + ' |') $builder
      }
      Add-MDLine "" $builder
    }

}

Process
{

    #---------------------------------------------------------------------
    # Process each ComputerName
    #---------------------------------------------------------------------

    if (!($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent))
    {
        Write-Host "Processing $ComputerName"
    }

    Write-Verbose "=====> Processing $ComputerName <====="

    $htmlreport = @()
    $htmlbody = @()
    $htmlfile = "$($ComputerName).html"
    $mdfile = "$($ComputerName).md"
    $spacer = "<br />"
    
    # Initialize Markdown StringBuilder
    $mdBuilder = New-Object System.Text.StringBuilder
    $reportime = Get-Date
    
    # Add Markdown header
    Add-MDLine "# $ComputerName — Server Information Report" $mdBuilder
    Add-MDLine "> Generated: $($reportime.ToString('yyyy-MM-dd HH:mm:ss'))" $mdBuilder
    Add-MDLine "" $mdBuilder

    #---------------------------------------------------------------------
    # Do 10 pings and calculate the fastest response time
    # Not using the response time in the report yet so it might be
    # removed later.
    #---------------------------------------------------------------------
    
    try
    {
        $bestping = (Test-Connection -ComputerName $ComputerName -Count 10 -ErrorAction STOP | Sort ResponseTime)[0].ResponseTime
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $bestping = "Unable to connect"
    }

    if ($bestping -eq "Unable to connect")
    {
        if (!($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent))
        {
            Write-Host "Unable to connect to $ComputerName"
        }

        "Unable to connect to $ComputerName"
    }
    else
    {

        #---------------------------------------------------------------------
        # Collect computer system information and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting computer system information"

        $subhead = "<h3>Computer System Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Computer System Information" $mdBuilder
    
        try
        {
            $csinfo = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object Name,Manufacturer,Model,
                            @{Name='Physical Processors';Expression={$_.NumberOfProcessors}},
                            @{Name='Logical Processors';Expression={$_.NumberOfLogicalProcessors}},
                            @{Name='Total Physical Memory (Gb)';Expression={
                                $tpm = $_.TotalPhysicalMemory/1GB;
                                "{0:F0}" -f $tpm
                            }},
                            DnsHostName,Domain
       
            $htmlbody += $csinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $csinfo @('Name','Manufacturer','Model','Physical Processors','Logical Processors','Total Physical Memory (Gb)','DnsHostName','Domain') $mdBuilder
       
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }



        #---------------------------------------------------------------------
        # Collect operating system information and convert to HTML fragment
        #---------------------------------------------------------------------
    
        Write-Verbose "Collecting operating system information"

        $subhead = "<h3>Operating System Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Operating System Information" $mdBuilder
    
        try
        {
            $osinfo = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction STOP | 
                Select-Object @{Name='Operating System';Expression={$_.Caption}},
                            @{Name='Architecture';Expression={$_.OSArchitecture}},
                            Version,Organization,
                            @{Name='Install Date';Expression={
                                $installdate = [datetime]::ParseExact($_.InstallDate.SubString(0,8),"yyyyMMdd",$null);
                                $installdate.ToShortDateString()
                            }},
                            WindowsDirectory

            $htmlbody += $osinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $osinfo @('Operating System','Architecture','Version','Organization','Install Date','WindowsDirectory') $mdBuilder
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }


        #---------------------------------------------------------------------
        # Collect physical memory information and convert to HTML fragment
        #---------------------------------------------------------------------

        Write-Verbose "Collecting physical memory information"

        $subhead = "<h3>Physical Memory Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Physical Memory Information" $mdBuilder

        try
        {
            $memorybanks = @()
            $physicalmemoryinfo = @(Get-WmiObject Win32_PhysicalMemory -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object DeviceLocator,Manufacturer,Speed,Capacity)

            foreach ($bank in $physicalmemoryinfo)
            {
                $memObject = New-Object PSObject
                $memObject | Add-Member NoteProperty -Name "Device Locator" -Value $bank.DeviceLocator
                $memObject | Add-Member NoteProperty -Name "Manufacturer" -Value $bank.Manufacturer
                $memObject | Add-Member NoteProperty -Name "Speed" -Value $bank.Speed
                $memObject | Add-Member NoteProperty -Name "Capacity (GB)" -Value ("{0:F0}" -f $bank.Capacity/1GB)

                $memorybanks += $memObject
            }

            $htmlbody += $memorybanks | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $memorybanks @('Device Locator','Manufacturer','Speed','Capacity (GB)') $mdBuilder
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }


        #---------------------------------------------------------------------
        # Collect pagefile information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>PageFile Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "PageFile Information" $mdBuilder

        Write-Verbose "Collecting pagefile information"

        try
        {
            $pagefileinfo = Get-WmiObject Win32_PageFileUsage -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object @{Name='Pagefile Name';Expression={$_.Name}},
                            @{Name='Allocated Size (Mb)';Expression={$_.AllocatedBaseSize}}

            $htmlbody += $pagefileinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $pagefileinfo @('Pagefile Name','Allocated Size (Mb)') $mdBuilder
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }


        #---------------------------------------------------------------------
        # Collect BIOS information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>BIOS Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "BIOS Information" $mdBuilder

        Write-Verbose "Collecting BIOS information"

        try
        {
            $biosinfo = Get-WmiObject Win32_Bios -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object Status,Version,Manufacturer,
                            @{Name='Release Date';Expression={
                                $releasedate = [datetime]::ParseExact($_.ReleaseDate.SubString(0,8),"yyyyMMdd",$null);
                                $releasedate.ToShortDateString()
                            }},
                            @{Name='Serial Number';Expression={$_.SerialNumber}}

            $htmlbody += $biosinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $biosinfo @('Status','Version','Manufacturer','Release Date','Serial Number') $mdBuilder
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }


        #---------------------------------------------------------------------
        # Collect logical disk information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Logical Disk Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Logical Disk Information" $mdBuilder

        Write-Verbose "Collecting logical disk information"

        try
        {
            $diskinfo = Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName -ErrorAction STOP | 
                Select-Object DeviceID,FileSystem,VolumeName,
                @{Expression={$_.Size /1Gb -as [int]};Label="Total Size (GB)"},
                @{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Space (GB)"}

            $htmlbody += $diskinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $diskinfo @('DeviceID','FileSystem','VolumeName','Total Size (GB)','Free Space (GB)') $mdBuilder
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }


        #---------------------------------------------------------------------
        # Collect volume information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Volume Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Volume Information" $mdBuilder

        Write-Verbose "Collecting volume information"

        try
        {
            $volinfo = Get-WmiObject Win32_Volume -ComputerName $ComputerName -ErrorAction STOP | 
                Select-Object Label,Name,DeviceID,SystemVolume,
                @{Expression={$_.Capacity /1Gb -as [int]};Label="Total Size (GB)"},
                @{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Space (GB)"}

            $htmlbody += $volinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $volinfo @('Label','Name','DeviceID','SystemVolume','Total Size (GB)','Free Space (GB)') $mdBuilder
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }


        #---------------------------------------------------------------------
        # Collect network interface information and convert to HTML fragment
        #---------------------------------------------------------------------    

        $subhead = "<h3>Network Interface Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Network Interface Information" $mdBuilder

        Write-Verbose "Collecting network interface information"

        try
        {
            $nics = @()
            $nicinfo = @(Get-WmiObject Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction STOP | Where {$_.PhysicalAdapter} |
                Select-Object Name,AdapterType,MACAddress,
                @{Name='ConnectionName';Expression={$_.NetConnectionID}},
                @{Name='Enabled';Expression={$_.NetEnabled}},
                @{Name='Speed';Expression={$_.Speed/1000000}})

            $nwinfo = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction STOP |
                Select-Object Description, DHCPServer,  
                @{Name='IpAddress';Expression={$_.IpAddress -join '; '}},  
                @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}},  
                @{Name='DefaultIPgateway';Expression={$_.DefaultIPgateway -join '; '}},  
                @{Name='DNSServerSearchOrder';Expression={$_.DNSServerSearchOrder -join '; '}}

            foreach ($nic in $nicinfo)
            {
                $nicObject = New-Object PSObject
                $nicObject | Add-Member NoteProperty -Name "Connection Name" -Value $nic.connectionname
                $nicObject | Add-Member NoteProperty -Name "Adapter Name" -Value $nic.Name
                $nicObject | Add-Member NoteProperty -Name "Type" -Value $nic.AdapterType
                $nicObject | Add-Member NoteProperty -Name "MAC" -Value $nic.MACAddress
                $nicObject | Add-Member NoteProperty -Name "Enabled" -Value $nic.Enabled
                $nicObject | Add-Member NoteProperty -Name "Speed (Mbps)" -Value $nic.Speed
        
                $ipaddress = ($nwinfo | Where {$_.Description -eq $nic.Name}).IpAddress
                $nicObject | Add-Member NoteProperty -Name "IPAddress" -Value $ipaddress

                $nics += $nicObject
            }

            $htmlbody += $nics | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $nics @('Connection Name','Adapter Name','Type','MAC','Enabled','Speed (Mbps)','IPAddress') $mdBuilder
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }


        #---------------------------------------------------------------------
        # Collect software information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Software Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Software Information" $mdBuilder
 
        Write-Verbose "Collecting software information"
        
        try
        {
            $software = Get-WmiObject Win32_Product -ComputerName $ComputerName -ErrorAction STOP | Select-Object Vendor,Name,Version | Sort-Object Vendor,Name
        
            $htmlbody += $software | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $software @('Vendor','Name','Version') $mdBuilder
        
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }
       
        #---------------------------------------------------------------------
        # Collect Hotfix information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>HotFix Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "HotFix Information" $mdBuilder
 
        Write-Verbose "Collecting Hotfix information"
        
        try
        {
            $hotfix = Get-WmiObject Win32_quickfixengineering -ComputerName $ComputerName -ErrorAction STOP | Select-Object HotFixID,Description,InstalledBy, InstalledOn | Sort-Object HotFixID
        
            $htmlbody += $hotfix | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $hotfix @('HotFixID','Description','InstalledBy','InstalledOn') $mdBuilder
        
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        #---------------------------------------------------------------------
        # Collect Services information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Services Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Services Information" $mdBuilder
 
        Write-Verbose "Collecting Services information"
        
        try
        {
            $Services = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "startmode='auto'" -ErrorAction STOP | Select-Object Name,State,ProcessId | Sort-Object Name
        
            $htmlbody += $Services | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $Services @('Name','State','ProcessId') $mdBuilder
        
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        #---------------------------------------------------------------------
        # Collect Share information and convert to HTML fragment
        #---------------------------------------------------------------------

        $subhead = "<h3>Shares Information</h3>"
        $htmlbody += $subhead
        Add-MDSection "Shares Information" $mdBuilder
 
        Write-Verbose "Collecting Share information"
        
        try
        {
            $Shares = Get-WmiObject Win32_Share -ComputerName $ComputerName -ErrorAction STOP | Select-Object Name,Path,Description | Sort-Object Name
        
            $htmlbody += $Shares | ConvertTo-Html -Fragment
            $htmlbody += $spacer
            Emit-MDTable $Shares @('Name','Path','Description') $mdBuilder
        
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        #---------------------------------------------------------------------
        # Collect Windows Server Features and Roles
        #---------------------------------------------------------------------

        $subhead = "<h3>Windows Server Features and Roles</h3>"
        $htmlbody += $subhead
        Add-MDSection "Windows Server Features and Roles" $mdBuilder
 
        Write-Verbose "Collecting Windows Server Features and Roles"
        
        try
        {
            if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                $features = Get-WindowsFeature | Where-Object { $_.Installed -eq $true }
                
                if ($features.Count -gt 0) {
                    $featureData = foreach($f in $features){
                      [pscustomobject]@{
                        DisplayName = $f.DisplayName
                        Name = $f.Name
                        FeatureType = $f.FeatureType
                        Path = $f.Path
                        InstallState = $f.InstallState
                      }
                    }
                    $htmlbody += $featureData | ConvertTo-Html -Fragment
                    $htmlbody += $spacer
                    Emit-MDTable $featureData @('DisplayName','Name','FeatureType','Path','InstallState') $mdBuilder
                    
                    # Role-specific details for Markdown
                    Add-MDSection "Installed Role Details" $mdBuilder
                    $roles = $features | Where-Object { $_.FeatureType -eq 'Role' }
                    if ($roles.Count -gt 0) {
                      foreach($role in $roles){
                        Add-MDLine "### $($role.DisplayName)" $mdBuilder
                        Add-MDLine "" $mdBuilder
                        Add-MDLine "- **Name**: $($role.Name)" $mdBuilder
                        Add-MDLine "- **Feature Type**: $($role.FeatureType)" $mdBuilder
                        Add-MDLine "- **Installation State**: $($role.InstallState)" $mdBuilder
                        
                        $roleServices = $features | Where-Object { $_.Path -like "*$($role.Name)*" -and $_.Name -ne $role.Name }
                        if ($roleServices.Count -gt 0) {
                          Add-MDLine "- **Role Services**:" $mdBuilder
                          foreach($rs in $roleServices){
                            Add-MDLine "  - $($rs.DisplayName) ($($rs.Name))" $mdBuilder
                          }
                        }
                        Add-MDLine "" $mdBuilder
                      }
                    }
                } else {
                    $htmlbody += "<p>No installed features found.</p>"
                    $htmlbody += $spacer
                    Add-MDLine "> _No installed features found._" $mdBuilder
                    Add-MDLine "" $mdBuilder
                }
            } else {
                $htmlbody += "<p>Get-WindowsFeature cmdlet not available. Server may not be running Server OS with ServerManager module.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _Get-WindowsFeature cmdlet not available._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
        }
        catch
        {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        #---------------------------------------------------------------------
        # Collect Local Security Policy settings using secedit
        #---------------------------------------------------------------------

        $subhead = "<h3>Local Security Policy Export (secedit)</h3>"
        $htmlbody += $subhead
        Add-MDSection "Local Security Policy Export (secedit)" $mdBuilder
 
        Write-Verbose "Collecting Local Security Policy"
        
        $tempInf = Join-Path $env:TEMP "$ComputerName-security-policy.inf"
        $secEditSuccess = $false
        
        try { 
            # For remote computers, use WMI to execute secedit
            # NOTE: Remote execution via WMI requires appropriate credentials and permissions.
            # This is consistent with the WMI-based approach used throughout this script.
            if ($ComputerName -ne $env:COMPUTERNAME) {
                $remoteInf = "C:\Windows\Temp\$ComputerName-security-policy.inf"
                # Execute secedit remotely via WMI Win32_Process
                $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList "secedit.exe /export /mergedpolicy /cfg `"$remoteInf`"" -ErrorAction Stop
                Start-Sleep -Seconds 3
                
                # Try to copy file back using administrative share
                # NOTE: Requires administrative share access (C$) and proper authentication.
                # If this fails, the section will be skipped gracefully.
                try {
                    $remotePath = "\\$ComputerName\C$\Windows\Temp\$ComputerName-security-policy.inf"
                    if (Test-Path $remotePath) {
                        Copy-Item $remotePath $tempInf -ErrorAction Stop
                        $secEditSuccess = $true
                    }
                } catch {
                    Write-Verbose "Unable to retrieve security policy file from remote computer: $($_.Exception.Message)"
                }
            } else {
                # Local execution
                & secedit.exe /export /mergedpolicy /cfg "$tempInf" | Out-Null
                if (Test-Path $tempInf) {
                    $secEditSuccess = $true
                }
            }
        } catch {
            Write-Verbose "secedit export failed: $($_.Exception.Message)"
        }
        
        if ($secEditSuccess -and (Test-Path $tempInf)) {
            $htmlbody += "<p>Export file: $tempInf</p>"
            $htmlbody += $spacer
            Add-MDLine "> Export file: $tempInf" $mdBuilder
            Add-MDLine "" $mdBuilder
            
            $infLines = Get-Content -Path $tempInf -ErrorAction SilentlyContinue
            
            function Get-InfSection([string[]]$Lines,[string]$SectionName){
                $start = ($Lines | Select-String -SimpleMatch "[$SectionName]").LineNumber
                if(-not $start){ return @() }
                $rest = $Lines[$start..($Lines.Length-1)]
                $end = ($rest | Select-String -Pattern "^\[.+\]" | Select-Object -First 1).LineNumber
                if($end){ $rest[1..($end-2)] } else { $rest[1..($rest.Length-1)] }
            }
            
            # System Access
            $subhead = "<h3>Security Template — [System Access]</h3>"
            $htmlbody += $subhead
            Add-MDSection "Security Template — [System Access]" $mdBuilder
            
            $sysAccess = Get-InfSection $infLines 'System Access' | Where-Object { $_ -match '=' } |
                ForEach-Object {
                  $kv = $_ -split '=',2
                  [pscustomobject]@{ Setting = $kv[0].Trim(); Value = $kv[1].Trim() }
                }
            if ($sysAccess.Count -gt 0) {
                $htmlbody += $sysAccess | ConvertTo-Html -Fragment
                $htmlbody += $spacer
                Emit-MDTable $sysAccess @('Setting','Value') $mdBuilder
            } else {
                $htmlbody += "<p>No System Access settings found.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _No System Access settings found._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
            
            # Event Audit
            $subhead = "<h3>Security Template — [Event Audit]</h3>"
            $htmlbody += $subhead
            Add-MDSection "Security Template — [Event Audit]" $mdBuilder
            
            $eventAudit = Get-InfSection $infLines 'Event Audit' | Where-Object { $_ -match '=' } |
                ForEach-Object {
                  $kv = $_ -split '=',2
                  [pscustomobject]@{ Category = $kv[0].Trim(); Setting = $kv[1].Trim() }
                }
            if ($eventAudit.Count -gt 0) {
                $htmlbody += $eventAudit | ConvertTo-Html -Fragment
                $htmlbody += $spacer
                Emit-MDTable $eventAudit @('Category','Setting') $mdBuilder
            } else {
                $htmlbody += "<p>No Event Audit settings found.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _No Event Audit settings found._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
            
            # Privilege Rights (User Rights Assignments)
            $subhead = "<h3>Security Template — [Privilege Rights]</h3>"
            $htmlbody += $subhead
            Add-MDSection "Security Template — [Privilege Rights] (User Rights Assignments)" $mdBuilder
            
            $privRights = Get-InfSection $infLines 'Privilege Rights' | Where-Object { $_ -match '=' } |
                ForEach-Object {
                  $kv = $_ -split '=',2
                  $principals = ($kv[1] -split ',') | ForEach-Object { $_.Trim() }
                  [pscustomobject]@{ Right = $kv[0].Trim(); Principals = ($principals -join ', ') }
                }
            if ($privRights.Count -gt 0) {
                $htmlbody += $privRights | ConvertTo-Html -Fragment
                $htmlbody += $spacer
                Emit-MDTable $privRights @('Right','Principals') $mdBuilder
            } else {
                $htmlbody += "<p>No Privilege Rights found.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _No Privilege Rights found._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
            
            # Registry Values
            $subhead = "<h3>Security Template — [Registry Values]</h3>"
            $htmlbody += $subhead
            Add-MDSection "Security Template — [Registry Values]" $mdBuilder
            
            $regVals = Get-InfSection $infLines 'Registry Values' | Where-Object { $_ -match '=' } |
                ForEach-Object {
                  $kv = $_ -split '=',2
                  [pscustomobject]@{ Key = $kv[0].Trim(); Raw = $kv[1].Trim() }
                }
            if ($regVals.Count -gt 0) {
                $htmlbody += $regVals | ConvertTo-Html -Fragment
                $htmlbody += $spacer
                Emit-MDTable $regVals @('Key','Raw') $mdBuilder
            } else {
                $htmlbody += "<p>No Registry Values found.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _No Registry Values found._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
        } else {
            $htmlbody += "<p>Export failed or unavailable.</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Export failed or unavailable._" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        #---------------------------------------------------------------------
        # Collect Firewall settings
        #---------------------------------------------------------------------

        $subhead = "<h3>Firewall Profiles</h3>"
        $htmlbody += $subhead
        Add-MDSection "Firewall Profiles" $mdBuilder
 
        Write-Verbose "Collecting Firewall Profiles"
        
        try {
            # Note: Get-NetFirewallProfile requires PowerShell remoting for remote computers
            # For cross-platform compatibility, we use local execution only
            if ($ComputerName -eq $env:COMPUTERNAME) {
                if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
                    $profiles = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen
                    
                    $htmlbody += $profiles | ConvertTo-Html -Fragment
                    $htmlbody += $spacer
                    Emit-MDTable $profiles @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction','NotifyOnListen') $mdBuilder
                } else {
                    $profText = & netsh advfirewall show allprofiles 2>$null
                    $htmlbody += "<pre>$profText</pre>"
                    $htmlbody += $spacer
                    Add-MDLine "``````text`n$profText`n``````" $mdBuilder
                    Add-MDLine "" $mdBuilder
                }
            } else {
                $htmlbody += "<p>Firewall profile collection requires local execution or PowerShell remoting. Skipping for remote computer.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _Firewall profile collection requires local execution. Skipped for remote computer._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
        }
        catch {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        # Enabled Firewall Rules
        $subhead = "<h3>Firewall Rules (Enabled)</h3>"
        $htmlbody += $subhead
        Add-MDSection "Firewall Rules (Enabled Inbound/Outbound)" $mdBuilder
 
        Write-Verbose "Collecting Enabled Firewall Rules"
        
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
                    $rules = Get-NetFirewallRule -Enabled True
                    $rows = foreach($r in $rules){
                        $pf = $null; $af = $null
                        try { $pf = ($r | Get-NetFirewallPortFilter) } catch {}
                        try { $af = ($r | Get-NetFirewallAddressFilter) } catch {}
                        [pscustomobject]@{
                          Display    = $r.DisplayName
                          Direction  = $r.Direction
                          Action     = $r.Action
                          Profile    = $r.Profile
                          Protocol   = if($pf){ $pf.Protocol } else { '' }
                          LocalPort  = if($pf){ ($pf.LocalPort -join ',') } else { '' }
                          RemotePort = if($pf){ ($pf.RemotePort -join ',') } else { '' }
                          LocalAddr  = if($af){ ($af.LocalAddress -join ',') } else { '' }
                          RemoteAddr = if($af){ ($af.RemoteAddress -join ',') } else { '' }
                        }
                    }
                    
                    $htmlbody += $rows | ConvertTo-Html -Fragment
                    $htmlbody += $spacer
                    Emit-MDTable $rows @('Display','Direction','Action','Profile','Protocol','LocalPort','RemotePort','LocalAddr','RemoteAddr') $mdBuilder
                } else {
                    $txt = & netsh advfirewall firewall show rule name=all 2>$null
                    $htmlbody += "<pre>$txt</pre>"
                    $htmlbody += $spacer
                    Add-MDLine "``````text`n$txt`n``````" $mdBuilder
                    Add-MDLine "" $mdBuilder
                }
            } else {
                $htmlbody += "<p>Firewall rules collection requires local execution or PowerShell remoting. Skipping for remote computer.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _Firewall rules collection requires local execution. Skipped for remote computer._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
        }
        catch {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        # Disabled Firewall Rules
        $subhead = "<h3>Firewall Rules (Disabled - for reference)</h3>"
        $htmlbody += $subhead
        Add-MDSection "Firewall Rules (Disabled - for reference)" $mdBuilder
 
        Write-Verbose "Collecting Disabled Firewall Rules"
        
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
                    $disabledRules = Get-NetFirewallRule -Enabled False
                    $disabledRows = foreach($r in $disabledRules){
                        $pf = $null; $af = $null
                        try { $pf = ($r | Get-NetFirewallPortFilter) } catch {}
                        try { $af = ($r | Get-NetFirewallAddressFilter) } catch {}
                        [pscustomobject]@{
                          Display    = $r.DisplayName
                          Direction  = $r.Direction
                          Action     = $r.Action
                          Profile    = $r.Profile
                          Protocol   = if($pf){ $pf.Protocol } else { '' }
                          LocalPort  = if($pf){ ($pf.LocalPort -join ',') } else { '' }
                          RemotePort = if($pf){ ($pf.RemotePort -join ',') } else { '' }
                        }
                    }
                    
                    if ($disabledRows.Count -gt 100) {
                        $htmlbody += "<p>Too many disabled rules ($($disabledRows.Count)). Showing first 100.</p>"
                        $htmlbody += ($disabledRows | Select-Object -First 100) | ConvertTo-Html -Fragment
                        $htmlbody += $spacer
                        Add-MDLine "> _Too many disabled rules ($($disabledRows.Count)). Showing first 100._" $mdBuilder
                        Emit-MDTable ($disabledRows | Select-Object -First 100) @('Display','Direction','Action','Profile','Protocol','LocalPort','RemotePort') $mdBuilder
                    } elseif ($disabledRows.Count -gt 0) {
                        $htmlbody += $disabledRows | ConvertTo-Html -Fragment
                        $htmlbody += $spacer
                        Emit-MDTable $disabledRows @('Display','Direction','Action','Profile','Protocol','LocalPort','RemotePort') $mdBuilder
                    } else {
                        $htmlbody += "<p>No disabled firewall rules found.</p>"
                        $htmlbody += $spacer
                        Add-MDLine "> _No disabled firewall rules found._" $mdBuilder
                        Add-MDLine "" $mdBuilder
                    }
                }
            } else {
                $htmlbody += "<p>Firewall rules collection requires local execution or PowerShell remoting. Skipping for remote computer.</p>"
                $htmlbody += $spacer
                Add-MDLine "> _Firewall rules collection requires local execution. Skipped for remote computer._" $mdBuilder
                Add-MDLine "" $mdBuilder
            }
        }
        catch {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
            Add-MDLine "> _Error: $($_.Exception.Message)_" $mdBuilder
            Add-MDLine "" $mdBuilder
        }

        #---------------------------------------------------------------------
        # Generate the reports and output to file(s)
        #---------------------------------------------------------------------
	
        Write-Verbose "Producing reports"
    
        # Generate HTML report if requested
        if ($OutputFormat -eq 'HTML' -or $OutputFormat -eq 'Both') {
            #Common HTML head and styles
            $htmlhead="<html>
				    <style>
				    BODY{font-family: Arial; font-size: 8pt;}
				    H1{font-size: 20px;}
				    H2{font-size: 18px;}
				    H3{font-size: 16px;}
				    TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				    TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
				    TD{border: 1px solid black; padding: 5px; }
				    td.pass{background: #7FFF00;}
				    td.warn{background: #FFE600;}
				    td.fail{background: #FF0000; color: #ffffff;}
				    td.info{background: #85D4FF;}
				    </style>
				    <body>
				    <h1 align=""center"">Server Info: $ComputerName</h1>
				    <h3 align=""center"">Generated: $reportime</h3>"

            $htmltail = "</body>
			    </html>"

            $htmlreport = $htmlhead + $htmlbody + $htmltail

            $htmlreport | Out-File $htmlfile -Encoding Utf8
            Write-Verbose "HTML report written to $htmlfile"
            if (!($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent))
            {
                Write-Host "HTML report written to $htmlfile"
            }
        }
        
        # Generate Markdown report if requested
        if ($OutputFormat -eq 'Markdown' -or $OutputFormat -eq 'Both') {
            Add-MDLine "" $mdBuilder
            Add-MDLine "---" $mdBuilder
            Add-MDLine "> End of report for **$ComputerName**" $mdBuilder
            
            $mdBuilder.ToString() | Out-File $mdfile -Encoding Utf8
            Write-Verbose "Markdown report written to $mdfile"
            if (!($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent))
            {
                Write-Host "Markdown report written to $mdfile"
            }
        }
    }

}

End
{
    #Wrap it up
    Write-Verbose "=====> Finished <====="
}