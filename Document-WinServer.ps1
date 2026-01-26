
<# 
.SYNOPSIS
  Remote-capable documentation generator for (air-gapped) Windows Servers.

.DESCRIPTION
  Collects:
    - Installed software (registry-based)
    - Local users & groups; service logon accounts
    - SMB shares & ACLs
    - OS & kernel (ntoskrnl) version/build
    - Installed security updates
    - Missing security patches (offline scan via wsusscn2.cab)
    - Windows Update history (WUA COM)
    - NTP peers/config/status (w32tm)
    - Windows Server Features and Roles (with details)
    - Local Security Policy export + INF parsing:
        * System Access
        * Event Audit
        * Privilege Rights (User Rights Assignments)
        * Registry Values
        * Account Policies
        * Security Options
    - Firewall:
        * Profiles (Domain/Private/Public)
        * Enabled inbound/outbound rules with action, protocol, ports, addresses
        * Disabled rules (for documentation purposes)
        * Fallback: netsh text capture if NetSecurity cmdlets unavailable

.OUTPUTS
  Markdown and/or HTML saved to <ComputerName>-system-report.[md|html] in -OutputDir on the local machine.

.PARAMETER ComputerName
  Target computer (defaults to local host). When remote, code runs on the target and returns the report text.

.PARAMETER Credential
  Optional PSCredential for remote connection.

.PARAMETER WsusCabPath
  Optional path to wsusscn2.cab on the target machine (for offline missing update scan).

.PARAMETER OutputDir
  Local directory to save the report. Defaults to current directory.

.PARAMETER IncludeAdminShares
  Include administrative shares (C$, ADMIN$, etc.) in SMB section.

.PARAMETER OutputFormat
  Output format: 'Markdown', 'HTML', or 'Both'. Defaults to 'Both'.

.EXAMPLE
  # Remote, with offline missing updates (CAB is on the remote server)
  .\Document-WinServer.ps1 -ComputerName SRV-FNB-01 -Credential (Get-Credential) -WsusCabPath 'C:\Temp\wsusscn2.cab' -Verbose

.EXAMPLE
  # Local server with HTML output only
  .\Document-WinServer.ps1 -OutputFormat HTML
#>

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$WsusCabPath,
    [string]$OutputDir = (Get-Location).Path,
    [switch]$IncludeAdminShares,
    [ValidateSet('Markdown','HTML','Both')]
    [string]$OutputFormat = 'Both'
)

#-------------------------------------------------------------------------------------
# Orchestrator: runs a collector on the local or remote machine and writes the output file(s)
#-------------------------------------------------------------------------------------
$MarkdownPath = Join-Path $OutputDir "$ComputerName-system-report.md"
$HtmlPath = Join-Path $OutputDir "$ComputerName-system-report.html"

$collector = {
param($WsusCabPath, $IncludeAdminShares)

#-------------------------
# Check elevation
#-------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

#-------------------------
# Markdown helpers
#-------------------------
$Computer = $env:COMPUTERNAME
$md = New-Object System.Text.StringBuilder
function Add-MD([string]$s){ [void]$md.AppendLine($s) }
function Add-Section([string]$Title){ Add-MD ""; Add-MD "## $Title"; Add-MD "" }

function Emit-Table([object[]]$Data,[string[]]$Cols){
  if(-not $Data -or $Data.Count -eq 0){ Add-MD "> _No data found_"; Add-MD ""; return }
  Add-MD ('| ' + ($Cols -join ' | ') + ' |')
  Add-MD ('| ' + (($Cols | ForEach-Object{'---'}) -join ' | ') + ' |')
  foreach($row in $Data){
    $cells = foreach($c in $Cols){
      $v = $row.$c
      if($v -is [DateTime]){ $v = $v.ToString('yyyy-MM-dd HH:mm') }
      ($v -as [string]).Replace('|','`\|').Replace("`r`n",' ').Replace("`n",' ')
    }
    Add-MD ('| ' + ($cells -join ' | ') + ' |')
  }
  Add-MD ""
}

Add-MD "# $Computer — System Documentation"
Add-MD "> Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
Add-MD "> Elevated: $IsAdmin"
Add-MD ""

#-------------------------
# OS & Kernel
#-------------------------
Add-Section "OS and Kernel Version"
try { $os = Get-CimInstance Win32_OperatingSystem } catch { $os = Get-WmiObject Win32_OperatingSystem }
$kernelVer = try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:windir\System32\ntoskrnl.exe").ProductVersion } catch { $null }
Emit-Table @([pscustomobject]@{
  OSCaption = $os.Caption; OSVersion = $os.Version; OSBuild = $os.BuildNumber
  OSArch = $os.OSArchitecture; KernelProductVersion = $kernelVer
}) @('OSCaption','OSVersion','OSBuild','OSArch','KernelProductVersion')

#-------------------------
# Windows Server Features and Roles
#-------------------------
Add-Section "Windows Server Features and Roles"
try {
  # Try using Get-WindowsFeature (Server 2008 R2+)
  if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    $features = Get-WindowsFeature | Where-Object { $_.Installed -eq $true }
    $featureData = foreach($f in $features){
      [pscustomobject]@{
        Name = $f.Name
        DisplayName = $f.DisplayName
        FeatureType = $f.FeatureType
        Path = $f.Path
        Depth = $f.Depth
        DependsOn = if($f.DependsOn) { ($f.DependsOn -join ', ') } else { '' }
      }
    }
    if ($featureData.Count -gt 0) {
      Emit-Table $featureData @('DisplayName','Name','FeatureType','Path','DependsOn')
    } else {
      Add-MD "> _No installed features found._"
    }
    
    # Role-specific details
    Add-Section "Installed Role Details"
    $roles = $features | Where-Object { $_.FeatureType -eq 'Role' }
    if ($roles.Count -gt 0) {
      foreach($role in $roles){
        Add-MD "### $($role.DisplayName)"
        Add-MD ""
        Add-MD "- **Name**: $($role.Name)"
        Add-MD "- **Feature Type**: $($role.FeatureType)"
        Add-MD "- **Installation State**: $($role.InstallState)"
        if ($role.DependsOn) {
          Add-MD "- **Dependencies**: $($role.DependsOn -join ', ')"
        }
        
        # Get role services (sub-features)
        $roleServices = $features | Where-Object { $_.Path -like "*$($role.Name)*" -and $_.Name -ne $role.Name }
        if ($roleServices.Count -gt 0) {
          Add-MD "- **Role Services**:"
          foreach($rs in $roleServices){
            Add-MD "  - $($rs.DisplayName) ($($rs.Name))"
          }
        }
        Add-MD ""
      }
    } else {
      Add-MD "> _No roles installed on this server._"
    }
  } else {
    # Fallback for systems without Get-WindowsFeature (unlikely for Server 2016+)
    Add-MD "> _Get-WindowsFeature cmdlet not available. Server may not be running Server OS with ServerManager module._"
  }
} catch {
  Add-MD "> _Feature collection failed: $($_.Exception.Message)_"
}

#-------------------------
# Installed Software (registry)
#-------------------------
Add-Section "Installed Software"
function Get-InstalledSoftware {
  $paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  $paths | ForEach-Object {
    Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue
  } | Where-Object {
    $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ReleaseType -and -not $_.ParentKeyName
  } | Select-Object @{n='Name';e={$_.DisplayName}},
                    @{n='Version';e={$_.DisplayVersion}},
                    @{n='Publisher';e={$_.Publisher}},
                    @{n='InstallDate';e={
                        if ($_.InstallDate -match '^\d{8}$') { [datetime]::ParseExact($_.InstallDate,'yyyyMMdd',$null) } else { $null }
                    }},
                    @{n='InstallLocation';e={$_.InstallLocation}}
}
$sw = Get-InstalledSoftware | Sort-Object Name
Emit-Table $sw @('Name','Version','Publisher','InstallDate','InstallLocation')

#-------------------------
# Local users & groups + service accounts
#-------------------------
Add-Section "Local Users"
function Get-LocalUsersSafe {
  try { Get-LocalUser -ErrorAction Stop }
  catch {
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | Where-Object {$_.SchemaClassName -eq 'user'} | ForEach-Object {
      [pscustomobject]@{ Name=$_.Name; Enabled=$true; SID=$_.objectSID; Description=$_.Description }
    }
  }
}
Emit-Table (Get-LocalUsersSafe | Select-Object Name,Enabled,SID,Description) @('Name','Enabled','SID','Description')

Add-Section "Local Groups and Memberships"
function Get-LocalGroupsSafe {
  try { Get-LocalGroup } catch {
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | Where-Object {$_.SchemaClassName -eq 'group'} | ForEach-Object { [pscustomobject]@{ Name = $_.Name } }
  }
}
$groups = Get-LocalGroupsSafe
$gm = foreach($g in $groups){
  try { $members = Get-LocalGroupMember -Name $g.Name | Select-Object -ExpandProperty Name }
  catch {
    $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$($g.Name),group"
    $members = $grp.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null) }
  }
  [pscustomobject]@{ Group=$g.Name; Members=($members -join ', ') }
}
Emit-Table $gm @('Group','Members')

Add-Section "Service Accounts (Service Logon Accounts)"
$svc = try { Get-CimInstance Win32_Service } catch { Get-WmiObject Win32_Service }
Emit-Table ($svc | Select-Object Name,DisplayName,State,StartMode,StartName,PathName) @('Name','DisplayName','State','StartMode','StartName','PathName')

Add-Section "Unique Accounts Used by Services"
$accounts = $svc | Group-Object StartName | ForEach-Object {
  [pscustomobject]@{ Account = $_.Name; Services = ($_.Group | Select-Object -Expand Name -join ', ') }
}
Emit-Table $accounts @('Account','Services')

#-------------------------
# SMB Shares & ACLs
#-------------------------
Add-Section "SMB Shares"
try {
  $shares = Get-SmbShare | Where-Object { $IncludeAdminShares -or ($_.Special -ne $true -and $_.Name -notmatch '^\$') }
  Emit-Table ($shares | Select-Object Name,Path,Description,EncryptData,ConcurrentUserLimit) @('Name','Path','Description','EncryptData','ConcurrentUserLimit')

  Add-Section "SMB Share ACLs"
  $aclRows = foreach($s in $shares){
    Get-SmbShareAccess -Name $s.Name | ForEach-Object {
      [pscustomobject]@{ Share=$s.Name; Account=$_.AccountName; Access=$_.AccessRight; Type=$_.AccessControlType }
    }
  }
  Emit-Table $aclRows @('Share','Account','Access','Type')
} catch {
  $shares = Get-WmiObject -Class Win32_Share
  Emit-Table ($shares | Select-Object Name,Path,Description,Type) @('Name','Path','Description','Type')
}

#-------------------------
# Windows Time (NTP)
#-------------------------
Add-Section "Windows Time (NTP) Configuration"
$conf   = & w32tm /query /configuration 2>$null
Add-MD "````text`n$conf`n````"

Add-Section "Windows Time Peers"
$peers  = & w32tm /query /peers 2>$null
Add-MD "````text`n$peers`n````"

Add-Section "Windows Time Status"
$status = & w32tm /query /status 2>$null
Add-MD "````text`n$status`n````"

#-------------------------
# Local Security Policy export + INF parsing
#-------------------------
Add-Section "Local Security Policy Export (secedit)"
$tempInf = Join-Path $env:TEMP "$Computer-security-policy.inf"
try { & secedit.exe /export /mergedpolicy /cfg "$tempInf" | Out-Null } catch {}
if (!(Test-Path $tempInf)) { Add-MD "> _Export failed or unavailable._" }
else {
  Add-MD "> Export file: $tempInf"
  $infLines = Get-Content -Path $tempInf -ErrorAction SilentlyContinue

  function Get-InfSection([string[]]$Lines,[string]$SectionName){
    $start = ($Lines | Select-String -SimpleMatch "[${SectionName}]").LineNumber
    if(-not $start){ return @() }
    $rest = $Lines[$start..($Lines.Length-1)]
    $end = ($rest | Select-String -Pattern "^\[.+\]" -SimpleMatch | Select-Object -First 1).LineNumber
    if($end){ $rest[1..($end-2)] } else { $rest[1..($rest.Length-1)] }
  }

  # System Access
  Add-Section "Security Template — [System Access]"
  $sysAccess = Get-InfSection $infLines 'System Access' | Where-Object { $_ -match '=' } |
    ForEach-Object {
      $kv = $_ -split '=',2
      [pscustomobject]@{ Setting = $kv[0].Trim(); Value = $kv[1].Trim() }
    }
  Emit-Table $sysAccess @('Setting','Value')

  # Event Audit
  Add-Section "Security Template — [Event Audit]"
  $eventAudit = Get-InfSection $infLines 'Event Audit' | Where-Object { $_ -match '=' } |
    ForEach-Object {
      $kv = $_ -split '=',2
      [pscustomobject]@{ Category = $kv[0].Trim(); Setting = $kv[1].Trim() }
    }
  Emit-Table $eventAudit @('Category','Setting')

  # Privilege Rights (User Rights Assignments)
  Add-Section "Security Template — [Privilege Rights] (User Rights Assignments)"
  $privRights = Get-InfSection $infLines 'Privilege Rights' | Where-Object { $_ -match '=' } |
    ForEach-Object {
      $kv = $_ -split '=',2
      $principals = ($kv[1] -split ',') | ForEach-Object { $_.Trim() }
      [pscustomobject]@{ Right = $kv[0].Trim(); Principals = ($principals -join ', ') }
    }
  Emit-Table $privRights @('Right','Principals')

  # Registry Values (raw view)
  Add-Section "Security Template — [Registry Values] (raw)"
  $regVals = Get-InfSection $infLines 'Registry Values' | Where-Object { $_ -match '=' } |
    ForEach-Object {
      $kv = $_ -split '=',2
      [pscustomobject]@{ Key = $kv[0].Trim(); Raw = $kv[1].Trim() }
    }
  Emit-Table $regVals @('Key','Raw')

  # Service General Setting (if present)
  Add-Section "Security Template — [Service General Setting] (if present)"
  $svcGeneral = Get-InfSection $infLines 'Service General Setting' | Where-Object { $_ -match '=' } |
    ForEach-Object {
      $kv = $_ -split '=',2
      [pscustomobject]@{ Service = $kv[0].Trim(); Setting = $kv[1].Trim() }
    }
  if ($svcGeneral.Count -gt 0) {
    Emit-Table $svcGeneral @('Service','Setting')
  } else {
    Add-MD "> _No service general settings found._"
  }
}

#-------------------------
# Audit Policy (auditpol)
#-------------------------
Add-Section "Audit Policy (auditpol /get /category:*)"
$audit = & auditpol /get /category:* 2>$null
Add-MD "````text`n$audit`n````"

#-------------------------
# Additional Security Settings
#-------------------------
Add-Section "Local Security Options (Additional)"
try {
  # Network security settings
  Add-MD "### Network Security Settings"
  $netSecSettings = @(
    [pscustomobject]@{
      Setting = 'LAN Manager authentication level'
      Registry = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
      Value = try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel } catch { 'N/A' }
    },
    [pscustomobject]@{
      Setting = 'Minimum session security for NTLM SSP (clients)'
      Registry = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec'
      Value = try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinClientSec' -ErrorAction SilentlyContinue).NTLMMinClientSec } catch { 'N/A' }
    },
    [pscustomobject]@{
      Setting = 'Minimum session security for NTLM SSP (servers)'
      Registry = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec'
      Value = try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -ErrorAction SilentlyContinue).NTLMMinServerSec } catch { 'N/A' }
    }
  )
  Emit-Table $netSecSettings @('Setting','Registry','Value')
  
  Add-MD "### Account Lockout Settings"
  $accountLockout = @(
    [pscustomobject]@{
      Setting = 'Account lockout duration'
      Command = 'net accounts'
      Value = try { $netAccounts = net accounts 2>$null; ($netAccounts | Select-String 'Lockout duration' | Out-String).Trim() } catch { 'N/A' }
    },
    [pscustomobject]@{
      Setting = 'Account lockout threshold'
      Command = 'net accounts'
      Value = try { $netAccounts = net accounts 2>$null; ($netAccounts | Select-String 'Lockout threshold' | Out-String).Trim() } catch { 'N/A' }
    },
    [pscustomobject]@{
      Setting = 'Reset account lockout counter after'
      Command = 'net accounts'
      Value = try { $netAccounts = net accounts 2>$null; ($netAccounts | Select-String 'Lockout observation window' | Out-String).Trim() } catch { 'N/A' }
    }
  )
  Emit-Table $accountLockout @('Setting','Value')
  
  Add-MD "### Password Policy"
  $pwdPolicy = @(
    [pscustomobject]@{
      Setting = 'Minimum password length'
      Value = try { $netAccounts = net accounts 2>$null; ($netAccounts | Select-String 'Minimum password length' | Out-String).Trim() } catch { 'N/A' }
    },
    [pscustomobject]@{
      Setting = 'Maximum password age'
      Value = try { $netAccounts = net accounts 2>$null; ($netAccounts | Select-String 'Maximum password age' | Out-String).Trim() } catch { 'N/A' }
    },
    [pscustomobject]@{
      Setting = 'Minimum password age'
      Value = try { $netAccounts = net accounts 2>$null; ($netAccounts | Select-String 'Minimum password age' | Out-String).Trim() } catch { 'N/A' }
    },
    [pscustomobject]@{
      Setting = 'Password history length'
      Value = try { $netAccounts = net accounts 2>$null; ($netAccounts | Select-String 'Length of password history' | Out-String).Trim() } catch { 'N/A' }
    }
  )
  Emit-Table $pwdPolicy @('Setting','Value')
} catch {
  Add-MD "> _Additional security settings collection failed: $($_.Exception.Message)_"
}

#-------------------------
# Installed HotFixes
#-------------------------
Add-Section "Installed Security Updates (HotFixes)"
try {
  $hf = Get-HotFix | Sort-Object InstalledOn
  Emit-Table ($hf | Select-Object HotFixID, Description, InstalledOn, InstalledBy) @('HotFixID','Description','InstalledOn','InstalledBy')
} catch {
  Add-MD "> _Get-HotFix failed (permission or OS issue)._"
}

#-------------------------
# Missing security patches (offline via wsusscn2.cab)
#-------------------------
Add-Section "Missing Security Patches (Offline Scan via wsusscn2.cab)"
if ($WsusCabPath -and (Test-Path $WsusCabPath)) {
  try {
    $UpdateSession        = New-Object -ComObject Microsoft.Update.Session
    $UpdateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
    $UpdateService        = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", $WsusCabPath, 1)
    $Searcher                          = $UpdateSession.CreateUpdateSearcher()
    $Searcher.ServerSelection           = 3    # ssOthers
    $Searcher.ServiceID                 = $UpdateService.ServiceID.ToString()
    $Searcher.IncludePotentiallySupersededUpdates = $true
    $SearchResult = $Searcher.Search("IsInstalled=0 and Type='Software'")
    $updates = for ($i=0; $i -lt $SearchResult.Updates.Count; $i++){
      $u = $SearchResult.Updates.Item($i)
      [pscustomobject]@{
        Title      = $u.Title
        KB         = ($u.KBArticleIDs -join ',')
        Severity   = $u.MsrcSeverity
        Categories = ($u.Categories | Select-Object -ExpandProperty Name -join ',')
      }
    }
    if ($updates.Count -eq 0) { Add-MD "> _No applicable missing updates found with the provided catalog._" }
    else { Emit-Table $updates @('Title','KB','Severity','Categories') }
  } catch { Add-MD "> _Offline scan error: $($_.Exception.Message)_"}
} else {
  Add-MD "> _Offline missing updates scan skipped. Provide -WsusCabPath (remote path) to enable._"
}

#-------------------------
# Windows Update history (WUA COM)
#-------------------------
Add-Section "Windows Update History"
function Convert-WuaResultCodeToName([int]$ResultCode){
  switch($ResultCode){ 2{'Succeeded'}; 3{'Succeeded With Errors'}; 4{'Failed'} default{$ResultCode} }
}
try {
  $session = New-Object -ComObject 'Microsoft.Update.Session'
  $entries = $session.QueryHistory("",0,5000)
  $hist = foreach($e in $entries){
    [pscustomobject]@{
      Date      = ([datetime]$e.Date)
      Title     = $e.Title
      Operation = $e.Operation
      Result    = (Convert-WuaResultCodeToName -ResultCode $e.ResultCode)
      UpdateId  = $e.UpdateIdentity.UpdateId
    }
  }
  Emit-Table ($hist | Sort-Object Date) @('Date','Title','Operation','Result','UpdateId')
} catch {
  Add-MD "> _Windows Update history collection failed: $($_.Exception.Message)_"
}

#-------------------------
# Firewall
#-------------------------
Add-Section "Firewall Profiles"
try {
  $profiles = Get-NetFirewallProfile
  Emit-Table ($profiles | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen) `
            @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction','NotifyOnListen')
} catch {
  $profText = & netsh advfirewall show allprofiles 2>$null
  Add-MD "````text`n$profText`n````"
}

Add-Section "Firewall Rules (Enabled Inbound/Outbound)"
if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue){
  $rules = Get-NetFirewallRule -Enabled True | Select-Object Name,DisplayName,Direction,Action,Profile,Enabled
  $rows = foreach($r in $rules){
    $pf = $null; $af = $null
    try { $pf = ($r | Get-NetFirewallPortFilter) } catch {}
    try { $af = ($r | Get-NetFirewallAddressFilter) } catch {}
    [pscustomobject]@{
      Name       = $r.Name
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
  Emit-Table $rows @('Display','Direction','Action','Profile','Protocol','LocalPort','RemotePort','LocalAddr','RemoteAddr')
  
  Add-Section "Firewall Rules (Disabled - for reference)"
  $disabledRules = Get-NetFirewallRule -Enabled False | Select-Object Name,DisplayName,Direction,Action,Profile,Enabled
  $disabledRows = foreach($r in $disabledRules){
    $pf = $null; $af = $null
    try { $pf = ($r | Get-NetFirewallPortFilter) } catch {}
    try { $af = ($r | Get-NetFirewallAddressFilter) } catch {}
    [pscustomobject]@{
      Name       = $r.Name
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
    Add-MD "> _Too many disabled rules ($($disabledRows.Count)). Showing first 100._"
    Emit-Table ($disabledRows | Select-Object -First 100) @('Display','Direction','Action','Profile','Protocol','LocalPort','RemotePort')
  } elseif ($disabledRows.Count -gt 0) {
    Emit-Table $disabledRows @('Display','Direction','Action','Profile','Protocol','LocalPort','RemotePort')
  } else {
    Add-MD "> _No disabled firewall rules found._"
  }
} else {
  $txt = & netsh advfirewall firewall show rule name=all 2>$null
  Add-MD "````text`n$txt`n````"
}

Add-MD ""
Add-MD "---"
Add-MD "> End of report for **$Computer**"
return $md.ToString()
} # end collector

#-------------------------
# Convert Markdown to HTML
#-------------------------
function ConvertTo-Html {
    param([string]$MarkdownText, [string]$ComputerName)
    
    $css = @"
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; color: #333; }
h1 { color: #0066cc; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
h2 { color: #0099cc; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; margin-top: 30px; }
h3 { color: #00aacc; margin-top: 20px; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
th { background-color: #0066cc; color: white; padding: 12px; text-align: left; font-weight: 600; }
td { padding: 10px; border-bottom: 1px solid #e0e0e0; }
tr:hover { background-color: #f0f8ff; }
tr:last-child td { border-bottom: none; }
pre { background-color: #f4f4f4; border: 1px solid #ddd; border-left: 3px solid #0066cc; padding: 15px; overflow-x: auto; }
code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', 'Monaco', monospace; }
blockquote { border-left: 4px solid #0066cc; padding-left: 15px; margin-left: 0; color: #666; font-style: italic; }
.container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
.header { background: linear-gradient(135deg, #0066cc 0%, #00aacc 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; }
.header h1 { color: white; border: none; margin: 0; }
.metadata { background-color: #f9f9f9; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
</style>
"@
    
    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<!DOCTYPE html>')
    [void]$html.AppendLine('<html lang="en">')
    [void]$html.AppendLine('<head>')
    [void]$html.AppendLine('<meta charset="UTF-8">')
    [void]$html.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    [void]$html.AppendLine("<title>$ComputerName - System Documentation</title>")
    [void]$html.AppendLine($css)
    [void]$html.AppendLine('</head>')
    [void]$html.AppendLine('<body>')
    [void]$html.AppendLine('<div class="container">')
    
    # Simple Markdown to HTML conversion
    $lines = $MarkdownText -split "`n"
    $inTable = $false
    $inCodeBlock = $false
    $tableHeaders = @()
    
    foreach($line in $lines){
        $line = $line.TrimEnd()
        
        # Code blocks
        if ($line -match '^````') {
            if ($inCodeBlock) {
                [void]$html.AppendLine('</code></pre>')
                $inCodeBlock = $false
            } else {
                [void]$html.AppendLine('<pre><code>')
                $inCodeBlock = $true
            }
            continue
        }
        
        if ($inCodeBlock) {
            $escaped = [System.Net.WebUtility]::HtmlEncode($line)
            [void]$html.AppendLine($escaped)
            continue
        }
        
        # Headers
        if ($line -match '^# (.+)') {
            if ($matches[1] -match '—') {
                [void]$html.AppendLine('<div class="header">')
                [void]$html.AppendLine("<h1>$($matches[1])</h1>")
                [void]$html.AppendLine('</div>')
            } else {
                [void]$html.AppendLine("<h1>$($matches[1])</h1>")
            }
            continue
        }
        if ($line -match '^## (.+)') {
            if ($inTable) { [void]$html.AppendLine('</table>'); $inTable = $false }
            [void]$html.AppendLine("<h2>$($matches[1])</h2>")
            continue
        }
        if ($line -match '^### (.+)') {
            if ($inTable) { [void]$html.AppendLine('</table>'); $inTable = $false }
            [void]$html.AppendLine("<h3>$($matches[1])</h3>")
            continue
        }
        
        # Blockquotes
        if ($line -match '^> (.+)') {
            if ($inTable) { [void]$html.AppendLine('</table>'); $inTable = $false }
            $content = $matches[1]
            if ($content -match 'Generated:|Elevated:') {
                [void]$html.AppendLine('<div class="metadata">')
                [void]$html.AppendLine("<p>$content</p>")
                [void]$html.AppendLine('</div>')
            } else {
                [void]$html.AppendLine("<blockquote>$content</blockquote>")
            }
            continue
        }
        
        # Tables
        if ($line -match '^\|(.+)\|$') {
            $cells = ($line -split '\|' | Where-Object { $_ }) | ForEach-Object { $_.Trim() }
            
            if ($line -match '^[\|\s\-]+$') {
                # Table separator - start table body
                [void]$html.AppendLine('<tbody>')
                continue
            }
            
            if (-not $inTable) {
                # Table header
                [void]$html.AppendLine('<table>')
                [void]$html.AppendLine('<thead><tr>')
                $tableHeaders = $cells
                foreach($cell in $cells){
                    [void]$html.AppendLine("<th>$cell</th>")
                }
                [void]$html.AppendLine('</tr></thead>')
                $inTable = $true
            } else {
                # Table row
                [void]$html.AppendLine('<tr>')
                foreach($cell in $cells){
                    $escaped = [System.Net.WebUtility]::HtmlEncode($cell)
                    [void]$html.AppendLine("<td>$escaped</td>")
                }
                [void]$html.AppendLine('</tr>')
            }
            continue
        } else {
            if ($inTable) {
                [void]$html.AppendLine('</tbody></table>')
                $inTable = $false
            }
        }
        
        # Lists
        if ($line -match '^[\s]*- (.+)') {
            [void]$html.AppendLine("<li>$($matches[1])</li>")
            continue
        }
        
        # Horizontal rules
        if ($line -match '^---+$') {
            [void]$html.AppendLine('<hr/>')
            continue
        }
        
        # Bold text
        $line = $line -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'
        
        # Regular paragraphs
        if ($line.Trim() -ne '') {
            [void]$html.AppendLine("<p>$line</p>")
        }
    }
    
    if ($inTable) { [void]$html.AppendLine('</tbody></table>') }
    if ($inCodeBlock) { [void]$html.AppendLine('</code></pre>') }
    
    [void]$html.AppendLine('</div>')
    [void]$html.AppendLine('</body>')
    [void]$html.AppendLine('</html>')
    
    return $html.ToString()
}

#-------------------------
# Local or remote exec
#-------------------------
if ($ComputerName -eq $env:COMPUTERNAME) {
    $mdText = & $collector $WsusCabPath $IncludeAdminShares
    
    # Save Markdown
    if ($OutputFormat -eq 'Markdown' -or $OutputFormat -eq 'Both') {
        Set-Content -Path $MarkdownPath -Value $mdText -Encoding UTF8
        Write-Host "Markdown report written: $MarkdownPath"
    }
    
    # Save HTML
    if ($OutputFormat -eq 'HTML' -or $OutputFormat -eq 'Both') {
        $htmlText = ConvertTo-Html -MarkdownText $mdText -ComputerName $ComputerName
        Set-Content -Path $HtmlPath -Value $htmlText -Encoding UTF8
        Write-Host "HTML report written: $HtmlPath"
    }
} else {
    $sessParams = @{ ComputerName = $ComputerName }
    if ($Credential) { $sessParams.Credential = $Credential }
    $sess = New-PSSession @sessParams
    try {
        $mdText = Invoke-Command -Session $sess -ScriptBlock $collector -ArgumentList $WsusCabPath,$IncludeAdminShares
        
        # Save Markdown
        if ($OutputFormat -eq 'Markdown' -or $OutputFormat -eq 'Both') {
            Set-Content -Path $MarkdownPath -Value $mdText -Encoding UTF8
            Write-Host "Markdown report written: $MarkdownPath"
        }
        
        # Save HTML
        if ($OutputFormat -eq 'HTML' -or $OutputFormat -eq 'Both') {
            $htmlText = ConvertTo-Html -MarkdownText $mdText -ComputerName $ComputerName
            Set-Content -Path $HtmlPath -Value $htmlText -Encoding UTF8
            Write-Host "HTML report written: $HtmlPath"
        }
    } finally {
        if ($sess) { Remove-PSSession $sess }
    }
}
