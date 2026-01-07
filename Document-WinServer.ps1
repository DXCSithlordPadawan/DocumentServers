
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
    - Local Security Policy export + INF parsing:
        * System Access
        * Event Audit
        * Privilege Rights (User Rights Assignments)
        * Registry Values
    - Firewall:
        * Profiles (Domain/Private/Public)
        * Enabled inbound/outbound rules with action, protocol, ports, addresses
        * Fallback: netsh text capture if NetSecurity cmdlets unavailable

.OUTPUTS
  Markdown saved to <ComputerName>-system-report.md in -OutputDir on the local machine.

.PARAMETER ComputerName
  Target computer (defaults to local host). When remote, code runs on the target and returns the Markdown text.

.PARAMETER Credential
  Optional PSCredential for remote connection.

.PARAMETER WsusCabPath
  Optional path to wsusscn2.cab on the target machine (for offline missing update scan).

.PARAMETER OutputDir
  Local directory to save the report. Defaults to current directory.

.PARAMETER IncludeAdminShares
  Include administrative shares (C$, ADMIN$, etc.) in SMB section.

.EXAMPLE
  # Remote, with offline missing updates (CAB is on the remote server)
  .\Document-WinServer.ps1 -ComputerName SRV-FNB-01 -Credential (Get-Credential) -WsusCabPath 'C:\Temp\wsusscn2.cab' -Verbose
#>

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$WsusCabPath,
    [string]$OutputDir = (Get-Location).Path,
    [switch]$IncludeAdminShares
)

#-------------------------------------------------------------------------------------
# Orchestrator: runs a collector on the local or remote machine and writes the .md file
#-------------------------------------------------------------------------------------
$ReportPath = Join-Path $OutputDir "$ComputerName-system-report.md"

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
  foreach($p in $paths){
    Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
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
}

#-------------------------
# Audit Policy (auditpol)
#-------------------------
Add-Section "Audit Policy (auditpol /get /category:*)"
$audit = & auditpol /get /category:* 2>$null
Add-MD "````text`n$audit`n````"

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
# Local or remote exec
#-------------------------
if ($ComputerName -eq $env:COMPUTERNAME) {
    $mdText = & $collector $WsusCabPath $IncludeAdminShares
    Set-Content -Path $ReportPath -Value $mdText -Encoding UTF8
    Write-Host "Report written: $ReportPath"
} else {
    $sessParams = @{ ComputerName = $ComputerName }
    if ($Credential) { $sessParams.Credential = $Credential }
    $sess = New-PSSession @sessParams
    try {
        $mdText = Invoke-Command -Session $sess -ScriptBlock $collector -ArgumentList $WsusCabPath,$IncludeAdminShares
        # Save locally with the remote computer's name
        Set-Content -Path $ReportPath -Value $mdText -Encoding UTF8
        Write-Host "Report written: $ReportPath"
    } finally {
        if ($sess) { Remove-PSSession $sess }
    }
}
