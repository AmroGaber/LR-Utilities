#requires -Version 5.1
<#
.SYNOPSIS
  Read-only GPO, service-account and network prerequisites audit for SIOS LifeKeeper / DataKeeper.
.DESCRIPTION
  Run locally on EACH node with the intended SIOS domain service account from an
  elevated Windows PowerShell 5.1 session. Captures Computer/User gpresult,
  merged local+domain security policy (secedit), effective user-right assignments,
  service identities and control permissions, firewall profiles/rules and optionally
  replication network evidence. Produces HTML, CSV, JSON and raw evidence.

  No GPUpdate, remote changes, service start/stop, or firewall modifications occur.
  User RSoP may be unavailable for service-only logon sessions; this is reported
  as REVIEW rather than as a GPO failure. A current token check does not prove
  that SIOS' service logon token can access a remote node.

.PARAMETER PeerNode
  Optional peer server name. Used for DNS resolution and reference.
.PARAMETER PeerReplicationIP
  Optional dedicated replication IPv4 address of the other node.
.PARAMETER LocalReplicationIP
  Optional local replication IPv4 address. Tests local IP existence and route.
.PARAMETER MirrorDriveLetters
  Optional DataKeeper mirrored volume letters (e.g. D,E). Determines target data
  port using DataKeeper's default TargetPortBase=10000 unless overridden by registry.
.PARAMETER ProtectedServices
  Service Name or Display Name for application services to be controlled by LifeKeeper.
  The script tests whether its CURRENT process token can open each for START+STOP
  rights, without actually starting or stopping the service.
.PARAMETER HeartbeatPorts
  TCP diagnostic probe ports supplied for this node pair (the name is retained
  for compatibility). Not every supplied port is necessarily a LifeKeeper
  heartbeat listener. Check the installed SIOS configuration and bindings.
.PARAMETER OutputRoot
  Output folder. Defaults to %TEMP%\SIOS-GPO-Audit.
.EXAMPLE
  .\Test-SIOS-GPOPrerequisites.ps1 `
      -PeerNode "XM01" `
      -LocalReplicationIP "10.20.30.11" `
      -PeerReplicationIP "192.168.1.11" `
      -MirrorDriveLetters D,L,S `
      -HeartbeatPorts 81,82,1500,1510,3278,2379,9999,10003,10011,10018 `
      -ProtectedServices "MSSQLSERVER","SQLSERVERAGENT"
.NOTES
  Supported design reference (validate for installed versions):
  SIOS DataKeeper: https://docs.us.sios.com/WindowsSPS/8.6/SPS4W/AllTechDocs/Content/DataKeeper/Installation/DataKeeper_Service_Log_On_ID_and_Password_Selection.htm
  SIOS current registry/ports: https://docs.us.sios.com/dkse/8.10.1/en/topic/registry-entries
  Microsoft gpresult: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult
  Microsoft secedit: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export
  Microsoft service access: https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
#>
[CmdletBinding()]
param(
    [string]$PeerNode,
    [string]$PeerReplicationIP,
    [string]$LocalReplicationIP,
    [ValidatePattern('^[A-Za-z]$')][string[]]$MirrorDriveLetters = @(),
    [string[]]$ProtectedServices = @(),
    [ValidateRange(1,65535)][int[]]$HeartbeatPorts = @(1500,1510),
    [string]$OutputRoot = (Join-Path ([System.IO.Path]::GetTempPath()) 'SIOS-GPO-Audit')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Now = Get-Date
$script:RunID = '{0}-{1}' -f $env:COMPUTERNAME, $script:Now.ToString('yyyyMMdd-HHmmss')
$script:Dir = Join-Path $OutputRoot $script:RunID
New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
$script:LogFile = Join-Path $script:Dir 'Audit.log'
$script:Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$script:Account = $script:Identity.Name
$script:SidSet = @{}
$script:SidSet[$script:Identity.User.Value.ToUpperInvariant()] = $true
foreach ($g in $script:Identity.Groups) { $script:SidSet[$g.Value.ToUpperInvariant()] = $true }
$script:WinPrincipal = [System.Security.Principal.WindowsPrincipal]::new($script:Identity)
$script:IsElevated = $script:WinPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

function Write-AuditLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
}
function Add-Finding {
    param(
        [string]$Id, [ValidateSet('BLOCKER','WARN','REVIEW','PASS','INFO')][string]$Status,
        [string]$Scope, [string]$Title, [string]$Evidence, [string]$Recommendation
    )
    $script:Findings.Add([pscustomobject]@{
        ID=$Id; Status=$Status; Scope=$Scope; Check=$Title;
        Evidence=$Evidence; Recommendation=$Recommendation
    })
    Write-AuditLog ("$Id [$Status] $Title - $Evidence") 'CHECK'
}
function Save-Text {
    param([string]$FileName, [object]$Text)
    $path = Join-Path $script:Dir $FileName
    $Text | Out-File -LiteralPath $path -Encoding UTF8 -Width 4096
    return $path
}
function ConvertTo-SidOrNull {
    param([string]$Principal)
    $p = $Principal.Trim().TrimStart('*').Trim('"')
    if (-not $p) { return $null }
    if ($p -match '^S-1-') { return $p.ToUpperInvariant() }
    try { return ([System.Security.Principal.NTAccount]::new($p)).Translate([System.Security.Principal.SecurityIdentifier]).Value.ToUpperInvariant() }
    catch { return $null }
}
function Get-RightEvaluation {
    param([hashtable]$Rights, [string]$RightName)
    if (-not $Rights.ContainsKey($RightName)) {
        return [pscustomobject]@{ State='Unknown'; Matches=@(); Unresolved=@(); Defined=$false; Entries='' }
    }
    $raw = [string]$Rights[$RightName]
    $entries = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $matches = @(); $unresolved = @()
    foreach ($entry in $entries) {
        $sid = ConvertTo-SidOrNull $entry
        if (-not $sid) { $unresolved += $entry; continue }
        if ($script:SidSet.ContainsKey($sid)) { $matches += $entry }
    }
    $state = if ($matches.Count -gt 0) {'Match'} elseif ($unresolved.Count -gt 0) {'Uncertain'} else {'NoMatch'}
    return [pscustomobject]@{ State=$state; Matches=$matches; Unresolved=$unresolved; Defined=$true; Entries=$raw }
}
function Get-RegistryValueOrNull {
    param([string]$Path,[string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}
function Invoke-GPResult {
    param([string]$Scope)
    Write-AuditLog "Collecting $Scope RSoP with gpresult.exe."
    $prefix = 'GPResult-{0}' -f $Scope
    $txt = Join-Path $script:Dir ($prefix + '.txt')
    $html = Join-Path $script:Dir ($prefix + '.html')
    try {
        $lines = & gpresult.exe /scope $Scope /r 2>&1
        $code = $LASTEXITCODE
        $lines | Out-File -LiteralPath $txt -Encoding UTF8 -Width 4096
        if ($code -eq 0) {
            Add-Finding ("GPO-{0}" -f $Scope.ToUpper()) PASS 'Group Policy' ("$Scope RSoP collected") "Result saved in $prefix.txt" 'Inspect applied/denied GPO names and policy precedence in exported evidence.'
        } else {
            $msg = (@($lines) | Out-String).Trim()
            $msg = if ($msg.Length -gt 420) { $msg.Substring(0,420) } else { $msg }
            Add-Finding ("GPO-{0}" -f $Scope.ToUpper()) REVIEW 'Group Policy' ("$Scope RSoP unavailable") "gpresult exit=$code; $msg" 'User RSoP requires a processed user logon and sufficient access. Service-only logons commonly lack User RSoP. Check account-scoped policy in GPMC/RSOP from a supported session; do not enable interactive logon just for this audit.'
        }
    }
    catch {
        Add-Finding ("GPO-{0}" -f $Scope.ToUpper()) REVIEW 'Group Policy' ("$Scope RSoP unavailable") $_.Exception.Message 'Check local elevated permissions and the Group Policy client/RSoP service.'
        return
    }
    try {
        $output = & gpresult.exe /scope $Scope /h $html /f 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-AuditLog ("HTML gpresult failed for $Scope: " + ((@($output) | Out-String).Trim())) 'WARN'
        }
    } catch { Write-AuditLog "HTML gpresult failed for ${Scope}: $($_.Exception.Message)" 'WARN' }
}
function Test-LocalServiceAccess {
    param([string]$ServiceName)
    # OpenService only requests an access check. It does not control or modify the service.
    try {
        $errorCode = 0
        $canOpen = [SiosAuditServiceProbe]::CanOpen($ServiceName, [uint32]0x0030, [ref]$errorCode)
        return [pscustomobject]@{ Allowed=$canOpen; Error=$errorCode }
    } catch { return [pscustomobject]@{ Allowed=$false; Error=-1 } }
}
function H {
    param([object]$Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

Write-AuditLog "Starting read-only SIOS GPO audit on $env:COMPUTERNAME as $script:Account."
Write-AuditLog "Report directory: $script:Dir"
Write-AuditLog "Elevated token: $script:IsElevated"
if (-not $script:IsElevated) {
    Add-Finding 'TOKEN-001' WARN 'Execution' 'PowerShell is not elevated' 'Current process token lacks enabled local Administrators role.' 'Run Windows PowerShell 5.1 elevated as the intended service account. Some security settings and service ACL checks may be incomplete.'
} else {
    Add-Finding 'TOKEN-001' PASS 'Execution' 'PowerShell token is elevated' $script:Account 'No change required.'
}

try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    [pscustomobject]@{ Node=$env:COMPUTERNAME; Domain=$cs.Domain; PartOfDomain=$cs.PartOfDomain;
      Account=$script:Account; SID=$script:Identity.User.Value; Elevated=$script:IsElevated;
      OS=$os.Caption; Build=$os.BuildNumber; Timestamp=$script:Now.ToString('o') } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $script:Dir 'SystemContext.json') -Encoding UTF8
    if ($cs.PartOfDomain) {
        Add-Finding 'DOMAIN-001' PASS 'Domain' 'Computer belongs to a domain' $cs.Domain 'Confirm both SIOS nodes belong to the same or appropriately trusted domain.'
    } else {
        Add-Finding 'DOMAIN-001' WARN 'Domain' 'Computer is not domain joined' $cs.Domain 'The shared-domain-account recommendation does not apply to workgroup configurations. Validate the workgroup account requirements with SIOS.'
    }
} catch { Add-Finding 'DOMAIN-001' REVIEW 'Domain' 'Unable to read computer domain information' $_.Exception.Message 'Check WMI/CIM permissions.' }

try {
    (& whoami.exe /all 2>&1) | Out-File -LiteralPath (Join-Path $script:Dir 'WhoAmI-All.txt') -Encoding UTF8 -Width 4096
} catch { Write-AuditLog "whoami evidence failed: $($_.Exception.Message)" 'WARN' }

Invoke-GPResult 'computer'
Invoke-GPResult 'user'

# Export effective local+domain security policy using the Microsoft supported secedit export.
$inf = Join-Path $script:Dir 'Effective-Security-Policy.inf'
$secLog = Join-Path $script:Dir 'SecEdit.log'
$rights = @{}
$policyExported = $false
Write-AuditLog 'Exporting merged effective security policy (user rights and security options).'
try {
    $output = & secedit.exe /export /mergedpolicy /cfg $inf /areas USER_RIGHTS SECURITYPOLICY /log $secLog /quiet 2>&1
    if (($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $inf)) {
        $policyExported = $true
        $section = ''
        foreach ($line in @(Get-Content -LiteralPath $inf)) {
            if ($line -match '^\s*\[(.+?)\]\s*$') { $section = $matches[1]; continue }
            if (($section -eq 'Privilege Rights') -and ($line -match '^\s*(Se\w+)\s*=\s*(.*)$')) {
                $rights[$matches[1]] = $matches[2].Trim()
            }
        }
        Add-Finding 'SECEDIT-001' PASS 'Security policy' 'Effective merged security policy exported' 'Effective-Security-Policy.inf' 'Review this export alongside Computer RSoP to identify the GPO controlling each value.'
    } else {
        Add-Finding 'SECEDIT-001' REVIEW 'Security policy' 'Effective security policy export failed' ((@($output) | Out-String).Trim()) 'Retry elevated. Check secedit permissions and local security policy database integrity.'
    }
} catch { Add-Finding 'SECEDIT-001' REVIEW 'Security policy' 'Effective security policy export failed' $_.Exception.Message 'Retry elevated; inspect SecEdit.log.' }

# Group Policy can configure service startup/security descriptors under System Services.
# Export that effective policy area separately; do not attempt to change it.
Write-AuditLog 'Exporting effective System Services security policy area.'
try {
    $svcPolicyFile = Join-Path $script:Dir 'Effective-SystemServices-Policy.inf'
    $svcSecLog = Join-Path $script:Dir 'SecEdit-Services.log'
    $svcSecOutput = & secedit.exe /export /mergedpolicy /cfg $svcPolicyFile /areas SERVICES /log $svcSecLog /quiet 2>&1
    if (($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $svcPolicyFile)) {
        Add-Finding 'GPO-SYSTEMSERVICES' INFO 'System Services GPO' 'Effective System Services policy area exported' 'Effective-SystemServices-Policy.inf' 'Compare the configured service DACL/start mode against protected services. A configured service security descriptor may remove START/STOP permissions.'
    } else {
        Add-Finding 'GPO-SYSTEMSERVICES' REVIEW 'System Services GPO' 'Unable to export System Services policy area' ((@($svcSecOutput) | Out-String).Trim()) 'Check secedit permissions; if no service policy is defined the export may be empty.'
    }
} catch {
    Add-Finding 'GPO-SYSTEMSERVICES' REVIEW 'System Services GPO' 'Unable to export System Services policy area' $_.Exception.Message 'Review Computer RSoP System Services settings manually.'
}

if ($policyExported) {
    $checks = @(
        @{ Right='SeDenyServiceLogonRight'; Id='RIGHT-001'; Title='Deny log on as a service'; Kind='Deny'; Scope='Service startup'; Impact='BLOCKER' },
        @{ Right='SeServiceLogonRight'; Id='RIGHT-002'; Title='Log on as a service'; Kind='Allow'; Scope='Service startup'; Impact='BLOCKER' },
        @{ Right='SeDenyNetworkLogonRight'; Id='RIGHT-003'; Title='Deny access to this computer from the network'; Kind='Deny'; Scope='Inter-node auth'; Impact='BLOCKER' },
        @{ Right='SeNetworkLogonRight'; Id='RIGHT-004'; Title='Access this computer from the network'; Kind='Allow'; Scope='Inter-node auth'; Impact='WARN' },
        @{ Right='SeDenyBatchLogonRight'; Id='RIGHT-005'; Title='Deny log on as a batch job'; Kind='DenyOptional'; Scope='Optional scheduled tasks'; Impact='WARN' },
        @{ Right='SeBatchLogonRight'; Id='RIGHT-006'; Title='Log on as a batch job'; Kind='AllowOptional'; Scope='Optional scheduled tasks'; Impact='WARN' },
        @{ Right='SeDenyInteractiveLogonRight'; Id='RIGHT-007'; Title='Deny log on locally'; Kind='AllowedDeny'; Scope='Service-account hardening'; Impact='INFO' },
        @{ Right='SeDenyRemoteInteractiveLogonRight'; Id='RIGHT-008'; Title='Deny log on through Remote Desktop Services'; Kind='AllowedDeny'; Scope='Service-account hardening'; Impact='INFO' }
    )
    foreach ($check in $checks) {
        $r = Get-RightEvaluation $rights $check.Right
        $desc = "Setting=$($check.Right); principals=$($r.Entries); matched=$($r.Matches -join ','); unresolved=$($r.Unresolved -join ',')"
        $recommend = switch ($check.Kind) {
            'Deny' { 'Remove the SIOS account and any relevant group from this Deny assignment in the controlling GPO. Deny supersedes allow.' }
            'Allow' { 'Ensure the SIOS service account is granted this user right through the winning policy. Confirm it after gpupdate/next service logon.' }
            'DenyOptional' { 'Required only when the SIOS account also runs scheduled tasks. Review task architecture and avoid broadening access unnecessarily.' }
            'AllowOptional' { 'Only required for scheduled-task logon under this account; not a core SIOS service requirement.' }
            'AllowedDeny' { 'Expected and often desirable hardening for service accounts. Not a SIOS service-logon blocker.' }
        }
        if ($r.State -eq 'Unknown') {
            $status = 'REVIEW'
            $desc = "Right not present in merged security export: $($check.Right). Cannot conclude effective result."
        } elseif ($r.State -eq 'Uncertain') {
            $status = 'REVIEW'
        } elseif ($check.Kind -eq 'Deny') {
            $status = if ($r.State -eq 'Match') {'BLOCKER'} else {'PASS'}
        } elseif ($check.Kind -eq 'Allow') {
            $status = if ($r.State -eq 'Match') {'PASS'} else {$check.Impact}
        } elseif ($check.Kind -eq 'DenyOptional') {
            $status = if ($r.State -eq 'Match') {'WARN'} else {'PASS'}
        } elseif ($check.Kind -eq 'AllowOptional') {
            $status = if ($r.State -eq 'Match') {'PASS'} else {'INFO'}
        } else {
            $status = 'INFO'
        }
        Add-Finding $check.Id $status $check.Scope $check.Title $desc $recommend
    }
}

# Export service information. Service names vary by version/edition.
Write-AuditLog 'Enumerating LifeKeeper, DataKeeper and protected services.'
try {
    $allServices = @(Get-CimInstance -Class Win32_Service)
    $siosServices = @($allServices | Where-Object { ($_.Name -match 'LifeKeeper|DataKeeper') -or ($_.DisplayName -match 'LifeKeeper|DataKeeper') })
    $siosServices | Select-Object Name,DisplayName,StartName,State,StartMode,PathName |
        Export-Csv -LiteralPath (Join-Path $script:Dir 'SIOS-Services.csv') -NoTypeInformation -Encoding UTF8
    if ($siosServices.Count -eq 0) {
        Add-Finding 'SVC-001' REVIEW 'SIOS services' 'No SIOS LifeKeeper/DataKeeper service found' 'Service search matched no names.' 'Confirm software is installed and service names for this SIOS version.'
    } else {
        $main = @($siosServices | Where-Object { ($_.Name -eq 'LifeKeeper') -or ($_.DisplayName -eq 'LifeKeeper') -or ($_.Name -match 'DataKeeper') -or ($_.DisplayName -match 'DataKeeper') })
        $identities = @($main | ForEach-Object { [string]$_.StartName } | Select-Object -Unique)
        if ($identities.Count -gt 1) {
            Add-Finding 'SVC-002' WARN 'SIOS services' 'LifeKeeper/DataKeeper service identities differ' (($main | ForEach-Object { "{0}={1}" -f $_.Name, $_.StartName }) -join '; ') 'For editions supporting account synchronization, use the same supported domain service identity on both nodes; confirm any exceptions with exact SIOS version before changing services.'
        } elseif ($identities.Count -eq 1) {
            Add-Finding 'SVC-002' PASS 'SIOS services' 'Core SIOS services share a local service logon identity' $identities[0] 'Also compare the identities reported by the other node.'
        }
        $normalized = $script:Account.Replace('/','\')
        foreach ($svc in $main) {
            if (($svc.StartName -notmatch '(?i)^(LocalSystem|NT AUTHORITY\\SYSTEM)$') -and ($svc.StartName -ine $normalized)) {
                Add-Finding 'SVC-003' WARN 'SIOS services' ("$($svc.Name) uses a different account than the audit") "Service=$($svc.StartName); audit=$normalized" 'Run the audit as the actual SIOS identity or adjust service identity through supported installation/service procedures.'
            }
        }
        foreach ($svc in $siosServices) {
            if ($svc.State -ne 'Running') {
                Add-Finding 'SVC-STATUS' WARN 'SIOS services' ("$($svc.DisplayName) not running") "Service=$($svc.Name); State=$($svc.State); StartMode=$($svc.StartMode)" 'Investigate service health, dependency errors and service logon; do not start or stop services as part of this audit.'
            }
        }
        if (@($main | Where-Object { $_.StartName -match '(?i)^(LocalSystem|NT AUTHORITY\\SYSTEM)$' }).Count -gt 0) {
            Add-Finding 'SVC-ACCOUNT' REVIEW 'SIOS services' 'At least one core SIOS service runs as LocalSystem' (($main | ForEach-Object { "{0}={1}" -f $_.Name, $_.StartName }) -join '; ') 'SIOS recommends a domain administrator-on-nodes service account for DataKeeper; validate the exact installed version before changing LifeKeeper or auxiliary services.'
        }
    }
    $targetServices = New-Object 'System.Collections.Generic.List[object]'
    if ($ProtectedServices.Count -eq 0) {
        Add-Finding 'ACL-NOTTESTED' REVIEW 'Protected application services' 'No protected services specified for START/STOP ACL testing' 'ProtectedServices parameter was omitted.' 'Supply the exact Windows service Name for applications under LifeKeeper control, e.g., MSSQLSERVER, SQLSERVERAGENT, or LogRhythm application services.'
    }
    foreach ($inputName in $ProtectedServices) {
        $matches = @($allServices | Where-Object { ($_.Name -eq $inputName) -or ($_.DisplayName -eq $inputName) })
        if ($matches.Count -eq 0) {
            Add-Finding 'ACL-NOTFOUND' REVIEW 'Protected application services' "Service not found: $inputName" $inputName 'Verify the exact Windows service Name using Get-Service or Win32_Service.'
            continue
        }
        foreach ($s in $matches) { if (-not @($targetServices | Where-Object Name -eq $s.Name).Count) { $targetServices.Add($s) } }
    }
    if ($targetServices.Count -gt 0) {
        $code = @'
using System;
using System.Runtime.InteropServices;
public static class SiosAuditServiceProbe {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr OpenService(IntPtr scm, string name, uint desiredAccess);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool CloseServiceHandle(IntPtr handle);
    public static bool CanOpen(string serviceName, uint desiredAccess, out int error) {
        error = 0;
        IntPtr scm = OpenSCManager(null, null, 0x0001);
        if (scm == IntPtr.Zero) { error = Marshal.GetLastWin32Error(); return false; }
        try {
            IntPtr service = OpenService(scm, serviceName, desiredAccess);
            if (service == IntPtr.Zero) { error = Marshal.GetLastWin32Error(); return false; }
            CloseServiceHandle(service); return true;
        } finally { CloseServiceHandle(scm); }
    }
}
'@
        try { Add-Type -TypeDefinition $code -ErrorAction Stop }
        catch { Add-Finding 'ACL-INIT' REVIEW 'Protected application services' 'Unable to load read-only service permission probe' $_.Exception.Message 'Check .NET Framework and Add-Type availability.' }
        foreach ($svc in $targetServices) {
            $file = Join-Path $script:Dir ("Service-SDDL-{0}.txt" -f ($svc.Name -replace '[^a-zA-Z0-9_.-]','_'))
            try { (& sc.exe sdshow $svc.Name 2>&1) | Out-File -LiteralPath $file -Encoding UTF8 -Width 4096 }
            catch { Write-AuditLog "Service SDDL retrieval failed for $($svc.Name)." 'WARN' }
            if ([System.Management.Automation.PSTypeName]'SiosAuditServiceProbe').Type) {
                $p = Test-LocalServiceAccess $svc.Name
                if ($p.Allowed) {
                    Add-Finding 'ACL-CONTROL' PASS 'Protected application services' "OpenService START+STOP allowed: $($svc.Name)" "Current process token can obtain SERVICE_START and SERVICE_STOP. Service is not modified." 'This proves the current elevated audit token, not necessarily the actual LifeKeeper service logon token, has rights. Validate in controlled maintenance test.'
                } else {
                    $state = if ($p.Error -eq 5) {'WARN'} else {'REVIEW'}
                    Add-Finding 'ACL-CONTROL' $state 'Protected application services' "OpenService START+STOP failed: $($svc.Name)" "Win32 error=$($p.Error), service account=$script:Account" 'Check System Services GPO, service DACL (sc sdshow), token elevation and the controlling application service permissions.'
                }
            }
        }
    }
} catch { Add-Finding 'SVC-ERROR' REVIEW 'SIOS services' 'Service inspection failed' $_.Exception.Message 'Check CIM service and local permissions.' }

# Domain account must be a local admin on both nodes; current effective token may be UAC-filtered.
$adminSid = 'S-1-5-32-544'
if ($script:SidSet.ContainsKey($adminSid)) {
    if ($script:IsElevated) {
        Add-Finding 'ADMIN-001' PASS 'Local administrators' 'Enabled local Administrator membership verified' 'S-1-5-32-544 present, elevated token' 'Confirm the same account is a local Administrator on the other node.'
    } else {
        Add-Finding 'ADMIN-001' REVIEW 'Local administrators' 'Administrators SID present but token is not elevated' 'S-1-5-32-544 may be deny-only due to UAC' 'Re-run elevated to test protected application service ACLs accurately.'
    }
} else {
    Add-Finding 'ADMIN-001' BLOCKER 'Local administrators' 'Administrators SID missing from current token' "Account=$script:Account" 'SIOS DataKeeper domain account must belong to Administrators locally on both nodes. Check GPO Restricted Groups or Group Policy Preferences membership management.'
}

# Security options that can interfere with negotiated remote authentication.
$ntlmReg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$ntlmOut = Get-RegistryValueOrNull $ntlmReg 'RestrictSendingNTLMTraffic'
$ntlmIn = Get-RegistryValueOrNull $ntlmReg 'RestrictReceivingNTLMTraffic'
if (($ntlmOut -eq 2) -or ($ntlmIn -eq 2)) {
    Add-Finding 'AUTH-NTLM' WARN 'Inter-node authentication' 'NTLM restriction policy may reject fallback authentication' "Outgoing=$ntlmOut; Incoming=$ntlmIn (2 indicates deny)" 'Kerberos is preferred; confirm working SPNs, DNS and SIOS authentication. Do NOT weaken NTLM policy without a documented compatibility requirement.'
} else {
    Add-Finding 'AUTH-NTLM' INFO 'Inter-node authentication' 'NTLM restriction registry settings reviewed' "Outgoing=$ntlmOut; Incoming=$ntlmIn" 'Validate actual Kerberos/NTLM negotiation if authentication errors are observed.'
}
$filterToken = Get-RegistryValueOrNull 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
if (($script:Account -notlike '*\*') -or ($script:Account.Split('\')[0] -ieq $env:COMPUTERNAME)) {
    if ($filterToken -ne 1) {
        Add-Finding 'AUTH-UAC' REVIEW 'Remote administration' 'Remote UAC token filtering may affect local accounts' "LocalAccountTokenFilterPolicy=$filterToken" 'Use the recommended shared domain identity instead of weakening UAC remote restrictions.'
    }
}

# Firewall: capture effective profiles and named SIOS rules. Rule existence != guaranteed effective network path.
try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $profiles | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules |
        Export-Csv -LiteralPath (Join-Path $script:Dir 'Firewall-Profiles.csv') -NoTypeInformation -Encoding UTF8
    foreach ($p in $profiles) {
        if (($p.Enabled -eq 'True') -and ($p.DefaultOutboundAction -eq 'Block')) {
            Add-Finding 'FW-OUTBOUND' WARN 'Firewall' "Default outbound firewall action is Block: $($p.Name)" 'Explicit egress allow rules are required.' 'Validate outbound rules for SIOS heartbeat, DataKeeper dispatch and volume replication; the audit cannot prove every address/port scope.'
        }
    }
    foreach ($p in $profiles) {
        if (($p.Enabled -eq 'True') -and ($p.AllowLocalFirewallRules -eq 'False')) {
            Add-Finding 'FW-GPO-MERGE' WARN 'Firewall / GPO' "Local firewall rule merge disabled: $($p.Name)" 'AllowLocalFirewallRules=False in ActiveStore' 'Ensure SIOS allowances exist in domain GPO firewall rules; locally installed exception rules may be ignored.'
        }
    }
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DisplayName -match 'LifeKeeper|DataKeeper|SIOS' })
    $rules | Select-Object DisplayName,Name,Enabled,Action,Direction,Profile,PolicyStoreSource,PolicyStoreSourceType |
        Export-Csv -LiteralPath (Join-Path $script:Dir 'SIOS-Firewall-Rules.csv') -NoTypeInformation -Encoding UTF8
    if ($rules.Count -eq 0) {
        Add-Finding 'FW-SIOS' REVIEW 'Firewall' 'No named SIOS firewall rules found' 'Rules may be named differently or managed by a GPO.' 'Inspect all effective network firewall rules and path ACLs; dedicated SIOS-named rules are not mandatory when equivalent allowances exist.'
    } else {
        foreach ($rule in $rules) {
            if ($rule.Enabled -eq 'True' -and $rule.Action -eq 'Block') {
                Add-Finding 'FW-RULE' WARN 'Firewall' "Enabled SIOS-named block rule: $($rule.DisplayName)" "Direction=$($rule.Direction), Profile=$($rule.Profile)" 'Review this rule and its port/address/program filters to determine whether it blocks actual SIOS traffic.'
            }
        }
    }
} catch { Add-Finding 'FW-COLLECT' REVIEW 'Firewall' 'Failed to export effective Windows Firewall settings' $_.Exception.Message 'Check NetSecurity PowerShell module, WMI and privileges.' }

# Optional replication NIC, route and TCP probes.
try {
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)
    $addresses | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState |
        Export-Csv -LiteralPath (Join-Path $script:Dir 'IPv4-Addresses.csv') -NoTypeInformation -Encoding UTF8
    @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop) |
        Select-Object DestinationPrefix,InterfaceAlias,InterfaceIndex,NextHop,RouteMetric |
        Export-Csv -LiteralPath (Join-Path $script:Dir 'IPv4-Routes.csv') -NoTypeInformation -Encoding UTF8
    if ($LocalReplicationIP) {
        $localNic = @($addresses | Where-Object { $_.IPAddress -eq $LocalReplicationIP })
        if ($localNic.Count -eq 0) {
            Add-Finding 'NIC-LOCAL' BLOCKER 'Replication network' 'Specified local replication IP is not assigned to this node' $LocalReplicationIP 'Correct the dedicated NIC IP or audit parameter.'
        } else {
            Add-Finding 'NIC-LOCAL' PASS 'Replication network' 'Specified local replication IP exists' "IP=$LocalReplicationIP; Interface=$($localNic[0].InterfaceAlias)" 'Ensure the other node uses its corresponding dedicated replication IP.'
        }
    }
    if ($PeerReplicationIP) {
        try {
            $routeResults = @(Find-NetRoute -RemoteIPAddress $PeerReplicationIP -ErrorAction Stop)
            $sourceAddress = @($routeResults | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' } | Select-Object -First 1)
            $selectedRoute = @($routeResults | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | Select-Object -First 1)
            $sourceIP = if ($sourceAddress.Count -gt 0) { [string]$sourceAddress[0].IPAddress } else { '' }
            $routeAlias = if ($selectedRoute.Count -gt 0) { [string]$selectedRoute[0].InterfaceAlias } elseif ($sourceAddress.Count -gt 0) { [string]$sourceAddress[0].InterfaceAlias } else { 'Unknown' }
            $routeInfo = "Interface=$routeAlias; Source=$sourceIP; Remote=$PeerReplicationIP"
            if ($LocalReplicationIP -and $sourceIP -and ($sourceIP -ne $LocalReplicationIP)) {
                Add-Finding 'NIC-ROUTE' WARN 'Replication network' 'Preferred route to peer does not select specified dedicated source IP' $routeInfo 'Validate host routes, NIC metrics and the DataKeeper mirror binding. Windows default route choice alone does not prove SIOS mirror source binding.'
            } else {
                Add-Finding 'NIC-ROUTE' INFO 'Replication network' 'Windows route selection recorded' $routeInfo 'Inspect mirror binding and packet captures if replication uses a different NIC.'
            }
        } catch { Add-Finding 'NIC-ROUTE' REVIEW 'Replication network' 'Unable to determine preferred route to replication peer' $_.Exception.Message 'Inspect IPv4-Routes.csv and actual source/destination binding in SIOS.' }
    }
} catch { Add-Finding 'NIC-COLLECT' REVIEW 'Replication network' 'Unable to collect NIC or route details' $_.Exception.Message 'Check NetTCPIP module and permissions.' }

if ($PeerNode) {
    try {
        $dns = @(Resolve-DnsName -Name $PeerNode -Type A -ErrorAction Stop)
        $dns | Select-Object Name,IPAddress,Type | Export-Csv -LiteralPath (Join-Path $script:Dir 'Peer-DNS.csv') -NoTypeInformation -Encoding UTF8
        Add-Finding 'DNS-PEER' PASS 'Inter-node DNS' 'Peer name resolved' (($dns | ForEach-Object IPAddress) -join ', ') 'Ensure DNS resolves to the intended management/application endpoint and Kerberos SPNs are valid.'
    } catch { Add-Finding 'DNS-PEER' WARN 'Inter-node DNS' 'Failed to resolve peer name' $_.Exception.Message 'Check DNS configuration, name resolution and domain connectivity.' }
}

$mirrorDispatch = Get-RegistryValueOrNull 'HKLM:\SYSTEM\CurrentControlSet\Services\ExtMirr\Parameters' 'TargetDispatchPort'
$mirrorBase = Get-RegistryValueOrNull 'HKLM:\SYSTEM\CurrentControlSet\Services\ExtMirr\Parameters' 'TargetPortBase'
if ($null -eq $mirrorDispatch) { $mirrorDispatch = 9999 }
if ($null -eq $mirrorBase) { $mirrorBase = 10000 }
Add-Finding 'DK-PORTS' INFO 'DataKeeper replication' 'DataKeeper base/dispatch ports (registry or defaults)' "TargetDispatchPort=$mirrorDispatch; TargetPortBase=$mirrorBase" 'Check both source and target registry overrides and the installed SIOS version; active mirror listeners may use shifted ports on conflicts.'
if ($PeerReplicationIP) {
    $ports = @([int]$mirrorDispatch)
    foreach ($letter in $MirrorDriveLetters) {
        $i = [int][char]$letter.ToUpperInvariant() - [int][char]'A'
        $ports += [int]$mirrorBase + $i
    }
    # Heartbeat paths may use other IP pairs; test against replication peer only as a diagnostic.
    $ports += $HeartbeatPorts
    foreach ($port in @($ports | Select-Object -Unique)) {
        Write-AuditLog "Probing TCP $($PeerReplicationIP):$port (diagnostic only; may not listen in current role)."
        try {
            $probe = Test-NetConnection -ComputerName $PeerReplicationIP -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($probe) {
                Add-Finding 'TCP-PORT' PASS 'Network diagnostic' "TCP connection succeeded to ${PeerReplicationIP}:$port" 'Probe completed.' 'Success only proves reachability of this port, not SIOS application health or replication NIC selection.'
            } else {
                Add-Finding 'TCP-PORT' REVIEW 'Network diagnostic' "TCP connection failed to ${PeerReplicationIP}:$port" 'Listener may be inactive on the passive node, port remapped, not used on this NIC, or blocked.' 'Check actual configured SIOS path IP/port, remote listener status, source IP, host and network firewall rules. Do not assume firewall blockage based solely on this test.'
            }
        } catch { Add-Finding 'TCP-PORT' REVIEW 'Network diagnostic' "TCP probe could not complete to ${PeerReplicationIP}:$port" $_.Exception.Message 'Investigate endpoint reachability and Test-NetConnection availability.' }
    }
}

# Local Windows diagnostic event log evidence (limited to 7 days, last 60 events per log).
$since = (Get-Date).AddDays(-7)
try {
    @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=@(7000,7001,7023,7034,7038,7041); StartTime=$since} -MaxEvents 60 -ErrorAction Stop) |
        Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message |
        Export-Csv -LiteralPath (Join-Path $script:Dir 'Service-Control-Events.csv') -NoTypeInformation -Encoding UTF8
    Add-Finding 'EVENT-SERVICE' INFO 'Event logs' 'Recent service-control errors captured' 'Service-Control-Events.csv' 'Look for 7038/7041 logon failures and 7000/7001 dependency failures.'
} catch { Write-AuditLog "Service-Control event export unavailable: $($_.Exception.Message)" 'WARN' }
try {
    @(Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 60 -ErrorAction Stop) |
        Where-Object TimeCreated -ge $since |
        Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message |
        Export-Csv -LiteralPath (Join-Path $script:Dir 'GroupPolicy-Events.csv') -NoTypeInformation -Encoding UTF8
} catch { Write-AuditLog "GroupPolicy Operational event export unavailable: $($_.Exception.Message)" 'WARN' }

# Summaries and portable report.
Write-AuditLog 'Exporting findings and report.'
$findCsv = Join-Path $script:Dir 'Findings.csv'
$findJson = Join-Path $script:Dir 'Findings.json'
$script:Findings | Export-Csv -LiteralPath $findCsv -NoTypeInformation -Encoding UTF8
@($script:Findings) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $findJson -Encoding UTF8
$counts = @{}
foreach ($s in @('BLOCKER','WARN','REVIEW','PASS','INFO')) { $counts[$s] = @($script:Findings | Where-Object Status -eq $s).Count }
$css = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;max-width:1500px;margin:25px auto;color:#172334;background:#f5f7fb}
h1{color:#153b62}table{border-collapse:collapse;width:100%;background:white}
th,td{border:1px solid #dde3ec;padding:9px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#183b60;color:white}tr:nth-child(even){background:#f0f5fa}
.BLOCKER{background:#ffd8d8;font-weight:bold}.WARN{background:#fff0c7}.REVIEW{background:#e4e9f5}.PASS{background:#def2e2}.INFO{background:#eaf5f9}
.summary{padding:12px;background:white;border:1px solid #dce3ed;margin:16px 0}small{color:#566677}code{background:#eef1f6;padding:2px}
</style>
'@
$rows = foreach ($f in $script:Findings) {
    '<tr><td>{0}</td><td class="{1}">{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f (H $f.ID),(H $f.Status),(H $f.Status),(H $f.Scope),(H $f.Check),(H $f.Evidence),(H $f.Recommendation)
}
$page = @"
<!doctype html><html><head><meta charset="utf-8"><title>SIOS GPO Audit - $(H $env:COMPUTERNAME)</title>$css</head><body>
<h1>SIOS LifeKeeper / DataKeeper - GPO and Prerequisite Audit</h1>
<div class="summary"><b>Node:</b> $(H $env:COMPUTERNAME) &nbsp; <b>Account:</b> $(H $script:Account)<br/>
<b>Time:</b> $(H $script:Now.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp; <b>Elevated:</b> $(H $script:IsElevated)<br/>
<b>BLOCKER:</b> $($counts['BLOCKER']) &nbsp; <b>WARN:</b> $($counts['WARN']) &nbsp;
<b>REVIEW:</b> $($counts['REVIEW']) &nbsp; <b>PASS:</b> $($counts['PASS']) &nbsp; <b>INFO:</b> $($counts['INFO'])</div>
<p><b>Interpretation:</b> BLOCKER = confirmed match against a blocking security right or an access failure in the audit token;
WARN = likely configuration concern; REVIEW = insufficient evidence or conditional conflict; PASS = locally verified test only.
The script does not attribute every security right to a specific GPO. Compare <code>Effective-Security-Policy.inf</code> and
<code>GPResult-computer.html</code> to find the controlling policy.</p>
<table><thead><tr><th>ID</th><th>Status</th><th>Scope</th><th>Check</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>$($rows -join "`n")</tbody></table>
<p><small>Read-only collection: no service state, GPO, firewall or cluster configuration was changed. User-policy RSoP is session-dependent.
These checks do not replace vendor-supported failover testing and cross-node validation.</small></p>
</body></html>
"@
$htmlFile = Join-Path $script:Dir 'SIOS-GPO-Audit.html'
[System.IO.File]::WriteAllText($htmlFile, $page, ([System.Text.UTF8Encoding]::new($false)))
Write-AuditLog "Completed. BLOCKER=$($counts['BLOCKER']) WARN=$($counts['WARN']) REVIEW=$($counts['REVIEW']) PASS=$($counts['PASS'])."
Write-Host "`nREPORT: $htmlFile"
Write-Host "FINDINGS: $findCsv"
Write-Host 'Run this same script on the second SIOS node and compare findings, SIOS-Services.csv, GPO reports, and routes.'
[pscustomobject]@{ Computer=$env:COMPUTERNAME; Account=$script:Account; Blockers=$counts['BLOCKER']; Warnings=$counts['WARN']; Reviews=$counts['REVIEW']; Report=$htmlFile }