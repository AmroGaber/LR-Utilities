# SIOS LifeKeeper and DataKeeper — Windows Prerequisites and GPO Audit

> Two-node Windows Server high availability deployment guide and read-only audit companion.
> Script: [Test-SIOS-GPOPrerequisites.ps1](./Test-SIOS-GPOPrerequisites.ps1). This is independent implementation guidance, not an official SIOS document. Validate against your installed SIOS version and recovery kit. The script has not been runtime-tested in a Windows/SIOS lab.

## Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Service account and permissions](#service-account-and-permissions)
- [GPO conflict matrix](#gpo-conflict-matrix)
- [Dedicated replication network](#dedicated-replication-network)
- [Execution](#execution)
- [Reports and interpretation](#reports-and-interpretation)
- [Troubleshooting and acceptance](#troubleshooting-and-acceptance)
- [References](#references)

## Architecture

LifeKeeper controls application resources, monitors health, and orchestrates start, stop, and failover. DataKeeper performs block-level disk replication. **Windows services are protected, not replicated.**

```text
       Application / client network
           |                 |
    +------+------+   +------+-----+
    | Node A      |   | Node B     |
    | LifeKeeper  |   | LifeKeeper |
    | DataKeeper  |   | DataKeeper |
    | SQL service |   | SQL service|
    +------+------+   +------+-----+
           |                 |
       Dedicated replication network
         (verify routes and endpoints)
```

Prefer a dedicated replication NIC/VLAN for predictable bandwidth and separation from client traffic. Also plan reliable, preferably redundant, LifeKeeper communication paths according to the supported configuration. A dedicated NIC does **not** automatically mean DataKeeper will select it; validate the actual mirror endpoints and route.

## Prerequisites

- [ ] Both servers joined to the intended Active Directory domain, with healthy DNS, clock synchronization and connectivity to domain controllers.
- [ ] Windows Server release, LifeKeeper/DataKeeper builds, application recovery kit and storage configuration are on the SIOS support matrix.
- [ ] Confirm versions, licenses, storage topology, target volume sizing, filesystem, drive letters and initial synchronization plan.
- [ ] Record each node's SIOS Windows services and actual service identities; do not assume there are only two services per node (LifeKeeper External Interfaces may be present).
- [ ] Record the protected service names, logon identities, dependency graph and recovery resource hierarchy.
- [ ] Verify account logon rights and effective local group membership on both nodes.
- [ ] Validate traffic direction, TCP/UDP protocols, port bindings, firewall and EDR rules against the installed version.
- [ ] Record dedicated NIC IPs, masks, interface metrics, routes, VLANs, MTU and communication path redundancy.
- [ ] Establish backups, change-control window and controlled failover/failback acceptance criteria.

## Service account and permissions

**Preferred consistency principle:** use one dedicated domain service identity across both nodes for those SIOS components whose installed version supports or recommends it. SIOS installation options may synchronize LifeKeeper and DataKeeper credentials; however **do not change all services to the same domain identity unconditionally**. Some older releases specify Local System for particular LifeKeeper components. Verify the version-specific SIOS service-account documentation and compare each installed Windows service's `StartName`.

| Setting / access | Potential problem | Recommendation |
|---|---|---|
| Log on as a service (`SeServiceLogonRight`) | Service Control Manager cannot log on service identity | Confirm effective grant to the account/group |
| Deny log on as a service (`SeDenyServiceLogonRight`) | Overrides allow rights | No effective matching deny SID |
| Access this computer from network (`SeNetworkLogonRight`) | Network logon may fail | Check if granted when needed by the SIOS path |
| Deny access from network (`SeDenyNetworkLogonRight`) | Overrides network rights | Ensure service account/group is not denied for required access |
| Administrators membership | May block management/replication functions | Confirm version-specific requirement on **both** hosts |
| Service control DACL | LifeKeeper cannot start or stop SQL services | Evaluate SERVICE_START and SERVICE_STOP with actual LifeKeeper token |
| Password, lockout, expiry, Kerberos/NTLM | Authentication fails after rotation or restart | Validate permitted authentication, credential lifecycle and event evidence |
| Batch logon | Scheduled helper task fails | Grant **only if the related task requires it** |
| Interactive/RDP logon | Service account cannot sign in for audit | Usually desirable hardening; **do not lift solely for diagnostics** |

SQL Server and SQL Server Agent service identities are **separate** from the SIOS service identities. Match their permissions to the protected application's requirements. Local Administrator membership of an interactive audit account is not proof of effective permissions of a service token.

### Read-only manual commands

```powershell
whoami /all
Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'LifeKeeper|DataKeeper' -or $_.DisplayName -match 'LifeKeeper|DataKeeper' } | Select-Object Name,DisplayName,State,StartMode,StartName
sc.exe qc MSSQLSERVER
sc.exe sdshow MSSQLSERVER
sc.exe qc SQLSERVERAGENT
sc.exe sdshow SQLSERVERAGENT
```

## GPO conflict matrix

Computer Configuration policies commonly assign machine user rights to domain user/group SIDs. User Configuration RSoP is session-dependent and **does not replace** the effective computer security policy export.

| GPO / control | Possible impact | Severity / investigation |
|---|---|---|
| Deny log on as a service | SIOS service cannot start | **BLOCKER** when service identity/group matches |
| Log on as a service | Required service identity not granted | **BLOCKER** if missing |
| Deny access from network | Peer network authentication blocked | **BLOCKER / REVIEW** based on identity/path |
| Local Users and Groups / Restricted Groups | Removes local administrators membership | **REVIEW / BLOCKER** where required by SIOS version |
| System Services security policy | Service start/stop or service config restricted | **REVIEW** service DACL and winning GPO |
| Defender Firewall with local-rule merge disabled | Local allow rules ineffective | **REVIEW** applied firewall policy and centralized allow rules |
| NTLM/Kerberos restrictions | Authentication fails with configured method | **REVIEW**; do not weaken domain authentication blindly |
| AppLocker/WDAC, EDR, PowerShell controls | Executables and recovery actions blocked | **REVIEW** enforcement logs and exclusions approval |
| Deny local/RDP logon | Interactive execution blocked | Generally acceptable service-account hardening |

Collect machine and (where applicable) session User RSoP plus effective rights:

```powershell
gpresult /scope computer /h .\GPResult-Computer.html /f
gpresult /scope user /h .\GPResult-User.html /f
secedit /export /mergedpolicy /cfg .\EffectiveSecurityPolicy.inf
Get-NetFirewallProfile
Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object DisplayName -Match 'LifeKeeper|DataKeeper|SIOS'
```

**User RSoP limitation:** service-only sessions often lack processed User GPO data. Missing User gpresult is **REVIEW**, not proof that no user policy exists. To name the *winning GPO* for an effective right, correlate gpresult/RSoP/GPMC with the merged security policy; the script cannot always attribute precedence automatically.

## Dedicated replication network

### Provided example

| Parameter | Value |
|---|---|
| Peer host | `XM01` |
| Local replication IP | `10.20.30.11` |
| Remote replication IP | `192.168.1.11` |
| Mirrored volumes | `D:`, `L:`, `S:` |
| TCP probe ports | `81,82,1500,1510,3278,2379,9999,10003,10011,10018` |

These local and peer IPv4 addresses fall into different commonly used private ranges. This is **not inherently incorrect** if intended inter-subnet routing exists; validate actual subnet masks, routing and *return path*, firewall, NIC selected by DataKeeper and peer listener binding. Avoid competing default gateways on multihomed servers. Do not assume `Test-NetConnection` forces the dedicated source interface.

The argument name `-HeartbeatPorts` is historical: the script treats its list as **TCP diagnostic probes**. It is **not a SIOS-certified list of LifeKeeper heartbeat ports**, and it does not test UDP. A failed probe can mean no listener rather than a denied firewall flow.

```powershell
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4
Find-NetRoute -RemoteIPAddress 192.168.1.11
Test-NetConnection 192.168.1.11 -InformationLevel Detailed
Get-NetAdapterStatistics
```

Check actual DataKeeper source/target IPs and replication state in SIOS separately. Validate throughput, NIC errors, latency and loss, and LifeKeeper communication-path redundancy.

## Execution

On the node whose local replication IP is `10.20.30.11`, run **Windows PowerShell 5.1 elevated** under the intended service account *if that logon method is authorized*. Otherwise use an approved privileged audit identity and clearly note that account-specific/token findings may differ.

```powershell
.\Test-SIOS-GPOPrerequisites.ps1 `
    -PeerNode "XM01" `
    -LocalReplicationIP "10.20.30.11" `
    -PeerReplicationIP "192.168.1.11" `
    -MirrorDriveLetters D,L,S `
    -HeartbeatPorts 81,82,1500,1510,3278,2379,9999,10003,10011,10018 `
    -ProtectedServices "MSSQLSERVER","SQLSERVERAGENT"
```

Run on **XM01** with `-LocalReplicationIP` set to **XM01's** actual replication IP, `-PeerReplicationIP` to the opposite node's IP, and `-PeerNode` to that other hostname. Do **not** run the sample unchanged on XM01.

Default report root: `%TEMP%\SIOS-GPO-Audit\<COMPUTER-DATE>\`. Optionally specify `-OutputRoot 'C:\SIOS-Audit'`.

## Reports and interpretation

| Artifact | Use |
|---|---|
| `SIOS-GPO-Audit.html` | Summary and evidence-backed recommendations |
| `Findings.csv`, `Findings.json` | Compare checks between the two nodes |
| `GPResult-computer.*` | Computer policy and winning-policy investigation |
| `GPResult-user.*` | User policy evidence, when session allows it |
| Policy INF, service, firewall and network evidence | Diagnose permissions, rules, route and listener differences |
| `Audit.log` | Timestamped collection log |

| Finding | Meaning |
|---|---|
| **BLOCKER** | Strong local evidence of a conflict; verify applied GPO/identity |
| **WARN** | Potentially disruptive or failed check requiring diagnosis |
| **REVIEW** | Conditional or incomplete evidence needing another test |
| **PASS** | Individual test passed, **not** proof the HA solution is healthy |
| **INFO** | Supporting inventory/context |

Compare both nodes' `Findings.csv` files; prioritize matching DENY rules, logon rights, effective admin membership, SIOS identities, protected-service DACL and asymmetric firewall/routing. Record policy owner, evidence, remediation and retest.

## Troubleshooting and acceptance

| Symptom | Investigate |
|---|---|
| SIOS service fails to start | Service identity/password, SCM events, SeServiceLogonRight and SeDenyServiceLogonRight |
| LifeKeeper can't start/stop SQL | SQL service DACL, active LifeKeeper identity, service dependency hierarchy and recovery kit |
| Disk mirror won't establish | Actual mirror endpoints, listener/port, route, return path, firewall, storage state |
| Replication lag/disconnect | NIC errors, bandwidth, disk latency, EDR, application/replication logs |
| User RSoP not found | Service-only session and gpresult limitations |
| Only one node fails | Differences in GPO, group membership, service configuration, firewall and routes |

### Before production sign-off

- [ ] Every **BLOCKER** has a reviewed disposition on both nodes.
- [ ] All installed SIOS services have **version-supported** logon identities and can start after controlled reboot.
- [ ] LifeKeeper can start/stop protected services using its **actual runtime token** in an approved test.
- [ ] The mirror reaches healthy/synchronized state, and replication uses the intended interface.
- [ ] Both communication/heartbeat and disk-replication paths are validated; test controlled path interruption and recovery where appropriate.
- [ ] Controlled failover and failback preserve expected application and data availability.
- [ ] Retain redacted evidence, GPO approvals, screenshot inventory and change record.

### Security and technical limits

The script is **read-only**: it does not apply GPOs, change firewall, start/stop services, modify security descriptors or trigger failover. Service-control checks use the **audit process token**, not necessarily the SIOS service token. TCP probes cannot prove UDP availability or exact firewall causality. Reports may expose internal IP addresses, privileged groups and service configuration: restrict access and **never upload production report output or secrets into a public GitHub repository**. Pilot in a non-production environment before operational use.

## References

- [SIOS: DataKeeper service logon ID and password](https://docs.us.sios.com/WindowsSPS/8.6/SPS4W/AllTechDocs/Content/DataKeeper/Installation/DataKeeper_Service_Log_On_ID_and_Password_Selection.htm)
- [SIOS: DataKeeper registry entries and ports](https://docs.us.sios.com/dkse/8.10.1/en/topic/registry-entries)
- [SIOS: LifeKeeper communication path](https://docs.us.sios.com/WindowsSPS/8.6/SPS4W/TechDoc/Content/Administration/Administrator_GUI_Tasks/Creating_a_Communication_Path.htm)
- [Microsoft: gpresult](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
- [Microsoft: secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
- [Microsoft: service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)

---

**Maintainer note:** This README replaces the need to publish the earlier PDF. Use actual environment screenshots and version-specific SIOS documentation when creating customer-facing implementation deliverables.
