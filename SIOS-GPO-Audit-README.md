# SIOS LifeKeeper/DataKeeper GPO and service-account audit

**File:** `Test-SIOS-GPOPrerequisites.ps1`  
**PowerShell:** Windows PowerShell 5.1, on Windows Server 2016/2019/2022/2025 (subject to installed SIOS/version support).  
**Behavior:** Read-only report collection. Does not apply GPO, edit registry/firewall, control services, or initiate HA failover.

## Run

1. Sign in to **the node being audited** using the domain user that runs the SIOS service (if permitted by your organization), and **run Windows PowerShell as administrator**. If interactive logon is deliberately denied, do not weaken that GPO merely for this audit: use an approved privileged diagnostic method and note that User RSOP is session-dependent.
2. Copy the script onto the machine and run:

   ```powershell
   Set-Location C:\SIOS-Audit
   .\Test-SIOS-GPOPrerequisites.ps1 `
      -PeerNode "XM01" `
      -LocalReplicationIP "10.20.30.11" `
      -PeerReplicationIP "192.168.1.11" `
      -MirrorDriveLetters D,L,S `
      -HeartbeatPorts 81,82,1500,1510,3278,2379,9999,10003,10011,10018 `
      -ProtectedServices "MSSQLSERVER","SQLSERVERAGENT"
   ```

3. Run the same audit on **XM01** with its own local replication IP and the other node as the peer. The example above assumes XM01 is the remote peer; do not run it unchanged on XM01.
4. Review `<TEMP>\SIOS-GPO-Audit\<COMPUTER-DATE>\SIOS-GPO-Audit.html`, `Findings.csv`, `GPResult-computer.html`, `GPResult-user.html` (if obtainable), and raw policy INF exports. Compare the two nodes' service identities and findings.

**Port scope:** The requested `-HeartbeatPorts` list is treated as **TCP diagnostic probes**. It includes ports that may belong to LifeKeeper, DataKeeper or protected applications; it does **not** establish that every port is a LifeKeeper heartbeat listener. Confirm each listener, protocol, destination interface and any vendor-specific mapping before interpreting failures. The probe to the replication peer does not force the source NIC.

**Replication network review:** Your supplied local `10.20.30.11` and peer `192.168.1.11` addresses are in different private IPv4 ranges. This is not automatically a failure, but verify the intended inter-subnet route, return route, firewall rules and that the actual DataKeeper mirror uses the intended dedicated NICs. Same-subnet, isolated replication VLANs often simplify operations, but routed dedicated networks are possible when supported and correctly configured.

## Check categories

| Result | Meaning |
|---|---|
| BLOCKER | Strong evidence of a security-right conflict or a missing configured local IP/domain administrative requirement |
| WARN | Potentially disruptive setting or token-specific inability to control a service; requires investigation |
| REVIEW | Inconclusive evidence, missing policy result, or a conditional requirement |
| PASS | A particular local test succeeded, not proof that the cluster is operational |
| INFO | Context or a hardening practice that is not inherently blocking |

The script checks: matching Deny/Allow service-logon rights, network-logon rights, batch-logon rights (optional), local/RDP logon hardening, NTLM restrictions (conditional), effective service identity, whether protected service control access can be opened, Windows Firewall profile/local-rule merge, SIOS-named firewall rules, System Services GPO area, DNS/IPv4 routing, DataKeeper registry-based target ports, heartbeat probes, and recent System/GroupPolicy event evidence.

## Important limits

- **User RSOP under a service-only logon can be missing:** `gpresult` needs a processed user policy/session. This does not mean no user GPOs exist. Computer GPO and effective local machine rights remain the primary source for service logon rights.
- The script uses the SID groups of the **audit process token**, which may not perfectly match the actual SIOS service logon token; stale group membership, UAC elevation, and service-specific identities can affect outcomes.
- The service access probe calls `OpenService` requesting `SERVICE_START | SERVICE_STOP`, but never starts or stops anything. ACL results describe only the current process token, and remote Service Control Manager permissions are not fully tested.
- A failed TCP connection is **not proof** that the firewall caused failure: the target listener may be absent, not yet active, or bound to a different NIC/port.
- Exact attribution of a privilege or registry value to the winning **GPO** requires reviewing Computer RSoP/GPMC alongside the merged policy export; the script does not claim perfect automatic policy provenance.
- Information in output (domain names, group memberships, service paths, network topology, security policies) is security-sensitive. Store and share reports according to your internal security procedures.
- Script **has not been executed in a Windows/SIOS test environment** here. Review and pilot on a non-production node before use in production.

## Vendor / Microsoft sources

- [SIOS DataKeeper service account recommendations](https://docs.us.sios.com/WindowsSPS/8.6/SPS4W/AllTechDocs/Content/DataKeeper/Installation/DataKeeper_Service_Log_On_ID_and_Password_Selection.htm)
- [SIOS DataKeeper configurable replication port registry entries](https://docs.us.sios.com/dkse/8.10.1/en/topic/registry-entries)
- [SIOS LifeKeeper communication path redundancy](https://docs.us.sios.com/WindowsSPS/8.6/SPS4W/TechDoc/Content/Administration/Administrator_GUI_Tasks/Creating_a_Communication_Path.htm)
- [Microsoft gpresult](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
- [Microsoft secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
- [Microsoft service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)