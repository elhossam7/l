# SOC LAB — ZERO TO HERO OPERATIONAL GUIDE
## Part 3: Investigation, Threat Hunting & DFIR

---

## MODULE A — KIBANA SIEM INVESTIGATION

### A.1 — KQL Queries for Each Attack

Open Kibana → Discover or Security → Alerts, and use these queries:

**Reconnaissance / Nmap:**
```kql
# Suricata Nmap detection
tags: "suricata" AND alert.signature: "NMAP*"

# LDAP enumeration events on DC01
event.code: "4662" AND winlog.computer_name: "DC01*"
```

**BloodHound Recon:**
```kql
# Excessive LDAP queries (BloodHound signature)
event.code: "4662" AND winlog.event_data.Properties: "*Read Property*"
| stats count by user.name, source.ip
| where count > 50

# AD object access flood
event.code: ("4661" OR "4662") AND @timestamp:[now-5m TO now]
```

**Kerberoasting:**
```kql
# Core Kerberoasting detection
event.code: "4769" AND winlog.event_data.TicketEncryptionType: "0x17"

# Detailed with service name
event.code: "4769"
  AND winlog.event_data.TicketEncryptionType: "0x17"
  AND winlog.event_data.ServiceName: "svc_sql"
```

**Mimikatz / Credential Dumping:**
```kql
# LSASS process access
event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe*"

# Mimikatz command line
process.command_line: (*sekurlsa* OR *lsadump* OR *privilege::debug* OR *mimikatz*)

# DLL loading for credential dumping
event.code: "7" AND winlog.event_data.ImageLoaded: (*wdigest* OR *samlib* OR *vaultcli*)
```

**Pass-the-Hash:**
```kql
# Network logon with NTLM
event.code: "4624"
  AND winlog.event_data.LogonType: "3"
  AND winlog.event_data.LogonProcessName: "NtLmSsp"
  AND winlog.event_data.AuthenticationPackageName: "NTLM"

# No password in logon process (PTH indicator)
event.code: "4624" AND NOT winlog.event_data.LogonType: "2"
  AND source.ip: "172.16.99.10"
```

**Brute Force:**
```kql
# Windows failed logons
event.code: "4625"
| stats count by source.ip, user.name, winlog.computer_name
| where count > 10

# Linux SSH failures
event.dataset: "system.auth" AND system.auth.ssh.event: "Failed"
| stats count by source.ip
| sort count desc
```

**Lateral Movement / Evil-WinRM:**
```kql
# WinRM network connection
event.code: "3" AND destination.port: (5985 OR 5986)

# Remote logon events
event.code: "4648" AND winlog.event_data.TargetServerName: "*"

# Sysmon DNS query for lateral target
event.code: "22" AND dns.question.name: "*.lab.local"
```

**Persistence:**
```kql
# Registry Run key modification
event.code: "13" AND winlog.event_data.TargetObject: "*\\CurrentVersion\\Run*"

# Scheduled task creation
event.code: ("4698" OR "4702")

# New service installation
event.code: "7045"
```

---

### A.2 — Timeline Reconstruction in Kibana

When an incident is detected, reconstruct the timeline:

```
1. Go to Kibana → Discover
2. Set time range to cover the attack window (e.g., last 2 hours)
3. Use multi-index: logs-*
4. Sort by @timestamp ascending
5. Add columns: host.name, user.name, event.code, process.name, source.ip
6. Search for the attacker IP:
   source.ip: "172.16.99.10" OR host.ip: "172.16.99.10"
7. Export as CSV for TheHive case notes
```

**Build an attack timeline query:**
```kql
# All events related to Kali machine in the last hour
(source.ip: "172.16.99.10" OR destination.ip: "172.16.99.10"
  OR user.name: ("alice.dupont" OR "bob.admin"))
AND @timestamp:[now-1h TO now]
```

---

## MODULE B — THEHIVE 5 — CASE MANAGEMENT

### B.1 — Creating a Case Manually

```
URL: http://10.30.40.50:9000
Login: admin@thehive.local

1. New Case → Click "+ New Case"
2. Fill fields:
   - Title: "Kerberoasting Attack - svc_sql - 2026-05-06"
   - Severity: HIGH (3)
   - TLP: AMBER
   - Tags: ["Kerberoasting", "T1558.003", "AD", "lab.local"]
   - Description: (paste from Kibana evidence)
3. Click Create
```

### B.2 — Adding Observables to Case

```
Inside the case → Observables tab → Add observable:
- IP Address: 172.16.99.10 (Kali attacker)    → Type: ip
- Username: svc_sql                            → Type: other
- Process hash (from Sysmon 1 event)           → Type: hash
- Domain: lab.local                            → Type: domain
- File: mimikatz.exe                           → Type: filename
```

### B.3 — Running Cortex Analyzers

```
Inside the case → Observables → Select IP 172.16.99.10
→ "Run Analyzers" button
→ Select:
   - AbuseIPDB_1_0       → IP reputation check
   - Shodan_Host_1_0     → Open ports/services on IP
→ Click Run

For file hashes:
→ Select the hash observable
→ Run: VirusTotal_GetReport_3_0
→ Results show malware classification
```

### B.4 — Adding Tasks to Case

```
Tasks tab → Add task:
1. "Verify attacker IP in Suricata logs"     → Assign to analyst
2. "Pull LSASS access timeline from Kibana"  → Assign to analyst
3. "Run Velociraptor hunt on WIN-TARGET-2"   → Assign to analyst
4. "Check OpenCTI for IOC match"             → Assign to analyst
5. "Confirm no persistence (registry/tasks)" → Assign to analyst
6. "Containment: block attacker in pfSense"  → Assign to analyst
```

### B.5 — Case Status Workflow

```
New → InProgress → Resolved → Closed
  ↓
TruePositive / FalsePositive / Indeterminate
```

---

## MODULE C — VELOCIRAPTOR THREAT HUNTING

### C.1 — Accessing Velociraptor

```
URL: https://10.30.40.50:8000
Login: admin / [velociraptor password]

1. Clients → view all connected agents
2. Click on WIN-TARGET-1 or WIN-TARGET-2
3. Shell → run live commands on endpoint
```

### C.2 — Live Shell Commands on Endpoint

```
In Velociraptor → Client → Shell:

# Check running processes
Get-Process | Select Name, Id, Path | Sort Name

# Check network connections
netstat -ano

# Check logged-on users
query users

# Check scheduled tasks
schtasks /query /fo LIST /v

# Check registry run keys
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Check recent files in temp
dir C:\Windows\Temp /OD /B
dir C:\Users\bob.admin\AppData\Local\Temp /OD /B

# Check event log for recent logons
Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 | Format-List
```

### C.3 — VQL Hunts (Run Against All Endpoints)

In Velociraptor → Hunts → New Hunt → VQL:

```sql
-- HUNT 1: Find Mimikatz or offensive tools on disk
SELECT FullPath, Size, Mtime, Hash.MD5, Hash.SHA256
FROM glob(globs="C:\\**\\mimikatz*", accessor="file")

-- HUNT 2: Find all running processes (network-connected)
SELECT Name, Pid, Ppid, CommandLine, Username, Exe
FROM pslist()
WHERE Name =~ "mimikatz|meterpreter|cobaltstrike|psexec|wce"

-- HUNT 3: Network connections to Kali (172.16.99.10)
SELECT Laddr, Lport, Raddr, Rport, Status, Pid, ProcessName
FROM netstat()
WHERE Raddr = "172.16.99.10"

-- HUNT 4: Check registry persistence (Run keys)
SELECT Key, Name, Data, Mtime
FROM read_reg_key(
  globs="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\**"
)

-- HUNT 5: Find scheduled tasks recently created
SELECT TaskName, TaskToRun, RunAsUser, Status, Triggers
FROM schtasks()
WHERE Mtime > now() - 3600   -- last hour

-- HUNT 6: LSASS access (via Windows event logs)
SELECT *
FROM parse_evtx(filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx")
WHERE EventID = 10 AND EventData.TargetImage =~ "lsass"

-- HUNT 7: Recent PowerShell commands
SELECT *
FROM parse_evtx(filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx")
WHERE EventID = 4104
ORDER BY EventTime DESC
LIMIT 50

-- HUNT 8: Large file downloads (possible exfil)
SELECT FullPath, Size, Mtime
FROM glob(globs="C:\\Users\\**\\Downloads\\*", accessor="file")
WHERE Size > 10000000  -- files > 10MB
```

### C.4 — Collect Artifacts from Endpoint

```
Velociraptor → Client → Artifacts → Collect Artifact

Key artifacts to collect:
1. Windows.KapeFiles.Targets      → Full forensic triage (MFT, registry hives, prefetch)
2. Windows.System.Pslist          → Process list snapshot
3. Windows.Network.Netstat        → Network connections
4. Windows.EventLogs.Evtx         → Export specific event logs
5. Windows.Registry.UserAssist    → Program execution history
6. Windows.Registry.Sysinternals  → Autoruns (persistence)
7. Generic.Forensic.LocalHashes   → Hash all executables in Windows\Temp

After collection → Download ZIP from Velociraptor
→ Transfer to SIFT VM for deep analysis
```

---

## MODULE D — DFIR WITH SIFT WORKSTATION

### D.1 — Acquire Memory Dump

**From ESXi (VM snapshot → .vmem file):**
```bash
# On ESXi host via SSH:
# Snapshot the running VM first, then locate .vmem file
ls /vmfs/volumes/datastore1/WIN-TARGET-2/

# SCP the .vmem file to SIFT VM
scp /vmfs/volumes/datastore1/WIN-TARGET-2/WIN-TARGET-2-Snapshot1.vmem \
  analyst@172.16.10.70:/mnt/cases/WIN-TARGET-2.vmem
```

### D.2 — Memory Analysis with Volatility 3

```bash
# SSH into SIFT VM
ssh analyst@172.16.10.70

cd /mnt/cases/

# List processes
vol -f WIN-TARGET-2.vmem windows.pslist.PsList

# Check for hidden processes (malfind)
vol -f WIN-TARGET-2.vmem windows.malfind.Malfind

# Network connections at time of dump
vol -f WIN-TARGET-2.vmem windows.netscan.NetScan

# Command history
vol -f WIN-TARGET-2.vmem windows.cmdline.CmdLine

# Dump LSASS credentials
vol -f WIN-TARGET-2.vmem windows.lsadump.Lsadump

# Find injected code
vol -f WIN-TARGET-2.vmem windows.malfind.Malfind --dump

# Check registry hives
vol -f WIN-TARGET-2.vmem windows.registry.hivelist.HiveList

# Find files in memory
vol -f WIN-TARGET-2.vmem windows.filescan.FileScan | grep -i "mimikatz\|temp\|downloads"

# Dump a specific file from memory
vol -f WIN-TARGET-2.vmem windows.dumpfiles.DumpFiles --virtaddr 0xADDRESS
```

### D.3 — Disk Analysis with Autopsy / Sleuth Kit

```bash
# Mount VMDK read-only (after exporting from ESXi)
sudo mkdir /mnt/evidence
sudo mount -o ro,offset=$((2048*512)) /path/to/WIN-TARGET-2.vmdk /mnt/evidence

# List all files modified in last 24h
find /mnt/evidence -newer /mnt/evidence/Windows/System32/ntdll.dll \
  -ls 2>/dev/null | sort -k8,8

# Find executables in suspicious locations
find /mnt/evidence/Windows/Temp -type f -name "*.exe" -o -name "*.dll"

# Check prefetch files (execution evidence)
ls -la /mnt/evidence/Windows/Prefetch/

# For GUI analysis — open Autopsy
autopsy &
# New Case → Add data source → select VMDK
```

### D.4 — Timeline Analysis with Plaso / log2timeline

```bash
# Create super-timeline from disk image
log2timeline.py \
  --storage-file /mnt/cases/WIN-TARGET-2-timeline.plaso \
  /mnt/evidence

# Filter and export to CSV
psort.py \
  -z UTC \
  -o l2tcsv \
  /mnt/cases/WIN-TARGET-2-timeline.plaso \
  > /mnt/cases/timeline.csv

# Search for attack artifacts in timeline
grep -i "mimikatz\|lsass\|psexec\|evil-winrm\|bloodhound" /mnt/cases/timeline.csv

# Show only events from attack time window
awk -F',' '$1 >= "2026-05-06 10:00:00" && $1 <= "2026-05-06 12:00:00"' \
  /mnt/cases/timeline.csv | head -100
```

### D.5 — Browser / Artifacts on Linux Target

```bash
# SSH into Linux Target post-compromise analysis
ssh labuser@172.16.30.10

# Check bash history
cat ~/.bash_history
cat /root/.bash_history

# Check auth logs
sudo cat /var/log/auth.log | grep -E "Failed|Accepted|Invalid"

# Check running crons
crontab -l
cat /etc/cron.d/*

# Check SUID files (privilege escalation)
find / -perm -4000 -type f 2>/dev/null

# Check /tmp for dropped files
ls -la /tmp/

# Check last logins
last -20
lastlog

# Check open files (for backdoor)
sudo lsof -i
sudo netstat -tupln

# Collect all auth logs for analysis
sudo cp /var/log/auth.log /mnt/cases/linux-auth.log
sudo cp /var/log/syslog /mnt/cases/linux-syslog.log
```

---

## MODULE E — OPENCTI THREAT INTELLIGENCE

### E.1 — Search for IOCs in OpenCTI

```
URL: http://10.30.40.50:8080
Login: admin@opencti.io

1. Search → type attacker IP: 172.16.99.10 (or real attacker IP)
2. Observations → Indicators → search for file hashes from Mimikatz
3. Arsenal → Malware → search "mimikatz"
4. Arsenal → Attack Patterns → search "Kerberoasting" → T1558.003
   → Shows related tools, campaigns, threat actors
```

### E.2 — Add Incident IOCs to OpenCTI

```
1. Analysis → Reports → Create new Report
   Title: "SOC Lab Incident - Kerberoasting - 2026-05-06"
   Type: Incident

2. Add entities to report:
   - Attack Pattern: T1558.003 (Kerberoasting)
   - Tool: Impacket
   - Observable: IP 172.16.99.10
   - Observable: Hash (from Mimikatz binary)
   - Vulnerability: Weak Kerberos service account password

3. Export as STIX 2.1 for sharing:
   Report → Export → STIX 2.1 JSON
```

### E.3 — View ATT&CK Navigator Coverage

```
URL: http://10.30.40.50:4242

1. Create new layer
2. Mark techniques used in your lab scenarios:
   - T1046  — Network Service Scanning (Nmap)
   - T1069.002 — Domain Groups (BloodHound)
   - T1558.003 — Kerberoasting
   - T1003.001 — LSASS Memory (Mimikatz)
   - T1550.002 — Pass-the-Hash
   - T1110   — Brute Force
   - T1021.006 — WinRM (Evil-WinRM)
   - T1021.002 — SMB (Lateral Movement)
3. Color-code: Red = Attacked, Green = Detected
4. Export as SVG or JSON for report
```

---

## MODULE F — SURICATA ALERT ANALYSIS

### F.1 — Live Suricata Alerts

```bash
# SSH into Suricata VM
ssh admin@172.16.10.40

# Watch live alerts
sudo tail -f /var/log/suricata/eve.json | jq '.'

# Filter only alerts (not DNS/flow)
sudo tail -f /var/log/suricata/eve.json | \
  jq 'select(.event_type=="alert") | {
    timestamp: .timestamp,
    src_ip: .src_ip,
    dest_ip: .dest_ip,
    dest_port: .dest_port,
    alert: .alert.signature,
    severity: .alert.severity,
    category: .alert.category
  }'

# Count alerts by signature
sudo jq -r 'select(.event_type=="alert") | .alert.signature' \
  /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head 20

# Count by source IP
sudo jq -r 'select(.event_type=="alert") | .src_ip' \
  /var/log/suricata/eve.json | sort | uniq -c | sort -rn

# DNS queries from targets (C2 beacon hunting)
sudo tail -f /var/log/suricata/eve.json | \
  jq 'select(.event_type=="dns" and .dns.type=="query") | .dns.rrname'
```

### F.2 — Update Suricata Rules

```bash
# Update Emerging Threats rules
sudo suricata-update

# Add custom rule for a new IOC
sudo nano /etc/suricata/rules/local.rules

# Example: Alert on specific hash in HTTP
alert http any any -> any any (msg:"Malware Hash in HTTP"; \
  http.uri; content:"mimikatz"; \
  sid:1000010; rev:1;)

# Reload rules without restart
sudo kill -USR2 $(pidof suricata)

# Test rule syntax
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

---

*Continue in Part 4: SOAR Automation, Playbooks & Final Checklist*
