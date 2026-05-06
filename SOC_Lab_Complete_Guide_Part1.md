# SOC LAB — ZERO TO HERO OPERATIONAL GUIDE
## Part 1: Lab Overview, Access & Health Checks

> **Lab Status:** Already implemented and running.
> **Goal of this guide:** Work WITH the lab from first login to last action.

---

## QUICK REFERENCE — ACCESS POINTS

| Service | URL (from School Network) | Internal IP | Credentials |
|---|---|---|---|
| ESXi Management | https://10.30.40.19 | — | root / [esxi pass] |
| pfSense WebUI | https://10.30.40.50 | 172.16.10.1 | admin / [pfsense pass] |
| Kibana SIEM | http://10.30.40.50:5601 | 172.16.10.10:5601 | elastic / [elk pass] |
| TheHive 5 | http://10.30.40.50:9000 | 172.16.10.20:9000 | admin@thehive.local |
| Cortex | http://10.30.40.50:9001 | 172.16.10.20:9001 | admin |
| Shuffle SOAR | http://10.30.40.50:3001 | 172.16.10.90:3001 | admin@shuffler.io |
| OpenCTI | http://10.30.40.50:8080 | 172.16.10.80:8080 | admin@opencti.io |
| Velociraptor | https://10.30.40.50:8000 | 172.16.10.50:8000 | admin |
| ATT&CK Navigator | http://10.30.40.50:4242 | 172.16.10.80:4242 | no auth |

---

## STEP 1 — VERIFY THE LAB IS HEALTHY (Run First Every Session)

### 1.1 Check All VMs Are Running (ESXi)
```
1. Open browser → https://10.30.40.19
2. Login as root
3. Go to Virtual Machines
4. Confirm ALL 13 VMs are powered ON:
   - pfSense 2.8.1
   - ELK Stack (SIEM)   → 172.16.10.10
   - TheHive 5 + Cortex → 172.16.10.20
   - Suricata IDS       → 172.16.10.40
   - Velociraptor       → 172.16.10.50
   - Forensics SIFT     → 172.16.10.70
   - OpenCTI            → 172.16.10.80
   - AI/SOAR VM         → 172.16.10.90
   - DC01 (AD)          → 172.16.20.10
   - WIN-TARGET-1       → 172.16.20.30
   - WIN-TARGET-2       → 172.16.20.31
   - Linux Target       → 172.16.30.10
   - Kali Linux         → 172.16.99.10
```

### 1.2 Check ELK Stack Health
SSH into ELK VM:
```bash
ssh admin@172.16.10.10

# Check all 3 services
sudo systemctl status elasticsearch kibana logstash

# Check Elasticsearch cluster health
curl -u elastic:MOT_DE_PASSE http://172.16.10.10:9200/_cluster/health?pretty

# Expected: "status" : "green" or "yellow"
# Count indices
curl -u elastic:MOT_DE_PASSE http://172.16.10.10:9200/_cat/indices?v
```

### 1.3 Check Suricata IDS
```bash
ssh admin@172.16.10.40
sudo systemctl status suricata
sudo tail -20 /var/log/suricata/eve.json
sudo tail -20 /var/log/suricata/suricata.log
```

### 1.4 Check Velociraptor
```bash
ssh admin@172.16.10.50
ps aux | grep velociraptor
# Or if running as service:
sudo systemctl status velociraptor
# Web UI check:
curl -k https://172.16.10.50:8000
```

### 1.5 Check Shuffle SOAR + Ollama
```bash
ssh admin@172.16.10.90
cd /opt/shuffle
sudo docker-compose ps    # All containers should be "Up"

# Check Ollama
curl http://localhost:11434/api/tags
# Expected: JSON with llama3:8b listed
```

### 1.6 Check OpenCTI + TheHive
```bash
ssh admin@172.16.10.80
cd /opt/opencti
sudo docker-compose ps

ssh admin@172.16.10.20
cd /opt/thehive
sudo docker-compose ps
```

### 1.7 Check Log Flow (Logs Arriving in Kibana)
```
1. Open http://10.30.40.50:5601
2. Login with elastic credentials
3. Go to Discover
4. Select index pattern: logs-winlogbeat-*
5. Set time range: Last 15 minutes
6. You should see Windows events from DC01, WIN-01, WIN-02
7. Switch to: logs-suricata-*  → Suricata network alerts
8. Switch to: logs-filebeat-*  → Linux target logs
```

If logs are NOT arriving → Troubleshoot agents (see Part 3).

---

## STEP 2 — UNDERSTAND THE LAB NETWORK

```
SCHOOL NETWORK (10.30.40.0/22)
          |
      pfSense (10.30.40.50 WAN / NAT)
          |
    LAB-SWITCH (vSwitch1 — no uplink)
    ┌─────────────────────────────────┐
    │  VLAN 10 — MGMT 172.16.10.0/24 │  ← SOC Tools (ELK, TheHive, Velociraptor...)
    │  VLAN 20 — CORP 172.16.20.0/24 │  ← AD Domain (DC01, WIN-01, WIN-02)
    │  VLAN 30 — DMZ  172.16.30.0/24 │  ← Linux Target (SSH, Apache, FTP)
    │  VLAN 99 — ATCK 172.16.99.0/24 │  ← Kali Linux attacker
    │  MONITOR-PG  (4095, no IP)     │  ← Suricata sniffing NIC
    └─────────────────────────────────┘
```

**Traffic Rules:**
- Kali (99) → CORP (20) and DMZ (30): ALLOWED (attack simulation)
- Targets → VLAN 10 port 5044: ALLOWED (log shipping to Logstash)
- CORP/DMZ → VLAN 99: BLOCKED (targets cannot reach attacker)
- VLAN 10 → Internet: BLOCKED (SOC tools isolated)

---

## STEP 3 — DAILY SOC ANALYST WORKFLOW (Before Any Attack)

Every session, open these dashboards in order:

### 3.1 Kibana Security Dashboard
```
URL: http://10.30.40.50:5601
1. Security → Overview         → Check open alerts count
2. Security → Alerts           → Review any pending detections
3. Security → Rules            → Verify all rules are ENABLED
4. Discover → logs-*           → Raw log search
```

### 3.2 TheHive — Case Management
```
URL: http://10.30.40.50:9000
1. Login → Dashboard           → Open cases count
2. Cases → All cases           → Review active investigations
3. Alerts → Incoming alerts    → Check auto-created alerts from ELK
```

### 3.3 Shuffle SOAR — Automation Status
```
URL: http://10.30.40.50:3001
1. Workflows → Check last runs → Verify triage workflow executed
2. Apps → Check integrations  → ELK, TheHive, Ollama, OpenCTI connected
```

### 3.4 Velociraptor — Endpoint Status
```
URL: https://10.30.40.50:8000
1. Clients → View all clients  → All 3 agents should be ONLINE:
   - WIN-TARGET-1 (172.16.20.30)
   - WIN-TARGET-2 (172.16.20.31)
   - Linux Target  (172.16.30.10)
2. Hunts → Recent hunts        → Review last hunt results
```

### 3.5 OpenCTI — Threat Intelligence
```
URL: http://10.30.40.50:8080
1. Dashboard → Recent entities → New IOCs imported?
2. Analysis → Reports          → Any new threat reports?
3. Arsenal → MITRE ATT&CK     → Verify framework is loaded
```

---

## STEP 4 — ENABLING ELASTIC SECURITY DETECTION RULES

Before running any attack scenario, make sure detection rules are active:

```
1. Kibana → Security → Rules → Detection rules (SIEM)
2. Search and ENABLE these rules:
```

| Rule Name | Event | Attack |
|---|---|---|
| Kerberos Traffic from Unusual Process | Event 4769 RC4 | Kerberoasting |
| LSASS Memory Read via Process Access | Sysmon 10 | Mimikatz |
| Mimikatz PowerShell Module Activity | Sysmon 1 | Credential Dump |
| Pass-the-Hash Detected | Event 4624 Type 3 | PTH |
| BloodHound AD Discovery | Event 4662 + LDAP | Recon |
| Multiple Failed Logon Attempts | Event 4625 x10+ | Brute Force |
| Lateral Movement via SMB | Event 4648 | Lateral Move |
| Evil-WinRM Remote Shell | Event 4624 + Sysmon 3/22 | Remote Shell |

```bash
# Also enable Sigma-based rules via KQL (run on ELK VM):
pip3 install sigmatools
git clone https://github.com/SigmaHQ/sigma.git /opt/sigma

# Convert Mimikatz rule to Elasticsearch KQL:
sigma convert -t es-qs -p ecs_windows \
  /opt/sigma/rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml

# Output example → paste into Kibana Rule as KQL:
# process.command_line:(*sekurlsa* OR *lsadump* OR *privilege::debug*)
```

---

*Continue in Part 2: Attack Scenarios (all 5 attacks with full commands)*
