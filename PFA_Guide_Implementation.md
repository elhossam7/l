**PROJET FIN D'ANNEE SOC / Active Directory / DFIR / Threat Hunting / AI Automation**

Guide Complet d'Implementation du Lab — v2.0

| Infrastructure — Dell PowerEdge R750 — VMware ESXi 7.0 | Reseau — LAB-SWITCH VLAN 10/20/30/99 — lab.local |
| --- | --- |
| VMs — 13 machines virtuelles — 88 GB RAM / 1010 GB | Date — Avril 2026 |

---

# 1. Vue d'Ensemble du Projet

Ce projet de fin d'annee consiste a deployer un laboratoire de securite informatique complet simulant un environnement d'entreprise reel. L'objectif est de couvrir cinq domaines fondamentaux de la cybersecurite :

> **Objectifs Principaux**
> - **SOC** : Collecte, correlation et analyse des evenements via ELK Stack + Elastic Security
> - **Active Directory** : Gestion des identites, Kerberos, GPO, simulation d'attaques AD
> - **DFIR** : Investigation numerique, analyse forensique, reponse aux incidents
> - **Threat Hunting** : Detection proactive via Velociraptor, Sigma Rules, OpenCTI, ATT&CK
> - **AI Automation** : Triage automatise des alertes via Shuffle SOAR + Ollama LLM local

## 1.1 Architecture Globale — Reseau VLAN

Le lab est heberge sur un serveur Dell PowerEdge R750 sous VMware ESXi 7.0. Un vSwitch interne (LAB-SWITCH) segmente le trafic en 5 zones via pfSense. Aucun uplink physique — le lab est completement isole du reseau de l'ecole sauf via pfSense (WAN NAT).

### Tableau des VMs

| VM | VLAN | IP | RAM | vCPU | Disque | Role |
| --- | --- | --- | --- | --- | --- | --- |
| pfSense 2.8.1 | ALL | .x.1 / 10.30.40.50 | 2 GB | 1 | 20 GB | Firewall / Router / NAT |
| ELK Stack (SIEM) | 10 | 172.16.10.10 | 16 GB | 4 | 200 GB | Elasticsearch, Kibana, Logstash |
| TheHive 5 + Cortex | 10 | 172.16.10.20 | 8 GB | 4 | 100 GB | Case management + Analyzers |
| Suricata IDS | 10 | 172.16.10.40 | 4 GB | 2 | 40 GB | Detection intrusion reseau |
| Velociraptor | 10 | 172.16.10.50 | 4 GB | 2 | 60 GB | Endpoint hunting + Forensics live |
| Forensics SIFT | 10 | 172.16.10.70 | 8 GB | 4 | 100 GB | Volatility, Autopsy, SIFT |
| OpenCTI | 10 | 172.16.10.80 | 8 GB | 4 | 80 GB | Threat Intel, IOC, ATT&CK Navigator |
| AI / SOAR VM | 10 | 172.16.10.90 | 16 GB | 6 | 150 GB | Shuffle SOAR + Ollama Llama3 |
| DC01 (Active Directory) | 20 | 172.16.20.10 | 4 GB | 2 | 80 GB | AD DS, DNS, Kerberos, lab.local |
| WIN-TARGET-1 | 20 | 172.16.20.30 | 4 GB | 2 | 60 GB | alice.dupont — Sysmon + Winlogbeat |
| WIN-TARGET-2 | 20 | 172.16.20.31 | 4 GB | 2 | 60 GB | bob.admin (DA) — Pass-the-Hash lab |
| Linux Target | 30 | 172.16.30.10 | 4 GB | 2 | 40 GB | SSH, Apache, FTP — Elastic Agent |
| Kali Linux | 99 | 172.16.99.10 | 8 GB | 4 | 80 GB | BloodHound, MSF, Mimikatz, Impacket |
| **TOTAL** | — | — | **88 GB** | **41** | **1010 GB** | **13 machines** |

### Tableau des VLANs (LAB-SWITCH)

| Port Group | VLAN ID | Reseau | Role |
| --- | --- | --- | --- |
| MGMT-PG | 10 | 172.16.10.0/24 | Outils SOC, SIEM, Threat Hunting, AI |
| CORP-PG | 20 | 172.16.20.0/24 | AD, cibles Windows |
| DMZ-PG | 30 | 172.16.30.0/24 | Cible Linux exposee |
| ATTACKER-PG | 99 | 172.16.99.0/24 | Machine attaquante Kali |
| MONITOR-PG | 4095 | Aucune IP | NIC Suricata promiscueux |

---

# 2. Prerequis et Preparation

## 2.1 Configuration ESXi

Avant de creer les VMs, configurer l'hyperviseur :

- Acceder a l'interface ESXi : https://10.30.40.19 (IP Management)
- Activer SSH sur l'hote ESXi pour la gestion a distance
- Creer **vSwitch0** avec uplink vmnic0 → WAN-PG (acces reseau ecole)
- Creer **vSwitch1 (LAB-SWITCH)** SANS uplink physique — mode promiscueux global
- Creer les 5 Port Groups sur LAB-SWITCH : MGMT-PG (10), CORP-PG (20), DMZ-PG (30), ATTACKER-PG (99), MONITOR-PG (4095)
- Configurer les datastores : minimum 1100 GB disponibles

> **IMPORTANT — Securite vSwitch**
> Le LAB-SWITCH ne doit JAMAIS avoir d'uplink physique.
> Les attaques simulees restent confinement dans le lab.
> Activer "Allow promiscuous mode" uniquement sur MONITOR-PG (VLAN 4095) pour Suricata.

## 2.2 ISOs et Licences Necessaires

| Systeme | Version | Remarque |
| --- | --- | --- |
| pfSense | 2.8.1-RELEASE | netgate.com/downloads |
| Windows Server 2022 | Evaluation 180j | ISO Microsoft Evaluation Center |
| Windows 10 Pro | 22H2 ou superieur | ISO Microsoft — 2 licences |
| Ubuntu Server 22.04 LTS | 22.04.x | ubuntu.com/download/server |
| Kali Linux 2024.x | Latest | kali.org/get-kali — amd64 |
| SIFT Workstation | Ubuntu 22.04 base | github.com/teamdfir/sift-saltstack |

---

# 3. Phase 1 — pfSense Firewall / Router (Semaine 1)

## 3.1 Installation pfSense (172.16.10.1 / WAN: 10.30.40.50)

pfSense est la piece centrale du lab. Il route entre tous les VLANs et fournit le NAT vers le reseau de l'ecole.

- Creer la VM : 2 GB RAM, 1 vCPU, 20 GB
- Ajouter **6 interfaces reseau** : em0 (WAN-PG), em1 (MGMT-PG), em2 (CORP-PG), em3 (DMZ-PG), em4 (ATTACKER-PG), em5 (MONITOR-PG)
- Installer pfSense 2.8.1 depuis l'ISO

### Configuration des Interfaces

Depuis la console pfSense (menu 2 — Set interface IP) :

| Interface | Adaptateur | IP / Mode |
| --- | --- | --- |
| WAN | em0 | DHCP (recoit 10.30.40.50 du reseau ecole) |
| LAN (MGMT) | em1 | 172.16.10.1/24 |
| OPT1 (CORP) | em2 | 172.16.20.1/24 |
| OPT2 (DMZ) | em3 | 172.16.30.1/24 |
| OPT3 (ATTACKER) | em4 | 172.16.99.1/24 |
| OPT4 (MONITOR) | em5 | Aucune IP |

### Regles de Firewall pfSense

Configurer dans WebUI (https://172.16.10.1) > Firewall > Rules :

| Source | Destination | Port | Action | Commentaire |
| --- | --- | --- | --- | --- |
| VLAN 99 (Kali) | VLAN 20 CORP | Any | ALLOW | Simulation d'attaques |
| VLAN 99 (Kali) | VLAN 30 DMZ | Any | ALLOW | Simulation d'attaques |
| VLAN 99 (Kali) | WAN | Any | ALLOW | Telechargements outils |
| VLAN 20/30 | VLAN 10 :5044 | TCP 5044 | ALLOW | Beats → Logstash |
| VLAN 20/30 | VLAN 10 :8000 | TCP 8000 | ALLOW | Velociraptor agents |
| VLAN 10 | VLAN 20/30 | Any | ALLOW | Acces analyste |
| School | VLAN 10 :5601 | TCP 5601 | ALLOW | Kibana (NAT) |
| School | VLAN 10 :9000 | TCP 9000 | ALLOW | TheHive (NAT) |
| School | VLAN 10 :3001 | TCP 3001 | ALLOW | Shuffle SOAR (NAT) |
| School | VLAN 10 :8080 | TCP 8080 | ALLOW | OpenCTI (NAT) |
| School | VLAN 10 :8000 | TCP 8000 | ALLOW | Velociraptor (NAT) |
| VLAN 20/30 | VLAN 99 | Any | **BLOCK** | Cibles ne peuvent atteindre attaquant |
| VLAN 10 | WAN | Any | **BLOCK** | MGMT isole d'internet |

### DHCP Servers (optionnel)

Activer DHCP sur chaque interface VLAN pour les VMs si vous ne souhaitez pas configurer les IPs manuellement.

---

# 4. Phase 2 — Infrastructure de Base (Semaine 1-2)

## 4.1 Active Directory Domain Controller (DC01 — 172.16.20.10)

### Installation Windows Server 2022

- Creer la VM : 4 GB RAM, 2 vCPU, 80 GB — interface sur CORP-PG (VLAN 20)
- Installer Windows Server 2022 (Desktop Experience recommande)
- Configurer l'IP fixe : 172.16.20.10 / 255.255.255.0 — Passerelle : 172.16.20.1 — DNS : 127.0.0.1

### Promotion en Controleur de Domaine

```powershell
# Installer le role ADDS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promouvoir en DC (nouvelle foret)
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -InstallDns:$true `
  -Force:$true
```

### Creation des Comptes et SPNs Vulnerables

```powershell
# Creer les utilisateurs du domaine
New-ADUser -Name "alice.dupont" -SamAccountName "alice.dupont" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
New-ADUser -Name "bob.admin" -SamAccountName "bob.admin" -AccountPassword (ConvertTo-SecureString "Admin@123" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true

# Ajouter bob.admin en tant que Domain Admin
Add-ADGroupMember -Identity "Domain Admins" -Members "bob.admin"

# Creer un compte de service avec SPN (vulnerable Kerberoasting)
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -AccountPassword (ConvertTo-SecureString "Service123!" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/dc01.lab.local:1433"}

# Configurer les GPO Sysmon/Winlogbeat (voir section 5.2)
```

## 4.2 Windows Target 1 (alice.dupont — 172.16.20.30)

- Creer la VM : 4 GB RAM, 2 vCPU, 60 GB — interface sur CORP-PG (VLAN 20)
- Installer Windows 10 Pro — IP fixe 172.16.20.30 — DNS : 172.16.20.10
- Joindre le domaine lab.local avec le compte alice.dupont
- Installer Sysmon + Winlogbeat (voir section 5)
- Installer l'agent Velociraptor (voir section 9.2)

## 4.3 Windows Target 2 (bob.admin — 172.16.20.31)

Configuration identique a Target 1, avec le compte bob.admin (Domain Admin). Ce poste simule un mouvement lateral apres compromission initiale.

- Creer la VM : 4 GB RAM, 2 vCPU, 60 GB — interface sur CORP-PG (VLAN 20)
- Installer Windows 10 Pro — IP fixe 172.16.20.31
- Joindre le domaine, connecter avec bob.admin
- Conserver des artefacts d'authentification pour les scenarios Pass-the-Hash

## 4.4 Linux Target (172.16.30.10)

- Creer la VM : 4 GB RAM, 2 vCPU, 40 GB — interface sur DMZ-PG (VLAN 30)
- Installer Ubuntu Server 22.04 — IP fixe 172.16.30.10 — Passerelle : 172.16.30.1

```bash
# Installer les services exposes (vulnerables)
sudo apt update && sudo apt install -y openssh-server apache2 vsftpd

# Configurer SSH avec authentification par mot de passe (lab uniquement)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Creer un utilisateur faible pour les scenarios brute-force
sudo useradd -m -s /bin/bash labuser
echo "labuser:password123" | sudo chpasswd

# Configurer vsftpd
sudo sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf
sudo systemctl enable vsftpd && sudo systemctl start vsftpd

# Installer Elastic Agent (voir section 5.4)
# Installer Velociraptor agent (voir section 9.2)
```

---

# 5. Phase 3 — ELK Stack SIEM (Semaine 2-3)

## 5.1 Installation ELK Stack (172.16.10.10)

L'ELK Stack est le coeur du SOC. Elle centralise tous les logs et fournit la detection via Elastic Security.

### Prerequisites Systeme

```bash
# Mise a jour du systeme (Ubuntu Server 22.04)
sudo apt update && sudo apt upgrade -y
sudo apt install -y apt-transport-https ca-certificates curl gnupg wget

# Ajouter la cle GPG Elastic
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Ajouter le depot Elastic 8.x
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
```

### Installation Elasticsearch

```bash
sudo apt install -y elasticsearch

# Configurer /etc/elasticsearch/elasticsearch.yml
sudo nano /etc/elasticsearch/elasticsearch.yml
```

```yaml
cluster.name: soc-lab
node.name: elk-node-1
network.host: 172.16.10.10
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.http.ssl.enabled: false   # Lab uniquement
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now elasticsearch
# Tester : curl -u elastic:MOT_DE_PASSE http://172.16.10.10:9200
```

### Installation Kibana

```bash
sudo apt install -y kibana
sudo nano /etc/kibana/kibana.yml
```

```yaml
server.port: 5601
server.host: "172.16.10.10"
server.name: "soc-kibana"
elasticsearch.hosts: ["http://172.16.10.10:9200"]
elasticsearch.username: "kibana_system"
# elasticsearch.password: "LE_MOT_DE_PASSE_ICI"
```

```bash
# Generer un token enrollment pour Kibana
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system
sudo systemctl enable --now kibana
# Interface : http://172.16.10.10:5601
```

### Installation Logstash

```bash
sudo apt install -y logstash
sudo nano /etc/logstash/conf.d/beats-input.conf
```

```
input {
  beats {
    port => 5044
    host => "172.16.10.10"
  }
}

filter {
  if [agent][type] == "winlogbeat" {
    mutate { add_tag => ["windows", "winlogbeat"] }
  }
  if [agent][type] == "filebeat" {
    mutate { add_tag => ["linux", "filebeat"] }
  }
  if "suricata" in [tags] {
    mutate { add_tag => ["ids", "suricata"] }
  }
}

output {
  elasticsearch {
    hosts => ["http://172.16.10.10:9200"]
    user => "elastic"
    password => "MOT_DE_PASSE_ELASTIC"
    index => "logs-%{[agent][type]}-%{+YYYY.MM.dd}"
  }
}
```

```bash
sudo systemctl enable --now logstash

# Ouvrir les ports UFW
sudo ufw allow 9200/tcp   # Elasticsearch
sudo ufw allow 5601/tcp   # Kibana
sudo ufw allow 5044/tcp   # Logstash Beats
sudo ufw enable
```

## 5.2 Installation Sysmon sur Windows (Targets 1 et 2)

> **Events Sysmon Critiques**
> - Event ID 1 — Process Creation (outils offensifs)
> - Event ID 3 — Network Connection (lateral movement)
> - Event ID 7 — Image Loaded (DLL injection)
> - Event ID 10 — Process Access (Mimikatz, LSASS dump)
> - Event ID 11 — File Created (malware dropped)
> - Event ID 22 — DNS Query (C2 beaconing)

```powershell
# Sur chaque Windows Target — PowerShell Administrateur
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# Telecharger la config SwiftOnSecurity
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Installer Sysmon
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
Get-Service Sysmon64
```

## 5.3 Installation Winlogbeat (Windows → Logstash)

```powershell
# Telecharger Winlogbeat 8.x
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.13.0-windows-x86_64.zip" -OutFile "C:\Tools\winlogbeat.zip"
Expand-Archive -Path "C:\Tools\winlogbeat.zip" -DestinationPath "C:\Program Files\Winlogbeat"
cd "C:\Program Files\Winlogbeat\winlogbeat-8.13.0-windows-x86_64"
notepad winlogbeat.yml
```

```yaml
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
  - name: Microsoft-Windows-Windows Defender/Operational

output.logstash:
  hosts: ["172.16.10.10:5044"]

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
  name: winlogbeat
  keepfiles: 7
```

```powershell
.\winlogbeat.exe test config -c winlogbeat.yml -e
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

## 5.4 Installation Elastic Agent sur Linux Target

```bash
# Sur la VM Linux Target (172.16.30.10)
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.0-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.13.0-linux-x86_64.tar.gz
cd elastic-agent-8.13.0-linux-x86_64

# Installer et connecter a ELK Fleet (ou directement Logstash)
sudo ./elastic-agent install \
  --url=https://172.16.10.10:8220 \
  --enrollment-token=TOKEN_ICI

# Activer auditd pour la collecte des evenements systeme
sudo apt install -y auditd
sudo systemctl enable --now auditd
```

---

# 6. Phase 4 — Suricata IDS Reseau (Semaine 3)

## 6.1 Installation Suricata (172.16.10.40)

Suricata analyse tout le trafic inter-VLAN via la NIC connectee a MONITOR-PG (VLAN 4095 — mode promiscueux).

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install -y suricata

# Identifier la NIC de monitoring (celle sur MONITOR-PG)
ip a   # ex: ens36

# Configurer /etc/suricata/suricata.yaml
sudo nano /etc/suricata/suricata.yaml
```

```yaml
af-packet:
  - interface: ens36
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

vars:
  address-groups:
    HOME_NET: "[172.16.0.0/16]"

outputs:
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - dns
        - http
        - tls
        - ssh
        - flow
```

```bash
sudo suricata-update   # Mettre a jour les regles Emerging Threats
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl enable --now suricata
```

### Regles de Detection Personnalisees

```bash
sudo nano /etc/suricata/rules/local.rules
```

```text
# Nmap SYN Scan
alert tcp any any -> $HOME_NET any (msg:"NMAP SYN Scan"; flags:S,12; threshold: type threshold, track by_src, count 20, seconds 5; sid:1000001; rev:1;)

# Brute Force SSH
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server; threshold: type threshold, track by_src, count 10, seconds 30; sid:1000002; rev:1;)

# Kerberoasting (TGS-REQ RC4)
alert dns any any -> any any (msg:"Possible Kerberoasting - TGS RC4"; content:"|17 00|"; sid:1000003; rev:1;)

# Pass-the-Hash SMB
alert smb any any -> $HOME_NET 445 (msg:"Possible Pass-the-Hash SMB"; flow:to_server,established; sid:1000004; rev:1;)

# BloodHound LDAP Recon
alert tcp any any -> $HOME_NET 389 (msg:"LDAP Recon - BloodHound"; threshold: type threshold, track by_src, count 50, seconds 10; sid:1000005; rev:1;)
```

```bash
sudo kill -USR2 $(pidof suricata)   # Recharger les regles sans arret
```

### Integration Suricata → ELK via Filebeat

```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install -y filebeat

sudo filebeat modules enable suricata
sudo nano /etc/filebeat/modules.d/suricata.yml
```

```yaml
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
```

```bash
sudo nano /etc/filebeat/filebeat.yml
```

```yaml
output.logstash:
  hosts: ["172.16.10.10:5044"]
setup.kibana:
  host: "172.16.10.10:5601"
```

```bash
sudo systemctl enable --now filebeat
```

---

# 7. Phase 5 — Machine Attaquante Kali Linux (Semaine 3-4)

La machine Kali Linux (172.16.99.10) est sur VLAN 99 — completement isolee des outils de defense.

## 7.1 Installation et Configuration Kali

- Creer la VM : 8 GB RAM, 4 vCPU, 80 GB — interface sur ATTACKER-PG (VLAN 99)
- IP fixe : 172.16.99.10 — Passerelle : 172.16.99.1

```bash
sudo apt update && sudo apt full-upgrade -y

sudo apt install -y \
  nmap hydra crackmapexec impacket-scripts \
  bloodhound neo4j smbclient python3-bloodhound \
  evil-winrm john hashcat metasploit-framework

# Configurer /etc/hosts pour resoudre lab.local
echo "172.16.20.10  dc01.lab.local  lab.local" | sudo tee -a /etc/hosts
echo "172.16.20.30  win01.lab.local" | sudo tee -a /etc/hosts
echo "172.16.20.31  win02.lab.local" | sudo tee -a /etc/hosts
echo "172.16.30.10  linux01.lab.local" | sudo tee -a /etc/hosts

# Verifier la connectivite via pfSense
ping -c 3 172.16.20.10   # DC01
ping -c 3 172.16.30.10   # Linux Target
```

## 7.2 Scenarios d'Attaques

> **Scenario 1 — Reconnaissance Initiale**
> - Objectif : Cartographier le domaine AD
> - Outils : Nmap, BloodHound
> - `nmap -sV -sC 172.16.20.0/24`
> - `bloodhound-python -u alice.dupont -p Password123 -d lab.local -ns 172.16.20.10 --zip`
> - Detection : Suricata alert (LDAP recon) + Event ID 4662

> **Scenario 2 — Kerberoasting**
> - Objectif : Extraire et cracker les tickets Kerberos des comptes de service
> - Outils : Impacket GetUserSPNs.py
> - `GetUserSPNs.py lab.local/alice.dupont:Password123 -dc-ip 172.16.20.10 -request`
> - `hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt`
> - Detection : Event ID 4769 (TGS-REQ RC4) sur DC01

> **Scenario 3 — Pass-the-Hash**
> - Objectif : Se connecter avec le hash NTLM sans le mot de passe
> - Outils : Mimikatz + CrackMapExec
> - `mimikatz # sekurlsa::logonpasswords`
> - `crackmapexec smb 172.16.20.31 -u bob.admin -H <hash_ntlm>`
> - Detection : Event ID 4624 (Logon Type 3) + Sysmon Event 10 (LSASS access)

> **Scenario 4 — Brute Force SSH/SMB**
> - Objectif : Tester la resilience des mots de passe
> - Outils : Hydra, Nmap scripts
> - `hydra -l labuser -P /usr/share/wordlists/rockyou.txt ssh://172.16.30.10`
> - `hydra -l Administrator -P wordlist.txt smb://172.16.20.30`
> - Detection : Suricata alertes + Event ID 4625 (echecs connexion)

> **Scenario 5 — Lateral Movement (Evil-WinRM)**
> - Objectif : Obtenir un shell distant apres compromission
> - Outils : Evil-WinRM
> - `evil-winrm -i 172.16.20.31 -u bob.admin -p Admin@123`
> - Detection : Event ID 4624 + Sysmon Event 3/22

---

# 8. Phase 6 — Forensics VM / DFIR (Semaine 4)

## 8.1 Installation SIFT Workstation (172.16.10.70)

- Creer la VM : 8 GB RAM, 4 vCPU, 100 GB — interface sur MGMT-PG (VLAN 10)
- Installer Ubuntu Server 22.04 — IP fixe 172.16.10.70

```bash
# Installer SIFT via script officiel SANS
sudo apt update && sudo apt install -y git
git clone https://github.com/teamdfir/sift-saltstack sift-saltstack
cd sift-saltstack
sudo ./install.sh
# Outils installes : Volatility 3, Autopsy, Plaso/log2timeline, Sleuth Kit, Wireshark
```

## 8.2 Acquisition de Preuves via Snapshots VMware

```bash
# Depuis ESXi, prendre un snapshot d'une VM compromise
# Monter le VMDK sur la VM Forensics via SSH/SCP
# Exemple : monter le VMDK de WIN-TARGET-1
sudo mkdir /mnt/evidence
sudo mount -o ro /dev/sdb1 /mnt/evidence   # adapter selon le disque
```

## 8.3 Analyse Memoire avec Volatility 3

```bash
# Creer un dump memoire depuis ESXi (snapshot .vmem)
# Transporter le fichier .vmem vers la VM Forensics

# Analyser avec Volatility 3
vol -f memory.vmem windows.pslist.PsList
vol -f memory.vmem windows.netscan.NetScan
vol -f memory.vmem windows.cmdline.CmdLine
vol -f memory.vmem windows.lsadump.Lsadump   # Credentials LSASS
vol -f memory.vmem windows.malfind.Malfind    # Code inject
```

## 8.4 Analyse Timeline avec Plaso / log2timeline

```bash
# Creer une timeline complete du disque
log2timeline.py --storage-file timeline.plaso /mnt/evidence

# Analyser avec psort
psort.py -z UTC -o l2tcsv timeline.plaso > timeline.csv

# Filtrer les evenements suspects
grep -i "mimikatz\|lsass\|psexec" timeline.csv
```

---

# 9. Phase 7 — Threat Hunting (Semaine 5)

## 9.1 Velociraptor Server (172.16.10.50)

Velociraptor permet la chasse aux menaces en temps reel sur tous les endpoints du lab.

```bash
# Sur la VM Velociraptor (Ubuntu 22.04) — IP 172.16.10.50
wget https://github.com/Velocidex/velociraptor/releases/download/v0.7.0/velociraptor-v0.7.0-linux-amd64
chmod +x velociraptor-v0.7.0-linux-amd64
sudo mv velociraptor-v0.7.0-linux-amd64 /usr/local/bin/velociraptor

# Generer la configuration serveur
velociraptor config generate -i
# Repondre aux questions : frontend IP = 172.16.10.50, port = 8000

# Creer un paquet installeur pour les agents clients
velociraptor --config server.config.yaml debian client

# Demarrer le serveur
velociraptor --config server.config.yaml frontend &

# Interface web : https://172.16.10.50:8000
```

## 9.2 Deploiement des Agents Velociraptor

```bash
# Sur chaque machine cible (VLAN 20 et 30)
# Copier le paquet .deb (Linux) ou .msi (Windows) genere ci-dessus

# Linux Target
sudo dpkg -i velociraptor_client.deb
sudo systemctl enable --now velociraptor_client

# Windows Targets (PowerShell Admin)
msiexec /i velociraptor_client.msi /quiet
```

## 9.3 Hunts VQL (Velociraptor Query Language)

```sql
-- Lister tous les processus actifs sur tous les endpoints
SELECT Name, Pid, Ppid, CommandLine, Username
FROM pslist()
ORDER BY Name

-- Rechercher des connexions reseau suspectes
SELECT Laddr, Lport, Raddr, Rport, Status, Pid
FROM netstat()
WHERE Raddr != "0.0.0.0" AND Raddr != "::"

-- Chercher des fichiers Mimikatz ou outils offensifs
SELECT FullPath, Size, Mtime, Hash.MD5
FROM glob(globs="C:\\**\\mimikatz*", accessor="file")

-- Rechercher des persistances (Run keys)
SELECT Key, Name, Data
FROM read_reg_key(globs="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\**")
```

## 9.4 Integration Sigma Rules dans ELK

Sigma Rules fournit des regles de detection generiques mappees MITRE ATT&CK.

```bash
# Sur la VM ELK
pip3 install sigmatools

# Telecharger les regles Sigma
git clone https://github.com/SigmaHQ/sigma.git /opt/sigma

# Convertir une regle Sigma en requete Elasticsearch
sigma convert -t es-qs -p ecs_windows \
  /opt/sigma/rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml

# Resultat : requete KQL a copier dans Kibana Detection Engine
# Exemple output : process.command_line:(*sekurlsa* OR *lsadump* OR *privilege::debug*)
```

## 9.5 OpenCTI — Threat Intelligence Platform (172.16.10.80)

```bash
# Sur la VM OpenCTI (Ubuntu 22.04) — IP 172.16.10.80
# Installer Docker
sudo apt install -y docker.io docker-compose

# Cloner le depot OpenCTI
git clone https://github.com/OpenCTI-Platform/docker.git /opt/opencti
cd /opt/opencti

# Configurer .env (definir les mots de passe, UUID)
cp .env.sample .env
nano .env
# OPENCTI_ADMIN_EMAIL=admin@opencti.io
# OPENCTI_ADMIN_PASSWORD=votre_mot_de_passe
# OPENCTI_ADMIN_TOKEN=uuid-genere

docker-compose up -d
# Interface : http://172.16.10.80:8080

# ATT&CK Navigator (container supplementaire)
docker run -d -p 4242:80 --name attack-navigator \
  ghcr.io/mitre-attack/attack-navigator:latest
# Interface : http://172.16.10.80:4242
```

### Import du framework MITRE ATT&CK dans OpenCTI

```
1. Aller dans Settings > Connectors
2. Activer le connecteur "MITRE ATT&CK"
3. Lancer l'import (environ 10 minutes)
4. Les techniques sont maintenant disponibles pour le tagging des cas TheHive
```

---

# 10. Phase 8 — TheHive 5 + Cortex (Semaine 5-6)

## 10.1 Installation TheHive 5 (172.16.10.20)

TheHive gere les cas d'incidents. Cortex execute des analyseurs automatises (VirusTotal, reputation IP, etc.).

```bash
# Sur la VM TheHive (Ubuntu 22.04) — IP 172.16.10.20
sudo apt install -y docker.io docker-compose

# Creer docker-compose.yml
mkdir /opt/thehive && cd /opt/thehive
nano docker-compose.yml
```

```yaml
version: "3.8"
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  thehive:
    image: strangebee/thehive:5-latest
    depends_on:
      - elasticsearch
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1g
    volumes:
      - thehive_data:/opt/thp/thehive/data

  cortex:
    image: thehiveproject/cortex:3-latest
    ports:
      - "9001:9001"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - cortex_data:/var/docker/cortex/data

volumes:
  es_data:
  thehive_data:
  cortex_data:
```

```bash
docker-compose up -d

# TheHive : http://172.16.10.20:9000
# Cortex  : http://172.16.10.20:9001
# Login par defaut TheHive : admin@thehive.local / secret
```

## 10.2 Configuration des Analyzers Cortex

```
1. Aller dans Cortex : http://172.16.10.20:9001
2. Menu Organizations > Ajouter une organisation "SOC-LAB"
3. Menu Analyzers > Activer :
   - VirusTotal_GetReport (necessite une cle API gratuite)
   - AbuseIPDB (cle API gratuite)
   - URLhaus (sans cle)
   - MalwareBazaar (sans cle)
   - Shodan_Host (cle API gratuite)
4. Dans TheHive Settings > Cortex > Ajouter le serveur Cortex
```

## 10.3 Connexion TheHive ↔ ELK (Alertes Automatiques)

```bash
# Installer ElastAlert2 sur la VM ELK pour envoyer les alertes vers TheHive
pip3 install elastalert2

# Creer une regle ElastAlert
mkdir /opt/elastalert/rules
nano /opt/elastalert/rules/kerberoasting.yaml
```

```yaml
name: Kerberoasting Detected
type: any
index: logs-winlogbeat-*
filter:
  - term:
      winlog.event_id: "4769"
  - term:
      winlog.event_data.TicketEncryptionType: "0x17"

alert: hivealerter
hive_connection:
  hive_host: http://172.16.10.20
  hive_port: 9000
  hive_apikey: VOTRE_API_KEY_THEHIVE
hive_alert_config:
  title: "Kerberoasting - TGS RC4 Detected"
  type: "external"
  source: "ELK"
  severity: 3
  tags: ["AD", "Kerberoasting", "T1558.003"]
```

---

# 11. Phase 9 — AI Automation : Shuffle SOAR + Ollama (Semaine 6-7)

## 11.1 Installation Shuffle SOAR + Ollama (172.16.10.90)

Cette VM orchestre le triage automatique des alertes avec un LLM local (Llama3).

```bash
# Sur la VM AI/SOAR (Ubuntu 22.04) — 16 GB RAM, 6 vCPU — IP 172.16.10.90
sudo apt install -y docker.io docker-compose curl

# Installer Shuffle SOAR
git clone https://github.com/Shuffle/Shuffle /opt/shuffle
cd /opt/shuffle
docker-compose up -d
# Interface : http://172.16.10.90:3001
# Login : admin@shuffler.io / password

# Installer Ollama (LLM local)
curl -fsSL https://ollama.ai/install.sh | sh
sudo systemctl enable --now ollama

# Telecharger le modele Llama3 (8B — ~5 GB)
ollama pull llama3:8b

# Verifier que l'API est active
curl http://localhost:11434/api/tags
```

## 11.2 Workflow Shuffle — Triage Automatique des Alertes

Creer le workflow suivant dans l'interface Shuffle (http://172.16.10.90:3001) :

```
[ELK Webhook Trigger]
        |
        v
[Extraire champs : src_ip, hash, event_id, hostname, rule_name]
        |
        v
[Appel Ollama API - Triage LLM]
POST http://172.16.10.90:11434/api/generate
{
  "model": "llama3:8b",
  "prompt": "Tu es un analyste SOC. Analyse cette alerte de securite et donne : severite (1-10), resume en 2 phrases, action recommandee, technique MITRE ATT&CK probable.\n\nAlerte: {{alert_json}}"
}
        |
        v
[Requete OpenCTI - Verifier IOC]
POST http://172.16.10.80:8080/graphql
Query: { stixCyberObservables(filters: [{key:"value", values:["{{src_ip}}"]}]) { edges { node { id entity_type } } } }
        |
        v
[Appel Cortex - VirusTotal Hash Lookup]
POST http://172.16.10.20:9001/api/analyzer/VirusTotal_GetReport_3_0/run
{"data": "{{process_hash}}", "dataType": "hash"}
        |
        v
[Creer Cas TheHive]
POST http://172.16.10.20:9000/api/v1/case
{
  "title": "{{rule_name}} sur {{hostname}}",
  "description": "{{llm_summary}}",
  "severity": {{llm_severity}},
  "tags": ["{{mitre_technique}}", "auto-triage"],
  "observables": [{"dataType": "ip", "data": "{{src_ip}}"}, {"dataType": "hash", "data": "{{process_hash}}"}]
}
        |
        v
[Si severite >= 7 : Trigger Velociraptor Hunt]
POST https://172.16.10.50:8000/api/v1/CreateHunt
{"HuntDescription": "Auto-Hunt: {{rule_name}}", "StartRequest": {"flow_name": "Generic.System.Pstree"}}
        |
        v
[Fin : Cas TheHive enrichi pret pour l'analyste]
```

## 11.3 Configuration du Webhook ELK → Shuffle

```bash
# Dans Kibana > Stack Management > Watcher
# Ou via Elasticsearch API :
curl -X PUT "http://172.16.10.10:9200/_watcher/watch/soc-alert-webhook" \
  -H 'Content-Type: application/json' \
  -u elastic:MOT_DE_PASSE \
  -d '{
    "trigger": {"schedule": {"interval": "1m"}},
    "input": {
      "search": {
        "request": {
          "indices": ["logs-*"],
          "body": {
            "query": {"range": {"@timestamp": {"gte": "now-1m"}}},
            "filter": [{"term": {"event.kind": "alert"}}]
          }
        }
      }
    },
    "actions": {
      "notify_shuffle": {
        "webhook": {
          "method": "POST",
          "url": "http://172.16.10.90:3001/api/v1/hooks/VOTRE_WEBHOOK_ID",
          "body": "{{ctx.payload}}"
        }
      }
    }
  }'
```

---

# 12. Configuration Elastic Security — Detection SIEM

## 12.1 Activation des Regles de Detection

```
1. Ouvrir Kibana : http://172.16.10.10:5601
2. Menu > Security > Rules > Detection rules
3. Activer les regles pre-integrees Active Directory :
   - "Kerberos Traffic from Unusual Process"
   - "LSASS Memory Read via Process Access"
   - "Mimikatz Powershell Module Activity"
   - "Pass-the-Hash - Detected via Winlogbeat"
   - "BloodHound AD Discovery"
4. Importer les regles Sigma converties (voir section 9.4)
```

## 12.2 Regles de Detection Critiques

| Regle | Event IDs | Attaque Detectee | MITRE |
| --- | --- | --- | --- |
| Kerberoasting Activity | 4769 (RC4) | Extraction tickets Kerberos | T1558.003 |
| LSASS Memory Read | Sysmon 10 | Dumping credentials (Mimikatz) | T1003.001 |
| Pass-the-Hash | 4624 Type 3 | Utilisation hash NTLM | T1550.002 |
| Brute Force Login | 4625 x10+ | Attaque par force brute | T1110 |
| Lateral Movement SMB | 4648 + Sysmon 3 | Mouvement lateral | T1021.002 |
| BloodHound Recon | 4662 + LDAP | Enumeration AD | T1069.002 |
| Evil-WinRM | 4624 + Sysmon 3/22 | Remote shell WinRM | T1021.006 |
| Nmap Scan | Suricata IDS | Reconnaissance reseau | T1046 |

## 12.3 Dashboards Kibana

- **Security Overview** : alertes par severite, MITRE ATT&CK heatmap
- **Windows Security Events** : Event IDs 4624, 4625, 4768, 4769, 4672
- **Sysmon Dashboard** : processus, connexions reseau, LSASS access
- **Suricata Alerts** : alertes IDS par categorie et IP source
- **DFIR Timeline** : reconstruction chronologique des evenements
- **Threat Hunting** : requetes KQL personnalisees

---

# 13. Checklist d'Implementation

| | Tache | Priorite | Statut |
| --- | --- | --- | --- |
| [ ] | Configurer ESXi — LAB-SWITCH + 5 Port Groups VLAN | CRITIQUE | A faire |
| [ ] | Installer pfSense 2.8.1 — 6 interfaces — regles firewall | CRITIQUE | A faire |
| [ ] | Installer Active Directory DC01 — lab.local (VLAN 20) | CRITIQUE | A faire |
| [ ] | Creer les comptes AD : alice.dupont, bob.admin, svc_sql | CRITIQUE | A faire |
| [ ] | Deployer WIN-TARGET-1 et WIN-TARGET-2 (VLAN 20) | HAUTE | A faire |
| [ ] | Deployer Linux Target — SSH/Apache/FTP (VLAN 30) | HAUTE | A faire |
| [ ] | Deployer ELK Stack — Elasticsearch + Kibana + Logstash | CRITIQUE | A faire |
| [ ] | Installer Sysmon sur Windows Target 1 et 2 | HAUTE | A faire |
| [ ] | Configurer Winlogbeat sur toutes les VMs Windows | HAUTE | A faire |
| [ ] | Installer Elastic Agent sur Linux Target | HAUTE | A faire |
| [ ] | Installer et configurer Suricata IDS (MONITOR-PG) | HAUTE | A faire |
| [ ] | Configurer Filebeat Suricata → ELK | HAUTE | A faire |
| [ ] | Configurer Kali Linux (VLAN 99) — outils offensifs | HAUTE | A faire |
| [ ] | Installer SIFT Workstation (Forensics VM — VLAN 10) | MOYENNE | A faire |
| [ ] | Installer Velociraptor Server (172.16.10.50) | HAUTE | A faire |
| [ ] | Deployer les agents Velociraptor sur toutes les cibles | HAUTE | A faire |
| [ ] | Integrer Sigma Rules dans Elasticsearch | HAUTE | A faire |
| [ ] | Installer OpenCTI + ATT&CK Navigator (172.16.10.80) | HAUTE | A faire |
| [ ] | Installer TheHive 5 + Cortex (172.16.10.20) | HAUTE | A faire |
| [ ] | Configurer les Analyzers Cortex (VirusTotal, AbuseIPDB) | MOYENNE | A faire |
| [ ] | Connecter ElastAlert2 → TheHive | HAUTE | A faire |
| [ ] | Installer Shuffle SOAR + Ollama Llama3 (172.16.10.90) | HAUTE | A faire |
| [ ] | Creer le workflow de triage automatique Shuffle | HAUTE | A faire |
| [ ] | Activer Elastic Security + regles detection AD + Sigma | HAUTE | A faire |
| [ ] | Executer Scenario 1 : Reconnaissance BloodHound | MOYENNE | A faire |
| [ ] | Executer Scenario 2 : Kerberoasting + alertes TheHive | MOYENNE | A faire |
| [ ] | Executer Scenario 3 : Pass-the-Hash + triage AI | MOYENNE | A faire |
| [ ] | Executer Scenario 4 : Brute Force + Suricata | MOYENNE | A faire |
| [ ] | Executer Scenario 5 : Lateral Movement + hunt Velociraptor | MOYENNE | A faire |
| [ ] | Analyse forensique Volatility 3 (memoire) | BASSE | A faire |
| [ ] | Creer les dashboards Kibana SOC | BASSE | A faire |
| [ ] | Valider le pipeline AI : alerte → Shuffle → TheHive case | HAUTE | A faire |
| [ ] | Documenter les resultats et rediger le rapport final | CRITIQUE | A faire |

---

# 14. Planning Suggere (8 Semaines)

| Semaine | Phase | Taches Principales |
| --- | --- | --- |
| S1 | Infrastructure Reseau | ESXi, LAB-SWITCH VLAN, pfSense, AD DC, Windows Targets |
| S2 | SIEM + Agents | ELK Stack, Sysmon, Winlogbeat, Elastic Agent, Filebeat |
| S3 | IDS + Attaque | Suricata MONITOR-PG, Kali VLAN 99, scenarios BloodHound/Kerberoasting |
| S4 | DFIR + Forensics | SIFT VM, Volatility 3, analyse memoire/disque, timeline Plaso |
| S5 | Threat Hunting | Velociraptor server/agents, hunts VQL, Sigma Rules, OpenCTI |
| S6 | TheHive + Cortex | Installation, analyzers Cortex, integration ELK via ElastAlert2 |
| S7 | AI Automation | Shuffle SOAR, Ollama Llama3, workflow triage automatique |
| S8 | Tests + Rapport | Validation complete, dashboards, documentation, rapport final |

## 14.1 Conseils pour la Reussite du Projet

- Documenter chaque etape avec des screenshots des configurations et resultats
- Tester la connectivite entre VLANs via pfSense avant chaque nouvelle phase
- Creer des snapshots VMware apres chaque etape majeure reussie
- Verifier que les logs arrivent dans Kibana avant de lancer les scenarios d'attaques
- Correpeler les alertes SIEM + TheHive avec les attaques Kali pour valider la detection
- Valider que le pipeline AI cree bien un cas TheHive enrichi pour chaque alerte critique
- Pour le rapport final : inclure des captures Kibana, TheHive, Velociraptor et Shuffle

> **Points d'Acces depuis les Postes de l'Ecole (via pfSense NAT)**
>
> | Service | URL | Port |
> | --- | --- | --- |
> | ESXi Management | https://10.30.40.19 | 443 |
> | pfSense WebUI | https://10.30.40.50 | 443 |
> | Kibana SIEM | http://10.30.40.50:5601 | 5601 |
> | TheHive 5 | http://10.30.40.50:9000 | 9000 |
> | Shuffle SOAR | http://10.30.40.50:3001 | 3001 |
> | OpenCTI | http://10.30.40.50:8080 | 8080 |
> | Velociraptor | https://10.30.40.50:8000 | 8000 |
> | ATT&CK Navigator | http://10.30.40.50:4242 | 4242 |

---

# 15. References et Ressources

## Documentation Officielle

- Elastic Documentation : https://www.elastic.co/guide/en/elastic-stack
- Sysmon Reference : https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- Suricata Docs : https://suricata.readthedocs.io
- BloodHound Wiki : https://github.com/BloodHoundAD/BloodHound/wiki
- Volatility 3 : https://volatility3.readthedocs.io
- SIFT Workstation : https://www.sans.org/tools/sift-workstation
- TheHive Project : https://docs.strangebee.com/thehive
- Cortex Analyzers : https://github.com/TheHive-Project/Cortex-Analyzers
- Velociraptor : https://docs.velociraptor.app
- OpenCTI Platform : https://docs.opencti.io
- Shuffle SOAR : https://shuffler.io/docs
- Ollama : https://ollama.ai/docs
- Sigma Rules : https://github.com/SigmaHQ/sigma
- MITRE ATT&CK : https://attack.mitre.org

## Ressources d'Apprentissage

- TryHackMe — SOC Level 1 : https://tryhackme.com/path/outline/soclevel1
- TryHackMe — Threat Hunting : https://tryhackme.com/path/outline/threatintel
- Hack The Box — Active Directory Tracks
- SANS SEC504 — Hacker Tools, Techniques and Incident Handling
- SANS FOR508 — Advanced Incident Response, Threat Hunting
- SwiftOnSecurity Sysmon Config : https://github.com/SwiftOnSecurity/sysmon-config
- Velociraptor VQL Reference : https://docs.velociraptor.app/vql_reference

---

**Projet PFA — SOC / Active Directory / DFIR / Threat Hunting / AI Automation**

Architecture Lab — Dell PowerEdge R750 — VMware ESXi 7.0 — VLAN 10/20/30/99 — lab.local

13 VMs — 88 GB RAM — 1010 GB — Avril 2026
