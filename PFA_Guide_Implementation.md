**PROJET FIN D'ANNEE SOC / Active Directory / DFIR**

Guide Complet d'Implementation du Lab

| Infrastructure — Dell PowerEdge R750 — VMware ESXi 7.0 | Reseau — 172.16.10.0/24 — lab.local (isole) |
| --- | --- |
| VMs — 7 machines virtuelles — 52 GB RAM / 660 GB | Date — Avril 2026 |

# 1. Vue d'Ensemble du Projet

Ce projet de fin d'annee consiste a deployer un laboratoire de securite informatique complet simulant un environnement d'entreprise reel. L'objectif est de mettre en oeuvre trois domaines fondamentaux de la cybersecurite :

> Objectifs Principaux
> SOC (Security Operations Center) : Collecte, correlation et analyse des evenements de securite en temps reel via ELK Stack
> Active Directory : Gestion centralisee des identites, authentification Kerberos, politiques GPO et simulation d'attaques AD
> DFIR (Digital Forensics & Incident Response) : Investigation numerique, analyse forensique des artefacts et reponse aux incidents

## 1.1 Architecture Globale

Le lab est hote sur un serveur Dell PowerEdge R750 sous VMware ESXi 7.0. Toutes les VMs communiquent sur un vSwitch isole (LAB-NET) sans connexion Internet, garantissant la securite des experimentations.

| VM | RAM | vCPU | Disque | IP | Role |
| --- | --- | --- | --- | --- | --- |
| ELK Stack (SIEM) | 16 GB | 4 | 200 GB | .10 | Collecte & analyse logs |
| Active Directory DC | 4 GB | 2 | 80 GB | .20 | DNS, Kerberos, LDAP, GPO |
| Suricata IDS | 4 GB | 2 | 40 GB | .40 | Detection intrusion reseau |
| Windows Target 1 | 4 GB | 2 | 60 GB | .30 | Victime — alice.dupont |
| Windows Target 2 | 4 GB | 2 | 60 GB | .31 | Victime — bob.admin |
| Linux Target | 4 GB | 2 | 40 GB | .35 | Serveur SSH/Apache/FTP |
| Kali Linux (Attaquant) | 8 GB | 4 | 80 GB | .50 | BloodHound, Metasploit, Mimikatz |
| Forensics VM (DFIR) | 8 GB | 4 | 100 GB | .70 | Volatility, Autopsy, SIFT |
| TOTAL | 52 GB | 22 | 660 GB | — | 7 machines virtuelles |

# 2. Prerequis et Preparation

## 2.1 Configuration ESXi

Avant de creer les VMs, configurer l'hyperviseur :

- Acceder a l'interface ESXi : https://10.30.40.19 (IP Management)
- Activer SSH sur l'hote ESXi pour la gestion a distance
- Creer le vSwitch isole LAB-NET (172.16.10.0/24) SANS uplink physique
- Creer un second vSwitch avec uplink pour l'acces Internet (ISO downloads uniquement)
- Configurer le datastore : minimum 700 GB disponibles
> IMPORTANT
> vSwitch Isole
> Le vSwitch LAB-NET ne doit JAMAIS avoir d'uplink physique.
> Ceci garantit que les attaques simulees restent confinement dans le lab.
> Les postes physiques accedent au lab via SSH et navigateur seulement.

## 2.2 ISOs et Licences Necessaires

| Systeme | Version | Remarque |
| --- | --- | --- |
| Windows Server 2022 | Evaluation 180j | ISO Microsoft Evaluation Center |
| Windows 10 Pro | 22H2 ou superieur | ISO Microsoft — 2 licences |
| Ubuntu Server 22.04 LTS | 22.04.x | ubuntu.com/download/server |
| Kali Linux 2024.x | Latest | kali.org/get-kali — amd64 |
| SIFT Workstation | Ubuntu 22.04 base | github.com/teamdfir/sift-saltstack |

# 3. Phase 1 — Infrastructure de Base (Semaine 1-2)

## 3.1 Active Directory Domain Controller

### Installation Windows Server 2022

- Creer la VM : 4 GB RAM, 2 vCPU, 80 GB — IP fixe 172.16.10.20
- Installer Windows Server 2022 (Desktop Experience recommande)
- Configurer l'IP fixe dans les parametres reseau

### Promotion en Controleur de Domaine

### Creation des Utilisateurs et Comptes

## 3.2 Windows Target 1 (alice.dupont — 172.16.10.30)

- Creer la VM : 4 GB RAM, 2 vCPU, 60 GB
- Installer Windows 10 Pro, IP fixe 172.16.10.30, DNS vers 172.16.10.20
- Joindre le domaine lab.local

- Ouvrir des ports et services vulnerables pour les scenarios d'attaque
- Installer Sysmon + Winlogbeat (voir section 4)
## 3.3 Windows Target 2 (bob.admin — 172.16.10.31)

Configuration identique a Target 1, avec le compte bob.admin (Domain Admin). Ce poste simule un mouvement lateral apres compromission initiale.

- Creer la VM : 4 GB RAM, 2 vCPU, 60 GB
- Installer Windows 10 Pro, IP fixe 172.16.10.31
- Joindre le domaine, connecter avec bob.admin
- Conserver des artefacts d'authentification pour les scenarios Pass-the-Hash
## 3.4 Linux Target (172.16.10.35)

# 4. Phase 2 — ELK Stack SIEM (Semaine 2-3)

## 4.1 Installation ELK Stack (172.16.10.10)

L'ELK Stack est le coeur du SOC. Elle centralise tous les logs et fournit la detection d'alertes via Elastic Security.

### Prerequis Systeme

Connectez-vous en SSH sur la VM ELK (Ubuntu Server 22.04, IP : 172.16.10.10) :

```bash
# Mise a jour du systeme
sudo apt update && sudo apt upgrade -y

# Installation des dependances
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release wget

# Ajouter la cle GPG Elastic
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Ajouter le depot Elastic 8.x
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Mettre a jour les paquets
sudo apt update
```

### Installation Elasticsearch

```bash
# Installer Elasticsearch
sudo apt install -y elasticsearch

# Conserver le mot de passe superuser affiche a l'installation !
# Il sera necessaire pour la configuration de Kibana.

# Configurer Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Modifier les parametres suivants dans `elasticsearch.yml` :

```yaml
cluster.name: soc-lab
node.name: elk-node-1
network.host: 172.16.10.10
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.http.ssl.enabled: false   # Pour le lab uniquement
```

```bash
# Activer et demarrer Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Verifier le statut
sudo systemctl status elasticsearch

# Tester la connexion (remplacer MOT_DE_PASSE par le mot de passe genere)
curl -u elastic:MOT_DE_PASSE http://172.16.10.10:9200
```

### Installation Kibana

```bash
# Installer Kibana
sudo apt install -y kibana

# Configurer Kibana
sudo nano /etc/kibana/kibana.yml
```

Modifier les parametres suivants dans `kibana.yml` :

```yaml
server.port: 5601
server.host: "172.16.10.10"
server.name: "soc-kibana"
elasticsearch.hosts: ["http://172.16.10.10:9200"]
elasticsearch.username: "kibana_system"
# elasticsearch.password: sera defini apres
```

```bash
# Generer un token d'enrollment Kibana depuis Elasticsearch
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# Definir le mot de passe du compte kibana_system
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system
# Copier le mot de passe genere et l'ajouter dans kibana.yml :
# elasticsearch.password: "LE_MOT_DE_PASSE_ICI"

# Activer et demarrer Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# Verifier le statut
sudo systemctl status kibana
# Interface accessible sur http://172.16.10.10:5601
```

### Installation Logstash

```bash
# Installer Logstash
sudo apt install -y logstash

# Creer le pipeline de configuration principal
sudo nano /etc/logstash/conf.d/beats-input.conf
```

Contenu du fichier `beats-input.conf` :

```
input {
  beats {
    port => 5044
    host => "172.16.10.10"
  }
}

filter {
  if [agent][type] == "winlogbeat" {
    mutate {
      add_tag => ["windows", "winlogbeat"]
    }
  }
  if [agent][type] == "filebeat" {
    mutate {
      add_tag => ["linux", "filebeat"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://172.16.10.10:9200"]
    user => "elastic"
    password => "MOT_DE_PASSE_ELASTIC"
    index => "logs-%{[agent][type]}-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}
```

```bash
# Tester la configuration Logstash
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/

# Activer et demarrer Logstash
sudo systemctl enable logstash
sudo systemctl start logstash

# Verifier le statut
sudo systemctl status logstash

# Verifier que le port 5044 est ouvert
ss -tlnp | grep 5044
```

```bash
# Ouvrir les ports dans le firewall (UFW)
sudo ufw allow 9200/tcp   # Elasticsearch API
sudo ufw allow 5601/tcp   # Kibana
sudo ufw allow 5044/tcp   # Logstash Beats input
sudo ufw enable
sudo ufw status
```

## 4.2 Installation Sysmon sur Windows (Targets 1 et 2)

Sysmon enrichit les logs Windows avec des evenements critiques pour la detection d'attaques.

> Events Sysmon Importants a Monitorer
> Event ID 1 
> Process Creation (detection d'outils offensifs)
> Event ID 3 
> Network Connection (lateral movement)
> Event ID 7 
> Image Loaded (DLL injection)
> Event ID 10
> Process Access (Mimikatz, LSASS dumping)
> Event ID 11
> File Created (malware dropped)
> Event ID 22
> DNS Query (C2 beaconing)

Sur chaque machine Windows Target (Target 1 — alice.dupont et Target 2 — bob.admin), ouvrir PowerShell en tant qu'Administrateur :

```powershell
# Telecharger Sysmon depuis Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# Telecharger la configuration Sysmon recommandee (SwiftOnSecurity)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Installer Sysmon avec la configuration
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verifier que Sysmon est bien installe et actif
Get-Service Sysmon64

# Verifier les logs dans l'Observateur d'evenements
# Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```

## 4.3 Installation Winlogbeat (Windows → Logstash)

Sur chaque machine Windows Target, ouvrir PowerShell en tant qu'Administrateur :

```powershell
# Telecharger Winlogbeat 8.x
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.13.0-windows-x86_64.zip" -OutFile "C:\Tools\winlogbeat.zip"
Expand-Archive -Path "C:\Tools\winlogbeat.zip" -DestinationPath "C:\Program Files\Winlogbeat"
cd "C:\Program Files\Winlogbeat\winlogbeat-8.13.0-windows-x86_64"

# Editer la configuration Winlogbeat
notepad winlogbeat.yml
```

Contenu de `winlogbeat.yml` :

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
# Tester la configuration
.\winlogbeat.exe test config -c winlogbeat.yml -e

# Tester la connexion vers Logstash
.\winlogbeat.exe test output -c winlogbeat.yml

# Installer Winlogbeat comme service Windows
.\install-service-winlogbeat.ps1

# Demarrer le service
Start-Service winlogbeat
Get-Service winlogbeat

# Verifier les logs de Winlogbeat
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 20
```

# 5. Phase 3 — Suricata IDS Reseau (Semaine 3)

## 5.1 Installation Suricata (172.16.10.40)

Suricata analyse le trafic reseau en mode NIC promiscueux pour detecter les attaques reseau (scan, brute-force, exploitation).

```bash
# Installer Suricata sur Ubuntu/Debian
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata

# Verifier la version
suricata --build-info

# Identifier l'interface reseau a surveiller
ip a
# Exemple : ens33

# Configurer Suricata
sudo nano /etc/suricata/suricata.yaml
```

**Extraits cles de `/etc/suricata/suricata.yaml` :**

```yaml
# Interface reseau
af-packet:
  - interface: ens33
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Repertoire des regles
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules

# Sortie EVE JSON (pour Filebeat)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
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
# Mettre a jour les regles Suricata (Emerging Threats)
sudo suricata-update

# Tester la configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Activer et demarrer Suricata
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata

# Verifier les logs en temps reel
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool
sudo tail -f /var/log/suricata/fast.log
```

### Regles de Detection

```bash
# Ajouter des regles personnalisees
sudo nano /etc/suricata/rules/local.rules
```

```text
# Detection scan Nmap
alert tcp any any -> $HOME_NET any (msg:"NMAP SYN Scan"; flags:S,12; threshold: type threshold, track by_src, count 20, seconds 5; sid:1000001; rev:1;)

# Detection brute force SSH
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server; threshold: type threshold, track by_src, count 10, seconds 30; sid:1000002; rev:1;)

# Detection Kerberoasting (TGS-REQ RC4)
alert dns any any -> any any (msg:"Possible Kerberoasting - TGS RC4"; content:"|17 00|"; sid:1000003; rev:1;)

# Detection Pass-the-Hash SMB
alert smb any any -> $HOME_NET 445 (msg:"Possible Pass-the-Hash SMB"; flow:to_server,established; sid:1000004; rev:1;)
```

```bash
# Ajouter le fichier local.rules dans suricata.yaml
# Puis recharger les regles sans redemarrage
sudo kill -USR2 $(pidof suricata)
```

### Integration Suricata → ELK via Filebeat

```bash
# Installer Filebeat sur la VM Suricata
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install -y filebeat

# Activer le module Suricata
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
# Configurer Filebeat pour envoyer vers Logstash
sudo nano /etc/filebeat/filebeat.yml
```

```yaml
output.logstash:
  hosts: ["172.16.10.11:5044"]

setup.kibana:
  host: "172.16.10.11:5601"
```

```bash
# Demarrer Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

---

# 6. Phase 4 — Machine Attaquante Kali Linux (Semaine 3-4)

La machine Kali Linux (172.16.10.50) simule un attaquant interne ou externe ayant un acces au reseau du lab.

## 6.1 Installation et Configuration Kali

```bash
# Mise a jour complete du systeme Kali
sudo apt update && sudo apt full-upgrade -y

# Installer les outils necessaires pour les scenarios
sudo apt install -y \
  nmap \
  hydra \
  crackmapexec \
  impacket-scripts \
  bloodhound \
  neo4j \
  mimikatz \
  smbclient \
  python3-bloodhound

# Configurer le fichier /etc/hosts pour resoudre lab.local
echo "172.16.10.20  dc01.lab.local  lab.local" | sudo tee -a /etc/hosts
echo "172.16.10.30  srv-win.lab.local" | sudo tee -a /etc/hosts
echo "172.16.10.35  srv-linux.lab.local" | sudo tee -a /etc/hosts

# Verifier la connectivite reseau
ping -c 3 172.16.10.20
nmap -sn 172.16.10.0/24
```

## 6.2 Scenarios d'Attaques a Implementer

> Scenario 1
> Reconnaissance Initiale
> Objectif : Cartographier le domaine AD depuis Kali
> Outil    : BloodHound + SharpHound collector
> Commande : nmap -sV -sC 172.16.10.0/24  (decouverte reseau)
> bloodhound-python -u alice.dupont -p Password123 -d lab.local -ns 172.16.10.20 --zip

> Scenario 2
> Kerberoasting
> Objectif : Extraire et cracker les tickets Kerberos des comptes de service
> Outil    : Impacket GetUserSPNs.py
> Commande : GetUserSPNs.py lab.local/alice.dupont:Password123 -dc-ip 172.16.10.20 -request
> Detection : Event ID 4769 (TGS-REQ avec chiffrement RC4) sur le DC

> Scenario 3
> Pass-the-Hash
> Objectif : Se connecter avec le hash NTLM sans connaitre le mot de passe
> Outil    : Mimikatz + CrackMapExec
> Commande : mimikatz # sekurlsa::logonpasswords
> crackmapexec smb 172.16.10.31 -u bob.admin -H <hash_ntlm>
> Detection : Event ID 4624 (Logon Type 3) + Sysmon Event 10 (LSASS access)

> Scenario 4
> Brute Force SSH/SMB
> Objectif : Tester la resilience des mots de passe
> Outils   : Hydra, Nmap scripts
> Commande : hydra -l alice.dupont -P /usr/share/wordlists/rockyou.txt ssh://172.16.10.35
> hydra -l Administrator -P wordlist.txt smb://172.16.10.30
> Detection : Suricata alertes + Event ID 4625 (echecs de connexion)

# 7. Phase 5 — Forensics VM / DFIR (Semaine 4-5)

## 7.1 Installation SIFT Workstation (172.16.10.70)

## 7.2 Acquisition de Preuves via Snapshots VMware

La VM Forensics peut analyser directement les fichiers VMDK des autres VMs. C'est l'avantage majeur d'un lab virtuel.

## 7.3 Analyse Forensique avec Volatility 3

## 7.4 Analyse des Logs Windows avec Autopsy

- Ouvrir Autopsy : sudo autopsy
- Creer un nouveau cas : File > New Case
- Ajouter une source de donnees : Image ou disque local
- Analyser les artefacts : Prefetch, LNK files, Registry hives, Event Logs
- Generer un rapport timeline avec log2timeline / plaso

# 8. Configuration Elastic Security (Detection SIEM)

## 8.1 Activation d'Elastic Security dans Kibana

- Ouvrir Kibana : http://172.16.10.10:5601
- Aller dans Menu > Security > Overview
- Activer Elastic Security et les regles de detection prebaties
- Importer les Detection Rules pour Active Directory :

## 8.2 Regles de Detection Critiques a Activer

| Regle | Event IDs | Attaque Detectee |
| --- | --- | --- |
| Kerberoasting Activity | 4769 | Extraction tickets Kerberos RC4 |
| LSASS Memory Read | Sysmon 10 | Dumping credentials (Mimikatz) |
| Pass-the-Hash | 4624 Type 3 | Utilisation hash NTLM |
| Brute Force Login | 4625 x10+ | Attaque par force brute |
| Lateral Movement SMB | 4648 + Sysmon 3 | Mouvement lateral |
| BloodHound Recon | 4662 + LDAP queries | Enumeration AD |
| Evil-WinRM Connection | 4624 + Sysmon 3/22 | Remote shell via WinRM |

## 8.3 Dashboards Kibana Recommandes

- Security Overview : vue globale des alertes par severite
- Windows Security Events : analyse des Event IDs critiques (4624, 4625, 4768, 4769, 4672)
- Sysmon Dashboard : processus, connexions reseau, acces LSASS
- Suricata Alerts : alertes IDS reseau par categorie et IP source
- DFIR Timeline : reconstruction chronologique des evenements
# 9. Checklist d'Implementation

Utilisez cette checklist pour suivre l'avancement du projet :

|  | Tache | Priorite | Statut |
| --- | --- | --- | --- |
| [ ] | Configurer ESXi — vSwitch LAB-NET isole | CRITIQUE | A faire |
| [ ] | Installer et configurer Active Directory DC (lab.local) | CRITIQUE | A faire |
| [ ] | Creer les comptes AD : alice.dupont, bob.admin | CRITIQUE | A faire |
| [ ] | Deployer ELK Stack + Elasticsearch + Kibana + Logstash | CRITIQUE | A faire |
| [ ] | Installer Sysmon sur Windows Target 1 et Target 2 | HAUTE | A faire |
| [ ] | Configurer Winlogbeat sur toutes les VMs Windows | HAUTE | A faire |
| [ ] | Installer et configurer Suricata IDS reseau | HAUTE | A faire |
| [ ] | Configurer Filebeat sur Suricata vers ELK | HAUTE | A faire |
| [ ] | Deployer Linux Target (SSH, Apache, FTP + Elastic Agent) | HAUTE | A faire |
| [ ] | Configurer Kali Linux avec BloodHound + Neo4j | HAUTE | A faire |
| [ ] | Installer SIFT Workstation (Forensics VM) | MOYENNE | A faire |
| [ ] | Activer Elastic Security + regles detection AD | HAUTE | A faire |
| [ ] | Executer Scenario 1 : Reconnaissance BloodHound | MOYENNE | A faire |
| [ ] | Executer Scenario 2 : Kerberoasting + verification alertes | MOYENNE | A faire |
| [ ] | Executer Scenario 3 : Pass-the-Hash + analyse SIEM | MOYENNE | A faire |
| [ ] | Executer Scenario 4 : Brute Force + Suricata alertes | MOYENNE | A faire |
| [ ] | Analyse forensique avec Volatility 3 (memoire) | BASSE | A faire |
| [ ] | Creer les dashboards Kibana SOC | BASSE | A faire |
| [ ] | Documenter les resultats et rediger le rapport final | CRITIQUE | A faire |

# 10. Planning Suggere (5 Semaines)

| Semaine | Phase | Taches Principales |
| --- | --- | --- |
| S1 | Infrastructure de Base | ESXi config, AD DC, Windows Targets, reseau LAB-NET |
| S2 | ELK Stack + Agents | Elasticsearch, Kibana, Logstash, Sysmon, Winlogbeat, Filebeat |
| S3 | Suricata + Kali | IDS reseau, regles de detection, outils offensifs, BloodHound |
| S4 | Scenarios d'Attaques | Kerberoasting, Pass-the-Hash, Brute Force, Lateral Movement |
| S5 | DFIR + Rapport | Forensics VM, analyse memoire/disque, dashboards, documentation |

## 10.1 Conseils pour la Reussite du Projet

- Documenter chaque etape : prendre des screenshots des configurations et resultats
- Tester la connectivite entre VMs avant de passer a la phase suivante
- Creer des snapshots VMware apres chaque etape majeure reussie
- Verifier que les logs arrivent bien dans Kibana avant de lancer les scenarios d'attaques
- Correleler les alertes SIEM avec les attaques lancees depuis Kali pour valider la detection
- Pour le rapport : inclure des captures Kibana montrant les alertes generees par chaque attaque
> Acces depuis les Postes de l'Ecole
> Kibana Dashboard : http://172.16.10.10:5601 (via navigateur)
> SSH vers VMs    : ssh user@172.16.10.XX (port 22)
> Aucun outil lourd a installer en local
> tout tourne sur le Dell R750
> Les postes physiques ne sont PAS sur le LAB-NET
> acces reseau de l'ecole uniquement

# 11. References et Ressources

## Documentation Officielle

- Elastic Documentation : https://www.elastic.co/guide/en/elastic-stack
- Sysmon Reference : https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- Suricata Docs : https://suricata.readthedocs.io
- BloodHound Wiki : https://github.com/BloodHoundAD/BloodHound/wiki
- Volatility 3 : https://volatility3.readthedocs.io
- SIFT Workstation : https://www.sans.org/tools/sift-workstation
## Ressources d'Apprentissage

- TryHackMe — SOC Level 1 : https://tryhackme.com/path/outline/soclevel1
- Hack The Box — Active Directory Tracks
- SANS SEC504 — Hacker Tools, Techniques and Incident Handling
- SwiftOnSecurity Sysmon Config : https://github.com/SwiftOnSecurity/sysmon-config
- Sigma Rules (detection generique) : https://github.com/SigmaHQ/sigma
**Projet PFA — SOC / Active Directory / DFIR**

Architecture Lab — Dell PowerEdge R750 — VMware ESXi 7.0 — lab.local — 172.16.10.0/24

Avril 2026
