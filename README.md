# Suricata IDS Detection Lab
Routing Inspection Gateway | Dual-NIC Architecture | Detection Engineering

---

## Overview

This project demonstrates a VirtualBox-based SOC lab where Suricata IDS operates as a **dual-NIC routing inspection gateway**, inspecting traffic between isolated attacker and victim networks.

The lab simulates real-world attack scenarios and validates detection using structured logging and packet inspection.

---

## Architecture Diagram

![Suricata Architecture](assets/diagrams/Suricata%20IDS%20Architecture%20Diagram.png)

---

## Lab Architecture Explanation

### VirtualBox Host

Two Internal Networks are configured:

- SOC-IN  → 192.168.100.0/24  
- SOC-OUT → 192.168.200.0/24  

---

### Attacker Machine (Kali Linux)

- Interface: SOC-IN  
- IP: 192.168.100.10  
- Gateway: 192.168.100.1 (Suricata)  

Used to simulate:

- ICMP test traffic
- Nmap SYN scanning
- SQL Injection
- Reflected XSS

---

### Suricata IDS VM (Routing Inspection Gateway)

Dual Network Interfaces:

- enp0s3 → SOC-IN → 192.168.100.1  
- enp0s8 → SOC-OUT → 192.168.200.1  

Key Configuration:

- net.ipv4.ip_forward = 1
- IDS Mode Deployment
- Packet Capture Engine Enabled

Traffic Path Enforced:

Kali → Suricata → DVWA

All traffic between networks must traverse the IDS.

---

### Victim Machine (Ubuntu + DVWA)

- Interface: SOC-OUT  
- IP: 192.168.200.10  
- Service: Apache + DVWA (HTTP)

Target for simulated web-based attacks.

---

## Tools & Technologies

- Suricata 7.x
- Kali Linux
- Ubuntu Server
- DVWA
- Nmap
- tcpdump
- VirtualBox (Dual Internal Networks)

---

## Project Structure

```
Suricata-IDS-Detection-Lab/
│
├── README.md
├── docs/
│   ├── 01-infrastructure-setup.md
│   ├── 02-rule-engine.md
│   ├── 03-network-path-validation.md
│   ├── 04-sqli-case-study.md
│   ├── 05-xss-case-study.md
│   └── 06-recon-scan.md
│
├── assets/
│   ├── diagrams/
│   │   └── Suricata IDS Architecture Diagram.png
│   └── screenshots/
│
├── rules/
│   └── local.rules
│
├── configs/
│   └── suricata.yaml
│
└── logs-samples/
    ├── fast.log.sample
    └── eve.json.sample
```

---

## Detection Scenarios

### 1. Infrastructure Deployment
- Dual-NIC configuration
- Routing enforcement validation
- Engine runtime verification

---

### 2. Rule Engine Validation
- Custom rule creation
- Rule parsing verification
- Alert trigger validation

---

### 3. Network Path Validation
- Routing table verification
- Packet inspection using tcpdump
- Traffic visibility on both interfaces

---

### 4. SQL Injection Detection

- SQLi payload executed against DVWA
- HTTP inspection rule triggered
- Alert validation via fast.log
- Structured event validation via eve.json

MITRE ATT&CK:
T1190 – Exploit Public-Facing Application

---

### 5. Cross-Site Scripting (XSS) Detection

- Reflected XSS payload testing
- HTTP content inspection
- Alert generation and JSON validation

MITRE ATT&CK:
T1059 – Command and Scripting Interpreter

---

### 6. Reconnaissance Detection

- Nmap SYN scan simulation
- Service discovery detection
- IDS monitoring validation

MITRE ATT&CK:
T1046 – Network Service Scanning

---

## Evidence Collection & Validation

Alerts verified using:

- /var/log/suricata/fast.log
- /var/log/suricata/eve.json
- tcpdump packet captures (interface-level validation)

Example validation command:

```bash
sudo tail -n 10 /var/log/suricata/fast.log
```

---

## Key Engineering Concepts Demonstrated

- IDS deployment in routed inspection mode
- Dual-NIC gateway architecture
- Network segmentation enforcement
- Custom rule development and validation
- Attack simulation with detection verification
- Structured JSON log analysis
- MITRE ATT&CK technique mapping

---

## Detection Workflow Demonstrated

Attack Simulation  
→ Traffic Inspection  
→ Rule Trigger  
→ Alert Logging  
→ Evidence Validation  
→ Technique Mapping  

This lab demonstrates practical detection engineering beyond basic IDS setup.

---
