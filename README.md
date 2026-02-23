# Suricata IDS Detection Lab
Routing Inspection Gateway | Attack Simulation | Detection Engineering

---

## Overview

This project demonstrates a VirtualBox-based SOC lab where Suricata IDS operates as a dual-NIC routing inspection gateway, inspecting traffic between:

- Attacker: Kali Linux  
- IDS: Suricata 7.x (Routing Gateway)  
- Victim: Ubuntu (DVWA Web Server)

The lab validates:

- Network path enforcement
- Custom rule creation
- Attack-driven detection
- Alert validation in fast.log and eve.json
- MITRE ATT&CK mapping

---

## Lab Architecture

![Architecture](assets/diagrams/architecture.png)

### Network Segmentation

SOC-IN  : 192.168.100.0/24  
SOC-OUT : 192.168.200.0/24  

Traffic Flow:
Kali → Suricata (Inspection Gateway) → DVWA

Suricata Interfaces:
- enp0s3 → SOC-IN (192.168.100.1)
- enp0s8 → SOC-OUT (192.168.200.1)

IP Forwarding enabled:
net.ipv4.ip_forward = 1

---

## Tools & Technologies

- Suricata 7.x
- Kali Linux
- Ubuntu Server
- DVWA
- Nmap
- THC-Hydra
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
│   ├── 06-recon-scan.md
│   └── 07-ssh-bruteforce-case-study.md
│
├── assets/
│   ├── diagrams/
│   │   └── architecture.png
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

### 1. Network Path Validation
- ICMP test traffic
- TCP validation via tcpdump
- Verified routed inspection

### 2. Reconnaissance Scan
- Nmap SYN scan
- Service discovery
- Suricata alert validation

MITRE Technique:
T1046 – Network Service Scanning

---

### 3. SQL Injection (DVWA)

- Exploit simulation via DVWA
- Custom Suricata rule detection
- fast.log alert validation
- eve.json structured output verification

MITRE Technique:
T1190 – Exploit Public-Facing Application

---

### 4. Cross-Site Scripting (XSS)

- Reflected XSS attack
- HTTP inspection
- Payload detection via custom rule

MITRE Technique:
T1059 – Command and Scripting Interpreter

---

### 5. SSH Brute Force (Hydra)

- SSH service discovery via Nmap
- Credential brute force using THC-Hydra
- Suricata detection validation

MITRE Technique:
T1110 – Brute Force

---

## Evidence Collection

Detection proof validated using:

- /var/log/suricata/fast.log
- /var/log/suricata/eve.json
- tcpdump (packet validation on enp0s3)

Sample Alert (fast.log):

[**] [1:1000005:1] SSH Brute Force Attempt [**]

Structured JSON validation via:

sudo tail -n 5 /var/log/suricata/eve.json

---

## Key Engineering Concepts Demonstrated

- IDS deployment in routed inspection mode
- Dual-NIC gateway enforcement
- Custom rule creation and testing
- Attack simulation with validation
- Detection evidence documentation
- MITRE ATT&CK mapping
- SOC-style alert investigation workflow

---

## Why This Project Matters

This lab simulates real SOC detection workflows:

Attack → Traffic Inspection → Alert Trigger → Log Validation → Technique Mapping

It demonstrates practical detection engineering beyond theoretical IDS configuration.

---
