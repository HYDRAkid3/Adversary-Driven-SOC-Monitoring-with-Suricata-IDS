# Suricata IDS Detection Lab  
### Inline Network Inspection | Detection Engineering | Recon + Web Attack Validation

---

## Overview

This project demonstrates a fully segmented, dual-homed Suricata IDS deployment built in a controlled virtual lab environment.

The objective of this lab was to:

- Deploy Suricata as an inline routing inspection gateway
- Enforce inter-subnet traffic inspection
- Validate detection of reconnaissance activity
- Detect SQL Injection and XSS attacks
- Analyze alerts using both fast.log and structured eve.json output
- Demonstrate practical detection engineering skills

This lab simulates a real-world SOC monitoring boundary.

---

# Lab Network Architecture

Below is the actual network architecture used in this lab:

![Suricata IDS Dual Network Architecture](evidence/screenshots/00_Architecture/01_suricata_ids_dual_network_architecture.png)

---

## Network Design Summary

Two isolated internal networks were created using VirtualBox:

- **SOC-IN** → 192.168.100.0/24 (Attacker Network)
- **SOC-OUT** → 192.168.200.0/24 (Victim Network)

Suricata operates as a dual-homed inline routing gateway:

- enp0s3 → 192.168.100.1 (SOC-IN)
- enp0s8 → 192.168.200.1 (SOC-OUT)

All traffic from Kali (192.168.100.10) to DVWA (192.168.200.10) must traverse Suricata.

No direct communication path exists between subnets.

---

# Design Principles

✔ Dual-homed routing gateway  
✔ Forced inspection boundary  
✔ Layer 3 segmentation  
✔ Layer 4 reconnaissance detection  
✔ Layer 7 payload inspection  
✔ IDS mode (alert-only, no blocking)  
✔ Deterministic attack validation  

All attacker-to-target traffic passes through the inspection engine.

---

# Technology Stack

| Component | Purpose |
|------------|----------|
| VirtualBox | Network segmentation |
| Kali Linux | Attacker machine |
| Ubuntu Server | Target host |
| DVWA | Vulnerable web application |
| Suricata 7.x | Intrusion Detection System |
| ET Open Rules | Community detection baseline |
| Custom Rules | Lab-specific detection logic |
| tcpdump | Packet-level inspection |
| eve.json | Structured SOC logging |

---

# Attack Scenarios Validated

## Reconnaissance

- ICMP Host Discovery
- Nmap SYN Scan
- TCP Connect Scan
- Service Enumeration

Detected:
- SYN scan alerts
- TCP flag anomalies
- Suspicious scan behavior

---

## SQL Injection

- Boolean-based injection
- UNION-based injection

Detected:
- Custom SQLi rule
- ET Open web attack signatures
- Structured JSON HTTP metadata logging

---

## Cross-Site Scripting (XSS)

- Script injection via DVWA
- Reflected XSS payload testing

Detected:
- Custom XSS signature
- HTTP payload inspection
- Structured eve.json alert records

---

# Detection Engineering Highlights

This lab integrates:

### ET Open Baseline Rules
Community threat intelligence providing broad detection coverage.

### Custom Local Rules
Developed specifically to:

- Validate detection deterministically
- Demonstrate signature authoring capability
- Inspect HTTP payload content
- Simulate SOC rule tuning

Example:

```
alert tcp any any -> 192.168.200.10 80 (msg:"RAW SQLI UNION DETECTED"; content:"UNION"; nocase; sid:1002001; rev:1;)
```

---

# Validation Methodology

Each attack was validated at multiple layers:

### Packet Level
- tcpdump on ingress and egress interfaces
- HTTP payload visibility confirmed
- SYN packets observed

### Alert Level
- fast.log verification
- SID confirmation
- Signature validation

### Structured Log Level
- eve.json inspection
- HTTP metadata extraction
- Source/destination correlation

This confirms full inspection pipeline integrity.

---

# Evidence Structure

All validation screenshots are organized under:

```
evidence/screenshots/
```

By category:

- 00_Architecture
- 01_Infrastructure_Setup
- 02_Rule_Engine_Validation
- 03_Network_Path_Validation
- 04_Recon_Scan
- 05_SQLi_Case_Study
- 06_XSS_Case_Study

---

# Security Concepts Demonstrated

- Network segmentation enforcement
- Inline IDS architecture
- Dual-interface routing
- East-West traffic inspection
- Payload-based detection
- Reconnaissance detection engineering
- Web attack signature validation
- SOC-style log analysis
- Structured event logging

---

# Project Outcome

The Suricata IDS Detection Lab successfully demonstrates:

✔ Proper inline IDS deployment  
✔ Full traffic visibility across segmented networks  
✔ Reconnaissance detection  
✔ SQL injection detection  
✔ XSS detection  
✔ ET Open integration  
✔ Custom signature engineering  
✔ Structured alert validation  

This lab reflects practical blue-team and detection engineering skills applicable to SOC and network security roles.

---

# Author

Harshit Krishna  
MS Cybersecurity - University of Delaware  
