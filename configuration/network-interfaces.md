# Network Interfaces & Segmentation Design

This document describes the network topology, interface configuration, IP addressing plan, and traffic enforcement model used in the Suricata IDS Detection Lab.

The goal of this design is to simulate a segmented internal environment where all inter-subnet traffic must traverse an inspection gateway.

---

# 1. Lab Network Architecture Overview

The lab is built using VirtualBox internal networks to simulate segmentation between attacker and victim systems.

Two isolated networks are created:

- SOC-IN  → 192.168.100.0/24
- SOC-OUT → 192.168.200.0/24

Suricata operates as a dual-homed routing gateway between these networks.

Traffic Flow Model:

Kali (Attacker)
→ Suricata (Inspection Gateway)
→ Ubuntu DVWA (Victim Web Server)

This enforces network-layer inspection before application access.

---

# 2. VirtualBox Network Configuration

Each VM is attached to a specific internal network:

SOC-IN:
- Used by Kali (Attacker)
- Connected to Suricata interface enp0s3

SOC-OUT:
- Used by DVWA (Victim Server)
- Connected to Suricata interface enp0s8

No direct connectivity exists between Kali and DVWA without routing through Suricata.

---

# 3. IP Addressing Plan

## Kali Linux (Attacker)

Network: SOC-IN  
IP Address: 192.168.100.10/24  
Default Gateway: 192.168.100.1  

Purpose:
- Performs reconnaissance (SYN scans)
- Launches SQL injection and XSS payloads
- Generates ICMP traffic for path validation

---

## Suricata IDS VM (Routing Inspection Gateway)

Interface: enp0s3  
Network: SOC-IN  
IP Address: 192.168.100.1/24  

Interface: enp0s8  
Network: SOC-OUT  
IP Address: 192.168.200.1/24  

Role:
- Acts as default gateway for both subnets
- Inspects traffic crossing trust boundaries
- Generates alerts but does not block traffic (IDS mode)

---

### IP Forwarding Configuration

To enable routing functionality:

```bash
sysctl net.ipv4.ip_forward
```

Expected:

```
net.ipv4.ip_forward = 1
```

If disabled:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

This ensures packets are forwarded between enp0s3 and enp0s8.

Without this, segmentation enforcement fails.

---

## Ubuntu DVWA (Victim Web Server)

Network: SOC-OUT  
IP Address: 192.168.200.10/24  
Default Gateway: 192.168.200.1  

Services:
- Apache Web Server
- DVWA (Damn Vulnerable Web Application)
- HTTP (Port 80)

Purpose:
- Target for exploitation testing
- Validates web-layer attack detection (SQLi, XSS)

---

# 4. Traffic Enforcement Model

Because both Kali and DVWA use Suricata as their default gateway:

- Kali cannot directly reach DVWA.
- All packets must pass through Suricata.
- Suricata observes and logs every inter-subnet packet.

This simulates:

- Network segmentation enforcement
- East-West traffic monitoring
- Perimeter-style inspection within internal networks

This is a realistic SOC monitoring scenario.

---

# 5. Interface Validation Commands

Before conducting attack simulations, verify interface correctness.

## View Interfaces

```bash
ip a
```

Confirm:
- enp0s3 → 192.168.100.1
- enp0s8 → 192.168.200.1

---

## Verify Routing Table

```bash
ip r
```

Confirm:
- Routes exist for both subnets
- Suricata acts as gateway

---

## Validate Packet Traversal

Monitor SOC-IN interface:

```bash
sudo tcpdump -i enp0s3
```

Monitor SOC-OUT interface:

```bash
sudo tcpdump -i enp0s8
```

When traffic is generated from Kali (e.g., ping or HTTP request):

- Packets should appear on enp0s3
- Forwarded packets should appear on enp0s8

This confirms correct placement of the IDS in the routing path.

---

# 6. Security Design Rationale

This segmentation model provides:

- Controlled attacker environment
- Isolated victim subnet
- Enforced inspection boundary
- Deterministic detection validation
- Clean traffic visibility

It reflects real-world scenarios such as:

- Internal network monitoring
- DMZ inspection gateways
- Lateral movement detection boundaries

---

# 7. Summary

This lab network design demonstrates:

- Dual-homed IDS deployment
- Enforced inter-subnet inspection
- Controlled segmentation
- Practical routing validation
- Wire-level traffic visibility

The topology ensures that detection results are accurate and reproducible.
