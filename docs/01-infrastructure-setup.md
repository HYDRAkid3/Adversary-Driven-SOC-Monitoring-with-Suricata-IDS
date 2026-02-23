# 01 - Infrastructure Setup

## Objective

Deploy a dual-NIC Suricata IDS VM operating as a routing inspection gateway between attacker and victim networks.

---

## Lab Environment

Attacker:
Kali Linux
IP: 192.168.100.10
Gateway: 192.168.100.1

IDS:
Suricata VM
enp0s3 → 192.168.100.1 (SOC-IN)
enp0s8 → 192.168.200.1 (SOC-OUT)

Victim:
Ubuntu DVWA Server
IP: 192.168.200.10
Gateway: 192.168.200.1

---

## Network Segmentation

SOC-IN  : 192.168.100.0/24  
SOC-OUT : 192.168.200.0/24  

Traffic Flow:
Kali → Suricata → DVWA

---

## Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Permanent change:

```bash
sudo nano /etc/sysctl.conf
```

Add:
net.ipv4.ip_forward=1

---

## Validation

From Kali:

```bash
ping 192.168.200.10
```

From Suricata:

```bash
tcpdump -i enp0s3
tcpdump -i enp0s8
```

---

## Evidence

![Topology](../assets/screenshots/infrastructure/01-topology.png)

![IP Forwarding](../assets/screenshots/infrastructure/02-ip-forwarding.png)

---

## Findings

- Traffic successfully routed via Suricata
- Network segmentation enforced
- IDS positioned as inspection gateway
