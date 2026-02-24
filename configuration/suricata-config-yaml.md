# Suricata Configuration (suricata.yaml) — Detailed Lab Reference

This document provides a **structured and descriptive reference** of the key `suricata.yaml` settings used in this detection engineering lab.

The objective is to clearly explain:

- How Suricata is deployed
- How rules are loaded
- How network scoping is defined
- Where alerts are generated
- How evidence is collected

This is not a full raw configuration dump.  
Instead, it highlights only the lab-relevant sections.

---

## Live Configuration Locations

Suricata VM paths:

- Main configuration file:  
  `/etc/suricata/suricata.yaml`

- Rule directory (ET Open + local rules):  
  `/var/lib/suricata/rules/`

- Log directory:  
  `/var/log/suricata/`

---

## 1. Deployment Mode

Suricata is deployed as a **routing inspection gateway** between two segmented networks.

### Network Layout

- SOC-IN  → 192.168.100.0/24  
- SOC-OUT → 192.168.200.0/24  

Traffic Flow:

Kali (Attacker)  
→ Suricata (Inspection Gateway)  
→ DVWA (Victim Web Server)

IP forwarding is enabled on the Suricata VM:

```
net.ipv4.ip_forward = 1
```

This ensures all inter-network traffic traverses the IDS.

Suricata is running in:

**IDS Mode (Detection Only)**  
- Generates alerts
- Logs events
- Does not block traffic

This mirrors a passive monitoring deployment common in SOC environments.

---

## 2. Network Variables (HOME_NET / EXTERNAL_NET)

Suricata uses network variables to determine what is considered internal versus external traffic.

In this lab, both subnets are controlled lab networks, so they are grouped into HOME_NET.

Recommended configuration:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.100.0/24,192.168.200.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
```

### Why This Matters

- Many ET Open rules reference `$HOME_NET`
- Correct scoping ensures alerts fire against intended targets
- Misconfigured HOME_NET can cause missed detections or excessive noise

In production environments, HOME_NET would represent trusted internal assets only.

---

## 3. Rule Loading Configuration

Suricata loads rule files from a default directory and processes them in sequence.

Lab configuration:

```yaml
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
  - local.rules
```

### Rule File Breakdown

- `suricata.rules`
  - ET Open baseline rule set
  - ~48,000+ alert signatures
  - Covers web attacks, reconnaissance, malware, protocol anomalies

- `local.rules`
  - Custom lab detection rules
  - Deterministic validation for:
    - ICMP path validation
    - SYN scan detection
    - SQL Injection indicators
    - XSS indicators

### Detection Strategy

Layered detection model:

1. Community baseline (ET Open)
2. Custom environment-specific rules (local.rules)

This mirrors enterprise SOC practices.

---

## 4. Logging Outputs (Evidence Generation)

Suricata generates both human-readable and structured outputs.

### 4.1 fast.log

Configuration:

```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
```

Purpose:

- Quick alert validation
- Screenshot-friendly proof
- Analyst-readable alert summary

Location:

```
/var/log/suricata/fast.log
```

---

### 4.2 eve.json (Structured Logging)

Configuration:

```yaml
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: yes
      types:
        - alert:
            tagged-packets: yes
        - http
        - dns
        - tls
        - flow
```

Purpose:

- Structured JSON output
- SIEM ingestion readiness
- Rich metadata for analysis
- Correlation across sessions

Location:

```
/var/log/suricata/eve.json
```

The `community-id` enables consistent flow hashing for correlation across tools.

---

## 5. Capture & Traffic Visibility

Suricata must bind to an interface that observes the traffic path.

In this lab:

- enp0s3 → SOC-IN
- enp0s8 → SOC-OUT

Packet-level validation is performed using:

```
tcpdump -i enp0s3
tcpdump -i enp0s8
```

This confirms:

- Traffic traversal
- Payload visibility
- IDS placement correctness

---

## 6. Configuration Validation Procedure

Before starting Suricata after configuration changes:

```
sudo suricata -T -c /etc/suricata/suricata.yaml
```

This verifies:

- YAML syntax validity
- Rule file loading
- Rule parsing success
- Output initialization

This prevents silent rule-loading failures.

---

## 7. Evidence Mapping

| Component | Location | Purpose |
|-----------|----------|----------|
| suricata.yaml | /etc/suricata/ | Core configuration |
| suricata.rules | /var/lib/suricata/rules/ | ET baseline signatures |
| local.rules | /var/lib/suricata/rules/ | Custom detection rules |
| fast.log | /var/log/suricata/ | Alert proof |
| eve.json | /var/log/suricata/ | Structured analysis |

---

## 8. Lab vs Production Considerations

This lab configuration is intentionally simplified:

- HTTP inspection only (no TLS decryption)
- No IPS blocking enabled
- No rule tuning for production-scale noise
- No SIEM integration in current phase

Future improvements:

- TLS metadata analysis
- SIEM integration (Wazuh / ELK)
- Rule performance benchmarking
- False-positive reduction methodology
- IPS inline mode validation

---

## Summary

This configuration demonstrates:

- Correct network scoping
- Proper rule loading hierarchy
- ET Open baseline integration
- Custom rule layering
- Structured event generation
- Operational validation discipline

It reflects a practical detection engineering approach rather than a minimal IDS lab setup.
