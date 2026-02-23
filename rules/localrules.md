# Suricata IDS Detection Lab - Custom Rules

Author: Harshit Krishna  
Purpose: Lab detection validation rules for Suricata IDS

---

## Overview

This file contains custom Suricata rules created to support controlled attack simulations within the lab environment.

These rules supplement the ET Open baseline rule set and are designed for:

- ICMP path validation
- SYN scan detection
- SQL Injection detection
- Cross-Site Scripting (XSS) detection

---

## Custom Rules

```rules
# ICMP Path Validation
alert icmp any any -> any any (
    msg:"LAB ICMP Traffic Observed (Path Validation)";
    itype:8;
    classtype:network-event;
    sid:1000001;
    rev:1;
)

# SYN Scan Detection
alert tcp any any -> 192.168.200.0/24 any (
    msg:"LAB Possible SYN Scan Detected";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 20, seconds 10;
    classtype:attempted-recon;
    sid:1000010;
    rev:1;
)

# SQL Injection - OR 1=1
alert http any any -> 192.168.200.10 80 (
    msg:"LAB SQL Injection Attempt - OR 1=1 Pattern";
    flow:to_server,established;
    http.uri;
    content:"or 1=1"; nocase;
    classtype:web-application-attack;
    sid:1000020;
    rev:1;
)

# SQL Injection - UNION
alert http any any -> 192.168.200.10 80 (
    msg:"LAB SQL Injection Attempt - UNION SELECT";
    flow:to_server,established;
    http.uri;
    content:"union"; nocase;
    classtype:web-application-attack;
    sid:1000021;
    rev:1;
)

# XSS Detection - Script Tag
alert http any any -> 192.168.200.10 80 (
    msg:"LAB XSS Attempt - Script Tag Detected";
    flow:to_server,established;
    http.uri;
    content:"<script"; nocase;
    classtype:web-application-attack;
    sid:1000030;
    rev:1;
)

# XSS Detection - Encoded Script
alert http any any -> 192.168.200.10 80 (
    msg:"LAB Encoded XSS Attempt Detected";
    flow:to_server,established;
    http.uri;
    content:"%3Cscript%3E"; nocase;
    classtype:web-application-attack;
    sid:1000031;
    rev:1;
)
```

---

## Notes

These rules are intentionally scoped to the lab network and target DVWA running on 192.168.200.10.

They are designed for controlled detection validation and do not replace enterprise-grade signature sets.
