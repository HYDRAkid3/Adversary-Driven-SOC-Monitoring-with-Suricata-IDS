# 05 - XSS Case Study

## Objective

Simulate reflected XSS attack and validate detection.

---

## XSS Payload Capture (tcpdump)

![XSS Packet](../assets/screenshots/5%20XSS%20Case%20Study/01_tcpdump_xss_payload.png)

Payload inspection at network layer.

---

## Suricata Alert (fast.log)

![fast.log XSS](../assets/screenshots/5%20XSS%20Case%20Study/02_fast_log_xss_alert.png)

Custom rule triggered successfully.

---

## eve.json Structured Alert

![eve.json XSS](../assets/screenshots/5%20XSS%20Case%20Study/03_eve_json_xss_alert.png)

Structured JSON event generated.

---

## MITRE ATT&CK

T1059 – Command and Scripting Interpreter

---

## Findings

- Reflected XSS detected
- HTTP inspection confirmed
- Structured logging validated
