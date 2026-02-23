# 01 - Infrastructure Setup

## Objective

Deploy Suricata IDS as a dual-NIC routing inspection gateway between attacker and victim networks.

---

## Suricata Engine Startup

![Engine Started](../assets/screenshots/1%20Infrastructure%20Setup/01_suricata_engine_started.png)

Suricata engine successfully initialized.

---

## Interface Verification

![Interfaces Up](../assets/screenshots/1%20Infrastructure%20Setup/02_suricata_interfaces_up.png)

Both interfaces (enp0s3 & enp0s8) confirmed active.

---

## IP Forwarding Enabled

![IP Forwarding](../assets/screenshots/1%20Infrastructure%20Setup/03_ip_forwarding_enabled.png)

Kernel IP forwarding enabled to allow routing inspection.

---

## Configuration Validation

![Config Validation](../assets/screenshots/1%20Infrastructure%20Setup/04_config_validation_success.png)

Suricata configuration successfully validated using:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

---

## Runtime Threads

![Engine Threads](../assets/screenshots/1%20Infrastructure%20Setup/05_engine_runtime_threads.png)

Suricata running in IDS mode with active packet processing threads.

---

## Findings

- Dual NIC routing configuration operational
- Suricata positioned inline as inspection gateway
- Traffic routing successfully enforced
