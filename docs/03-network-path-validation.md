# 03 - Network Path Validation

## Objective

Confirm all attacker-to-victim traffic traverses Suricata.

---

## Kali Routing Table

![Kali Routing](../assets/screenshots/3%20Network%20Path%20Validation/01_kali_routing_table.png)

Kali gateway correctly pointing to Suricata.

---

## Packet Capture Validation

![Packet Capture](../assets/screenshots/3%20Network%20Path%20Validation/02_packet_capture_validation.png)

Traffic visible on Suricata interfaces.

---

## Raw HTTP SQLi Traffic (tcpdump)

![Raw SQLi](../assets/screenshots/3%20Network%20Path%20Validation/03_tcpdump_raw_http_sqli.png)

Payload inspection validated at packet level.

---

## Findings

- Routing enforcement confirmed
- Suricata successfully intercepting traffic
- Traffic inspection validated using tcpdump
