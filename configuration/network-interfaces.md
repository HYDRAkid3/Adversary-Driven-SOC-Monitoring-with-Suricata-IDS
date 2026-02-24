# Network Interfaces & Segmentation Design

This document defines the network topology, interface configuration, IP addressing model, and enforcement architecture used in the Suricata IDS Detection Lab.

The lab simulates a segmented environment where all inter-subnet traffic must traverse an inspection gateway before reaching its destination.

Attacker: 192.168.100.10  
Inspection Gateway (Suricata): 192.168.100.1 / 192.168.200.1  
Target Server (DVWA): 192.168.200.10  

## 1) Virtual Network Architecture

Two isolated VirtualBox Internal Networks are created:

SOC-IN  → 192.168.100.0/24  
SOC-OUT → 192.168.200.0/24  

Suricata is deployed as a dual-homed routing gateway between these networks.

Traffic flow:

Kali (192.168.100.10)  
→ Suricata (Inspection Gateway)  
→ Ubuntu DVWA (192.168.200.10)

This guarantees:
- No direct attacker-to-victim communication
- Mandatory routing through Suricata
- Full packet visibility at the inspection boundary

## 2) VirtualBox Adapter Configuration

Suricata Adapter 1 (SOC-IN):

![SOC-IN Adapter Configuration](../evidence/screenshots/01_Infrastructure_Setup/01_suricata_adapter_soc_in.png)

Configuration:
- Attached to: Internal Network
- Network Name: SOC-IN
- Promiscuous Mode: Allow All
- Adapter Type: Intel PRO/1000 MT Desktop

Suricata Adapter 2 (SOC-OUT):

![SOC-OUT Adapter Configuration](../evidence/screenshots/01_Infrastructure_Setup/02_suricata_adapter_soc_out.png)

Configuration:
- Attached to: Internal Network
- Network Name: SOC-OUT
- Promiscuous Mode: Allow All
- Adapter Type: Intel PRO/1000 MT Desktop

This dual-homed setup allows Suricata to route and inspect traffic between isolated subnets.

## 3) Interface State Validation

After booting Suricata, interfaces were validated.

Command executed:
ip -br a

![Interfaces Up Verification](../evidence/screenshots/01_Infrastructure_Setup/03_suricata_interfaces_up.png)

Confirmed:
- enp0s3 → 192.168.100.1/24
- enp0s8 → 192.168.200.1/24
- Both interfaces UP
- Proper subnet assignment

This verifies correct IP configuration and dual-interface availability.

## 4) IP Addressing Model

Kali Linux (Attacker):
- Network: SOC-IN
- IP: 192.168.100.10/24
- Default Gateway: 192.168.100.1

Suricata IDS Gateway:
- enp0s3 → 192.168.100.1/24
- enp0s8 → 192.168.200.1/24

Ubuntu DVWA (Victim):
- Network: SOC-OUT
- IP: 192.168.200.10/24
- Default Gateway: 192.168.200.1

Because both subnets use Suricata as their gateway, all inter-subnet traffic must traverse the inspection engine.

## 5) IP Forwarding Configuration

To enable routing functionality, IPv4 forwarding must be enabled.

Command:
sudo sysctl -w net.ipv4.ip_forward=1

Verification:
cat /proc/sys/net/ipv4/ip_forward

![IP Forwarding Enabled](../evidence/screenshots/01_Infrastructure_Setup/04_ip_forwarding_enabled.png)

Expected output:
1

Without IP forwarding:
- Packets would not traverse between enp0s3 and enp0s8
- Segmentation enforcement would fail
- IDS inspection would be bypassed

## 6) Suricata Configuration Validation

Before activating detection mode, Suricata configuration was validated.

Command:
sudo suricata -T -c /etc/suricata/suricata.yaml

![Configuration Validation Success](../evidence/screenshots/01_Infrastructure_Setup/05_configuration_validation_success.png)

This confirms:
- Configuration syntax valid
- Rule files successfully loaded
- No YAML parsing errors

## 7) Suricata Runtime Engine Initialization

When Suricata starts, engine initialization and thread creation are verified.

![Engine Initialization](../evidence/screenshots/01_Infrastructure_Setup/06_suricata_engine_initialized.png)

![Runtime Threads Created](../evidence/screenshots/01_Infrastructure_Setup/07_suricata_runtime_threads.png)

Observed:
- Multi-threaded packet processing
- Flow manager initialized
- Both capture interfaces active
- IDS engine running in system mode

This confirms Suricata is actively inspecting traffic on both network boundaries.

## 8) Traffic Enforcement Model

Because Kali and DVWA both use Suricata as their default gateway:

- Kali cannot directly reach 192.168.200.10
- Packets must traverse enp0s3 → routing engine → enp0s8
- Suricata inspects packets at Layer 3, 4, and 7

Validation using tcpdump:

Monitor ingress:
sudo tcpdump -i enp0s3

Monitor egress:
sudo tcpdump -i enp0s8

When generating traffic (ICMP or HTTP), packets appear first on enp0s3 and then on enp0s8, confirming correct inline routing and inspection placement.

## 9) Security Design Rationale

This architecture simulates:

- Segmented internal networks
- East-West traffic inspection
- SOC monitoring boundary
- Controlled attacker environment
- Reproducible detection validation

Advantages:
- Deterministic traffic path
- No bypass routes
- Full packet visibility
- Clear trust boundary enforcement

## 10) Summary

The network design demonstrates:

- Dual-homed IDS deployment
- Enforced inter-subnet inspection
- Validated routing configuration
- Active packet capture on both interfaces
- Controlled segmentation model

This topology ensures that all reconnaissance and exploitation traffic is inspected, logged, and reproducible within a structured detection environment.
