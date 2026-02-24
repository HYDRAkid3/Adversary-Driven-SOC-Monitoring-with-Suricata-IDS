# ============================================================
# Suricata IDS Detection Lab - Config Snippets (Sanitized)
# Author: Harshit Krishna
# Purpose: Lab-relevant Suricata configuration excerpts
# ============================================================

# -----------------------------
# Network Variables
# -----------------------------
vars:
  address-groups:
    HOME_NET: "[192.168.100.0/24,192.168.200.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

# -----------------------------
# Rule Loading (ET Open + Local)
# -----------------------------
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
  - local.rules

# -----------------------------
# Outputs (Evidence)
# -----------------------------
outputs:
  # Fast alert log (human-readable)
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  # EVE JSON (structured logging)
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

# -----------------------------
# Capture / Deployment Notes
# -----------------------------
# This lab uses Suricata as an inspection gateway between SOC-IN and SOC-OUT.
# Traffic traversal is validated with tcpdump on enp0s3/enp0s8.
#
# The live capture interface is configured on the VM runtime (service/unit or CLI),
# for example:
#   sudo suricata -D -c /etc/suricata/suricata.yaml -i enp0s3
#
# Full configuration remains on the Suricata VM:
#   /etc/suricata/suricata.yaml
