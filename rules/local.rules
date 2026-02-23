# ============================================================
# Suricata IDS Detection Lab - Custom Rules
# Author: Harshit Krishna
# Purpose: Lab detection validation rules
# ============================================================


# ------------------------------------------------------------
# 1. ICMP Path Validation
# ------------------------------------------------------------
alert icmp any any -> any any (
    msg:"LAB ICMP Traffic Observed (Path Validation)";
    itype:8;
    classtype:network-event;
    sid:1000001;
    rev:1;
)


# ------------------------------------------------------------
# 2. SYN Scan Detection (Threshold-Based)
# ------------------------------------------------------------
alert tcp any any -> 192.168.200.0/24 any (
    msg:"LAB Possible SYN Scan Detected";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 20, seconds 10;
    classtype:attempted-recon;
    sid:1000010;
    rev:1;
)


# ------------------------------------------------------------
# 3. SQL Injection Detection
# ------------------------------------------------------------

# OR 1=1 pattern
alert http any any -> 192.168.200.10 80 (
    msg:"LAB SQL Injection Attempt - OR 1=1 Pattern";
    flow:to_server,established;
    http.uri;
    content:"or 1=1"; nocase;
    classtype:web-application-attack;
    sid:1000020;
    rev:1;
)

# UNION SELECT pattern
alert http any any -> 192.168.200.10 80 (
    msg:"LAB SQL Injection Attempt - UNION SELECT";
    flow:to_server,established;
    http.uri;
    content:"union"; nocase;
    classtype:web-application-attack;
    sid:1000021;
    rev:1;
)


# ------------------------------------------------------------
# 4. Cross-Site Scripting (XSS) Detection
# ------------------------------------------------------------

# <script> tag detection
alert http any any -> 192.168.200.10 80 (
    msg:"LAB XSS Attempt - Script Tag Detected";
    flow:to_server,established;
    http.uri;
    content:"<script"; nocase;
    classtype:web-application-attack;
    sid:1000030;
    rev:1;
)

# Encoded script detection
alert http any any -> 192.168.200.10 80 (
    msg:"LAB Encoded XSS Attempt Detected";
    flow:to_server,established;
    http.uri;
    content:"%3Cscript%3E"; nocase;
    classtype:web-application-attack;
    sid:1000031;
    rev:1;
)
