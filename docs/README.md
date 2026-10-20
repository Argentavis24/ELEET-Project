# 📚 CYBERDEFEND NIDS — Engineering & Operations Guide

This documentation provides an in-depth reference for the CyberDefend Network Intrusion Detection System (NIDS), covering detection algorithms, API specifications, database schemas, and threat vectors.

---

## 1. Detection Rule Signatures & Heuristics

### A. Port Scanning (`PortScanRule`)
- **File**: `app/engine/rules/port_scan.py`
- **Mechanism**: Correlates destination ports hit by a given `src_ip` within a sliding time window (default 12.0 seconds).
- **Threshold**: When `len(distinct_ports) >= 5`, an alert is generated.
- **Classification**: `Port Scan` | **Severity**: `High` | **Risk Score**: `0.85`
- **Mitigation**: Quarantine `src_ip` and verify host firewall configuration.

### B. Brute-Force Login Attempts (`BruteForceRule`)
- **File**: `app/engine/rules/brute_force.py`
- **Target Ports**: 22 (SSH), 3389 (RDP), 21 (FTP), 23 (Telnet), 3306 (MySQL), 5432 (PostgreSQL), 8080 (Auth).
- **Threshold**: $\ge 4$ attempts within 15.0 seconds.
- **Classification**: `Brute Force` | **Severity**: `High` | **Risk Score**: `0.88`
- **Mitigation**: Deploy fail2ban / rate-limiting, isolate source host.

### C. Volumetric DDoS & Flood Behavior (`DdosFloodRule`)
- **File**: `app/engine/rules/ddos_flood.py`
- **Mechanism**: Aggregates packet and byte counts within a short 5.0 second window.
- **Threshold**: Total packets $\ge 400$ or flow count $\ge 25$ or single flow packet count $\ge 250$.
- **Classification**: `DDoS Flood` | **Severity**: `Critical` | **Risk Score**: `0.95`
- **Mitigation**: Drop traffic at perimeter border gateway (BGP/ACL).

### D. Suspicious Outbound Traffic (`SuspiciousTrafficRule`)
- **File**: `app/engine/rules/suspicious_traffic.py`
- **Target Ports**: 4444 (Metasploit Meterpreter), 1337 (Trojan backdoor), 6667 (IRC C2), 31337 (BackOrifice), 8888, 9999, 5555.
- **Data Exfiltration**: Single flow payload $\ge 5,000,000$ bytes (5 MB).
- **Classification**: `Suspicious Outbound` | **Severity**: `High / Critical` | **Risk Score**: `0.82 - 0.88`
- **Mitigation**: Isolate host, dump memory for forensics, check running processes.

### E. ARP Poisoning / MAC Spoofing (`ArpSpoofRule`)
- **File**: `app/engine/rules/arp_spoof.py`
- **Mechanism**: Maintains stateful IP-to-MAC mapping.
- **Detection**: Flags conflict when a new packet arrives claiming an IP that is already assigned to a different physical MAC address.
- **Classification**: `ARP Spoofing` | **Severity**: `Critical` | **Risk Score**: `0.92`
- **Mitigation**: Enable Dynamic ARP Inspection (DAI) on switches.

### F. Blacklisted Threat Actor Intelligence (`BlacklistRule`)
- **File**: `app/engine/rules/blacklist.py`
- **Mechanism**: Compares source and destination IPs against known threat actor intelligence feeds.
- **Classification**: `Blacklisted IP` | **Severity**: `Critical` | **Risk Score**: `0.98`
- **Mitigation**: Immediate host isolation and perimeter firewall blacklisting.

---

## 2. Machine Learning Anomaly Detection

- **File**: `app/engine/ml_detector.py`
- **Algorithm**: `sklearn.ensemble.IsolationForest`
- **Feature Vector**:
  1. $\ln(1 + \text{duration})$
  2. $\ln(1 + \text{packet\_count})$
  3. $\ln(1 + \text{byte\_count})$
  4. $\ln(1 + \text{bytes\_per\_packet})$
  5. $\ln(1 + \text{packets\_per\_second})$
  6. $\ln(1 + \text{bytes\_per\_second})$
  7. $\text{destination\_port} / 65535.0$
  8. $\text{protocol\_code}$ (TCP=1.0, UDP=2.0, ICMP=3.0)
- **Scoring**: Maps raw decision function into normalized $[0.0, 1.0]$ risk score via sigmoid transformation. Alerts trigger for scores $\ge 0.75$.

---

## 3. Active Defense & Quarantine Flow

```
[Incoming Flow] -> [Check Quarantined IPs]
                          |
             +------------+------------+
             |                         |
       (IP is Quarantined)        (IP is Clean)
             |                         |
     [Mark as Blocked]           [Sliding Window]
     [Risk Score = 1.0]          [Heuristics + ML]
     [Drop Immediately]          [Process normally]
```

Analysts can toggle quarantine in two ways:
1. **1-Click Alert Drawer Quarantine**: While investigating an alert in the modal, clicking "Quarantine IP" adds the threat actor to the active blocklist.
2. **Dedicated Quarantine View**: Manually add or release IPs with real-time database persistence.

---

## 4. Sample Seed Data

The database initializes automatically with:
- **Default Users**:
  - `admin` / `CyberDefense2026!`
  - `analyst` / `Analyst2026!`
- **90 Baseline Flows**: Normal enterprise traffic (HTTP/S, DNS, NTP, SSH, PostgreSQL, MySQL) distributed across internal workstations and servers.
- **Sample Intrusion Alerts**:
  - Pre-seeded Port Scan, SSH Brute Force, Volumetric Flood, Metasploit C2 Exfiltration, ARP Poisoning, and Blacklisted IP communications.
- **Initial Quarantined Hosts**:
  - `198.51.100.23` (Mirai C2 Botnet)
  - `10.0.0.88` (Volumetric Flood Source)
  - `185.220.101.5` (Tor Exit Relay)
