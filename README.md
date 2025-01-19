Suricata-to-ONOS Mitigation Scripts

This repository contains scripts designed to detect and mitigate network-based attacks using Suricata as an Intrusion Detection System (IDS). 
Detected threats are communicated to an ONOS controller to enforce mitigation by redirecting malicious traffic to specified ports.

Features
- Real-time Detection: Monitors /var/log/suricata/eve.json for potential attack patterns such as ICMP Floods or SYN Floods.
- Automated Mitigation: Sends flow rules to the ONOS SDN controller to handle malicious traffic.
- Non-intrusive: Works as an IDS by analyzing logs without directly interrupting normal traffic flows.
- Extensible: Can be adapted to detect and respond to various attack types.

Scripts Overview
1.) icmp-flood.py
This script focuses on detecting ICMP Flood attacks:
-Continuously monitors Suricata logs for "ICMP Flood Detected" alerts.
-Sends instructions to ONOS to redirect traffic from malicious IPs to a mitigation port.

Key Features:
-Efficient detection of ICMP-based attacks.
-Tracks mitigated source IPs to avoid duplicate flow rules.


2.) syn-flood.py
This script is tailored for detecting SYN Flood attacks:
- Monitors Suricata logs for "SYN Flood Detected" alerts.
- Automatically communicates with ONOS to mitigate the attack by redirecting traffic.

Key Features:
- Handles high-volume SYN packets efficiently.
- Configurable rules for redirecting traffic to specific ports.

How It Works

- IDS Monitoring:
  Suricata is configured as an Intrusion Detection System to analyze network traffic and generate alerts in /var/log/suricata/eve.json.

- Attack Detection:
  Scripts parse the Suricata logs to identify specific attack patterns, such as ICMP Flood or SYN Flood.

- Mitigation:
  For detected attacks, scripts send flow rules to the ONOS controller using its REST API to redirect malicious traffic.

Running the Scripts
- python3 icmp-flood.py
- python3 syn-flood.py
