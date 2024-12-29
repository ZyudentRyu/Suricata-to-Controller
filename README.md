# ICMP-FLOOD_onos_suricata
This script detects and mitigates ICMP Flood attacks using Suricata logs. It monitors /var/log/suricata/eve.json in real-time, identifies suspicious patterns, and communicates with ONOS via REST API to create flows redirecting attacker traffic to a mitigation port. It ensures efficient handling and avoids duplicate processing.
