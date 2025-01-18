import json
import requests
import time

# Configuration
suricata_log_file = "/var/log/suricata/eve.json"  # Path to the Suricata log file
onos_api_url = "http://192.168.86.3:8181/onos/v1/flows"  # ONOS API URL
onos_auth = ("onos", "rocks")  # ONOS credentials
mitigation_ports = {
    80: "",  # Redirect traffic from port 80 to port mitigation
    22: ""   # Redirect traffic from port 22 to port mitigation
}

def monitor_suricata_log():
    """
    Monitors the Suricata log file for SYN Flood attacks.
    """
    with open(suricata_log_file, "r") as log_file:
        log_file.seek(0, 2)  # Move the pointer to the end of the file
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(1)  # Wait if there are no new lines
                continue
            line = line.strip()
            if not line:
                continue
            try:
                log_data = json.loads(line)
                # Process only if the event_type is "alert" and SYN Flood is detected
                if log_data.get("event_type") == "alert" and "SYN Flood Detected" in log_data.get("alert", {}).get("signature", ""):
                    src_ip = log_data.get("src_ip", "")
                    dest_port = log_data.get("dest_port", "")
                    print("SYN Flood detected from {} on port {}".format(src_ip, dest_port))
                    handle_syn_flood(src_ip, dest_port)
            except json.JSONDecodeError:
                print("Warning: Invalid JSON line ignored. Line: {}".format(line))
                continue

def handle_syn_flood(src_ip, dest_port):
    """
    Handles the detection of SYN Flood attacks based on the destination port.
    """
    if dest_port in mitigation_ports:
        mitigation_port = mitigation_ports[dest_port]  # Determine mitigation port based on the attacked port
        print("Redirecting traffic from {} targeting port {} to mitigation port {}".format(src_ip, dest_port, mitigation_port))
        add_flow_to_onos(src_ip, mitigation_port)
    else:
        print("Port {} not recognized for mitigation. No action taken.".format(dest_port))

def add_flow_to_onos(src_ip, mitigation_port):
    """
    Adds a flow to ONOS to redirect traffic to the mitigation port.
    """
    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000eafec7cab942",  # Replace with your switch's Device ID
        "treatment": {
            "instructions": [
                {"type": "OUTPUT", "port": mitigation_port}
            ]
        },
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},  # IPv4
                {"type": "IP_PROTO", "protocol": 6},  # TCP
                {"type": "IPV4_SRC", "ip": src_ip + "/32"}
            ]
        }
    }

    data = {"flows": [flow]}
    headers = {"Content-Type": "application/json"}
    response = requests.post(onos_api_url, auth=onos_auth, headers=headers, json=data)
    if response.status_code in (200, 201):
        print("Flow successfully added for IP {}, redirecting to port {}".format(src_ip, mitigation_port))
    else:
        print("Failed to add flow: {} - {}".format(response.status_code, response.text))

# Start monitoring the Suricata log
monitor_suricata_log()
