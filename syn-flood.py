import json
import requests
import time

# Configuration
suricata_log_file = "/path/to/suricata/eve.json"  # Path to the Suricata log file
onos_api_url = "http://<controller-ip>:<controller-port>/onos/v1/flows"  # ONOS API URL
onos_auth = ("username", "password")  # ONOS credentials
mitigation_ports = {
    # Example: {<attacked_port>: "<mitigation_port>"}
    # Define ports here, e.g., 80: "5", 22: "4"
}

def monitor_suricata_log():
    """
    Monitors the Suricata log file for potential alerts.
    Reads the file line by line and processes JSON data for specific alert types.
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
                # Example condition: Check for specific alert type
                if log_data.get("event_type") == "alert" and "Specific Alert" in log_data.get("alert", {}).get("signature", ""):
                    src_ip = log_data.get("src_ip", "")
                    dest_port = log_data.get("dest_port", "")
                    print(f"Alert detected from {src_ip} on port {dest_port}")
                    handle_alert(src_ip, dest_port)
            except json.JSONDecodeError:
                print(f"Warning: Invalid JSON line ignored. Line: {line}")
                continue

def handle_alert(src_ip, dest_port):
    """
    Handles the detection of specific alerts based on the destination port.
    Checks if the port is in the mitigation_ports mapping and redirects traffic if applicable.
    """
    if dest_port in mitigation_ports:
        mitigation_port = mitigation_ports[dest_port]  # Determine mitigation port
        print(f"Redirecting traffic from {src_ip} targeting port {dest_port} to mitigation port {mitigation_port}")
        add_flow_to_onos(src_ip, mitigation_port)
    else:
        print(f"Port {dest_port} not recognized for mitigation. No action taken.")

def add_flow_to_onos(src_ip, mitigation_port):
    """
    Adds a flow to ONOS to redirect traffic to the mitigation port.
    Uses ONOS REST API to create a flow rule for the specified IP and port.
    """
    flow = {
        "priority": 40000,  # Example priority for the flow
        "timeout": 0,  # 0 means no timeout (permanent flow)
        "isPermanent": True,  # Set to True to keep the flow rule active
        "deviceId": "<switch_device_id>",  # Replace with your switch's Device ID (e.g., "of:0000000000000001")
        "treatment": {
            "instructions": [
                {"type": "OUTPUT", "port": mitigation_port}
            ]
        },
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},  # IPv4 (Ethernet type)
                {"type": "IP_PROTO", "protocol": 6},  # Protocol 6 = TCP
                {"type": "IPV4_SRC", "ip": f"{src_ip}/32"}  # Source IP address
            ]
        }
    }

    data = {"flows": [flow]}
    headers = {"Content-Type": "application/json"}
    response = requests.post(onos_api_url, auth=onos_auth, headers=headers, json=data)
    if response.status_code in (200, 201):
        print(f"Flow successfully added for IP {src_ip}, redirecting to port {mitigation_port}")
    else:
        print(f"Failed to add flow: {response.status_code} - {response.text}")

# Start monitoring the Suricata log
monitor_suricata_log()
