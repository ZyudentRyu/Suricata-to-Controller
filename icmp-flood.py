import json
import requests
import time
import threading

# Configuration
suricata_log_file = "/path/to/suricata/eve.json"  # Path to the Suricata log file
onos_api_url = "http://<controller-ip>:<controller-port>/onos/v1/flows"  # ONOS API URL
onos_auth = ("username", "password")  # ONOS authentication credentials
mitigation_port = "<mitigation_port>"  # Mitigation port for ICMP Flood
mitigated_ips = set()  # Set to store mitigated IPs

def monitor_suricata_log():
    """
    Monitors the Suricata log file in real-time to detect ICMP Flood attacks.
    Reads the log continuously, checks for alerts, and triggers mitigation if an attack is detected.
    """
    with open(suricata_log_file, "r") as log_file:
        log_file.seek(0, 2)  # Move to the end of the file to fetch the latest logs
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(0.1)  # Wait briefly if there are no new logs
                continue
            line = line.strip()
            if not line:
                continue
            try:
                log_data = json.loads(line)
                # Detect attack based on ICMP Flood alert
                if log_data.get("event_type") == "alert":
                    signature = log_data.get("alert", {}).get("signature", "")
                    src_ip = log_data.get("src_ip", "")

                    # Detect relevant signatures for ICMP Flood
                    if "<ICMP_Flood_Signature>" in signature:
                        # Only process IPs that have not been mitigated
                        if src_ip not in mitigated_ips:
                            print(f"Detected ICMP Flood from {src_ip}")
                            handle_icmp_flood(src_ip)
                        else:
                            continue
            except json.JSONDecodeError:
                print("Warning: Invalid JSON log entry, ignored.")
                continue

def handle_icmp_flood(src_ip):
    """
    Handles detected ICMP Flood attacks by creating a flow on the ONOS controller
    to redirect traffic from the attacker's IP to the mitigation port.
    """
    print(f"Handling ICMP Flood from {src_ip}")
    add_flow_to_onos(src_ip, mitigation_port)
    # Mark the IP as mitigated
    mitigated_ips.add(src_ip)

def add_flow_to_onos(src_ip, mitigation_port):
    """
    Creates and sends a flow to the ONOS controller to redirect traffic to the mitigation port.
    The flow filters ICMP traffic from the attacker's IP and applies the redirection.
    """
    flow = {
        "priority": <priority>,  # Example: 40000
        "timeout": <timeout>,  # Example: 0 (no timeout)
        "isPermanent": <true_or_false>,  # Example: True
        "deviceId": "<switch_device_id>",  # Replace with your switch's Device ID
        "treatment": {
            "instructions": [
                {"type": "OUTPUT", "port": mitigation_port}
            ]
        },
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "<ethType>"},  # Example: 0x0800 (IPv4)
                {"type": "IP_PROTO", "protocol": <protocol>},  # Example: 1 (ICMP)
                {"type": "IPV4_SRC", "ip": f"{src_ip}/32"}  # Filter by source IP
            ]
        }
    }

    data = {"flows": [flow]}
    headers = {"Content-Type": "application/json"}
    response = requests.post(onos_api_url, auth=onos_auth, headers=headers, json=data)

    # Log the response for debugging
    print("Response Status:", response.status_code)
    print("Response Text:", response.text)

    if response.status_code in (200, 201):
        print(f"Flow successfully added for IP {src_ip}, redirecting to port {mitigation_port}")
    else:
        print(f"Failed to add flow: {response.status_code} - {response.text}")

# Start monitoring the Suricata log in a separate thread for faster response
def start_monitoring():
    """
    Starts the log monitoring process in a separate thread to ensure efficient operation.
    """
    monitoring_thread = threading.Thread(target=monitor_suricata_log)
    monitoring_thread.daemon = True  # The thread will stop when the main program stops
    monitoring_thread.start()

# Begin monitoring the Suricata log
start_monitoring()

# Keep the main program running
while True:
    time.sleep(10)  # Keep the program alive
