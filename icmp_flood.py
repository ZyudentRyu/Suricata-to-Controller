import json
import requests
import time
import threading

# Configuration
suricata_log_file = "/var/log/suricata/eve.json"  # Path to the Suricata log file
onos_api_url = "http://192.168.86.3:8181/onos/v1/flows"  # ONOS API URL
onos_auth = ("onos", "rocks")  # ONOS authentication credentials
mitigation_port = "6"  # Mitigation port for ICMP Flood
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
                time.sleep(0.1)  # Wait briefly if there are no new logs for faster responsiveness
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
                    if "Potential ICMP Flood Attack" in signature or "ICMP Flood Detected" in signature:
                        # Only process IPs that have not been mitigated
                        if src_ip not in mitigated_ips:
                            print("Detected ICMP Flood from {}".format(src_ip))
                            handle_icmp_flood(src_ip)
                        else:
                            # Skip already mitigated IPs
                            continue
            except json.JSONDecodeError:
                print("Warning: Invalid JSON log entry, ignored.")
                continue

def handle_icmp_flood(src_ip):
    """
    Handles detected ICMP Flood attacks by creating a flow on the ONOS controller
    to redirect traffic from the attacker's IP to the mitigation port.
    """
    print("Handling ICMP Flood from {}".format(src_ip))
    add_flow_to_onos(src_ip, mitigation_port)
    # Mark the IP as mitigated
    mitigated_ips.add(src_ip)

def add_flow_to_onos(src_ip, mitigation_port):
    """
    Creates and sends a flow to the ONOS controller to redirect traffic to the mitigation port.
    The flow filters ICMP traffic from the attacker's IP and applies the redirection.
    """
    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000ce88b0279447",  # Replace with your switch Device ID
        "treatment": {
            "instructions": [
                {"type": "OUTPUT", "port": mitigation_port}
            ]
        },
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},  # IPv4
                {"type": "IP_PROTO", "protocol": 1},  # ICMP
                {"type": "IPV4_SRC", "ip": src_ip + "/32"}  # Filter by source IP
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
        print("Flow successfully added for IP {}, redirecting to port {}".format(src_ip, mitigation_port))
    else:
        print("Failed to add flow: {} - {}".format(response.status_code, response.text))

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
