import joblib
import pickle
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from scapy.arch.windows import get_windows_if_list
from collections import defaultdict
from time import time
import pandas as pd
import os
import sys
import ctypes

# ---------------------------
# 1. ADMIN PRIVILEGE CHECK
# ---------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print(" This script requires administrator privileges.")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit(0)  # Exit original process after requesting admin privileges

# ---------------------------
# 2. MANUAL INTERFACE SETTING
# ---------------------------
MANUAL_INTERFACE = "Wi-Fi"  # Change this if needed

# ---------------------------
# 3. VERIFY INTERFACES
# ---------------------------
def get_npcap_interfaces():
    """Check and return available Npcap interfaces."""
    valid = []
    scapy_guids = get_if_list()
    
    print("🔍 Scapy detected interfaces:", scapy_guids)  

    for iface in get_windows_if_list():
        try:
            if iface['guid'] in scapy_guids:
                valid.append({
                    'name': iface.get('name', 'Unknown'),
                    'guid': iface['guid'],
                    'description': iface.get('description', 'No description')
                })
        except KeyError:
            continue
            
    print(" Valid interfaces:", valid)  
    return valid

try:
    # Load model artifacts
    model = pickle.load(open("tabnet_ids_model.pkl", "rb"))
    scaler = joblib.load("scaler.joblib")
    encoder = joblib.load("encoder.joblib")
    
    # Get interfaces
    interfaces = get_npcap_interfaces()
    
    if not interfaces:
        print(" No Npcap interfaces detected!")
        print("Verify with: ping 8.8.8.8 | wireshark -k -i <interface>")
        sys.exit(1)

    # Validate manually set interface
    interface_names = [iface['name'] for iface in interfaces]
    if MANUAL_INTERFACE not in interface_names:
        print(f" Error: Interface '{MANUAL_INTERFACE}' not found. Available interfaces:")
        for iface in interfaces:
            print(f"  - {iface['name']} ({iface['description']})")
        sys.exit(1)

    # ---------------------------
    # 4. PACKET PROCESSING SETUP
    # ---------------------------
    FLOW_TIMEOUT = 120
    FEATURE_NAMES = scaler.feature_names_in_
    
    ACTIVE_FLOWS = defaultdict(lambda: {
        **{feature: 0.0 for feature in FEATURE_NAMES},
        'start_time': None,
        'end_time': None,
        'src_ip': '',
        'dst_ip': '',
        'src_port': 0,
        'dst_port': 0,
        'Protocol': 0,
        '_last_packet': None
    })

    def get_flow_key(packet):
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            proto = 6 if packet.haslayer(TCP) else (17 if packet.haslayer(UDP) else 0)
            src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0
            return f"{ip_layer.src}-{ip_layer.dst}-{src_port}-{dst_port}-{proto}"
        return None

    def update_flow_stats(flow_key, packet):
        flow = ACTIVE_FLOWS[flow_key]
        flow['end_time'] = time()
        
        if flow['start_time'] is None:
            flow['start_time'] = time()
            flow['src_ip'] = packet[IP].src
            flow['dst_ip'] = packet[IP].dst
            flow['Protocol'] = 6 if packet.haslayer(TCP) else 17 if packet.haslayer(UDP) else 0

        # Remove stale flows outside this function to prevent unwanted deletion

    def remove_stale_flows():
        """Removes flows that exceed FLOW_TIMEOUT."""
        current_time = time()
        keys_to_delete = [key for key, flow in ACTIVE_FLOWS.items() if current_time - flow['start_time'] > FLOW_TIMEOUT]
        for key in keys_to_delete:
            del ACTIVE_FLOWS[key]

    def process_packet(packet):
        if packet.haslayer(IP):
            flow_key = get_flow_key(packet)
            if not flow_key:
                return
            update_flow_stats(flow_key, packet)

            # Extract features for ML model
            try:
                features = [ACTIVE_FLOWS[flow_key][feat] for feat in FEATURE_NAMES]
                scaled_features = scaler.transform([features])
                encoded_features = encoder.transform(scaled_features)
                prediction = model.predict(encoded_features)

                print(f" Prediction for {flow_key}: {prediction}")
            except Exception as e:
                print(f" Feature extraction error: {e}")

        # Periodically clean old flows
        remove_stale_flows()

    # ---------------------------
    # 5. START MONITORING
    # ---------------------------
    print(f"\n🔍 Starting on interface: {MANUAL_INTERFACE}...\n")

    sniff(
        prn=process_packet,
        store=False,
        iface=MANUAL_INTERFACE,  
        filter="ip",
        timeout=None
    )

except Exception as e:
    print(f" Fatal error: {str(e)}")
    if "The operation was canceled by the user" in str(e):
        print("Monitoring stopped by user")
    elif "No permission" in str(e):
        print(" Required: Run as Administrator AND install Npcap properly")
    input("Press Enter to exit...")
