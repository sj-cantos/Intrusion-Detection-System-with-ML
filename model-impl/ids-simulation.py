import torch
import numpy as np
import joblib
from torch import nn

# Load preprocessing artifacts
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# Define the model architecture (must match training)
class OriginalNet(nn.Module):
    def __init__(self, input_size, num_classes):
        super().__init__()
        self.conv_block = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=5, padding=2),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Dropout(0.3)
        )
        self.lstm = nn.LSTM(64, 128, num_layers=2, 
                           bidirectional=True, 
                           batch_first=True)
        self.classifier = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, num_classes)
        )

    def forward(self, x):
        x = self.conv_block(x)
        x = x.permute(0, 2, 1)
        x, _ = self.lstm(x)
        return self.classifier(x[:, -1, :])
# Initialize model
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = OriginalNet(
    input_size=scaler.n_features_in_,
    num_classes=len(label_encoder.classes_)
).to(device)
model.load_state_dict(torch.load("best_model.pth", map_location=device))
model.eval()

from scapy.all import *
import numpy as np

def extract_flow_features(stats):
    """
    Extract features directly from flow statistics instead of raw packets.
    """
    syn_count = sum(1 for f in stats['flags'] if 'S' in str(f))  # Count SYN flags
    total_packets = stats['packet_count']
    packet_rate = total_packets / (stats['end_time'] - stats['start_time'] + 0.0001)
    avg_packet_size = stats['bytes'] / total_packets if total_packets else 0

    # Estimate source IP uniqueness as 1 (not available in stats)
    # In full implementation, you'd track IPs per flow.
    unique_ips = 1

    features = {
        'syn_count': syn_count,
        'total_packets': total_packets,
        'packet_rate': packet_rate,
        'unique_ips': unique_ips,
        'average_packet_size': avg_packet_size,
        'Protocol': stats.get('protocol', 0),  # Safely fetch 'protocol'
        'attack_detected': syn_count > 50 and packet_rate > 10
    }


    return features







def preprocess_live_data(features_dict):
    # Drop 'attack_detected' if present
    if 'attack_detected' in features_dict:
        features_dict.pop('attack_detected')

    # Ensure consistent feature order
    feature_order = scaler.feature_names_in_
    feature_vector = [features_dict[feat] for feat in feature_order]

    # Scale features
    scaled = scaler.transform([feature_vector])

    # Convert to tensor
    return torch.tensor(scaled, dtype=torch.float32).unsqueeze(1).to(device)  # Shape: [1, 1, num_features]


import torch

def detect_anomalies(inputs_tensor):
    model.eval()
    with torch.no_grad():
        outputs = model(inputs_tensor)
        probabilities = torch.softmax(outputs, dim=1)
        confidence, predicted_class = torch.max(probabilities, 1)
        return {
            'predicted_class': label_encoder.inverse_transform([predicted_class.item()])[0],
            'confidence': confidence.item()
        }




from scapy.all import sniff, IP, TCP, UDP
import time
from collections import defaultdict

# Flow tracking dictionary
flow_stats = defaultdict(lambda: {
    'start_time': None,
    'end_time': None,
    'packet_count': 0,
    'bytes': 0,
    'protocol': None,
    'flags': set(),
    'packet_lengths': [],
    'iat': []
})

def process_packet(packet):
    """Process live network packets and maintain flow statistics"""
    try:
        if IP in packet:
            current_time = time.time()  # Get timestamp once per packet

            src = f"{packet[IP].src}:{packet.sport}" if TCP in packet or UDP in packet else packet[IP].src
            dst = f"{packet[IP].dst}:{packet.dport}" if TCP in packet or UDP in packet else packet[IP].dst
            flow_id = (src, dst) if src < dst else (dst, src)

            # Update flow statistics
            stats = flow_stats[flow_id]
            if not stats['start_time']:
                stats['start_time'] = current_time
                stats['protocol'] = packet[IP].proto
                stats['end_time'] = current_time  # Initialize end_time
            else:
                # Calculate inter-arrival time correctly
                stats['iat'].append(current_time - stats['end_time'])
                stats['end_time'] = current_time

            stats['packet_count'] += 1
            stats['bytes'] += len(packet)
            stats['packet_lengths'].append(len(packet))

            if TCP in packet:
                stats['flags'].add(packet[TCP].flags)
                
            # Check flow timeout (15 seconds of inactivity)
            if current_time - stats['end_time'] > 15:
                analyze_flow(flow_id, stats)
                del flow_stats[flow_id]

    except Exception as e:
        print(f"Error processing packet: {e}")
import numpy as np
import time
from scapy.layers.inet import TCP

flow_stats = {
    "timestamps": [],
    "packet_lengths": [],
    "flags": [],
}
# def parse_flags(f):
#     from scapy.all import FlagValue

#     flag_map = {
#         'FIN': 0x01,
#         'SYN': 0x02,
#         'RST': 0x04,
#         'PSH': 0x08,
#         'ACK': 0x10,
#         'URG': 0x20,
#     }

#     if isinstance(f, int):
#         return f
#     elif isinstance(f, FlagValue):
#         return int(f)
#     elif isinstance(f, set):
#         bits = 0
#         for flag in f:
#             flag_str = str(flag).upper()  # <--- MAKE SURE the flag is a string
#             bits |= flag_map.get(flag_str, 0)
#         return bits
#     else:
#         return 0




# def analyze_flow(flow_id, stats):
#     """Analyze completed network flow"""
#     try:
#         # Extract features
#         features = extract_flow_features(stats)
        
#         # Detect anomalies
#         result = detect_anomalies(features)  # Pass features directly
        
#         # Generate alert if anomaly detected
#         if result['predicted_class'] != 'Benign':
#             print(f" ANOMALY DETECTED ")
#             print(f"Flow: {flow_id[0]} → {flow_id[1]}")
#             print(f"Type: {result['predicted_class']}")
#             print(f"Confidence: {result['confidence']:.2%}")
            
#             # Add your alerting logic here (email, SMS, SIEM integration, etc.)
            
#         else:
#             print(f"✓ Normal traffic: {flow_id[0]} → {flow_id[1]}")

#     except Exception as e:
#         print(f"Error analyzing flow: {e}")

import logging
from scapy.all import (
    IP, TCP, UDP, ICMP,  # Explicit protocol imports
    Ether, Raw,           # Additional layers seen in your logs
    sniff
)
from scapy.all import sniff, conf, get_if_list
import time
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def show_interfaces():
    """List available network interfaces"""
    print("Available interfaces:")
    for interface in get_if_list():
        print(f"  - {interface.decode() if isinstance(interface, bytes) else interface}")

def packet_handler(packet):
    """Simplified debug version of packet processor"""
    try:
        logging.info(f"Received packet from: {packet.summary()}")
        
        # Immediate test: ping detection
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP echo request
            logging.warning("Ping detected! Generating test alert...")
            print("\nTEST ALERT: Ping detected")
            
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

import time
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import torch

# Flow tracking dictionary
flow_stats = defaultdict(lambda: {
    'start_time': None,
    'end_time': None,
    'packet_count': 0,
    'bytes': 0,
    'protocol': None,
    'flags': set(),
    'packet_lengths': [],
    'iat': []  # Inter-arrival times
})

def process_packet(packet):
    """Process live network packets and maintain flow statistics"""
    try:
        if IP in packet:
            current_time = time.time()  # Get timestamp once per packet

            src = f"{packet[IP].src}:{packet.sport}" if TCP in packet else packet[IP].src
            dst = f"{packet[IP].dst}:{packet.dport}" if TCP in packet else packet[IP].dst
            flow_id = (src, dst) if src < dst else (dst, src)

            # Update flow statistics
            stats = flow_stats[flow_id]
            if not stats['start_time']:
                stats['start_time'] = current_time
                stats['protocol'] = packet[IP].proto
                stats['end_time'] = current_time  # Initialize end_time
            else:
                # Calculate inter-arrival time correctly
                stats['iat'].append(current_time - stats['end_time'])
                stats['end_time'] = current_time

            stats['packet_count'] += 1
            stats['bytes'] += len(packet)
            stats['packet_lengths'].append(len(packet))

            if TCP in packet:
                stats['flags'].add(packet[TCP].flags)

            # Check flow timeout (e.g., 15 seconds of inactivity)
            if current_time - stats['end_time'] > 15:
                analyze_flow(flow_id, stats)
                del flow_stats[flow_id]

    except Exception as e:
        print(f"Error processing packet: {e}")

def analyze_flow(flow_id, stats):
    try:
        # Extract and preprocess features
        features = extract_flow_features(stats)  # You might need to simulate a list of packets
        input_tensor = preprocess_live_data(features)

        # Classify
        result = detect_anomalies(input_tensor)

        if result['predicted_class'] != 'Benign':
            print(f"🚨 ANOMALY DETECTED in flow: {flow_id[0]} → {flow_id[1]}")
            print(f"Type: {result['predicted_class']}")
            print(f"Confidence: {result['confidence']:.2%}")
        else:
            print(f"✓ Normal traffic: {flow_id[0]} → {flow_id[1]}")

    except Exception as e:
        print(f"Error analyzing flow: {e}")



# Start sniffing packets and process them
def start_sniffing(interface="Wi-Fi"):
    print(f"\nStarting monitoring on {interface}...")
    try:
        # Capture packets in real-time
        sniff(iface=interface, filter="ip", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
import atexit

def flush_remaining_flows():
    for flow_id, stats in list(flow_stats.items()):
        analyze_flow(flow_id, stats)
    flow_stats.clear()

atexit.register(flush_remaining_flows)

if __name__ == "__main__":
    show_interfaces()
    iface = input("Enter interface to monitor (default: Wi-Fi): ") or "Wi-Fi"
    start_sniffing(interface=iface)

