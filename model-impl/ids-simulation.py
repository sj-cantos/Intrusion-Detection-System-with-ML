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

def extract_flow_features(flow_stats):
    """Extract 77 flow features for model input (updated)."""
    pkt_lengths = np.array(flow_stats['packet_lengths'])
    iat = np.array(flow_stats['iat']) if flow_stats['iat'] else np.array([0])

    total_packets = len(pkt_lengths)
    total_bytes = pkt_lengths.sum()
    duration = max(flow_stats['end_time'] - flow_stats['start_time'], 1e-6)  # Avoid divide-by-zero

    features = [
        total_packets,                     # Total packets
        total_bytes,                        # Total bytes
        total_bytes / duration,             # Bytes per second
        total_packets / duration,           # Packets per second
        pkt_lengths.mean() if total_packets else 0,  # Avg packet size
        pkt_lengths.std() if total_packets else 0,   # Std dev packet size
        pkt_lengths.min() if total_packets else 0,   # Min packet size
        pkt_lengths.max() if total_packets else 0,   # Max packet size
        iat.mean() if len(iat) > 0 else 0,   # Mean IAT
        iat.std() if len(iat) > 0 else 0,    # Std IAT
        iat.min() if len(iat) > 0 else 0,    # Min IAT
        iat.max() if len(iat) > 0 else 0,    # Max IAT
        len(flow_stats['flags']),            # Number of unique TCP flags
        flow_stats['protocol'],              # Protocol (TCP=6, UDP=17, ICMP=1)
        # ... continue adding features until you hit 77 ...
    ]

 
    # - Packet rate
    # - Flag counts (SYN, ACK, etc.)
    # - Ratios (incoming/outgoing)
    # - Flow bytes per packet
    # - Average header length
    # - etc.

    # Pad with zeros if less than 77
    while len(features) < 77:
        features.append(0.0)
        
    # Truncate if longer than 77
    features = features[:77]

    return np.array(features, dtype=np.float32)


def preprocess_live_data(raw_packet):
    """Process raw network packet into model-ready format"""
    # Feature extraction
    features = extract_flow_features(raw_packet)
    
    # Validate feature dimensions
    if len(features) != scaler.n_features_in_:
        raise ValueError(f"Expected {scaler.n_features_in_} features, got {len(features)}")
    
    # Scale features
    scaled = scaler.transform([features])
    
    # Convert to tensor
    return torch.tensor(scaled, dtype=torch.float32).unsqueeze(0).to(device)

import torch

def detect_anomalies(features):
    model.eval()

    with torch.no_grad():
        inputs = torch.tensor(features, dtype=torch.float32)

        # Reshape input: (batch_size=1, channels=1, length=features_dim)
        inputs = inputs.unsqueeze(0).unsqueeze(0)  
        # OR: inputs = inputs.view(1, 1, -1)

        outputs = model(inputs)

        probabilities = torch.softmax(outputs, dim=1)
        confidence, predicted_class = torch.max(probabilities, 1)

        predicted_class = predicted_class.item()
        confidence = confidence.item()

    return {
        'predicted_class': predicted_class,
        'confidence': confidence
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
def parse_flags(f):
    from scapy.all import FlagValue

    flag_map = {
        'FIN': 0x01,
        'SYN': 0x02,
        'RST': 0x04,
        'PSH': 0x08,
        'ACK': 0x10,
        'URG': 0x20,
    }

    if isinstance(f, int):
        return f
    elif isinstance(f, FlagValue):
        return int(f)
    elif isinstance(f, set):
        bits = 0
        for flag in f:
            flag_str = str(flag).upper()  # <--- MAKE SURE the flag is a string
            bits |= flag_map.get(flag_str, 0)
        return bits
    else:
        return 0

def extract_flow_features(packet):
    # Check if packet is a dict or scapy packet
    if isinstance(packet, dict):
        # Assume dict already has fields
        packet_len = packet.get('length', 0)
        flags = packet.get('flags', 0)
    else:
        # Scapy packet
        packet_len = len(packet)
        flags = 0
        if packet.haslayer(TCP):
            flags = packet[TCP].flags

    # 1. Capture timestamp and packet length
    flow_stats["timestamps"].append(time.time())
    flow_stats["packet_lengths"].append(packet_len)
    flow_stats["flags"].append(flags)

    # 2. Compute features
    timestamps = flow_stats["timestamps"]
    packet_lengths = flow_stats["packet_lengths"]
    flags_list = flow_stats["flags"]

    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0

    total_packets = len(packet_lengths)
    total_bytes = np.sum(packet_lengths)
    mean_pkt_size = np.mean(packet_lengths)
    std_pkt_size = np.std(packet_lengths)
    max_pkt_size = np.max(packet_lengths)
    min_pkt_size = np.min(packet_lengths)

    pkt_rate = total_packets / duration if duration > 0 else 0
    byte_rate = total_bytes / duration if duration > 0 else 0

    syn_count = sum(1 for f in flags_list if parse_flags(f) & 0x02)
    ack_count = sum(1 for f in flags_list if parse_flags(f) & 0x10)
    rst_count = sum(1 for f in flags_list if parse_flags(f) & 0x04)
    fin_count = sum(1 for f in flags_list if parse_flags(f) & 0x01)

    features = [
        duration,
        total_packets,
        total_bytes,
        mean_pkt_size,
        std_pkt_size,
        max_pkt_size,
        min_pkt_size,
        pkt_rate,
        byte_rate,
        syn_count,
        ack_count,
        rst_count,
        fin_count,
    ]

    return np.array(features, dtype=np.float32)


def analyze_flow(flow_id, stats):
    """Analyze completed network flow"""
    try:
        # Extract features
        features = extract_flow_features(stats)
        
        # Detect anomalies
        result = detect_anomalies(features)  # Pass features directly
        
        # Generate alert if anomaly detected
        if result['predicted_class'] != 'Benign':
            print(f" ANOMALY DETECTED ")
            print(f"Flow: {flow_id[0]} → {flow_id[1]}")
            print(f"Type: {result['predicted_class']}")
            print(f"Confidence: {result['confidence']:.2%}")
            
            # Add your alerting logic here (email, SMS, SIEM integration, etc.)
            
        else:
            print(f"✓ Normal traffic: {flow_id[0]} → {flow_id[1]}")

    except Exception as e:
        print(f"Error analyzing flow: {e}")

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

if __name__ == "__main__":
    show_interfaces()
    interface = "Wi-Fi"  # Update to your correct interface

    print(f"\nStarting monitoring on {interface}...")
    print("Send test traffic (e.g., ping or browse) to verify")
    print("Press Ctrl+C to stop\n")

    try:
        # Capture packets temporarily for verification
        packets = sniff(
            iface=interface,
            filter="tcp or udp or icmp",
            prn=packet_handler,
            store=1,
            timeout=10
        )
        
        # Instead of passing raw packets, simulate a flow first
        if packets:
            # Create a dummy flow_stats from captured packets (basic example)
            dummy_flow = {
                'start_time': time.time(),
                'end_time': time.time() + 1,
                'packet_count': len(packets),
                'bytes': sum(len(pkt) for pkt in packets),
                'protocol': packets[0][IP].proto if IP in packets[0] else None,
                'flags': set(pkt[TCP].flags for pkt in packets if TCP in pkt),
                'packet_lengths': [len(pkt) for pkt in packets],
                'iat': []  # Could calculate real IATs if needed
            }

            # Now properly extract features
            features = extract_flow_features(dummy_flow)

            # Then detect anomaly
            result = detect_anomalies(features)

            print(f"Predicted: {result['predicted_class']}")
            print(f"Confidence: {result['confidence']:.2%}")
        else:
            print("No packets captured.")

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
