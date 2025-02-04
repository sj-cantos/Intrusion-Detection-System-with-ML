from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import joblib

# Load trained model and preprocessing tools
clf = joblib.load('ids_model.pkl')
scaler = joblib.load('scaler.pkl')
train_columns = joblib.load('train_columns.pkl')
label_encoder = joblib.load('label_encoder.pkl')

# Mapping known services
service_ports = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                 80: "http", 443: "https", 445: "smb", 3306: "mysql"}

# Extract features from packets
def extract_features(packet):
    if IP in packet:
        protocol_type = "tcp" if TCP in packet else "udp" if UDP in packet else "other"
        service = service_ports.get(packet.dport, "unknown")

        flag = "OTH"
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN
                flag = "S0"
            elif flags & 0x12:  # SYN-ACK
                flag = "S1"
            elif flags & 0x10:  # ACK
                flag = "SF"

        features = {
            'duration': 1,  # Live packets don't have "duration" so setting it as 1
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': len(packet),
            'dst_bytes': 0,  # Can't calculate in real-time
            'wrong_fragment': 0
        }
        
        return features
    return None

# Convert extracted features into a format the model understands
def preprocess_features(features):
    df = pd.DataFrame([features])

    # One-hot encode categorical values
    df = pd.get_dummies(df, columns=['protocol_type', 'service', 'flag'])

    # Ensure all columns match the training set
    missing_cols = set(train_columns) - set(df.columns)
    if missing_cols:
        df = pd.concat([df, pd.DataFrame(0, index=df.index, columns=list(missing_cols))], axis=1)
    df = df[train_columns]  # Ensure correct column order

    df = df[train_columns]  # Reorder columns

    # Scale numerical values
    return scaler.transform(df)

# Detect attack from live packets
def detect_attack(packet):
    features = extract_features(packet)
    if features:
        processed_features = preprocess_features(features)
        prediction = clf.predict(processed_features)
        attack_type = label_encoder.inverse_transform(prediction)[0]

        print(f"🔍 Packet: {packet.summary()}")
        print(f"🛑 Detected Attack: {attack_type}\n")

# Sniff packets and analyze them in real-time
print("🚀 IDS Running... Capturing Live Packets...")
sniff(prn=detect_attack, store=0)
