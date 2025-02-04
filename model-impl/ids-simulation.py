import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff
from sklearn.preprocessing import StandardScaler

# Load the pre-trained model, label encoder, and scaler
model = joblib.load('ids_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')
scaler = joblib.load('scaler.pkl')
train_columns = joblib.load('train_columns.pkl')

# Define function to extract features from packets
def extract_features(packet):
    # Basic feature extraction from packet (e.g., protocol type, source/destination port, bytes, etc.)
    features = {
        "duration": 0,  # Set default or calculate based on packet times
        "protocol_type": packet.proto if packet.haslayer('IP') else 0,  # Just an example, extend as needed
        "service": 0,  # Placeholder
        "flag": 0,  # Placeholder
        "src_bytes": len(packet),  # Just an example feature (length of packet)
        "dst_bytes": len(packet),  # Placeholder
        "land": 0,  # Placeholder, check for special network conditions
        "wrong_fragment": 0,  # Placeholder
        "urgent": 0,  # Placeholder
        "hot": 0,  # Placeholder
        "num_failed_logins": 0,  # Placeholder
        "logged_in": 0,  # Placeholder
        "num_compromised": 0,  # Placeholder
        "root_shell": 0,  # Placeholder
        "su_attempted": 0,  # Placeholder
        "num_root": 0,  # Placeholder
        "num_file_creations": 0,  # Placeholder
        "num_shells": 0,  # Placeholder
        "num_access_files": 0,  # Placeholder
        "num_outbound_cmds": 0,  # Placeholder
        "is_host_login": 0,  # Placeholder
        "is_guest_login": 0,  # Placeholder
        "count": 0,  # Placeholder
        "srv_count": 0,  # Placeholder
        "serror_rate": 0,  # Placeholder
        "srv_serror_rate": 0,  # Placeholder
        "rerror_rate": 0,  # Placeholder
        "srv_rerror_rate": 0,  # Placeholder
        "same_srv_rate": 0,  # Placeholder
        "diff_srv_rate": 0,  # Placeholder
        "srv_diff_host_rate": 0,  # Placeholder
        "dst_host_count": 0,  # Placeholder
        "dst_host_srv_count": 0,  # Placeholder
        "dst_host_same_srv_rate": 0,  # Placeholder
        "dst_host_diff_srv_rate": 0,  # Placeholder
        "dst_host_same_src_port_rate": 0,  # Placeholder
        "dst_host_srv_diff_host_rate": 0,  # Placeholder
        "dst_host_serror_rate": 0,  # Placeholder
        "dst_host_srv_serror_rate": 0,  # Placeholder
        "dst_host_rerror_rate": 0,  # Placeholder
        "dst_host_srv_rerror_rate": 0,  # Placeholder
    }

    # Convert features to DataFrame
    feature_df = pd.DataFrame([features])
    
    # One-Hot Encoding for Categorical Features (protocol_type, service, flag)
    feature_df = pd.get_dummies(feature_df, columns=['protocol_type', 'service', 'flag'])
    
    # Align feature columns with the model's expected feature set
    missing_columns = [col for col in train_columns if col not in feature_df.columns]
    for col in missing_columns:
        feature_df[col] = 0  # Fill missing columns with 0 or default value
    
    # Reorder columns to match the trained model's columns
    feature_df = feature_df[train_columns]
    
    return feature_df

# Function to classify packets
def classify_packet(packet):
    # Extract features from the packet
    features = extract_features(packet)
    
    # Standardize the features
    features_scaled = scaler.transform(features)
    
    # Predict with the trained model
    prediction = model.predict(features_scaled)
    predicted_label = label_encoder.inverse_transform(prediction)[0]
    
    # Log or alert based on the prediction
    if predicted_label == 1:  # If it's an attack (assuming label 1 corresponds to an attack)
        print("Attack detected! Packet:", packet.summary())
    else:
        print("Normal traffic detected. Packet:", packet.summary())

# Start sniffing network traffic
def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=classify_packet, store=0)  # Capture packets and classify them in real-time

if __name__ == "__main__":
    start_sniffing()
