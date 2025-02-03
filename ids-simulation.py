import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP


clf = joblib.load("ids_model.pkl")  
scaler = joblib.load("scaler.pkl") 
label_encoder = joblib.load("label_encoder.pkl")  


expected_features = scaler.feature_names_in_

def extract_features(packet):
    if IP in packet:
        protocol_type = "tcp" if TCP in packet else "udp" if UDP in packet else "other"

        # Check if the packet has a destination port
        if TCP in packet or UDP in packet:
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            service = "http" if dport == 80 else "https" if dport == 443 else "unknown"
        else:
            service = "unknown"

        flag = "SF" if TCP in packet and packet[TCP].flags == 0x02 else "OTH"

        features = {
            'duration': 1,  # Placeholder
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': len(packet),  # Packet size from source
            'dst_bytes': 0,  # Placeholder
            'wrong_fragment': 0  # Placeholder
        }
        return features
    return None

def predict_attack(packet):
    features = extract_features(packet)
    if features:
        try:
            new_data = pd.DataFrame([features])
            new_data = pd.get_dummies(new_data)
            new_data = new_data.reindex(columns=expected_features, fill_value=0)

            new_data = scaler.transform(new_data)
            prediction = clf.predict(new_data)
            predicted_label = label_encoder.inverse_transform(prediction)

            print(f" Predicted Attack Type: {predicted_label[0]}")
            print(f" Predicted Class: {prediction}")

        except Exception as e:
            print(f"Error processing packet: {e}")


sniff(prn=predict_attack, filter="ip", iface="Wi-Fi", count=10)
