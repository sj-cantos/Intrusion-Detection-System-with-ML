def capture_live_traffic():
    packets = scapy.sniff(count=10)  # Capture 10 packets
    extracted_features = []
    
    for packet in packets:
        packet_data = [
            len(packet),  # Packet length
            packet.time,  # Timestamp
            int(packet.haslayer(scapy.IP)),  # IP Layer Presence
            int(packet.haslayer(scapy.TCP)),  # TCP Layer Presence
            int(packet.haslayer(scapy.UDP)),  # UDP Layer Presence
        ]
        extracted_features.append(packet_data)
    
    # Convert to DataFrame
    live_df = pd.DataFrame(extracted_features, columns=['PacketLen', 'Time', 'IP', 'TCP', 'UDP'])
    live_X = scaler.transform(live_df)
    live_X_tensor = torch.tensor(live_X, dtype=torch.float32).unsqueeze(2).to(device)
    
    # Predict Anomalies
    model.eval()
    with torch.no_grad():
        outputs = model(live_X_tensor)
        predictions = torch.argmax(outputs, axis=1).cpu().numpy()
    
    for i, pred in enumerate(predictions):
        print(f'Packet {i+1}:', label_encoder.inverse_transform([pred])[0])

# Run Live Traffic Detection
capture_live_traffic()