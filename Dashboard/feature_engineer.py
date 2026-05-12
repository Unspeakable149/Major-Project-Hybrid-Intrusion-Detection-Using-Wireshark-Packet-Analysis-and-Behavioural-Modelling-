import pandas as pd
import numpy as np
import warnings

warnings.filterwarnings("ignore")

print("1. Loading Advanced Packet Data (This may take a moment)...")
df = pd.read_csv("master_advanced_dataset.csv", low_memory=False)

print("2. Scrubbing Dirty Data (Bulletproof Numeric Conversion)...")
# List of every single column we are about to do math on
math_columns = [
    'Packet Size', 'SYN Flag', 'ACK Flag', 'FIN Flag', 
    'RST Flag', 'TTL', 'Window Size', 'Timestamp'
]

for col in math_columns:
    if col in df.columns:
        # 1. Turn it into text to safely split any "64,64" double values from tshark
        df[col] = df[col].astype(str).str.split(',').str[0]
        
        # 2. Force it into a strict decimal number. If it's pure garbage text, turn it into 0.
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

print("3. Engineering Enterprise-Grade Behavioral Flows...")
flows = df.groupby('Source IP').agg(
    total_packets=('Packet Size', 'count'),
    total_bytes=('Packet Size', 'sum'),
    unique_target_ips=('Dest IP', 'nunique'),
    unique_target_ports=('Dest Port', 'nunique'),
    
    # TCP Flag Behaviors
    total_syn_flags=('SYN Flag', 'sum'),
    total_ack_flags=('ACK Flag', 'sum'),
    total_fin_flags=('FIN Flag', 'sum'),
    total_rst_flags=('RST Flag', 'sum'),
    
    # Network Layer Metrics
    avg_ttl=('TTL', 'mean'),
    avg_window_size=('Window Size', 'mean'),
    
    # Timing
    first_packet_time=('Timestamp', 'min'),
    last_packet_time=('Timestamp', 'max')
).reset_index()

print("4. Calculating Mathematical Time/Velocity Features...")
flows['flow_duration_sec'] = flows['last_packet_time'] - flows['first_packet_time']
# Prevent division by zero if duration is exactly 0
flows['flow_duration_sec'] = flows['flow_duration_sec'].replace(0, 0.1) 

# Calculate Velocity Features
flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']

# Calculate the SYN-to-ACK Ratio
flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)

print("5. Cleaning and Finalizing AI Training Set...")
# Drop the raw timestamps, keep only the behavioral features
final_features = flows.drop(columns=['first_packet_time', 'last_packet_time'])

# Save the Ultimate Training Dataset
final_features.to_csv("ai_ready_advanced_flows.csv", index=False)

print("\nSUCCESS! Extracted 14 advanced behavioral features per IP.")
print(f"Dataset saved as 'ai_ready_advanced_flows.csv'. Shape: {final_features.shape}")