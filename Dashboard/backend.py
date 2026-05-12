import os
import subprocess
import pandas as pd
import time
import sqlite3
import joblib
import warnings
from datetime import datetime

warnings.filterwarnings("ignore")

# --- CORE CONFIGURATION ---
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
WINDOW_SECONDS = 2
DB_FILE = "ids_logs.db"

# --- AUTO-DISCOVERY ENGINE ---
def get_wifi_interface():
    print("[*] Running Auto-Discovery for Wi-Fi Interface...")
    try:
        output = subprocess.check_output([TSHARK_PATH, "-D"], text=True, stderr=subprocess.DEVNULL)
        for line in output.split('\n'):
            if "wifi" in line.lower():
                interface_num = line.split('.')[0]
                print(f"[+] SUCCESS: Auto-detected Wi-Fi on Interface #{interface_num}")
                return interface_num
        return "1"
    except Exception as e:
        return "1"

INTERFACE = get_wifi_interface()

print("\n1. Loading Advanced AI Brain and Translator...")
ai_model = joblib.load("advanced_kmeans_model.pkl")
scaler = joblib.load("advanced_data_scaler.pkl")

print("2. Initializing SQLite Active Defense Database...")
# --- DATABASE INITIALIZATION ---
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS live_threat_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        packets_per_sec REAL,
        avg_window_size REAL,
        syn_ack_ratio REAL,
        total_bytes INTEGER,
        traffic_profile TEXT,
        threat_level TEXT
    )
''')
conn.commit()
conn.close()

print(f"3. ENGINE ACTIVE. Sniffing Interface #{INTERFACE} in {WINDOW_SECONDS}-second blocks...\n")

while True:
    try:
        print(f"[*] {datetime.now().strftime('%H:%M:%S')} - Starting {WINDOW_SECONDS}-second network sniff...")
        
        # 1. LIVE CAPTURE
        subprocess.run([
            TSHARK_PATH, "-i", INTERFACE, "-a", f"duration:{WINDOW_SECONDS}", 
            "-w", "temp_live.pcap"
        ], stderr=subprocess.DEVNULL)
        
        # 2. EXTRACTION
        tshark_extract = [
            TSHARK_PATH, "-r", "temp_live.pcap", "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "udp.srcport", "-e", "tcp.dstport", "-e", "udp.dstport",
            "-e", "_ws.col.Protocol", "-e", "frame.len",
            "-e", "tcp.flags.syn", "-e", "tcp.flags.ack", "-e", "tcp.flags.fin", "-e", "tcp.flags.reset",
            "-e", "ip.ttl", "-e", "tcp.window_size",
            "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
        ]
        
        with open("temp_raw.csv", "w") as outfile:
            subprocess.run(tshark_extract, stdout=outfile, stderr=subprocess.DEVNULL)
            
        # 3. LOAD & CLEAN DATA
        df = pd.read_csv("temp_raw.csv", low_memory=False)
        
        if df.empty or len(df) < 2:
            print("[!] 0 packets caught. Looping again...\n")
            continue
            
        print(f"[+] Successfully caught and crushed {len(df)} packets. Sending to AI...")
            
        df.columns = ["Timestamp", "Source IP", "Dest IP", "TCP Src", "UDP Src", "TCP Dst", "UDP Dst", "Protocol", "Packet Size", "SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", "TTL", "Window Size"]
        df['Dest Port'] = df['TCP Dst'].fillna(df['UDP Dst']).fillna(0)
        
        math_columns = ['Packet Size', 'SYN Flag', 'ACK Flag', 'FIN Flag', 'RST Flag', 'TTL', 'Window Size', 'Timestamp']
        for col in math_columns:
            df[col] = df[col].astype(str).str.split(',').str[0]
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            
        # 4. BEHAVIORAL FEATURE ENGINEERING
        flows = df.groupby('Source IP').agg(
            total_packets=('Packet Size', 'count'),
            total_bytes=('Packet Size', 'sum'),
            unique_target_ips=('Dest IP', 'nunique'),
            unique_target_ports=('Dest Port', 'nunique'),
            total_syn_flags=('SYN Flag', 'sum'),
            total_ack_flags=('ACK Flag', 'sum'),
            total_fin_flags=('FIN Flag', 'sum'),
            total_rst_flags=('RST Flag', 'sum'),
            avg_ttl=('TTL', 'mean'),
            avg_window_size=('Window Size', 'mean'),
            first_packet_time=('Timestamp', 'min'),
            last_packet_time=('Timestamp', 'max')
        ).reset_index()
        
        flows['flow_duration_sec'] = flows['last_packet_time'] - flows['first_packet_time']
        flows['flow_duration_sec'] = flows['flow_duration_sec'].replace(0, 0.1) 
        flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
        flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
        flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']
        flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)
        
        feature_cols = ['total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports', 'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags', 'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second', 'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio']
        
        # 5. PREDICT & WRITE TO SQLITE DATABASE
        db_conn = sqlite3.connect(DB_FILE, timeout=10)
        db_cursor = db_conn.cursor()

        for index, row in flows.iterrows():
            flow_features = row[feature_cols].to_frame().T
            flow_features = flow_features.replace([float('inf'), float('-inf')], 0).fillna(0)
            
            scaled_data = scaler.transform(flow_features)
            cluster = ai_model.predict(scaled_data)[0]
            
            pps = row['packets_per_second']
            sar = row['syn_ack_ratio']
            ports = row['unique_target_ports']
            avg_size = row['avg_packet_size']
            
            if pps > 500 and sar > 5:
                threat = "Severe (Critical Anomaly)"
                profile = "DDoS SYN Flood"
            elif pps > 300 and avg_size > 800:
                threat = "Moderate (Bandwidth Spike)" 
                profile = "Speed Test / Large Data Transfer"
            elif ports > 20:
                threat = "Moderate (Suspicious)"
                profile = "Port Scan / Reconnaissance"
            elif pps <= 5 and avg_size < 150:
                threat = "Baseline (Safe)"
                profile = "Ping / Background Telemetry"
            else:
                threat = "Baseline (Safe)"
                profile = "Standard Web Traffic"
                
            current_time = datetime.now().strftime("%H:%M:%S")
            
            # Insert directly into the SQL Database
            db_cursor.execute('''
                INSERT INTO live_threat_logs 
                (timestamp, source_ip, packets_per_sec, avg_window_size, syn_ack_ratio, total_bytes, traffic_profile, threat_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (current_time, row['Source IP'], round(pps, 2), round(row['avg_window_size'], 2), round(sar, 2), int(row['total_bytes']), profile, threat))
            
            print(f"[AI VERDICT] {row['Source IP']} -> {profile} | Threat: {threat}")
            
        db_conn.commit()
        db_conn.close()
        print("\n---------------------------------------------------")

    except Exception as e:
        print(f"Live Sniffing Error: {e}")
        time.sleep(1)