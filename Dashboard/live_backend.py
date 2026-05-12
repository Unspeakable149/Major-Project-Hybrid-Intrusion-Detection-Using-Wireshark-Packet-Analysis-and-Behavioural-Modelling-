import os
import subprocess
import pandas as pd
import time
import sqlite3
import joblib
import warnings
from datetime import datetime

warnings.filterwarnings("ignore")

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
WINDOW_SECONDS = 2
DB_FILE = "ids_logs.db"

INTERFACE_OVERRIDE = None

THREAT_LABEL_MAP = {
    0: "Baseline (Safe)",
    1: "Moderate (Suspicious)",
    2: "Severe (Critical Anomaly)"
}

SEVERITY_RANK = {
    "Baseline (Safe)": 0,
    "Moderate (Suspicious)": 1,
    "Moderate (Bandwidth Spike)": 1,
    "Severe (Critical Anomaly)": 2
}

FEATURE_COLS = [
    'total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports',
    'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags',
    'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second',
    'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio'
]

def get_wifi_interface():
    print("[*] Running auto-discovery for Wi-Fi interface...")
    try:
        output = subprocess.check_output([TSHARK_PATH, "-D"], text=True, stderr=subprocess.DEVNULL)
        for line in output.split('\n'):
            if "wifi" in line.lower():
                interface_num = line.split('.')[0]
                print(f"[+] Auto-detected Wi-Fi on interface #{interface_num}")
                return interface_num
        return "1"
    except Exception:
        return "1"

def classify_profile(pps, sar, ports, avg_size):
    if pps > 500 and sar > 5:
        return "DDoS SYN Flood", "Severe (Critical Anomaly)"
    elif pps > 1000:
        return "High-Volume Flood Attack", "Severe (Critical Anomaly)"
    elif pps > 300 and avg_size > 800:
        return "Speed Test / Large Data Transfer", "Moderate (Bandwidth Spike)"
    elif ports > 20:
        return "Port Scan / Reconnaissance", "Moderate (Suspicious)"
    elif pps <= 5 and avg_size < 150:
        return "Ping / Background Telemetry", "Baseline (Safe)"
    else:
        return "Standard Web Traffic", "Baseline (Safe)"


INTERFACE = INTERFACE_OVERRIDE if INTERFACE_OVERRIDE else get_wifi_interface()

print("\n[*] Loading AI classification model...")
USE_RF = False
try:
    ai_model = joblib.load("rf_model.pkl")
    scaler = joblib.load("rf_scaler.pkl")
    USE_RF = True
    print("[+] Random Forest model loaded successfully.")
except FileNotFoundError:
    ai_model = joblib.load("advanced_kmeans_model.pkl")
    scaler = joblib.load("advanced_data_scaler.pkl")
    print("[+] K-Means model loaded (run trainai_rf.py to upgrade to Random Forest).")

print("[*] Initializing SQLite database...")
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
        threat_level TEXT,
        confidence REAL DEFAULT 0.0
    )
''')
conn.commit()

try:
    cursor.execute('ALTER TABLE live_threat_logs ADD COLUMN confidence REAL DEFAULT 0.0')
    conn.commit()
except Exception:
    pass

conn.close()

model_label = "Random Forest" if USE_RF else "K-Means"
print(f"[+] Engine active. Model: {model_label}. Sniffing interface #{INTERFACE} in {WINDOW_SECONDS}-second windows.\n")

while True:
    try:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting {WINDOW_SECONDS}-second capture window...")

        subprocess.run(
            [TSHARK_PATH, "-i", INTERFACE, "-a", f"duration:{WINDOW_SECONDS}", "-w", "temp_live.pcap"],
            stderr=subprocess.DEVNULL
        )

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

        df = pd.read_csv("temp_raw.csv", low_memory=False)

        if df.empty or len(df) < 2:
            print("[!] No packets captured. Retrying...\n")
            continue

        print(f"[+] {len(df)} packets captured. Processing flows...")

        df.columns = [
            "Timestamp", "Source IP", "Dest IP", "TCP Src", "UDP Src",
            "TCP Dst", "UDP Dst", "Protocol", "Packet Size",
            "SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", "TTL", "Window Size"
        ]
        df['Dest Port'] = df['TCP Dst'].fillna(df['UDP Dst']).fillna(0)

        flag_cols = ['SYN Flag', 'ACK Flag', 'FIN Flag', 'RST Flag']
        for col in flag_cols:
            df[col] = df[col].astype(str).str.split(',').str[0].str.strip()
            df[col] = df[col].replace({'True': 1, 'False': 0, 'true': 1, 'false': 0, '': 0, 'nan': 0, 'NaN': 0})
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        numeric_cols = ['Packet Size', 'TTL', 'Window Size', 'Timestamp']
        for col in numeric_cols:
            df[col] = df[col].astype(str).str.split(',').str[0]
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

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

        flows['flow_duration_sec'] = (flows['last_packet_time'] - flows['first_packet_time']).replace(0, 0.1)
        flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
        flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
        flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']
        flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)

        db_conn = sqlite3.connect(DB_FILE, timeout=10)
        db_cursor = db_conn.cursor()

        for _, row in flows.iterrows():
            flow_features = row[FEATURE_COLS].to_frame().T
            flow_features = flow_features.replace([float('inf'), float('-inf')], 0).fillna(0)
            scaled_data = scaler.transform(flow_features)

            pps = row['packets_per_second']
            sar = row['syn_ack_ratio']
            ports = row['unique_target_ports']
            avg_size = row['avg_packet_size']

            profile, heuristic_threat = classify_profile(pps, sar, ports, avg_size)

            if USE_RF:
                rf_label = int(ai_model.predict(scaled_data)[0])
                proba = ai_model.predict_proba(scaled_data)[0]
                confidence = float(max(proba))
                rf_threat = THREAT_LABEL_MAP.get(rf_label, "Baseline (Safe)")
                if SEVERITY_RANK.get(heuristic_threat, 0) > SEVERITY_RANK.get(rf_threat, 0):
                    threat = heuristic_threat
                else:
                    threat = rf_threat
            else:
                confidence = 0.0
                threat = heuristic_threat

            current_time = datetime.now().strftime("%H:%M:%S")

            db_cursor.execute('''
                INSERT INTO live_threat_logs
                (timestamp, source_ip, packets_per_sec, avg_window_size, syn_ack_ratio, total_bytes, traffic_profile, threat_level, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                current_time,
                row['Source IP'],
                round(pps, 2),
                round(row['avg_window_size'], 2),
                round(sar, 2),
                int(row['total_bytes']),
                profile,
                threat,
                round(confidence, 4)
            ))

            confidence_str = f"{confidence * 100:.1f}%" if USE_RF else "N/A"
            syn_count = int(row['total_syn_flags'])
            print(f"  [{row['Source IP']}]  {profile:<35}  {threat:<30}  Conf: {confidence_str}  pps={pps:.0f}  sar={sar:.1f}  syn={syn_count}")

        db_conn.commit()
        db_conn.close()
        print("")

    except Exception as e:
        print(f"[ERROR] {e}")
        time.sleep(1)
