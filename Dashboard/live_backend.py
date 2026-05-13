"""Real-time hybrid IDS engine.

Pipeline (loops every WINDOW_SECONDS):
    tshark live capture  ->  per-source-IP flow aggregation
                          ->  Random Forest behavioral classifier
                          ->  heuristic signature engine
                          ->  fusion (max severity)
                          ->  SQLite alert log consumed by app.py
"""

import os
import subprocess
import sqlite3
import time
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore")

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
WINDOW_SECONDS = 2
DB_FILE = "ids_logs.db"
INTERFACE_OVERRIDE = None  # set to a tshark interface index (string) to skip auto-detect
THREAT_INTEL_FILE = "threat_intel.txt"  # optional newline-separated known-malicious IPs
ROLLING_WINDOWS = 15  # number of past 2s windows kept per src IP (=> 30s history)

THREAT_LABEL_MAP = {
    0: "Baseline (Safe)",
    1: "Moderate (Suspicious)",
    2: "Severe (Critical Anomaly)",
}

SEVERITY_RANK = {
    "Baseline (Safe)": 0,
    "Moderate (Suspicious)": 1,
    "Moderate (Bandwidth Spike)": 1,
    "Severe (Critical Anomaly)": 2,
}

# Per-source-IP rolling history across capture windows. Enables slow-rate /
# brute-force detection that a single 2s window can't see on its own.
ROLLING_STATE: dict[str, list[dict]] = {}

FEATURE_COLS = [
    'total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports',
    'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags',
    'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second',
    'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio',
    'packet_size_std', 'iat_mean', 'iat_std',
]

TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
    "_ws.col.Protocol", "frame.len",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "ip.ttl", "tcp.window_size",
]

RAW_COLUMNS = [
    "Timestamp", "Source IP", "Dest IP", "TCP Src", "UDP Src",
    "TCP Dst", "UDP Dst", "Protocol", "Packet Size",
    "SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", "TTL", "Window Size",
]

FLAG_COLS = ['SYN Flag', 'ACK Flag', 'FIN Flag', 'RST Flag']
NUMERIC_COLS = ['Packet Size', 'TTL', 'Window Size', 'Timestamp']


def get_wifi_interface() -> str:
    print("[*] Auto-detecting Wi-Fi interface...")
    try:
        output = subprocess.check_output([TSHARK_PATH, "-D"], text=True, stderr=subprocess.DEVNULL)
        for line in output.split('\n'):
            if "wifi" in line.lower():
                idx = line.split('.')[0]
                print(f"[+] using interface #{idx}")
                return idx
    except Exception:
        pass
    print("[!] auto-detect failed, defaulting to interface #1")
    return "1"


def classify_profile(pps: float, sar: float, ports: int, avg_size: float):
    if pps > 500 and sar > 5:
        return "DDoS SYN Flood", "Severe (Critical Anomaly)"
    if pps > 1000:
        return "High-Volume Flood Attack", "Severe (Critical Anomaly)"
    if pps > 300 and avg_size > 800:
        return "Speed Test / Large Data Transfer", "Moderate (Bandwidth Spike)"
    if ports > 20:
        return "Port Scan / Reconnaissance", "Moderate (Suspicious)"
    if pps <= 5 and avg_size < 150:
        return "Ping / Background Telemetry", "Baseline (Safe)"
    return "Standard Web Traffic", "Baseline (Safe)"


def load_threat_intel() -> set[str]:
    """Load newline-separated known-malicious IPs from THREAT_INTEL_FILE.

    Lines starting with '#' are comments. File is optional; missing file
    returns an empty set so the runtime falls back to behavioral detection.
    """
    if not os.path.exists(THREAT_INTEL_FILE):
        return set()
    ips = set()
    with open(THREAT_INTEL_FILE, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    if ips:
        print(f"[+] Threat intel feed loaded: {len(ips)} known-malicious IP(s).")
    return ips


def update_rolling(src_ip: str, total_packets: int, unique_ports: int, syn_flags: int) -> dict:
    """Maintain bounded per-IP history; return aggregated stats across history."""
    history = ROLLING_STATE.setdefault(src_ip, [])
    history.append({"packets": total_packets, "ports": unique_ports, "syn": syn_flags})
    if len(history) > ROLLING_WINDOWS:
        del history[:-ROLLING_WINDOWS]
    return {
        "rolling_windows": len(history),
        "rolling_packets": sum(h["packets"] for h in history),
        "rolling_unique_ports": sum(h["ports"] for h in history),
        "rolling_syn": sum(h["syn"] for h in history),
    }


def slow_attack_check(rolling: dict) -> tuple[str, str] | None:
    """Catch attacks that hide below the single-window pps threshold."""
    n = rolling["rolling_windows"]
    if n < 5:  # need at least 10s of history
        return None
    # Slow port scan: low single-window port count but huge total port spread over time.
    if rolling["rolling_unique_ports"] > 60:
        return "Slow Port Scan (multi-window)", "Moderate (Suspicious)"
    # Sustained SYN beacon / brute-force: many SYNs over time, never crosses single-window flood.
    if rolling["rolling_syn"] > 150 and rolling["rolling_packets"] > 200:
        return "Sustained SYN / Brute-Force Probe", "Moderate (Suspicious)"
    return None


def load_models():
    """Prefer RF; fall back to K-Means if RF artifacts missing."""
    try:
        model = joblib.load("rf_model.pkl")
        scaler = joblib.load("rf_scaler.pkl")
        print("[+] Random Forest model loaded.")
        return model, scaler, True
    except FileNotFoundError:
        model = joblib.load("advanced_kmeans_model.pkl")
        scaler = joblib.load("advanced_data_scaler.pkl")
        print("[+] K-Means fallback loaded. Run trainai_rf.py to upgrade.")
        return model, scaler, False


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('''
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
    try:
        cur.execute('ALTER TABLE live_threat_logs ADD COLUMN confidence REAL DEFAULT 0.0')
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()
    conn.close()


def capture_window(interface: str) -> pd.DataFrame:
    """Run a single tshark capture + extraction cycle."""
    subprocess.run(
        [TSHARK_PATH, "-i", interface, "-a", f"duration:{WINDOW_SECONDS}", "-w", "temp_live.pcap"],
        stderr=subprocess.DEVNULL,
    )

    extract_cmd = [TSHARK_PATH, "-r", "temp_live.pcap", "-T", "fields"]
    for field in TSHARK_FIELDS:
        extract_cmd += ["-e", field]
    extract_cmd += ["-E", "header=y", "-E", "separator=,", "-E", "quote=d"]

    with open("temp_raw.csv", "w", encoding="utf-8") as outfile:
        subprocess.run(extract_cmd, stdout=outfile, stderr=subprocess.DEVNULL)

    return pd.read_csv("temp_raw.csv", low_memory=False)


def clean_packets(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = RAW_COLUMNS
    df['Dest Port'] = df['TCP Dst'].fillna(df['UDP Dst']).fillna(0)

    for col in FLAG_COLS:
        df[col] = df[col].astype(str).str.split(',').str[0].str.strip()
        df[col] = df[col].replace(
            {'True': 1, 'False': 0, 'true': 1, 'false': 0, '': 0, 'nan': 0, 'NaN': 0}
        )
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    for col in NUMERIC_COLS:
        df[col] = df[col].astype(str).str.split(',').str[0]
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    return df


def engineer_flows(df: pd.DataFrame) -> pd.DataFrame:
    flows = df.groupby('Source IP').agg(
        total_packets=('Packet Size', 'count'),
        total_bytes=('Packet Size', 'sum'),
        packet_size_std=('Packet Size', 'std'),
        unique_target_ips=('Dest IP', 'nunique'),
        unique_target_ports=('Dest Port', 'nunique'),
        total_syn_flags=('SYN Flag', 'sum'),
        total_ack_flags=('ACK Flag', 'sum'),
        total_fin_flags=('FIN Flag', 'sum'),
        total_rst_flags=('RST Flag', 'sum'),
        avg_ttl=('TTL', 'mean'),
        avg_window_size=('Window Size', 'mean'),
        first_packet_time=('Timestamp', 'min'),
        last_packet_time=('Timestamp', 'max'),
    ).reset_index()

    iat_rows = []
    for src_ip, grp in df.groupby('Source IP'):
        times = grp['Timestamp'].sort_values().to_numpy()
        if len(times) < 2:
            iat_rows.append({'Source IP': src_ip, 'iat_mean': 0.0, 'iat_std': 0.0})
        else:
            iats = np.diff(times)
            iat_rows.append({'Source IP': src_ip, 'iat_mean': float(iats.mean()), 'iat_std': float(iats.std())})
    flows = flows.merge(pd.DataFrame(iat_rows), on='Source IP', how='left')

    # Clamp duration to floor 0.1s so a single-packet flow doesn't produce
    # absurd pps values that trip the heuristic.
    flows['flow_duration_sec'] = (flows['last_packet_time'] - flows['first_packet_time']).clip(lower=0.1)
    flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
    flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
    flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']
    flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)
    flows['packet_size_std'] = flows['packet_size_std'].fillna(0)

    return flows.replace([np.inf, -np.inf], 0).fillna(0)


def fuse(*threats: str) -> str:
    return max(threats, key=lambda t: SEVERITY_RANK.get(t, 0))


def write_alerts(flows: pd.DataFrame, model, scaler, use_rf: bool, intel_ips: set) -> None:
    conn = sqlite3.connect(DB_FILE, timeout=10)
    cur = conn.cursor()

    for _, row in flows.iterrows():
        try:
            feat_df = row[FEATURE_COLS].to_frame().T.replace([np.inf, -np.inf], 0).fillna(0)
        except KeyError as e:
            print(f"[!] feature mismatch ({e}); skipping flow {row.get('Source IP')}")
            continue

        scaled = scaler.transform(feat_df)

        src_ip = row['Source IP']
        pps = row['packets_per_second']
        sar = row['syn_ack_ratio']
        ports = row['unique_target_ports']
        avg_size = row['avg_packet_size']
        syn_count = int(row['total_syn_flags'])

        profile, heuristic_threat = classify_profile(pps, sar, ports, avg_size)

        # Layer 1: ML classifier
        if use_rf:
            rf_label = int(model.predict(scaled)[0])
            confidence = float(np.max(model.predict_proba(scaled)[0]))
            rf_threat = THREAT_LABEL_MAP.get(rf_label, "Baseline (Safe)")
        else:
            rf_threat = heuristic_threat
            confidence = 0.0

        # Layer 2: multi-window rolling state (slow attacks)
        rolling = update_rolling(src_ip, int(row['total_packets']), int(ports), syn_count)
        slow_hit = slow_attack_check(rolling)
        if slow_hit:
            slow_profile, slow_threat = slow_hit
        else:
            slow_profile, slow_threat = None, "Baseline (Safe)"

        # Layer 3: threat intel feed (overrides everything else)
        intel_hit = src_ip in intel_ips

        threat = fuse(rf_threat, heuristic_threat, slow_threat)
        if intel_hit:
            threat = "Severe (Critical Anomaly)"
            profile = "Known Malicious IP (Threat Intel Match)"
        elif slow_hit and SEVERITY_RANK.get(slow_threat, 0) >= SEVERITY_RANK.get(threat, 0):
            profile = slow_profile

        cur.execute('''
            INSERT INTO live_threat_logs
            (timestamp, source_ip, packets_per_sec, avg_window_size, syn_ack_ratio,
             total_bytes, traffic_profile, threat_level, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%H:%M:%S"),
            src_ip,
            round(pps, 2),
            round(row['avg_window_size'], 2),
            round(sar, 2),
            int(row['total_bytes']),
            profile,
            threat,
            round(confidence, 4),
        ))

        conf_str = f"{confidence*100:5.1f}%" if use_rf else "  n/a"
        intel_tag = "  [INTEL]" if intel_hit else ""
        print(f"  [{src_ip:>15}]  {profile:<40}  {threat:<30}  "
              f"conf={conf_str}  pps={pps:6.0f}  sar={sar:4.1f}  syn={syn_count}{intel_tag}")

    conn.commit()
    conn.close()


def main():
    interface = INTERFACE_OVERRIDE or get_wifi_interface()

    print("\n[*] Loading classifier...")
    model, scaler, use_rf = load_models()

    print("[*] Initializing SQLite log database...")
    init_db()

    print("[*] Loading threat intel feed (optional)...")
    intel_ips = load_threat_intel()

    label = "Random Forest" if use_rf else "K-Means"
    print(f"\n[+] Engine active. Model: {label}. Window: {WINDOW_SECONDS}s. Iface: #{interface}\n")

    while True:
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] capturing {WINDOW_SECONDS}s window...")
            df = capture_window(interface)

            if df.empty or len(df) < 2:
                print("[!] no packets in window; retrying...\n")
                continue

            print(f"[+] {len(df)} packets captured, engineering flows...")
            df = clean_packets(df)
            flows = engineer_flows(df)
            write_alerts(flows, model, scaler, use_rf, intel_ips)
            print("")

        except KeyboardInterrupt:
            print("\n[*] shutdown requested, exiting.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
