"""Engineer per-Source-IP behavioral flow features from the parsed packet dataset.

Input:  master_advanced_dataset.csv  (produced by advanced_parser.py)
Output: ai_ready_advanced_flows.csv  (consumed by trainai_rf.py / trainai.py)

Feature coverage maps to the project spec's feature categories:
    - Packet-level    -> total_packets, total_bytes, avg_packet_size, packet_size_std
    - Flow-level      -> flow_duration_sec, packets_per_second, bytes_per_second,
                         iat_mean, iat_std
    - Session-level   -> total_{syn,ack,fin,rst}_flags, syn_ack_ratio
    - Behavioral      -> unique_target_ips, unique_target_ports
    - Network-layer   -> avg_ttl, avg_window_size
"""

import pandas as pd
import numpy as np
import warnings

warnings.filterwarnings("ignore")

INPUT_CSV = "master_advanced_dataset.csv"
OUTPUT_CSV = "ai_ready_advanced_flows.csv"

NUMERIC_COLS = [
    'Packet Size', 'SYN Flag', 'ACK Flag', 'FIN Flag',
    'RST Flag', 'TTL', 'Window Size', 'Timestamp'
]


def coerce_numeric(df: pd.DataFrame, columns: list) -> pd.DataFrame:
    for col in columns:
        if col not in df.columns:
            continue
        df[col] = df[col].astype(str).str.split(',').str[0]
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    return df


def compute_iat_stats(group: pd.DataFrame) -> pd.Series:
    times = group['Timestamp'].sort_values().to_numpy()
    if len(times) < 2:
        return pd.Series({'iat_mean': 0.0, 'iat_std': 0.0})
    iats = np.diff(times)
    return pd.Series({'iat_mean': float(iats.mean()), 'iat_std': float(iats.std())})


def main():
    print("[1/5] Loading parsed packet dataset...")
    df = pd.read_csv(INPUT_CSV, low_memory=False)
    print(f"      {len(df):,} packet rows loaded.")

    print("[2/5] Coercing numeric columns (tshark emits multi-value fields)...")
    df = coerce_numeric(df, NUMERIC_COLS)

    print("[3/5] Aggregating flows grouped by Source IP...")
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
        last_packet_time=('Timestamp', 'max')
    ).reset_index()

    print("[4/5] Computing inter-arrival time stats per source IP...")
    iat_stats = df.groupby('Source IP').apply(compute_iat_stats).reset_index()
    flows = flows.merge(iat_stats, on='Source IP', how='left')

    print("[5/5] Deriving velocity + ratio features...")
    flows['flow_duration_sec'] = (flows['last_packet_time'] - flows['first_packet_time']).clip(lower=0.1)
    flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
    flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
    flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']
    flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)
    flows['packet_size_std'] = flows['packet_size_std'].fillna(0)
    flows['iat_mean'] = flows['iat_mean'].fillna(0)
    flows['iat_std'] = flows['iat_std'].fillna(0)

    final = flows.drop(columns=['first_packet_time', 'last_packet_time'])
    final = final.replace([np.inf, -np.inf], 0).fillna(0)
    final.to_csv(OUTPUT_CSV, index=False)

    print(f"\nSUCCESS. Wrote {OUTPUT_CSV}  shape={final.shape}")
    print(f"Features per flow: {final.shape[1] - 1}")


if __name__ == "__main__":
    main()
