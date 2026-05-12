# Hybrid Intrusion Detection Using Wireshark Packet Analysis and Behavioral Modeling

Major Project (CMP3602) — Diploma in Cybersecurity & Digital Forensics, Temasek Polytechnic.

A real-time hybrid Intrusion Detection System (IDS) that combines rule-based signatures with a Random Forest behavioral model to classify network flows as Baseline, Moderate, or Severe. Built around tshark for live capture, scikit-learn for ML, SQLite for alert logging, and Streamlit for the SOC dashboard.

## System Architecture

```
[ tshark live capture (2s windows) ]
              |
              v
[ Pandas flow engineering — 15 features per Source IP ]
              |
       +------+------+
       |             |
       v             v
[ RF model ]   [ Heuristic rules ]
       \             /
        v           v
        [ Fusion: max severity ]
              |
              v
   [ SQLite alert log ] -> [ Streamlit dashboard ]
                                |
                                v
                  [ One-Click firewall mitigation ]
```

## Components

### Training pipeline (offline, run once)
| File | Purpose |
|---|---|
| `Dashboard/advanced_parser.py` | Parses PCAP files via tshark, extracts packet-level features |
| `Dashboard/feature_engineer.py` | Groups packets into flows per Source IP, engineers 15 behavioral features |
| `Dashboard/trainai_rf.py` | Trains Random Forest classifier, saves `rf_model.pkl` + `rf_scaler.pkl` |
| `Dashboard/trainai.py` | (Legacy) K-Means clustering, kept as fallback |

### Runtime engine
| File | Purpose |
|---|---|
| `Dashboard/live_backend.py` | Live capture loop — 2-second tshark windows, flow engineering, hybrid classification, writes alerts to `ids_logs.db` |
| `Dashboard/app.py` | Streamlit SOC dashboard — live threat table, charts, top talkers, one-click firewall block |
| `Dashboard/start_system.bat` | Launches the backend and dashboard simultaneously |

## Detection Logic

**Heuristic rules** (`classify_profile()` in `live_backend.py`):
- `pps > 500` and `syn_ack_ratio > 5` → DDoS SYN Flood (Severe)
- `pps > 1000` → High-Volume Flood Attack (Severe)
- `pps > 300` and `avg_size > 800` → Bandwidth Spike (Moderate)
- `unique_target_ports > 20` → Port Scan (Moderate)
- `pps <= 5` and `avg_size < 150` → Ping/Telemetry (Baseline)
- else → Standard Web Traffic (Baseline)

**Random Forest** predicts 0/1/2 (Baseline/Moderate/Severe) with confidence via `predict_proba`. The fusion engine takes the higher severity between RF and heuristics.

## Feature Set (per flow)

Packet/session level: `total_packets`, `total_bytes`, `total_syn_flags`, `total_ack_flags`, `total_fin_flags`, `total_rst_flags`, `avg_ttl`, `avg_window_size`.

Flow/behavioral level: `flow_duration_sec`, `packets_per_second`, `bytes_per_second`, `avg_packet_size`, `syn_ack_ratio`, `unique_target_ips`, `unique_target_ports`.

## Running Locally

Requirements: Windows, Wireshark (with tshark at `C:\Program Files\Wireshark\tshark.exe`), Python 3.10+, packages: `pandas`, `scikit-learn`, `joblib`, `streamlit`.

1. **Train the model** (one-time):
   ```
   python Dashboard/advanced_parser.py
   python Dashboard/feature_engineer.py
   python Dashboard/trainai_rf.py
   ```
2. **Launch the system** (as Administrator, required for tshark live capture and firewall rule injection):
   ```
   Dashboard\start_system.bat
   ```
3. Open the dashboard at `http://localhost:8501`.

## Testing With Real Attacks

Validated against a Kali Linux VM (VirtualBox, Bridged networking):
- `sudo nmap -sS <target>` → flagged as Port Scan / Moderate
- `sudo hping3 -S --flood -V -p 80 <target>` → flagged as High-Volume Flood / Severe

Attack the gateway router (not the host machine) — VirtualBox's bridge driver routes VM-to-host traffic internally, bypassing the physical NIC tshark is listening on.

## Spec Compliance (CMP3602 Deliverables)

| Deliverable | Status |
|---|---|
| Packet capture (Wireshark/tshark) | Done |
| Feature extraction pipeline | Done |
| Signature detection engine | Done |
| ML behavioral model (Random Forest) | Done |
| Fusion/decision engine | Done |
| Real-time processing loop | Done |
| Alert logging & dashboard | Done |
| Active response (firewall rule push) | Done (Optional v2) |
| Evaluation against benchmark dataset | In progress |
| LSTM behavioral model | Pending |
| SHAP explainability | Pending (Optional v2) |
| Model retraining pipeline | Pending (Optional v2) |

## Data Note

The `Bulk PCAPS/`, `archive/`, and intermediate `*.csv`/`*.pkl` files are excluded from this repository via `.gitignore` due to size (~22 GB). They are regenerable from public sources (CIC-IDS-2017, custom captures) and via the training pipeline.
