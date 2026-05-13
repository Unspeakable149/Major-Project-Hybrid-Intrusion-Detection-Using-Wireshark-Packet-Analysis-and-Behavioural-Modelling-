# Hybrid Intrusion Detection Using Wireshark Packet Analysis and Behavioral Modeling

Major Project (CMP3602) — Diploma in Cybersecurity & Digital Forensics, Temasek Polytechnic.

A real-time hybrid Intrusion Detection System (IDS) that combines rule-based signatures with a Random Forest behavioral model to classify network flows as Baseline, Moderate, or Severe. Built around tshark for live capture, scikit-learn for ML, SQLite for alert logging, and Streamlit for the SOC dashboard.

## System Architecture

```
[ tshark live capture (2s windows) ]
              |
              v
[ Pandas flow engineering — 18 features per Source IP ]
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
| `Dashboard/advanced_parser.py` | Parses PCAP files via tshark, extracts packet-level fields |
| `Dashboard/feature_engineer.py` | Groups packets into flows per Source IP, derives 18 behavioral features (packet, flow, IAT, session, behavioral) |
| `Dashboard/trainai_rf.py` | Trains Random Forest classifier, reports DR/FPR/Precision/F1/latency vs spec targets, saves `rf_model.pkl` + `rf_scaler.pkl` |
| `Dashboard/trainai.py` | Legacy unsupervised K-Means trainer, fallback only |
| `Dashboard/evaluate_benchmark.py` | Evaluates the trained RF model against a labeled benchmark CSV (CIC-IDS-2017/2018) |

### Runtime engine
| File | Purpose |
|---|---|
| `Dashboard/live_backend.py` | Live capture loop — 2-second tshark windows, flow engineering, hybrid classification, writes alerts to `ids_logs.db` |
| `Dashboard/app.py` | Streamlit SOC dashboard — live threat table, charts, top talkers, one-click firewall block |
| `Dashboard/start_system.bat` | Launches the backend and dashboard simultaneously |
| `Dashboard/debug_flags.py` | Inspect raw tshark output when flag parsing misbehaves |

## Detection Logic

**Heuristic rules** (`classify_profile()` in `live_backend.py`):
- `pps > 500` and `syn_ack_ratio > 5` → DDoS SYN Flood (Severe)
- `pps > 1000` → High-Volume Flood Attack (Severe)
- `pps > 300` and `avg_size > 800` → Bandwidth Spike (Moderate)
- `unique_target_ports > 20` → Port Scan (Moderate)
- `pps <= 5` and `avg_size < 150` → Ping/Telemetry (Baseline)
- else → Standard Web Traffic (Baseline)

**Random Forest** predicts 0/1/2 (Baseline/Moderate/Severe) with confidence via `predict_proba`. The fusion engine takes the higher severity between RF and heuristics.

**Multi-window rolling state** tracks per-source-IP aggregates across the last 15 capture windows (~30s) so the engine catches attacks that hide below a single window's pps threshold:
- `rolling_unique_ports > 60` → Slow Port Scan
- `rolling_syn > 150` and `rolling_packets > 200` → Sustained SYN / Brute-Force Probe

**Threat Intelligence Feed** (`threat_intel.txt`, optional): newline-separated known-malicious IPv4 addresses. Any captured source IP on the list is auto-escalated to Severe regardless of behavioral metrics. Populate from AbuseIPDB / FireHOL / Spamhaus DROP / Emerging Threats.

## Feature Set (18 per flow)

| Category | Features |
|---|---|
| Packet-level | `total_packets`, `total_bytes`, `avg_packet_size`, `packet_size_std` |
| Flow-level | `flow_duration_sec`, `packets_per_second`, `bytes_per_second`, `iat_mean`, `iat_std` |
| Session-level | `total_syn_flags`, `total_ack_flags`, `total_fin_flags`, `total_rst_flags`, `syn_ack_ratio` |
| Behavioral | `unique_target_ips`, `unique_target_ports` |
| Network-layer | `avg_ttl`, `avg_window_size` |

## Running Locally

Requirements: Windows, Wireshark (with tshark at `C:\Program Files\Wireshark\tshark.exe`), Python 3.10+, packages: `pandas`, `numpy`, `scikit-learn`, `joblib`, `streamlit`.

1. **Train the model** (one-time, or re-run after updating feature set):
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
4. **Optional — benchmark evaluation**:
   ```
   python Dashboard/evaluate_benchmark.py <path-to-CIC-IDS-2017.csv>
   ```

## Testing With Real Attacks

Validated against a Kali Linux VM (VirtualBox, Bridged networking):
- `sudo nmap -sS <target>` → flagged as Port Scan / Moderate
- `sudo hping3 -S --flood -V -p 80 <target>` → flagged as High-Volume Flood / Severe

Attack the gateway router (not the host machine) — VirtualBox's bridge driver routes VM-to-host traffic internally, bypassing the physical NIC tshark is listening on.

## Spec Targets vs Implementation

| Metric | Target | Reported by |
|---|---|---|
| Detection Rate (TP / (TP+FN)) | > 95% | `trainai_rf.py`, `evaluate_benchmark.py` |
| False Positive Rate (FP / (FP+TN)) | < 5% | `trainai_rf.py`, `evaluate_benchmark.py` |
| Precision (TP / (TP+FP)) | > 90% | `trainai_rf.py`, `evaluate_benchmark.py` |
| F1-Score | > 92% | `trainai_rf.py`, `evaluate_benchmark.py` |
| Latency per decision | < 10 ms | `trainai_rf.py`, `evaluate_benchmark.py` |

## Spec Compliance (CMP3602 Deliverables)

| Deliverable | Status |
|---|---|
| Packet capture (Wireshark/tshark) | Done |
| Feature extraction pipeline (packet, flow, IAT, session, behavioral) | Done |
| Signature detection engine | Done |
| ML behavioral model (Random Forest) | Done |
| Fusion/decision engine | Done |
| Real-time processing loop | Done |
| Alert logging & dashboard | Done |
| Evaluation against benchmark dataset | Done (`evaluate_benchmark.py`) |
| Active response (firewall rule push) | Done (Optional v2) |
| LSTM behavioral model | Pending (Optional v2) |
| SHAP explainability | Pending (Optional v2) |
| Model retraining pipeline | Pending (Optional v2) |

## Note on Label Source

`trainai_rf.py` derives labels using the same heuristic rules the runtime engine uses (weak supervision) because raw PCAP captures don't ship ground-truth labels. The RF model therefore learns a smoothed, non-linear approximation of the rule boundary and adds calibrated `predict_proba` confidences that the heuristic alone can't provide. For independent validation, use `evaluate_benchmark.py` against CIC-IDS-2017 (or any labeled flow CSV).

## Data Note

The `Bulk PCAPS/`, `archive/`, and intermediate `*.csv`/`*.pkl` files are excluded from this repository via `.gitignore` due to size (~22 GB). They are regenerable from public sources (CIC-IDS-2017, custom captures) and via the training pipeline.
