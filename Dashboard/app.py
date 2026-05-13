import os
import sqlite3
import subprocess
import time

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(
    page_title="Hybrid IDS — SOC Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    [data-testid="stMetric"] {
        background-color: #1E1E2E;
        border: 1px solid #2E2E3E;
        border-radius: 8px;
        padding: 16px 20px;
    }
    [data-testid="stMetricLabel"] { font-size: 13px; color: #888; }
    [data-testid="stMetricValue"] { font-size: 28px; font-weight: 700; }
    .section-divider { border-top: 1px solid #2E2E3E; margin: 20px 0; }
    .threat-header {
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #888;
        margin-bottom: 8px;
    }
    .block-panel {
        background-color: #1E1E2E;
        border: 1px solid #3A1A1A;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .ip-label { font-family: monospace; font-size: 15px; color: #FF6B6B; font-weight: 600; }
    .blocked-label { font-family: monospace; font-size: 14px; color: #888; }
    .reasoning-card {
        background-color: #15151F;
        border-left: 3px solid #4A6FA5;
        border-radius: 4px;
        padding: 12px 16px;
        margin: 8px 0;
        font-size: 13px;
        color: #DDD;
    }
    .reasoning-card code { color: #FFB347; background: #0E0E18; padding: 1px 5px; border-radius: 3px; }
    .status-pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 10px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.05em;
    }
    .status-online { background: #003A1F; color: #00E68A; }
    .status-paused { background: #3A2000; color: #FFB347; }
</style>
""", unsafe_allow_html=True)


if 'blocked_ips' not in st.session_state:
    st.session_state.blocked_ips = {}


def apply_firewall_block(ip_address):
    rule_name = f"IDS_BLOCK_{ip_address.replace('.', '_')}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def remove_firewall_block(ip_address):
    rule_name = f"IDS_BLOCK_{ip_address.replace('.', '_')}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def load_threat_logs():
    try:
        conn = sqlite3.connect('ids_logs.db', timeout=15)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(live_threat_logs)")
        existing_cols = [row[1] for row in cursor.fetchall()]

        if 'confidence' in existing_cols:
            query = """
                SELECT timestamp        AS "Time",
                       source_ip        AS "Source IP",
                       packets_per_sec  AS "Packets/Sec",
                       avg_window_size  AS "Avg Window",
                       syn_ack_ratio    AS "SYN/ACK Ratio",
                       total_bytes      AS "Total Bytes",
                       traffic_profile  AS "Traffic Profile",
                       threat_level     AS "Threat Level",
                       ROUND(confidence * 100, 1) AS "Confidence (%)"
                FROM live_threat_logs
                ORDER BY id DESC
                LIMIT 500
            """
        else:
            query = """
                SELECT timestamp        AS "Time",
                       source_ip        AS "Source IP",
                       packets_per_sec  AS "Packets/Sec",
                       avg_window_size  AS "Avg Window",
                       syn_ack_ratio    AS "SYN/ACK Ratio",
                       total_bytes      AS "Total Bytes",
                       traffic_profile  AS "Traffic Profile",
                       threat_level     AS "Threat Level"
                FROM live_threat_logs
                ORDER BY id DESC
                LIMIT 500
            """

        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def detection_engine_status():
    if os.path.exists("rf_model.pkl"):
        return "Hybrid (Behavioral ML + Signature Rules)"
    if os.path.exists("advanced_kmeans_model.pkl"):
        return "Hybrid (Anomaly Clustering + Signature Rules)"
    return "Signature Rules Only"


def highlight_threat_row(row):
    threat = str(row.get("Threat Level", ""))
    base = [""] * len(row)
    idx = row.index.tolist().index("Threat Level") if "Threat Level" in row.index else -1
    if idx == -1:
        return base
    if "Severe" in threat:
        base[idx] = "background-color: #4A0A0A; color: #FF6B6B; font-weight: bold"
    elif "Moderate" in threat:
        base[idx] = "background-color: #3A2000; color: #FFB347; font-weight: bold"
    elif "Baseline" in threat:
        base[idx] = "background-color: #003A1F; color: #00E68A"
    return base


st.title("Hybrid Intrusion Detection System")
st.caption("Real-time network behavioral analysis with hybrid signature + machine learning detection")

tab1, tab2 = st.tabs(["Live SOC Dashboard", "Educational Simulator"])

with tab1:
    st.sidebar.header("Monitoring Controls")
    enable_live = st.sidebar.checkbox("Enable Live Monitoring", value=False)
    refresh_rate = st.sidebar.selectbox("Refresh Interval (seconds)", [2, 5, 10, 30], index=1)
    severity_filter = st.sidebar.multiselect(
        "Show severity levels",
        options=["Severe", "Moderate", "Baseline"],
        default=["Severe", "Moderate", "Baseline"],
    )
    st.sidebar.markdown("---")
    status_class = "status-online" if enable_live else "status-paused"
    status_text = "MONITORING" if enable_live else "PAUSED"
    st.sidebar.markdown(
        f'<span class="status-pill {status_class}">{status_text}</span>',
        unsafe_allow_html=True,
    )
    st.sidebar.caption(f"Detection Engine: {detection_engine_status()}")

    if enable_live:
        logs_df = load_threat_logs()

        if logs_df.empty:
            st.info("Connected to alert database. Waiting for network telemetry...")
        else:
            def severity_of(value: str) -> str:
                if "Severe" in str(value):
                    return "Severe"
                if "Moderate" in str(value):
                    return "Moderate"
                return "Baseline"

            logs_df["__sev__"] = logs_df["Threat Level"].map(severity_of)
            filtered_df = logs_df[logs_df["__sev__"].isin(severity_filter)].drop(columns="__sev__")
            logs_df = logs_df.drop(columns="__sev__")

            severe_mask = logs_df["Threat Level"] == "Severe (Critical Anomaly)"
            severe_df = logs_df[severe_mask]
            unique_sources = logs_df["Source IP"].nunique()
            blocked_count = len(st.session_state.blocked_ips)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Flows Logged", len(logs_df))
            m2.metric("Critical Threats", len(severe_df))
            m3.metric("Unique Source IPs", unique_sources)
            m4.metric("Blocked IPs", blocked_count)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            table_col, chart_col = st.columns([3, 1])

            with table_col:
                st.markdown('<p class="threat-header">Live Network Telemetry</p>', unsafe_allow_html=True)
                display_df = filtered_df.head(100)
                try:
                    st.dataframe(
                        display_df.style.apply(highlight_threat_row, axis=1),
                        use_container_width=True,
                        height=420
                    )
                except Exception:
                    st.dataframe(display_df, use_container_width=True, height=420)

                csv_bytes = filtered_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="Export Filtered Logs (CSV)",
                    data=csv_bytes,
                    file_name=f"ids_threat_logs_{int(time.time())}.csv",
                    mime="text/csv",
                )

            with chart_col:
                st.markdown('<p class="threat-header">Threat Distribution</p>', unsafe_allow_html=True)
                threat_counts = logs_df["Threat Level"].value_counts().reset_index()
                threat_counts.columns = ["Threat Level", "Count"]
                st.bar_chart(threat_counts.set_index("Threat Level"))

                st.markdown('<p class="threat-header">Top Talkers</p>', unsafe_allow_html=True)
                top_ips = logs_df["Source IP"].value_counts().head(5).reset_index()
                top_ips.columns = ["Source IP", "Flows"]
                st.dataframe(top_ips, use_container_width=True, hide_index=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown('<p class="threat-header">Threat Activity Timeline</p>', unsafe_allow_html=True)

            timeline_df = logs_df.copy()
            timeline_df["Severity"] = timeline_df["Threat Level"].map(
                lambda v: "Severe" if "Severe" in str(v) else ("Moderate" if "Moderate" in str(v) else "Baseline")
            )
            timeline_pivot = (
                timeline_df.groupby(["Time", "Severity"]).size().unstack(fill_value=0).sort_index()
            )
            for sev in ["Severe", "Moderate", "Baseline"]:
                if sev not in timeline_pivot.columns:
                    timeline_pivot[sev] = 0
            st.line_chart(timeline_pivot[["Severe", "Moderate", "Baseline"]])

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown('<p class="threat-header">One-Click Threat Mitigation</p>', unsafe_allow_html=True)

            severe_ips = severe_df["Source IP"].unique().tolist()
            unmitigated = [ip for ip in severe_ips if ip not in st.session_state.blocked_ips]

            if unmitigated:
                st.warning(f"{len(unmitigated)} critical threat source(s) detected and awaiting mitigation.")

                for ip in unmitigated:
                    ip_flows = len(severe_df[severe_df["Source IP"] == ip])
                    col_info, col_btn = st.columns([5, 1])
                    with col_info:
                        st.markdown(
                            f'<div class="block-panel">'
                            f'<span class="ip-label">{ip}</span>'
                            f'&nbsp;&nbsp;&nbsp;Severe (Critical Anomaly)'
                            f'&nbsp;&nbsp;|&nbsp;&nbsp;{ip_flows} alert(s) logged'
                            f'</div>',
                            unsafe_allow_html=True
                        )
                    with col_btn:
                        if st.button("Block IP", key=f"block_{ip}", type="primary"):
                            success = apply_firewall_block(ip)
                            if success:
                                st.session_state.blocked_ips[ip] = True
                                st.success(f"Firewall rule applied. Inbound traffic from {ip} is now blocked.")
                            else:
                                st.error(
                                    f"Unable to apply firewall rule for {ip}. "
                                    f"Administrator privileges required."
                                )
            elif severe_ips:
                st.success("All detected critical threat sources have been mitigated.")
            else:
                st.info("No critical threats detected in the current dataset.")

            if st.session_state.blocked_ips:
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">Blocked IP Registry</p>', unsafe_allow_html=True)

                registry_col, action_col = st.columns([3, 2])

                with registry_col:
                    blocked_table = pd.DataFrame(
                        {"Blocked Source IP": list(st.session_state.blocked_ips.keys())}
                    )
                    st.dataframe(blocked_table, use_container_width=True, hide_index=True)

                with action_col:
                    st.caption("Remove a firewall rule to restore access for a previously blocked IP.")
                    ip_to_unblock = st.selectbox(
                        "Select IP to unblock",
                        list(st.session_state.blocked_ips.keys()),
                        label_visibility="collapsed"
                    )
                    if st.button("Remove Block", key="unblock_btn"):
                        success = remove_firewall_block(ip_to_unblock)
                        if success:
                            del st.session_state.blocked_ips[ip_to_unblock]
                            st.success(f"Firewall rule removed. {ip_to_unblock} is now unblocked.")
                            st.rerun()
                        else:
                            st.error(
                                f"Could not remove the rule for {ip_to_unblock}. "
                                f"Administrator privileges required."
                            )

        time.sleep(refresh_rate)
        st.rerun()

    else:
        st.info("Live monitoring is paused. Enable it from the sidebar to begin real-time analysis.")
        st.markdown("---")
        st.markdown("**System Overview**")
        col_a, col_b, col_c = st.columns(3)
        col_a.markdown("**Capture Layer**\n\nLive packet capture across the active network interface in 2-second windows.")
        col_b.markdown("**Detection Layer**\n\n" + detection_engine_status() + " with multi-window correlation.")
        col_c.markdown("**Response Layer**\n\nOne-click firewall isolation and persistent alert logging.")


with tab2:
    st.subheader("Network Traffic and Attack Simulator")
    st.markdown("Visualize how different network behaviors trigger the detection engine.")

    scenario = st.radio(
        "Select Scenario:",
        ("Normal Web Browsing", "Reconnaissance (Port Scan)", "DDoS Flood",
         "Brute-Force Login", "C2 Beacon (Stealth)"),
        horizontal=True
    )

    if scenario == "Normal Web Browsing":
        sim_mode = "normal"
        st.success("Classification: BASELINE — Standard web traffic pattern. No anomaly detected.")
        reasoning = [
            ("packets/sec", "low", "well below the 300 pps moderate threshold"),
            ("syn_ack_ratio", "~1.0", "balanced — every SYN is acknowledged"),
            ("unique_dest_ports", "1–3", "far below the 20-port scan threshold"),
            ("traffic_profile", "Standard Web Traffic", "no rule matched"),
        ]
    elif scenario == "Reconnaissance (Port Scan)":
        sim_mode = "scan"
        st.warning("Classification: MODERATE — Sequential port probing across many destination ports.")
        reasoning = [
            ("unique_dest_ports", "> 20", "triggers `ports > 20` Port Scan rule"),
            ("packets/sec", "moderate", "sustained probing, not flood-level"),
            ("syn_ack_ratio", "elevated", "many SYNs sent, few ACKs returned (closed ports)"),
            ("traffic_profile", "Port Scan / Reconnaissance", "Moderate severity"),
        ]
    elif scenario == "DDoS Flood":
        sim_mode = "ddos"
        st.error("Classification: SEVERE — Extreme SYN packet rate with anomalous SYN/ACK ratio.")
        reasoning = [
            ("packets/sec", "> 500", "triggers high-volume flood rule"),
            ("syn_ack_ratio", "> 5", "overwhelming SYNs vs returning ACKs"),
            ("total_syn_flags", "very high", "SYN flood signature"),
            ("traffic_profile", "DDoS SYN Flood", "Severe — fusion engine picks max severity"),
        ]
    elif scenario == "Brute-Force Login":
        sim_mode = "brute"
        st.warning("Classification: MODERATE — Sustained authentication attempts across many windows.")
        reasoning = [
            ("rolling_syn (30s)", "> 150", "multi-window slow-attack detector trips"),
            ("packets/sec (single window)", "low", "below the 500 pps single-window flood threshold"),
            ("unique_dest_ports", "1", "all targeting one auth port (e.g. 22 / 3389)"),
            ("traffic_profile", "Sustained SYN / Brute-Force Probe", "caught by rolling-state layer"),
        ]
    else:
        sim_mode = "c2"
        st.warning("Classification: MODERATE — Low-and-slow periodic beacon, likely command-and-control.")
        reasoning = [
            ("packets/sec", "very low", "stealth — single-window heuristic alone misses this"),
            ("iat_std", "near 0", "highly regular beacon interval (telemetry-like rhythm)"),
            ("unique_dest_ips", "1", "single hard-coded callback host"),
            ("detection path", "ML + rolling state", "ML flags rhythmic IAT pattern as suspicious"),
        ]

    reasoning_html = "".join(
        f'<div class="reasoning-card"><b>{label}</b>: <code>{value}</code> — {note}</div>'
        for label, value, note in reasoning
    )
    st.markdown("**Detection Reasoning**", help="Which feature values trigger which rule path.")
    st.markdown(reasoning_html, unsafe_allow_html=True)

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                margin: 0; padding: 0;
                background-color: #0E1117;
                color: white;
                font-family: 'Segoe UI', sans-serif;
                overflow: hidden;
            }}
            canvas {{
                display: block;
                margin: 0 auto;
                background-color: #1A1A2E;
                border-radius: 8px;
                border: 1px solid #2E2E4E;
            }}
            #legend {{
                text-align: center;
                margin-top: 10px;
                font-size: 12px;
                color: #aaa;
            }}
            .dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 4px; }}
        </style>
    </head>
    <body>
        <canvas id="networkCanvas" width="820" height="280"></canvas>
        <div id="legend">
            <span><span class="dot" style="background:#00FFAA;"></span>Safe (Port 80/443)</span>
            &nbsp;&nbsp;
            <span><span class="dot" style="background:#FFCC00;"></span>Probe / Brute-Force</span>
            &nbsp;&nbsp;
            <span><span class="dot" style="background:#FF3333;"></span>SYN Flood</span>
            &nbsp;&nbsp;
            <span><span class="dot" style="background:#9B6BFF;"></span>C2 Beacon</span>
        </div>
        <script>
            const canvas = document.getElementById('networkCanvas');
            const ctx = canvas.getContext('2d');
            const mode = "{sim_mode}";

            const nodes = {{
                source: {{ x: 110, y: 140, label: "Source Host" }},
                firewall: {{ x: 410, y: 140, label: "Firewall / IDS" }},
                server: {{ x: 710, y: 140, label: "Target Server" }}
            }};

            let packets = [];
            let scanPort = 1;
            let frameCount = 0;

            class Packet {{
                constructor() {{
                    this.x = nodes.source.x;
                    this.y = nodes.source.y + (Math.random() - 0.5) * 20;
                    this.targetX = nodes.firewall.x;
                    this.targetY = nodes.firewall.y;
                    this.stage = 1;
                    this.speed = (mode === 'ddos') ? 9 : (mode === 'c2' ? 3 : 4);
                    this.alpha = 1.0;
                    if (mode === 'normal') {{
                        this.port = Math.random() > 0.5 ? 80 : 443;
                        this.color = "#00FFAA";
                        this.radius = 4;
                    }} else if (mode === 'scan') {{
                        this.port = scanPort++;
                        if (scanPort > 1024) scanPort = 1;
                        this.color = "#FFCC00";
                        this.radius = 3;
                    }} else if (mode === 'ddos') {{
                        this.port = 80;
                        this.color = "#FF3333";
                        this.radius = 5;
                    }} else if (mode === 'brute') {{
                        this.port = (Math.random() > 0.5) ? 22 : 3389;
                        this.color = "#FFCC00";
                        this.radius = 4;
                    }} else {{
                        this.port = 443;
                        this.color = "#9B6BFF";
                        this.radius = 4;
                    }}
                }}

                update() {{
                    const dx = this.targetX - this.x;
                    const dy = this.targetY - this.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist > this.speed) {{
                        this.x += (dx / dist) * this.speed;
                        this.y += (dy / dist) * this.speed;
                    }} else {{
                        if (this.stage === 1) {{
                            this.stage = 2;
                            this.targetX = nodes.server.x;
                            this.targetY = nodes.server.y;
                        }} else {{
                            this.stage = 3;
                        }}
                    }}
                }}

                draw() {{
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                    ctx.fillStyle = this.color;
                    ctx.globalAlpha = 0.9;
                    ctx.fill();
                    ctx.globalAlpha = 1.0;
                    ctx.fillStyle = "rgba(255,255,255,0.6)";
                    ctx.font = "9px monospace";
                    ctx.fillText(":" + this.port, this.x + 6, this.y - 4);
                }}
            }}

            function drawNode(node, fillColor, borderColor) {{
                ctx.shadowColor = borderColor;
                ctx.shadowBlur = 12;
                ctx.fillStyle = fillColor;
                ctx.beginPath();
                ctx.roundRect(node.x - 36, node.y - 28, 72, 56, 6);
                ctx.fill();
                ctx.shadowBlur = 0;
                ctx.strokeStyle = borderColor;
                ctx.lineWidth = 1.5;
                ctx.stroke();
                ctx.fillStyle = "rgba(255,255,255,0.85)";
                ctx.font = "11px 'Segoe UI'";
                ctx.textAlign = "center";
                ctx.fillText(node.label, node.x, node.y + 44);
            }}

            function drawConnections() {{
                ctx.beginPath();
                ctx.moveTo(nodes.source.x + 36, nodes.source.y);
                ctx.lineTo(nodes.firewall.x - 36, nodes.firewall.y);
                ctx.strokeStyle = "#2E3A4E";
                ctx.lineWidth = 2;
                ctx.stroke();

                ctx.beginPath();
                ctx.moveTo(nodes.firewall.x + 36, nodes.firewall.y);
                ctx.lineTo(nodes.server.x - 36, nodes.server.y);
                ctx.strokeStyle = "#2E3A4E";
                ctx.lineWidth = 2;
                ctx.stroke();
            }}

            function spawnRateFor(mode) {{
                if (mode === 'ddos') return 0.85;
                if (mode === 'scan') return 0.25;
                if (mode === 'brute') return 0.12;
                if (mode === 'c2') return 0.0;  // beacon uses fixed-interval spawning
                return 0.04;
            }}

            function animate() {{
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                frameCount++;

                drawConnections();
                drawNode(nodes.source,   "#1A2A3A", "#3A6A9A");
                drawNode(nodes.firewall, "#1A2A1A", "#3A7A3A");
                drawNode(nodes.server,   "#2A1A1A", "#7A2A2A");

                const burstCount = (mode === 'ddos') ? 4 : 1;

                // C2 beacon: fire a single packet every ~90 frames (regular cadence).
                if (mode === 'c2') {{
                    if (frameCount % 90 === 0) packets.push(new Packet());
                }} else if (Math.random() < spawnRateFor(mode)) {{
                    for (let i = 0; i < burstCount; i++) packets.push(new Packet());
                }}

                for (let i = packets.length - 1; i >= 0; i--) {{
                    packets[i].update();
                    packets[i].draw();
                    if (packets[i].stage === 3) packets.splice(i, 1);
                }}

                if (packets.length > 300) packets.splice(0, packets.length - 300);

                requestAnimationFrame(animate);
            }}

            animate();
        </script>
    </body>
    </html>
    """

    components.html(html_code, height=380)

    st.markdown("---")
    st.markdown("**Behavioral Signatures by Scenario**")
    sig_data = {
        "Scenario": [
            "Normal Web Browsing", "Reconnaissance (Port Scan)", "DDoS SYN Flood",
            "Brute-Force Login", "C2 Beacon (Stealth)"
        ],
        "Typical Packets/Sec": ["< 5", "10 — 50", "> 500", "low (sustained)", "very low (periodic)"],
        "Unique Dest Ports": ["1 — 3", "> 20", "1", "1 (22 / 3389)", "1 (443)"],
        "SYN/ACK Ratio": ["~1.0", "~1.2", "> 5.0", "elevated", "~1.0"],
        "Detection Path": [
            "Rules", "Rules", "Rules + ML",
            "Rolling multi-window state",
            "ML pattern + rolling state"
        ],
        "Threat Classification": [
            "Baseline (Safe)", "Moderate (Suspicious)", "Severe (Critical Anomaly)",
            "Moderate (Suspicious)", "Moderate (Suspicious)"
        ]
    }
    st.dataframe(pd.DataFrame(sig_data), use_container_width=True, hide_index=True)
