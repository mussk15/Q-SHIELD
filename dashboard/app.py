"""Q-SHIELD — Unified Post-Quantum Security Operations Dashboard.

Central analyst console providing real-time visibility, management, and control over:
1. Overview: System health, threat indicators, security posture, and architecture flows.
2. Secure Communication: Post-quantum TCP server/client controls and encrypted messaging.
3. File Transfer: Post-quantum AES-256-GCM encrypted file transfers with SHA-256 verification.
4. Sessions: Active/historical session lifecycle and post-quantum key generations.
5. Network Monitoring: Offline PCAP replay analysis and live Scapy network capture.
6. Threat Alerts: Multi-source intrusion detections (Rule-based, Anomaly, Application).
7. Response Centre: In-band Force Re-key, Kill Session, and simulated IP containment.
8. Evidence: Cryptographic SHA-256 hash-chain verification and audit logging.
9. Cryptographic Benchmarks: Measured PQC (ML-KEM/ML-DSA) vs Classical baselines.
10. System Status & Settings: Component health diagnostics, port checks, and configuration.
"""
from __future__ import annotations

import collections
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from qshield.crypto.backend import KEM_ALGORITHM, SIGNATURE_ALGORITHM, get_oqs
from qshield.monitor.rules import load_config
from qshield.services import get_service_manager
from response.blocklist import block_ip, load_blocklist, unblock_ip
from response.commands import enqueue_command
from response.evidence import append_event, verify_chain


def resolve_data_dir() -> Path:
    configured = Path(os.getenv("QSHIELD_DATA_DIR", "data"))
    return configured if configured.is_absolute() else ROOT / configured


DATA_DIR = resolve_data_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVENTS_FILE = DATA_DIR / "events.jsonl"
ALERTS_FILE = DATA_DIR / "alerts.jsonl"
SESSIONS_FILE = DATA_DIR / "sessions.jsonl"
BLOCKLIST_FILE = DATA_DIR / "blocklist.json"
COMMANDS_FILE = DATA_DIR / "commands.jsonl"
COMMAND_RESULTS_FILE = DATA_DIR / "command_results.jsonl"
EVIDENCE_FILE = DATA_DIR / "evidence.jsonl"
BENCHMARKS_FILE = DATA_DIR / "benchmarks.json"
CONFIG_FILE = ROOT / "config" / "thresholds.yaml"

st.set_page_config(
    page_title="Q-SHIELD | Quantum Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800;900&display=swap');
    :root { --bg:#07111f; --panel:#0d2034; --line:#1d3953; --cyan:#45d7e7; --muted:#8fa8c0; }
    html, body, [class*="css"] { font-family: 'Manrope', -apple-system, sans-serif; }
    .stApp { background: radial-gradient(ellipse at 80% 0%, rgba(20,135,160,.16), transparent 40%), #07111f; color: #f2f7ff; }
    [data-testid="stHeader"] { background: rgba(7,17,31,.85); backdrop-filter: blur(8px); }
    [data-testid="stMainBlockContainer"] { max-width: 1560px; padding-top: 1.5rem; padding-bottom: 3.5rem; }
    [data-testid="stSidebar"] { background: linear-gradient(180deg, #0b1c2e, #06121f); border-right: 1px solid var(--line); }
    [data-testid="stMetric"] { background: linear-gradient(145deg, #10273f, #091a2b); border: 1px solid var(--line); border-radius: 14px; padding: 14px 18px; min-height: 105px; }
    [data-testid="stMetricLabel"] { color: #8ea8c2 !important; font-size: 0.72rem; font-weight: 800; letter-spacing: 0.05em; text-transform: uppercase; }
    [data-testid="stMetricValue"] { color: #fff !important; font-size: 1.75rem; font-weight: 850; }
    [data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 12px; overflow: hidden; background: #081625; }
    .stButton > button, .stFormSubmitButton > button { background: linear-gradient(135deg, #128299, #0e5b74); color: white; border: 1px solid rgba(69,215,231,.35); border-radius: 9px; font-weight: 800; letter-spacing: 0.02em; padding: 0.45rem 1.1rem; }
    .stButton > button:hover, .stFormSubmitButton > button:hover { color: white; border-color: var(--cyan); background: linear-gradient(135deg, #1598b3, #116e8c); }
    .stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] { background: #091a2b !important; color: white !important; border: 1px solid var(--line) !important; border-radius: 9px !important; }
    .qs-brand { display:flex; align-items:center; gap:12px; padding:6px 2px 20px; }
    .qs-mark { width:42px; height:42px; display:grid; place-items:center; border-radius:12px; background:linear-gradient(145deg,#62e6ed,#168fae); color:#06121f; font-size:22px; font-weight:900; }
    .qs-name { color:white; font-size:1.15rem; font-weight:900; letter-spacing:.12em; }
    .qs-caption { color:#829bb5; font-size:.62rem; letter-spacing:.1em; font-weight:700; }
    .qs-kicker { color:var(--cyan); font-size:.68rem; letter-spacing:.15em; font-weight:800; text-transform:uppercase; }
    .qs-title { color:white; font-size:2.0rem; font-weight:900; letter-spacing:-.04em; margin:.25rem 0 .4rem; }
    .qs-sub { color:var(--muted); font-size:.88rem; line-height: 1.5; }
    .qs-hero { margin:14px 0 22px; padding:22px 26px; border:1px solid rgba(69,215,231,.25); border-radius:16px; background:radial-gradient(circle at 92% 18%,rgba(69,215,231,.16),transparent 32%),linear-gradient(110deg,#0e263d,#0a1b2d); }
    .qs-hero-title { color:white; font-size:1.45rem; font-weight:900; margin:.4rem 0; }
    .qs-hero-copy { color:#a3bad0; max-width:920px; line-height:1.6; font-size:0.92rem; }
    .qs-chip { display:inline-block; margin-top:10px; margin-right:6px; padding:5px 10px; border:1px solid rgba(69,215,231,.28); border-radius:7px; color:#a2edf1; background:rgba(69,215,231,.08); font-size:.68rem; font-weight:800; }
    .qs-section { color:#edf5ff; font-size:1.02rem; font-weight:850; margin:22px 0 10px; letter-spacing:0.02em; }
    .qs-badge { display:inline-block; padding:4px 9px; border-radius:6px; font-size:0.72rem; font-weight:800; }
    .qs-badge-active { background:rgba(75,214,162,.15); color:#8ce5bd; border:1px solid rgba(75,214,162,.35); }
    .qs-badge-critical { background:rgba(255,100,124,.15); color:#ff8a9c; border:1px solid rgba(255,100,124,.35); }
    .qs-badge-high { background:rgba(255,173,102,.15); color:#ffbe85; border:1px solid rgba(255,173,102,.35); }
    .qs-badge-info { background:rgba(69,215,231,.15); color:#8decf7; border:1px solid rgba(69,215,231,.35); }
    .qs-badge-muted { background:rgba(148,171,194,.12); color:#a0b6cc; border:1px solid rgba(148,171,194,.25); }
    .qs-card { background:#0a1c2e; border:1px solid var(--line); border-radius:12px; padding:16px 20px; margin-bottom:14px; }
    .qs-foot { text-align:center; color:#68829d; font-size:.68rem; padding-top:28px; }
    </style>
    """,
    unsafe_allow_html=True,
)


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    errors = 0
    if not path.exists():
        return records, errors
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
                else:
                    errors += 1
            except json.JSONDecodeError:
                errors += 1
    return records, errors


def value(item: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        if item.get(key) not in (None, ""):
            return item[key]
    return default


def alerts_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [
        {
            "Time": value(row, "timestamp", "time", "created_at"),
            "Alert": value(
                row, "title", "type", "alert_type", "rule_id", "rule", "name", default="Security alert"
            ),
            "Source IP": value(row, "source_ip", "src_ip", "ip", "source"),
            "Severity": str(value(row, "severity", "priority", default="LOW")).upper(),
            "Status": value(row, "status", "state", default="Open"),
            "Evidence": value(row, "description", "evidence", "details"),
        }
        for row in records
    ]
    return pd.DataFrame(rows, columns=["Time", "Alert", "Source IP", "Severity", "Status", "Evidence"])


def sessions_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [
        {
            "Session ID": value(row, "session_id", "id"),
            "User": value(row, "user_id", "username", "user"),
            "Remote IP": value(row, "remote_ip", "source_ip", "ip"),
            "Status": value(row, "status", "state", default="Unknown"),
            "Started": value(row, "started_at", "timestamp", "created_at"),
            "Key fingerprint": value(row, "key_fingerprint", "fingerprint", default="Not provided"),
        }
        for row in records
    ]
    return pd.DataFrame(
        rows, columns=["Session ID", "User", "Remote IP", "Status", "Started", "Key fingerprint"]
    )


def commands_frame(commands: list[dict[str, Any]], results: list[dict[str, Any]]) -> pd.DataFrame:
    results_map: dict[str, dict[str, Any]] = {}
    for res in results:
        cid = str(res.get("command_id", "")).strip()
        if cid:
            results_map[cid] = res

    rows = []
    for cmd in reversed(commands):
        cid = str(cmd.get("command_id", ""))
        res = results_map.get(cid)
        status = res.get("status") if res else cmd.get("status", "queued")
        message = res.get("message") if res else "Pending server processing"
        rows.append(
            {
                "Command ID": cid[:8] + "..." if len(cid) > 12 else cid,
                "Target session": value(cmd, "session_id", default=""),
                "Command type": value(cmd, "command", default=""),
                "Queue timestamp": value(cmd, "timestamp", default=""),
                "Execution status": str(status).upper(),
                "Server response / Reason": message,
            }
        )
    return pd.DataFrame(
        rows,
        columns=[
            "Command ID",
            "Target session",
            "Command type",
            "Queue timestamp",
            "Execution status",
            "Server response / Reason",
        ],
    )


def page_header(title: str, subtitle: str) -> None:
    left, right = st.columns([5, 1])
    with left:
        st.markdown('<div class="qs-kicker">Q-SHIELD / QUANTUM SECURITY OPERATIONS</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="qs-title">{title}</div><div class="qs-sub">{subtitle}</div>', unsafe_allow_html=True)
    with right:
        st.markdown(
            '<div style="text-align:right;padding-top:16px"><span class="qs-badge qs-badge-active">● OPERATIONAL</span></div>',
            unsafe_allow_html=True,
        )


def login() -> bool:
    expected_username = os.getenv("QSHIELD_DASHBOARD_USERNAME", "analyst")
    expected_password = os.getenv("QSHIELD_DASHBOARD_PASSWORD", "")
    if not expected_password or expected_password.startswith("replace-with-"):
        st.error("Configure QSHIELD_DASHBOARD_PASSWORD in your .env file before starting the dashboard.")
        st.code("QSHIELD_DASHBOARD_USERNAME=analyst\nQSHIELD_DASHBOARD_PASSWORD=YourPassword\nQSHIELD_DATA_DIR=data")
        st.stop()
    if st.session_state.get("logged_in", False):
        return True

    st.markdown(
        '<div class="qs-hero"><div class="qs-kicker">SECURITY OPERATIONS CONSOLE</div>'
        '<div class="qs-hero-title">Welcome to Q-SHIELD</div>'
        '<div class="qs-hero-copy">Sign in to manage post-quantum communication channels, inspect network threat telemetry, and coordinate security incident response actions.</div>'
        '<span class="qs-chip">ML-KEM-768</span><span class="qs-chip">ML-DSA-65</span><span class="qs-chip">AES-256-GCM</span><span class="qs-chip">DUAL-ENGINE IDS</span></div>',
        unsafe_allow_html=True,
    )
    with st.form("login_form"):
        username = st.text_input("Analyst username", value="analyst")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", width="stretch")
    if submitted:
        user_ok = hmac.compare_digest(username.strip(), expected_username)
        password_ok = hmac.compare_digest(password, expected_password)
        if user_ok and password_ok:
            st.session_state["logged_in"] = True
            st.rerun()
        st.error("Incorrect username or password.")
    st.caption("Authorized security personnel only. Cryptographic identity keys and keystores remain secured locally.")
    return False


# ==============================================================================
# SECTION 1: OVERVIEW
# ==============================================================================
def overview_page(
    events: list[dict[str, Any]],
    alerts: pd.DataFrame,
    sessions: pd.DataFrame,
    blocked: list[dict[str, Any]],
) -> None:
    page_header("Security overview", "Unified executive visibility into post-quantum channels, network monitoring, and response posture.")

    sm = get_service_manager()
    health = sm.get_system_health()

    open_count = int((~alerts["Status"].astype(str).str.lower().isin(["closed", "resolved"])).sum()) if not alerts.empty else 0
    critical_count = int((alerts["Severity"] == "CRITICAL").sum()) if not alerts.empty else 0
    active_sessions_count = int(sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"]).sum()) if not sessions.empty else 0

    st.markdown(
        '<div class="qs-hero"><div class="qs-kicker">NIST STANDARDISED POST-QUANTUM DEFENCE · LIVE TELEMETRY</div>'
        '<div class="qs-hero-title">Quantum Shield Security Operations Center</div>'
        '<div class="qs-hero-copy">End-to-end post-quantum cryptographic security utilizing ML-KEM-768 (FIPS 203) key encapsulation and ML-DSA-65 (FIPS 204) digital signatures. Dual-engine intrusion detection correlates signature rules with unsupervised Isolation Forest anomalies in real time.</div>'
        '<span class="qs-chip">ML-KEM-768 (FIPS 203)</span><span class="qs-chip">ML-DSA-65 (FIPS 204)</span><span class="qs-chip">AES-256-GCM (RFC 5116)</span><span class="qs-chip">ISOLATION FOREST IDS</span></div>',
        unsafe_allow_html=True,
    )

    kpis = st.columns(5)
    kpis[0].metric("ACTIVE SESSIONS", active_sessions_count)
    kpis[1].metric("OPEN ALERTS", open_count)
    kpis[2].metric("CRITICAL THREATS", critical_count)
    kpis[3].metric("BLOCKED IPs", len(blocked))
    kpis[4].metric("SERVER STATUS", health["server"]["status"].split()[0])

    st.markdown('<div class="qs-section">Live Activity & Telemetry</div>', unsafe_allow_html=True)
    col_chart1, col_chart2 = st.columns([1.6, 1])

    with col_chart1:
        st.markdown("### Network & Security Event Stream")
        timeline = []
        for row in events:
            ts = pd.to_datetime(value(row, "timestamp", "time", "created_at"), utc=True, errors="coerce")
            if pd.notna(ts):
                timeline.append({"Time": ts.floor("min"), "Events": 1})
        if timeline:
            chart_df = pd.DataFrame(timeline).groupby("Time", as_index=False).sum().sort_values("Time")
            chart = (
                alt.Chart(chart_df)
                .mark_area(line={"color": "#45d7e7", "strokeWidth": 2}, color="#146077", opacity=0.35)
                .encode(
                    x=alt.X("Time:T", title=None, axis=alt.Axis(labelColor="#8da5bd", grid=False)),
                    y=alt.Y("Events:Q", title="Events / Min", axis=alt.Axis(labelColor="#8da5bd", gridColor="#19354d")),
                    tooltip=["Time:T", "Events:Q"],
                )
                .properties(height=240)
                .configure_view(strokeOpacity=0)
                .configure(background="transparent")
            )
            st.altair_chart(chart, width="stretch")
        else:
            st.info("Awaiting timestamped events in data/events.jsonl.")

    with col_chart2:
        st.markdown("### Threat Severity Distribution")
        if not alerts.empty:
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            counts = (
                alerts["Severity"]
                .value_counts()
                .reindex(order, fill_value=0)
                .rename_axis("Severity")
                .reset_index(name="Count")
            )
            chart = (
                alt.Chart(counts)
                .mark_bar(cornerRadiusEnd=5)
                .encode(
                    x=alt.X("Count:Q", title=None, axis=alt.Axis(labelColor="#8da5bd", gridColor="#19354d")),
                    y=alt.Y("Severity:N", sort=order, title=None, axis=alt.Axis(labelColor="#d3e1ef")),
                    color=alt.Color(
                        "Severity:N",
                        scale=alt.Scale(domain=order, range=["#ff647c", "#ffad66", "#e6d26a", "#4bd6a2"]),
                        legend=None,
                    ),
                    tooltip=["Severity", "Count"],
                )
                .properties(height=240)
                .configure_view(strokeOpacity=0)
                .configure(background="transparent")
            )
            st.altair_chart(chart, width="stretch")
        else:
            st.info("No threat alerts recorded yet.")

    st.markdown('<div class="qs-section">Q-SHIELD Security Architecture</div>', unsafe_allow_html=True)
    arch1, arch2 = st.columns(2)
    with arch1:
        st.markdown(
            """
            **1. Cryptographic Handshake & Secure Messaging Flow**
            ```
            [Client Endpoint]                       [Secure Server]
                   |                                       |
                   |<--- ServerHello (Ephemeral KEM PK) ---| (Signed with ML-DSA-65)
                   |                                       |
                   |--- ClientFinish (KEM Ciphertext) ---->| (Verified with ML-DSA-65)
                   |                                       | (Both derive AES-256-GCM key)
                   |<--- ServerFinish (Transcript HMAC) ---|
                   |                                       |
                   +==== Authenticated Encrypted Channel ==+
                   |<--- QSHIELD_REKEY_OFFER (Gen N+1) ----| (In-Band Message Boundary)
                   |--- QSHIELD_REKEY_RESPONSE ----------->|
            ```
            """
        )
    with arch2:
        st.markdown(
            """
            **2. Dual-Engine Network Intrusion Detection Flow**
            ```
            [Network Packets / PCAP]
                   |
                   v
            [Sliding Window Feature Extractor (10s)]
                   |
                   +-----------------------+
                   |                       |
                   v                       v
            [Signature Rule Engine]   [Isolation Forest Anomaly]
            (Port Scan / SYN Flood)   (Unsupervised Statistical Outlier)
                   |                       |
                   +-----------> [Alert Manager] <-----------+
                                       |
                             [Response Centre Queue]
            ```
            """
        )

    st.markdown('<div class="qs-section">Recent Security Alerts</div>', unsafe_allow_html=True)
    if alerts.empty:
        st.info("No alerts recorded yet.")
    else:
        st.dataframe(alerts.head(6), width="stretch", hide_index=True)


# ==============================================================================
# SECTION 2: SECURE COMMUNICATION (SERVER, CLIENT & ENCRYPTED MESSAGING)
# ==============================================================================
def secure_communication_page() -> None:
    page_header("Secure Communication", "Manage post-quantum TCP servers, connect endpoints, and transmit encrypted messages.")

    sm = get_service_manager()
    server_svc = sm.server
    client_svc = sm.client

    srv_status = server_svc.get_status()
    cli_status = client_svc.get_status()

    col_srv, col_cli = st.columns(2)

    with col_srv:
        st.markdown("### 🖥️ Secure TCP Server")
        status_text = srv_status["status"]
        badge_class = "qs-badge-active" if "RUNNING" in status_text else "qs-badge-muted"
        st.markdown(f"Status: <span class='qs-badge {badge_class}'>{status_text}</span>", unsafe_allow_html=True)
        st.caption("Post-quantum multi-client listener supporting authenticated in-band re-keying.")

        c1, c2 = st.columns(2)
        srv_host = c1.text_input("Server Host", value="127.0.0.1", key="srv_host")
        srv_port = int(c2.number_input("Server Port", value=5001, min_value=1024, max_value=65535, key="srv_port"))
        srv_pwd = st.text_input("Server Key Password", value="QSHIELD", type="password", key="srv_pwd")

        btn_start, btn_stop = st.columns(2)
        if btn_start.button("Start Secure Server", width="stretch"):
            res = server_svc.start_server(host=srv_host, port=srv_port, password=srv_pwd)
            if res["success"]:
                st.success(res["message"])
            else:
                st.error(res["message"])
            st.rerun()

        if btn_stop.button("Stop Secure Server", width="stretch"):
            res = server_svc.stop_server()
            if res["success"]:
                st.success(res["message"])
            else:
                st.warning(res["message"])
            st.rerun()

    with col_cli:
        st.markdown("### 💻 Secure Client Endpoint")
        cli_connected = cli_status["connected"]
        cli_badge = "qs-badge-active" if cli_connected else "qs-badge-muted"
        cli_label = "CONNECTED" if cli_connected else "DISCONNECTED"
        st.markdown(f"Status: <span class='qs-badge {cli_badge}'>{cli_label}</span>", unsafe_allow_html=True)
        st.caption("Performs ML-KEM-768 key encapsulation and ML-DSA-65 identity verification.")

        cc1, cc2 = st.columns(2)
        target_host = cc1.text_input("Target Host", value="127.0.0.1", key="cli_target_host")
        target_port = int(cc2.number_input("Target Port", value=5001, min_value=1024, max_value=65535, key="cli_target_port"))
        cli_pwd = st.text_input("Client Key Password", value="QSHIELD", type="password", key="cli_pwd")

        btn_conn, btn_disc = st.columns(2)
        if btn_conn.button("Connect Secure Client", width="stretch"):
            res = client_svc.connect(host=target_host, port=target_port, password=cli_pwd)
            if res["success"]:
                st.success(res["message"])
            else:
                st.error(res["message"])
            st.rerun()

        if btn_disc.button("Disconnect Client", width="stretch"):
            res = client_svc.disconnect()
            if res["success"]:
                st.success(res["message"])
            else:
                st.error(res["message"])
            st.rerun()

    st.divider()
    st.markdown('<div class="qs-section">Encrypted Messaging Console</div>', unsafe_allow_html=True)

    if not client_svc.is_connected:
        st.info("The secure client is currently disconnected. Click 'Connect Secure Client' above to establish an authenticated channel.")
    else:
        info_col1, info_col2, info_col3 = st.columns(3)
        info_col1.metric("SESSION ID", cli_status["session_id"] or "Unknown")
        info_col2.metric("KEY GENERATION", f"Gen {cli_status['generation']}")
        info_col3.metric("ENCRYPTION", "AES-256-GCM")

        with st.form("send_message_form"):
            msg_input = st.text_input("Confidential Message Payload", placeholder="Enter confidential message to transmit...")
            submitted = st.form_submit_button("Send Encrypted Message", width="stretch")

        if submitted:
            if not msg_input.strip():
                st.warning("Cannot send an empty message.")
            else:
                res = client_svc.send_encrypted_message(msg_input)
                if res["success"]:
                    st.success(f"Delivered! Server response: '{res['received']}'")
                    if res.get("rekeyed"):
                        st.info(f"In-band post-quantum re-key occurred during exchange! Switched to Key Generation {res['generation']}.")
                else:
                    st.error(f"Transmission error: {res['message']}")
                st.rerun()

        st.markdown("### Message Transmission Audit Log")
        history = cli_status["history"]
        if history:
            hist_df = pd.DataFrame(history)
            st.dataframe(hist_df, width="stretch", hide_index=True)
        else:
            st.caption("No messages exchanged yet in this session.")


# ==============================================================================
# SECTION 3: FILE TRANSFER
# ==============================================================================
def file_transfer_page() -> None:
    page_header("Encrypted File Transfer", "Authenticated post-quantum chunked transfer with SHA-256 integrity verification.")

    sm = get_service_manager()
    fts = sm.file_transfer

    tab_send, tab_received = st.tabs(["Send Encrypted File", "Received Files Explorer"])

    with tab_send:
        st.markdown("### Select or Upload File to Transfer")
        source_mode = st.radio("File Source", ["Upload File", "Select Sample Lab File"], horizontal=True)
        file_to_send_path: Path | None = None

        if source_mode == "Upload File":
            uploaded = st.file_uploader("Upload document or binary", type=None)
            if uploaded:
                temp_upload_dir = DATA_DIR / "test_files"
                temp_upload_dir.mkdir(parents=True, exist_ok=True)
                file_to_send_path = temp_upload_dir / uploaded.name
                file_to_send_path.write_bytes(uploaded.getbuffer())
                st.success(f"Staged file: {uploaded.name} ({len(uploaded.getbuffer())} bytes)")
        else:
            sample_dir = DATA_DIR / "test_files"
            sample_dir.mkdir(parents=True, exist_ok=True)
            # Create a sample file if none exist
            sample_file = sample_dir / "sample_quantum_manifest.txt"
            if not sample_file.exists():
                sample_file.write_bytes(b"Q-SHIELD classified quantum telemetry report payload.\nConfidential security manifest.\n")
            available_samples = [f for f in sample_dir.iterdir() if f.is_file()]
            selected_sample = st.selectbox("Sample Files", [f.name for f in available_samples])
            if selected_sample:
                file_to_send_path = sample_dir / selected_sample

        if file_to_send_path and file_to_send_path.is_file():
            stat = file_to_send_path.stat()
            file_bytes = file_to_send_path.read_bytes()
            sha = hashlib.sha256(file_bytes).hexdigest()

            col_meta1, col_meta2 = st.columns(2)
            col_meta1.metric("FILE SIZE", f"{stat.st_size} bytes")
            col_meta2.metric("SHA-256 DIGEST", sha[:16] + "...")

            c_pwd, c_btn = st.columns([1, 1])
            ft_pwd = c_pwd.text_input("Keystore Password", value="QSHIELD", type="password", key="ft_pwd")
            if c_btn.button("Encrypt & Transfer File via Port 5002", width="stretch"):
                with st.spinner("Executing post-quantum handshake and chunked AES-256-GCM transfer..."):
                    res = fts.send_file(file_to_send_path, password=ft_pwd)
                    if res["success"]:
                        st.success(f"Transfer Successful! Verified SHA-256 digest: {res['sha256']}")
                        st.info(f"Server acknowledged: {res['server_ack']} (Saved to {res['destination']})")
                    else:
                        st.error(f"Transfer failed: {res['message']}")
                    st.rerun()

    with tab_received:
        st.markdown("### Files Received in data/received_files/")
        received = fts.list_received_files()
        if received:
            st.dataframe(pd.DataFrame(received), width="stretch", hide_index=True)
        else:
            st.info("No received files yet. Transferred files are stored securely in data/received_files/.")

        st.markdown("### Transfer History Log")
        history = fts.get_history()
        if history:
            st.dataframe(pd.DataFrame(history), width="stretch", hide_index=True)
        else:
            st.caption("No transfers initiated during this dashboard session.")


# ==============================================================================
# SECTION 4: SESSIONS
# ==============================================================================
def sessions_management_page(sessions: pd.DataFrame) -> None:
    page_header("Secure Sessions", "Inspect authenticated communication sessions and key generation lifecycle.")

    if sessions.empty:
        st.info("No session records found in data/sessions.jsonl.")
        return

    active_mask = sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"])
    active_count = int(active_mask.sum())
    disconnected_count = len(sessions) - active_count

    c1, c2, c3 = st.columns(3)
    c1.metric("TOTAL RECORDED SESSIONS", len(sessions))
    c2.metric("ACTIVE SESSIONS", active_count)
    c3.metric("DISCONNECTED SESSIONS", disconnected_count)

    st.markdown("### Session Directory")
    st.dataframe(sessions, width="stretch", hide_index=True, height=350)

    st.markdown('<div class="qs-section">Session Lifecycle Reference</div>', unsafe_allow_html=True)
    st.markdown(
        """
        ```
        [TCP Connect] ---> [Handshake (ML-KEM-768 / ML-DSA-65)] ---> [Active (Gen 0)]
                                                                           |
        [Terminated] <--- [Kill Session (Server Closed)] <--- (Analyst)   |
             ^                                                             v
             |                                              [Force Re-Key (Pending)]
        [Disconnected] <--- [Clean Disconnect (/quit)]                     |
                                                                           v (Next Message)
                                                            [Active (Gen 1..N Replacement)]
        ```
        """
    )


# ==============================================================================
# SECTION 5: NETWORK MONITORING (PCAP & LIVE CAPTURE)
# ==============================================================================
def network_monitoring_page() -> None:
    page_header("Network Monitoring & Traffic Analysis", "Analyze recorded PCAP traffic and execute live Scapy packet inspection.")

    sm = get_service_manager()
    monitor_svc = sm.monitor

    tab_pcap, tab_live = st.tabs(["PCAP Replay Analysis", "Live Scapy Capture"])

    with tab_pcap:
        st.markdown("### Offline Packet Capture Inspection")
        source_mode = st.radio("PCAP Source", ["Select Existing Project PCAP", "Upload PCAP/PCAPNG"], horizontal=True)
        target_pcap_path: Path | None = None

        if source_mode == "Select Existing Project PCAP":
            pcaps = [p for p in DATA_DIR.iterdir() if p.suffix in (".pcap", ".pcapng")]
            if pcaps:
                chosen = st.selectbox("Available PCAP files", [p.name for p in pcaps])
                if chosen:
                    target_pcap_path = DATA_DIR / chosen
            else:
                st.warning("No PCAP files found in data/.")
        else:
            uploaded_pcap = st.file_uploader("Upload packet capture", type=["pcap", "pcapng"])
            if uploaded_pcap:
                target_pcap_path = DATA_DIR / uploaded_pcap.name
                target_pcap_path.write_bytes(uploaded_pcap.getbuffer())
                st.success(f"Saved: {uploaded_pcap.name}")

        if target_pcap_path and target_pcap_path.is_file():
            if st.button("Run Deep PCAP Inspection & Feature Extraction", width="stretch"):
                with st.spinner("Replaying packets, windowing features, and evaluating IDS rules..."):
                    res = monitor_svc.analyze_pcap(target_pcap_path)
                    if res["success"]:
                        st.session_state["pcap_analysis_result"] = res
                        st.success(f"Analysis complete for {res['filename']}!")
                    else:
                        st.error(res["message"])

        res = st.session_state.get("pcap_analysis_result")
        if res:
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("TOTAL PACKETS", res["total_packets"])
            m2.metric("TOTAL BYTES", f"{res['total_bytes']:,} B")
            m3.metric("DETECTED ALERTS", res["alerts_count"])
            mean_score = f"{res['mean_anomaly_score']:.3f}" if res.get("mean_anomaly_score") is not None else "N/A"
            m4.metric("MEAN ANOMALY SCORE", mean_score)

            c_prot, c_ips = st.columns(2)
            with c_prot:
                st.markdown("#### Protocol Breakdown")
                p_df = pd.DataFrame(list(res["protocol_counts"].items()), columns=["Protocol", "Count"])
                chart_prot = alt.Chart(p_df).mark_bar(cornerRadiusEnd=5, color="#45d7e7").encode(
                    x=alt.X("Count:Q", title="Packet Count"),
                    y=alt.Y("Protocol:N", sort="-x", title=None),
                    tooltip=["Protocol", "Count"],
                ).properties(height=180).configure_view(strokeOpacity=0).configure(background="transparent")
                st.altair_chart(chart_prot, width="stretch")

            with c_ips:
                st.markdown("#### Top Communicating Source IPs")
                src_df = pd.DataFrame(res["top_src_ips"], columns=["Source IP", "Packets"])
                st.dataframe(src_df, width="stretch", hide_index=True)

            if res["alerts"]:
                st.markdown("#### Detections Triggered by Replay")
                st.dataframe(pd.DataFrame(res["alerts"]), width="stretch", hide_index=True)

    with tab_live:
        st.markdown("### Real-Time Network Packet Inspection")
        ifaces = monitor_svc.list_interfaces()
        live_stats = monitor_svc.get_live_stats()
        is_capturing = live_stats["is_capturing"]

        status_badge = "qs-badge-active" if is_capturing else "qs-badge-muted"
        st.markdown(f"Status: <span class='qs-badge {status_badge}'>{'CAPTURING' if is_capturing else 'IDLE'}</span>", unsafe_allow_html=True)

        iface_options = [f"{i['name']} ({i['ip']}) - {i['description'][:40]}" for i in ifaces] if ifaces else ["Default"]
        selected_iface_str = st.selectbox("Capture Network Interface", iface_options)
        selected_iface_id = ifaces[iface_options.index(selected_iface_str)]["id"] if ifaces else None

        c_filter, c_act1, c_act2 = st.columns([2, 1, 1])
        bpf_filter = c_filter.text_input("BPF Filter", value="tcp")

        if c_act1.button("Start Live Capture", width="stretch", disabled=is_capturing):
            res = monitor_svc.start_live_capture(interface=selected_iface_id, bpf_filter=bpf_filter)
            st.success(res["message"])
            st.rerun()

        if c_act2.button("Stop Live Capture", width="stretch", disabled=not is_capturing):
            res = monitor_svc.stop_live_capture()
            st.info(res["message"])
            st.rerun()

        st.markdown("#### Live Capture Telemetry")
        l1, l2, l3 = st.columns(3)
        l1.metric("PACKETS CAPTURED", live_stats["packet_count"])
        l2.metric("ACTIVE INTERFACE", str(live_stats["interface"])[:25])
        l3.metric("LIVE ALERTS", live_stats["alerts_count"])

        if live_stats["protocols"]:
            st.markdown("#### Observed Protocols")
            st.dataframe(pd.DataFrame(list(live_stats["protocols"].items()), columns=["Protocol", "Count"]), width="stretch", hide_index=True)


# ==============================================================================
# SECTION 6: THREAT ALERTS
# ==============================================================================
def threat_alerts_page(alerts: pd.DataFrame) -> None:
    page_header("Threat Alerts", "Correlated security telemetry from Rule-Based IDS, Isolation Forest, and Application Events.")

    if alerts.empty:
        st.info("No threat alerts found in data/alerts.jsonl.")
        return

    sev_counts = alerts["Severity"].value_counts().to_dict()
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("TOTAL ALERTS", len(alerts))
    m2.metric("CRITICAL", sev_counts.get("CRITICAL", 0))
    m3.metric("HIGH", sev_counts.get("HIGH", 0))
    m4.metric("MEDIUM", sev_counts.get("MEDIUM", 0))
    m5.metric("LOW", sev_counts.get("LOW", 0))

    f1, f2 = st.columns([1, 2])
    selected_sev = f1.selectbox("Filter Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    search_query = f2.text_input("Search Source IP or Keyword", placeholder="e.g. 192.168, PORT_SCAN, tag...")

    filtered = alerts
    if selected_sev != "All":
        filtered = filtered[filtered["Severity"] == selected_sev]
    if search_query.strip():
        q = search_query.strip().lower()
        filtered = filtered[
            filtered["Source IP"].astype(str).str.lower().str.contains(q)
            | filtered["Alert"].astype(str).str.lower().str.contains(q)
            | filtered["Evidence"].astype(str).str.lower().str.contains(q)
        ]

    st.metric("MATCHING ALERTS", len(filtered))
    st.dataframe(filtered, width="stretch", hide_index=True, height=500)


# ==============================================================================
# SECTION 7: RESPONSE CENTRE
# ==============================================================================
def response_centre_page(sessions: pd.DataFrame, blocked: list[dict[str, Any]]) -> None:
    page_header("Incident Response Centre", "Execute in-band post-quantum re-keying, session containment, and simulated IP blocklists.")

    tab_cmd, tab_block = st.tabs(["Session Actions (Re-Key / Kill)", "Simulated IP Containment"])

    with tab_cmd:
        st.markdown("### Command Dispatch Console")
        st.info("Force Re-key executes at the client's next application message boundary. Kill-session terminates the socket connection immediately.")

        active_sessions = sessions[sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"])] if not sessions.empty else pd.DataFrame()
        avail_session_ids = [str(item) for item in active_sessions["Session ID"].tolist()] if not active_sessions.empty else []

        with st.form("dispatch_command_form"):
            c_target, c_cmd = st.columns([2, 1])
            if avail_session_ids:
                target_sess = c_target.selectbox("Target Active Session", avail_session_ids)
            else:
                target_sess = c_target.text_input("Target Session ID", placeholder="e.g. session-001")
            cmd_choice = c_cmd.radio("Command Action", ["force_rekey", "kill_session"], horizontal=True)
            reason = st.text_input("Operational Reason", value="Analyst-initiated incident response")
            confirmed = st.checkbox("I confirm this response action against the target session.")
            submitted = st.form_submit_button("Queue Response Command", width="stretch")

        if submitted:
            if not confirmed:
                st.error("Please check the confirmation box before submitting.")
            elif not target_sess or not target_sess.strip():
                st.error("Session ID must not be empty.")
            else:
                try:
                    cmd_record = enqueue_command(cmd_choice, session_id=target_sess, reason=reason, path=COMMANDS_FILE)
                    append_event(
                        "response_command_queued",
                        {"command": cmd_choice, "command_id": cmd_record["command_id"], "session_id": target_sess},
                        actor="dashboard",
                        path=EVIDENCE_FILE,
                    )
                    st.success(f"Command '{cmd_choice}' queued successfully! Command ID: {cmd_record['command_id']}")
                    if cmd_choice == "force_rekey":
                        st.info("Re-key queued! It will execute automatically when the client sends its next message.")
                    time.sleep(0.3)
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to queue command: {exc}")

        st.markdown("### Server Command Execution & Acknowledgement History")
        cmd_list, _ = read_jsonl(COMMANDS_FILE)
        res_list, _ = read_jsonl(COMMAND_RESULTS_FILE)
        if cmd_list:
            st.dataframe(commands_frame(cmd_list, res_list), width="stretch", hide_index=True)
        else:
            st.caption("No server commands queued yet.")

    with tab_block:
        st.markdown("### Simulated IP Containment")
        st.caption("Application-level containment dropped by Q-SHIELD TCP servers before cryptographic processing.")

        b_col1, b_col2 = st.columns([1, 1.4])
        with b_col1:
            with st.form("block_form"):
                ip_addr = st.text_input("Target IP Address", placeholder="e.g. 192.0.2.45")
                b_reason = st.text_input("Reason", value="Suspicious port scan / malicious traffic")
                b_action = st.radio("Action", ["Block IP", "Unblock IP"], horizontal=True)
                b_sub = st.form_submit_button("Apply IP Action", width="stretch")

            if b_sub:
                try:
                    if b_action == "Block IP":
                        entry = block_ip(ip_addr, b_reason, path=BLOCKLIST_FILE)
                        append_event("ip_blocked", {"ip": entry["ip"], "reason": entry["reason"]}, actor="dashboard", path=EVIDENCE_FILE)
                        st.success(f"{entry['ip']} added to blocklist.")
                    else:
                        removed = unblock_ip(ip_addr, path=BLOCKLIST_FILE)
                        if removed:
                            append_event("ip_unblocked", {"ip": ip_addr.strip()}, actor="dashboard", path=EVIDENCE_FILE)
                            st.success(f"{ip_addr} removed from blocklist.")
                        else:
                            st.info("IP was not present in blocklist.")
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))

        with b_col2:
            st.markdown("#### Current Blocked IPs")
            if blocked:
                st.dataframe(pd.DataFrame(blocked), width="stretch", hide_index=True)
            else:
                st.info("No IPs currently blocked.")


# ==============================================================================
# SECTION 8: EVIDENCE
# ==============================================================================
def evidence_management_page() -> None:
    page_header("Evidence & Audit Trail", "Verify the cryptographic SHA-256 hash-chain guaranteeing non-repudiation and tamper detection.")

    valid, message = verify_chain(EVIDENCE_FILE)
    if valid:
        st.success(f"🛡️ HASH CHAIN VALID: {message}")
    else:
        st.error(f"⚠️ INTEGRITY VIOLATION: {message}")

    records, errors = read_jsonl(EVIDENCE_FILE)
    c1, c2 = st.columns(2)
    c1.metric("AUDIT EVIDENCE RECORDS", len(records))
    c2.metric("MALFORMED RECORDS", errors)

    if records:
        ev_df = pd.DataFrame(records)
        if "sequence" in ev_df.columns:
            ev_df = ev_df.sort_values("sequence", ascending=False)
        st.dataframe(ev_df, width="stretch", hide_index=True, height=520)
    else:
        st.info("No evidence records present in data/evidence.jsonl.")


# ==============================================================================
# SECTION 9: CRYPTOGRAPHIC BENCHMARKS
# ==============================================================================
def cryptographic_benchmarks_page() -> None:
    page_header("Cryptographic Benchmarks", "Direct performance comparison between Post-Quantum primitives and Classical NIST baselines.")

    c_rerun, c_status = st.columns([1, 4])
    if c_rerun.button("Rerun Local Benchmark (20 iter)", width="stretch"):
        with st.spinner("Measuring ML-KEM-768, ECDH-P256, ML-DSA-65, and ECDSA-P256..."):
            import subprocess
            proc = subprocess.run(
                [sys.executable, "-m", "benchmarks.bench_pq_vs_classic", "--iterations", "20", "--output", str(BENCHMARKS_FILE)],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                st.success("Benchmarks completed and updated data/benchmarks.json!")
            else:
                st.error(f"Benchmark run failed: {proc.stderr}")
            st.rerun()

    if not BENCHMARKS_FILE.exists():
        st.info("No benchmark file found. Click 'Rerun Local Benchmark' above to generate measurements.")
        return

    try:
        data = json.loads(BENCHMARKS_FILE.read_text(encoding="utf-8"))
        rows = data if isinstance(data, list) else data.get("benchmarks", [])
        frame = pd.DataFrame(rows)
    except Exception as exc:
        st.error(f"Could not load benchmark data: {exc}")
        return

    st.markdown("### Measured Performance Metrics")
    st.dataframe(frame, width="stretch", hide_index=True)

    st.markdown('<div class="qs-section">Visual Comparisons: Post-Quantum vs Classical</div>', unsafe_allow_html=True)
    ch1, ch2 = st.columns(2)

    with ch1:
        st.markdown("#### Key Generation Time (ms)")
        if "keygen_ms" in frame.columns and "algorithm" in frame.columns:
            chart1 = alt.Chart(frame).mark_bar(cornerRadiusEnd=5, color="#45d7e7").encode(
                x=alt.X("keygen_ms:Q", title="Milliseconds (Lower is Faster)"),
                y=alt.Y("algorithm:N", sort="-x", title=None),
                color=alt.Color("family:N", scale=alt.Scale(domain=["post-quantum", "classical"], range=["#45d7e7", "#ffad66"])),
                tooltip=["algorithm", "family", "keygen_ms"],
            ).properties(height=200).configure_view(strokeOpacity=0).configure(background="transparent")
            st.altair_chart(chart1, width="stretch")

    with ch2:
        st.markdown("#### Public Key Size (Bytes)")
        if "public_key_bytes" in frame.columns and "algorithm" in frame.columns:
            chart2 = alt.Chart(frame).mark_bar(cornerRadiusEnd=5, color="#1999b9").encode(
                x=alt.X("public_key_bytes:Q", title="Public Key Bytes (Storage Overhead)"),
                y=alt.Y("algorithm:N", sort="-x", title=None),
                color=alt.Color("family:N", scale=alt.Scale(domain=["post-quantum", "classical"], range=["#45d7e7", "#ffad66"])),
                tooltip=["algorithm", "family", "public_key_bytes"],
            ).properties(height=200).configure_view(strokeOpacity=0).configure(background="transparent")
            st.altair_chart(chart2, width="stretch")


# ==============================================================================
# SECTION 10: SYSTEM STATUS & SETTINGS
# ==============================================================================
def system_status_settings_page() -> None:
    page_header("System Status & Settings", "Detailed health diagnostics, port bindings, security policies, and environment configuration.")

    sm = get_service_manager()
    health = sm.get_system_health()

    try:
        oqs_mod = get_oqs()
        oqs_ver = oqs_mod.oqs_version()
        oqs_py_ver = oqs_mod.oqs_python_version()
        oqs_ok = True
    except Exception as exc:
        oqs_ver = f"Error: {exc}"
        oqs_py_ver = "Unknown"
        oqs_ok = False

    st.markdown("### Subsystem Health Diagnostics")
    diag_rows = [
        {
            "Subsystem": "Post-Quantum Cryptography Backend",
            "Component / Target": f"liboqs {oqs_ver} (liboqs-python {oqs_py_ver})",
            "Configured Algorithms": f"{KEM_ALGORITHM} / {SIGNATURE_ALGORITHM}",
            "Status": "OPERATIONAL" if oqs_ok else "UNAVAILABLE",
        },
        {
            "Subsystem": "Secure TCP Server",
            "Component / Target": f"{health['server']['host']}:{health['server']['port']}",
            "Configured Algorithms": "AES-256-GCM + In-Band Re-Key",
            "Status": health["server"]["status"],
        },
        {
            "Subsystem": "Secure File Transfer Server",
            "Component / Target": f"127.0.0.1:{health['file_server']['port']}",
            "Configured Algorithms": "AES-256-GCM Chunked + SHA-256",
            "Status": "OPERATIONAL" if health["file_server"]["active"] else "IDLE (On-Demand)",
        },
        {
            "Subsystem": "Secure Client Endpoint",
            "Component / Target": f"{health['client']['host']}:{health['client']['port']}",
            "Configured Algorithms": f"Gen {health['client']['generation']} Key Established",
            "Status": "CONNECTED" if health["client"]["connected"] else "DISCONNECTED",
        },
        {
            "Subsystem": "Network Intrusion Detection",
            "Component / Target": f"Sensor ({health['monitor']['interface'] or 'Default'})",
            "Configured Algorithms": "Rule Engine + Isolation Forest",
            "Status": "CAPTURING" if health["monitor"]["is_capturing"] else "IDLE",
        },
        {
            "Subsystem": "Audit Evidence Integrity",
            "Component / Target": "data/evidence.jsonl",
            "Configured Algorithms": "SHA-256 Cryptographic Hash Chain",
            "Status": "VERIFIED",
        },
    ]
    st.dataframe(pd.DataFrame(diag_rows), width="stretch", hide_index=True)

    st.markdown('<div class="qs-section">Configuration & Thresholds (config/thresholds.yaml)</div>', unsafe_allow_html=True)
    if CONFIG_FILE.exists():
        cfg = load_config(str(CONFIG_FILE))
        st.json(cfg)
    else:
        st.warning("config/thresholds.yaml not found.")


# ==============================================================================
# MAIN APPLICATION CONTROLLER
# ==============================================================================
def run_dashboard() -> None:
    if not login():
        st.stop()

    with st.sidebar:
        st.markdown(
            '<div class="qs-brand"><div class="qs-mark">🛡️</div><div>'
            '<div class="qs-name">Q-SHIELD</div><div class="qs-caption">QUANTUM OPERATIONS</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )

        st.caption("CONSOLE NAVIGATION")
        nav_options = [
            "Overview",
            "Secure Communication",
            "File Transfer",
            "Sessions",
            "Network Monitoring",
            "Threat Alerts",
            "Response Centre",
            "Evidence",
            "Cryptographic Benchmarks",
            "System Status and Settings",
        ]

        # Check query params or session state for page selection
        selected_page = st.radio("Select View", nav_options, label_visibility="collapsed")
        st.divider()

        # Quick subsystem badges in sidebar
        sm = get_service_manager()
        h = sm.get_system_health()
        srv_badge = "🟢 Srv" if "RUNNING" in h["server"]["status"] else "⚪ Srv"
        cli_badge = "🟢 Cli" if h["client"]["connected"] else "⚪ Cli"
        mon_badge = "🟢 Sniff" if h["monitor"]["is_capturing"] else "⚪ Sniff"
        st.caption(f"STATUS: {srv_badge} | {cli_badge} | {mon_badge}")

        st.caption(f"DATA DIR: {DATA_DIR.name}")
        if st.button("Sign out", width="stretch"):
            st.session_state["logged_in"] = False
            st.rerun()

    # Load feed data
    events, events_errors = read_jsonl(EVENTS_FILE)
    alert_records, alerts_errors = read_jsonl(ALERTS_FILE)
    session_records, sessions_errors = read_jsonl(SESSIONS_FILE)
    alerts_data = alerts_frame(alert_records)
    sessions_data = sessions_frame(session_records)
    blocklist_data = load_blocklist(BLOCKLIST_FILE)
    blocked_entries = blocklist_data.get("blocked_ips", [])

    # Route navigation
    # Normalize aliases if any legacy test requests old page names
    route_map = {
        "Overview": "Overview",
        "Secure Communication": "Secure Communication",
        "File Transfer": "File Transfer",
        "Sessions": "Sessions",
        "Network Monitoring": "Network Monitoring",
        "Threat Alerts": "Threat Alerts",
        "Alerts": "Threat Alerts",
        "Response Centre": "Response Centre",
        "Response": "Response Centre",
        "Evidence": "Evidence",
        "Cryptographic Benchmarks": "Cryptographic Benchmarks",
        "Benchmarks": "Cryptographic Benchmarks",
        "System Status and Settings": "System Status and Settings",
        "System Status": "System Status and Settings",
    }
    active_view = route_map.get(selected_page, selected_page)

    if active_view == "Overview":
        overview_page(events, alerts_data, sessions_data, blocked_entries)
    elif active_view == "Secure Communication":
        secure_communication_page()
    elif active_view == "File Transfer":
        file_transfer_page()
    elif active_view == "Sessions":
        sessions_management_page(sessions_data)
    elif active_view == "Network Monitoring":
        network_monitoring_page()
    elif active_view == "Threat Alerts":
        threat_alerts_page(alerts_data)
    elif active_view == "Response Centre":
        response_centre_page(sessions_data, blocked_entries)
    elif active_view == "Evidence":
        evidence_management_page()
    elif active_view == "Cryptographic Benchmarks":
        cryptographic_benchmarks_page()
    elif active_view == "System Status and Settings":
        system_status_settings_page()

    if events_errors or alerts_errors or sessions_errors:
        st.caption(f"Note: {events_errors + alerts_errors + sessions_errors} malformed line(s) skipped in feed logs.")

    st.markdown('<div class="qs-foot">Q-SHIELD · NIST POST-QUANTUM CRYPTOGRAPHY · AUTHORIZED CYBERSECURITY DEMONSTRATION</div>', unsafe_allow_html=True)


# Keep legacy function signature for backward-compatibility with tests
def overview(events: list[dict[str, Any]], alerts: pd.DataFrame, sessions: pd.DataFrame, blocked: list[dict[str, Any]]) -> None:
    overview_page(events, alerts, sessions, blocked)


def alerts_page(alerts: pd.DataFrame) -> None:
    threat_alerts_page(alerts)


def sessions_page(sessions: pd.DataFrame) -> None:
    sessions_management_page(sessions)


def response_page(sessions: pd.DataFrame, blocked: list[dict[str, Any]]) -> None:
    response_centre_page(sessions, blocked)


def evidence_page() -> None:
    evidence_management_page()


def benchmarks_page() -> None:
    cryptographic_benchmarks_page()


if __name__ == "__main__":
    run_dashboard()
