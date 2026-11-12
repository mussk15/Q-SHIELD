from __future__ import annotations

import hmac
import json
import os
import socket
import subprocess
import sys
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

from response.blocklist import block_ip, load_blocklist, unblock_ip  # noqa: E402
from response.commands import enqueue_command  # noqa: E402
from response.evidence import append_event, verify_chain  # noqa: E402


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

st.set_page_config(
    page_title="Q-SHIELD | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
    :root { --bg:#07111f; --panel:#10243a; --line:#203a51; --cyan:#45d7e7; --muted:#94abc2; }
    html, body, [class*="css"] { font-family:Manrope,sans-serif; }
    .stApp { background:radial-gradient(ellipse at 75% 0%,rgba(25,130,155,.18),transparent 35%),#07111f; color:#f2f7ff; }
    [data-testid="stHeader"] { background:rgba(7,17,31,.82); }
    [data-testid="stMainBlockContainer"] { max-width:1500px; padding-top:1.8rem; padding-bottom:3rem; }
    [data-testid="stSidebar"] { background:linear-gradient(180deg,#0c1c2e,#071321); border-right:1px solid var(--line); }
    [data-testid="stMetric"] { background:linear-gradient(145deg,#122b43,#0c1d30); border:1px solid var(--line); border-radius:15px; padding:16px; min-height:112px; }
    [data-testid="stMetricLabel"] { color:#9bb1c8 !important; font-size:.75rem; font-weight:800; }
    [data-testid="stMetricValue"] { color:#fff !important; font-size:1.85rem; font-weight:850; }
    [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:12px; overflow:hidden; }
    .stButton > button,.stFormSubmitButton > button { background:linear-gradient(135deg,#117f94,#125d79); color:white; border:1px solid rgba(69,215,231,.3); border-radius:9px; font-weight:800; }
    .stButton > button:hover,.stFormSubmitButton > button:hover { color:white; border-color:var(--cyan); }
    .stTextInput input,.stTextArea textarea { background:#0b1b2c !important; color:white !important; border:1px solid var(--line) !important; border-radius:9px !important; }
    .qs-brand { display:flex; align-items:center; gap:12px; padding:8px 2px 22px; }
    .qs-mark { width:43px; height:43px; display:grid; place-items:center; border-radius:13px; background:linear-gradient(145deg,#62e6ed,#1999b9); color:#06121f; font-size:23px; font-weight:900; }
    .qs-name { color:white; font-size:1.12rem; font-weight:900; letter-spacing:.12em; }
    .qs-caption { color:#8da5bd; font-size:.63rem; letter-spacing:.1em; }
    .qs-kicker { color:var(--cyan); font-size:.68rem; letter-spacing:.15em; font-weight:800; text-transform:uppercase; }
    .qs-title { color:white; font-size:2.1rem; font-weight:900; letter-spacing:-.05em; margin:.35rem 0; }
    .qs-sub { color:var(--muted); font-size:.9rem; }
    .qs-hero { margin:18px 0 20px; padding:25px; border:1px solid rgba(69,215,231,.27); border-radius:18px; background:radial-gradient(circle at 90% 20%,rgba(69,215,231,.18),transparent 30%),linear-gradient(110deg,#102d45,#0d2034); }
    .qs-hero-title { color:white; font-size:1.55rem; font-weight:900; margin:.5rem 0; }
    .qs-hero-copy { color:#a8bdd1; max-width:850px; line-height:1.65; }
    .qs-chip { display:inline-block; margin-top:13px; padding:7px 11px; border:1px solid rgba(69,215,231,.28); border-radius:8px; color:#a2edf1; background:rgba(69,215,231,.1); font-size:.68rem; font-weight:800; }
    .qs-section { color:#edf5ff; font-size:1.05rem; font-weight:850; margin:25px 0 12px; }
    .qs-live { display:inline-block; padding:7px 11px; border-radius:30px; color:#8ce5bd; border:1px solid rgba(75,214,162,.3); background:rgba(75,214,162,.08); font-size:.68rem; font-weight:800; }
    .qs-foot { text-align:center; color:#7189a3; font-size:.68rem; padding-top:28px; }
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


def is_server_listening(host: str = "127.0.0.1", port: int = 5001) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def alerts_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [
        {
            "Time": value(row, "timestamp", "time", "created_at"),
            "Alert": value(
                row, "title", "type", "alert_type", "rule_id",
                "rule", "name", default="Security alert"
            ),
            "Source IP": value(row, "source_ip", "src_ip", "ip", "source"),
            "Severity": str(
                value(row, "severity", "priority", default="LOW")
            ).upper(),
            "Status": value(row, "status", "state", default="Open"),
            "Evidence": value(row, "description", "evidence", "details"),
        }
        for row in records
    ]

    return pd.DataFrame(
        rows,
        columns=[
            "Time", "Alert", "Source IP",
            "Severity", "Status", "Evidence"
        ],
    )


def sessions_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for row in records:
        sid = value(row, "session_id", "id", default="")
        remote_ip = value(row, "remote_ip", "source_ip", "ip", default="127.0.0.1")
        user = value(row, "user_id", "username", "user", default="unauthenticated")
        if user.lower() in ("verified-client", "verified client", "verified"):
            identity = "Verified client"
        elif user.lower() in ("unauthenticated", "unknown"):
            identity = "Unverified"
        else:
            identity = user

        raw_status = value(row, "status", "state", default="Unknown")
        if str(raw_status).lower() in ("active", "connected", "established"):
            status = "Active"
        elif str(raw_status).lower() in ("disconnected", "closed", "terminated"):
            status = "Disconnected"
        else:
            status = str(raw_status).title()

        gen = row.get("key_generation")
        if gen is not None:
            gen_str = f"Gen {gen}"
        else:
            gen_str = "Gen 0"

        started = value(row, "started_at", "timestamp", "created_at", default="")
        fingerprint = value(row, "key_fingerprint", "fingerprint", default="Not provided")

        rows.append({
            "Session ID": sid,
            "Client IP": remote_ip,
            "Identity": identity,
            "Status": status,
            "Key Generation": gen_str,
            "Started": started,
            # Legacy alias columns for backwards compatibility with test assertions
            "User": identity,
            "Remote IP": remote_ip,
            "Key fingerprint": fingerprint,
        })

    return pd.DataFrame(
        rows,
        columns=[
            "Session ID",
            "Client IP",
            "Identity",
            "Status",
            "Key Generation",
            "Started",
            "User",
            "Remote IP",
            "Key fingerprint",
        ],
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
        rows.append({
            "Command ID": cid[:8] + "..." if len(cid) > 12 else cid,
            "Target session": value(cmd, "session_id", default=""),
            "Command type": value(cmd, "command", default=""),
            "Queue timestamp": value(cmd, "timestamp", default=""),
            "Execution status": str(status).upper(),
            "Server response / Reason": message,
        })
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
        st.markdown('<div class="qs-kicker">Q-SHIELD / SECURITY OPERATIONS</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="qs-title">{title}</div><div class="qs-sub">{subtitle}</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div style="text-align:right;padding-top:18px"><span class="qs-live">● LOCAL CONSOLE</span></div>', unsafe_allow_html=True)


def login() -> bool:
    expected_username = os.getenv("QSHIELD_DASHBOARD_USERNAME", "analyst")
    expected_password = os.getenv("QSHIELD_DASHBOARD_PASSWORD", "")
    if not expected_password or expected_password.startswith("replace-with-"):
        st.error("Configure QSHIELD_DASHBOARD_PASSWORD in your .env file before starting the dashboard.")
        st.code("QSHIELD_DASHBOARD_USERNAME=analyst\nQSHIELD_DASHBOARD_PASSWORD=choose-your-own-strong-password\nQSHIELD_DATA_DIR=data")
        st.stop()
    if st.session_state.get("logged_in", False):
        return True

    st.markdown(
        '<div class="qs-hero"><div class="qs-kicker">SECURITY OPERATIONS CONSOLE</div>'
        '<div class="qs-hero-title">Welcome to Q-SHIELD</div>'
        '<div class="qs-hero-copy">Sign in to review security alerts, monitor secure sessions and coordinate incident response.</div>'
        '<span class="qs-chip">ML-KEM · ML-DSA · AES-256-GCM · IDS</span></div>',
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
    st.caption("Local classroom prototype only; this is not production-grade authentication.")
    return False


# -------------------- 1. OVERVIEW PAGE --------------------
def overview(events: list[dict[str, Any]], alerts: pd.DataFrame, sessions: pd.DataFrame, blocked: list[dict[str, Any]]) -> None:
    server_online = is_server_listening()
    server_status = "ONLINE (Port 5001)" if server_online else "OFFLINE"

    open_count = 0
    critical_count = 0
    if not alerts.empty:
        open_count = int((~alerts["Status"].astype(str).str.lower().isin(["closed", "resolved"])).sum())
        critical_count = int((alerts["Severity"] == "CRITICAL").sum())

    active_count = 0
    if not sessions.empty:
        active_count = int(sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"]).sum())
    total_sessions = len(sessions)

    valid_evidence, evidence_msg = verify_chain(EVIDENCE_FILE)
    evidence_status = "VALID" if valid_evidence else "TAMPERED"

    st.markdown(
        '<div class="qs-hero"><div class="qs-kicker">POST-QUANTUM DEFENCE · LIVE MONITORING</div>'
        '<div class="qs-hero-title">Q-SHIELD Security Operations Overview</div>'
        '<div class="qs-hero-copy">Monitor real-time backend state, post-quantum terminal sessions, network intrusion alerts and auditable response evidence.</div>'
        '<span class="qs-chip">ML-KEM-768 · ML-DSA-65 · AES-256-GCM · Dual IDS</span></div>',
        unsafe_allow_html=True,
    )

    cards = st.columns(6)
    cards[0].metric("SERVER STATUS", server_status)
    cards[1].metric("ACTIVE SESSIONS", active_count)
    cards[2].metric("TOTAL SESSIONS", total_sessions)
    cards[3].metric("OPEN ALERTS", open_count)
    cards[4].metric("CRITICAL ALERTS", critical_count)
    cards[5].metric("EVIDENCE INTEGRITY", evidence_status)

    st.markdown('<div class="qs-section">Network Intelligence & Detections</div>', unsafe_allow_html=True)
    left, right = st.columns([1.5, 1])
    with left:
        st.markdown("### Recent Activity Feed")
        timeline = []
        for row in events:
            timestamp = pd.to_datetime(value(row, "timestamp", "time", "created_at"), utc=True, errors="coerce")
            if pd.notna(timestamp):
                timeline.append({"Time": timestamp.floor("min"), "Events": 1})
        if timeline:
            chart_data = pd.DataFrame(timeline).groupby("Time", as_index=False).sum().sort_values("Time")
            chart = alt.Chart(chart_data).mark_area(
                line={"color": "#45d7e7", "strokeWidth": 2}, color="#1b7185", opacity=0.35
            ).encode(
                x=alt.X("Time:T", title=None, axis=alt.Axis(labelColor="#8da5bd", grid=False)),
                y=alt.Y("Events:Q", title="Events per minute", axis=alt.Axis(labelColor="#8da5bd", gridColor="#20384e")),
                tooltip=["Time:T", "Events:Q"],
            ).properties(height=260).configure_view(strokeOpacity=0).configure(background="transparent")
            st.altair_chart(chart, width="stretch")
        else:
            st.info("Waiting for timestamped server events in data/events.jsonl.")

    with right:
        st.markdown("### Threat Severity Distribution")
        if not alerts.empty:
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            counts = alerts["Severity"].value_counts().reindex(order, fill_value=0).rename_axis("Severity").reset_index(name="Count")
            chart = alt.Chart(counts).mark_bar(cornerRadiusEnd=5).encode(
                x=alt.X("Count:Q", title=None, axis=alt.Axis(labelColor="#8da5bd", gridColor="#20384e")),
                y=alt.Y("Severity:N", sort=order, title=None, axis=alt.Axis(labelColor="#d3e1ef")),
                color=alt.Color("Severity:N", scale=alt.Scale(domain=order, range=["#ff647c", "#ffad66", "#e6d26a", "#4bd6a2"]), legend=None),
                tooltip=["Severity", "Count"],
            ).properties(height=260).configure_view(strokeOpacity=0).configure(background="transparent")
            st.altair_chart(chart, width="stretch")
        else:
            st.info("No IDS alerts available yet.")

    st.markdown('<div class="qs-section">Latest Security Events</div>', unsafe_allow_html=True)
    if events:
        events_df = pd.DataFrame([
            {
                "Time": value(e, "timestamp", "time", "created_at"),
                "Event Type": value(e, "event_type", "type"),
                "Source IP": value(e, "source_ip", "ip", default="127.0.0.1"),
                "Status": value(e, "status", default="INFO"),
                "Details": value(e, "details", "message", default=""),
            }
            for e in reversed(events[-8:])
        ])
        st.dataframe(events_df, width="stretch", hide_index=True)
    else:
        st.info("No security events recorded in data/events.jsonl yet.")


# -------------------- 2. THREAT ALERTS PAGE --------------------
def alerts_page(alerts: pd.DataFrame) -> None:
    page_header("Threat Alerts", "Review detections, severity levels and supporting evidence from dual IDS engines.")
    if alerts.empty:
        st.info("No alerts are available yet. Run the IDS sensor or PCAP replay to inspect traffic.")
        return

    filter_cols = st.columns([1, 2])
    with filter_cols[0]:
        selected = st.selectbox("Filter by severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with filter_cols[1]:
        search_query = st.text_input("Search alert description or source IP", placeholder="e.g. port scan, 127.0.0.1")

    filtered = alerts.copy()
    if selected != "All":
        filtered = filtered[filtered["Severity"] == selected]
    if search_query.strip():
        q = search_query.strip().lower()
        filtered = filtered[
            filtered["Alert"].str.lower().str.contains(q, na=False)
            | filtered["Source IP"].str.lower().str.contains(q, na=False)
            | filtered["Evidence"].str.lower().str.contains(q, na=False)
        ]

    st.metric("MATCHING ALERTS", len(filtered))
    st.dataframe(filtered, width="stretch", hide_index=True, height=500)


# -------------------- 3. SESSIONS PAGE --------------------
def sessions_page(sessions: pd.DataFrame) -> None:
    page_header("Secure Sessions", "Review actual active and historical terminal sessions without exposing key material.")
    if sessions.empty:
        st.info("No session records found in data/sessions.jsonl. Start the server and client to create active sessions.")
        return

    active = int(sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"]).sum())
    disconnected = len(sessions) - active

    col1, col2, col3 = st.columns(3)
    col1.metric("TOTAL SESSIONS", len(sessions))
    col2.metric("ACTIVE SESSIONS", active)
    col3.metric("DISCONNECTED SESSIONS", disconnected)

    # Filter selector
    filter_choice = st.radio("Session filter", ["All", "Active Only", "Disconnected Only"], horizontal=True)
    display_df = sessions.copy()
    if filter_choice == "Active Only":
        display_df = display_df[display_df["Status"].astype(str).str.lower().isin(["active", "connected", "established"])]
    elif filter_choice == "Disconnected Only":
        display_df = display_df[~display_df["Status"].astype(str).str.lower().isin(["active", "connected", "established"])]

    # Display exact requested table headers: Session ID | Client IP | Identity | Status | Key Generation | Started
    view_cols = ["Session ID", "Client IP", "Identity", "Status", "Key Generation", "Started"]
    st.dataframe(
        display_df[view_cols],
        width="stretch",
        hide_index=True,
        height=480,
    )


# -------------------- 4. RESPONSE CENTRE PAGE --------------------
def response_page(sessions: pd.DataFrame, blocked: list[dict[str, Any]]) -> None:
    page_header("Response Centre", "Apply simulated IP containment and dispatch authenticated session commands.")
    st.warning("IP containment is an application-level filter maintained in data/blocklist.json. Kill-session and Force-rekey commands are processed and executed asynchronously by the secure server.")
    tab_ip, tab_session = st.tabs(["IP Containment", "Session Commands"])

    with tab_ip:
        left, right = st.columns(2)
        with left:
            with st.form("ip_action_form"):
                ip = st.text_input("IP address", placeholder="192.0.2.10")
                reason = st.text_input("Reason", value="Suspicious activity detected by IDS")
                action = st.radio("Action", ["Block IP", "Unblock IP"], horizontal=True)
                submitted = st.form_submit_button("Apply Action", width="stretch")
            if submitted:
                try:
                    if action == "Block IP":
                        entry = block_ip(ip, reason, path=BLOCKLIST_FILE)
                        append_event("ip_blocked", {"ip": entry["ip"], "reason": entry["reason"]}, actor="dashboard", path=EVIDENCE_FILE)
                        st.success(f"{entry['ip']} added to simulated blocklist.")
                    else:
                        removed = unblock_ip(ip, path=BLOCKLIST_FILE)
                        if removed:
                            append_event("ip_unblocked", {"ip": ip.strip()}, actor="dashboard", path=EVIDENCE_FILE)
                            st.success("IP removed from simulated blocklist.")
                        else:
                            st.info("IP was not present in the blocklist.")
                    st.rerun()
                except (ValueError, RuntimeError, OSError) as exc:
                    st.error(str(exc))
        with right:
            st.markdown("### Active Simulated Blocklist")
            if blocked:
                st.dataframe(pd.DataFrame(blocked), width="stretch", hide_index=True)
            else:
                st.info("No IPs blocked currently.")

    with tab_session:
        # Populate session dropdown with actual active sessions if available
        active_mask = sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"]) if not sessions.empty else []
        active_sids = sessions[active_mask]["Session ID"].dropna().astype(str).tolist() if not sessions.empty else []
        all_sids = sessions["Session ID"].dropna().astype(str).tolist() if not sessions.empty else []

        with st.form("session_command_form"):
            if active_sids:
                session_id = st.selectbox("Target session (Active)", active_sids)
            elif all_sids:
                session_id = st.selectbox("Target session (Historical)", all_sids)
            else:
                session_id = st.text_input("Target session ID", placeholder="e.g. live-session-1234")
            command_label = st.radio("Command type", ["Force re-key", "Kill session"], horizontal=True)
            reason = st.text_input("Command reason", value="Analyst-initiated incident response")
            submitted = st.form_submit_button("Queue Server Command", width="stretch")

        if submitted:
            try:
                command = "force_rekey" if command_label == "Force re-key" else "kill_session"
                item = enqueue_command(command, session_id=session_id.strip(), reason=reason.strip(), path=COMMANDS_FILE)
                append_event("response_command_queued", {"command": command, "command_id": item["command_id"], "session_id": session_id.strip()}, actor="dashboard", path=EVIDENCE_FILE)
                st.success(f"{command_label} request queued for session '{session_id.strip()}'.")
                st.info("Status: QUEUED. The secure server will execute the authenticated re-key at the next client message boundary, or terminate the socket immediately for kill-session.")
            except (ValueError, OSError, RuntimeError) as exc:
                st.error(str(exc))

        st.markdown("### Server Command History & Acknowledgements")
        commands_list, _ = read_jsonl(COMMANDS_FILE)
        results_list, _ = read_jsonl(COMMAND_RESULTS_FILE)
        if commands_list:
            st.dataframe(commands_frame(commands_list, results_list), width="stretch", hide_index=True)
        else:
            st.info("No server commands queued yet.")


# -------------------- 5. EVIDENCE PAGE --------------------
def evidence_page() -> None:
    page_header("Evidence Integrity", "Verify the SHA-256 hash chain for incident response audit records.")
    valid, message = verify_chain(EVIDENCE_FILE)
    if valid:
        st.success(message)
    else:
        st.error(message)

    records, errors = read_jsonl(EVIDENCE_FILE)
    col1, col2 = st.columns(2)
    col1.metric("EVIDENCE RECORDS", len(records))
    col2.metric("MALFORMED JSON LINES", errors)

    if records:
        frame = pd.DataFrame(records)
        if "sequence" in frame.columns:
            frame = frame.sort_values("sequence", ascending=False)
        st.dataframe(frame, width="stretch", hide_index=True, height=480)
    else:
        st.info("No evidence records found in data/evidence.jsonl.")
    st.caption("A cryptographic hash chain makes post-facto modification detectable when validated against previous event hashes.")


# -------------------- 6. CRYPTOGRAPHIC BENCHMARKS PAGE --------------------
def benchmarks_page() -> None:
    page_header("Cryptographic Benchmarks", "Display measured timings and byte sizes for Post-Quantum vs Classical algorithms.")

    if not BENCHMARKS_FILE.exists():
        st.info("No benchmark file found. Run: python -m benchmarks.bench_pq_vs_classic --iterations 20 --output data/benchmarks.json")
        return

    try:
        data = json.loads(BENCHMARKS_FILE.read_text(encoding="utf-8"))
        rows = data if isinstance(data, list) else data.get("benchmarks", [])
        frame = pd.DataFrame(rows)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        st.error(f"Could not read benchmark data: {exc}")
        return

    if frame.empty:
        st.info("Benchmark file is empty.")
        return

    st.dataframe(frame, width="stretch", hide_index=True)

    numeric = frame.select_dtypes(include="number").columns.tolist()
    label = next((col for col in ["algorithm", "name", "scheme"] if col in frame.columns), None)
    if numeric and label:
        metric = st.selectbox("Metric to chart", numeric)
        chart = alt.Chart(frame).mark_bar(cornerRadiusEnd=5, color="#45d7e7").encode(
            x=alt.X(f"{metric}:Q", title=metric),
            y=alt.Y(f"{label}:N", sort="-x", title=None),
            tooltip=[label, metric],
        ).properties(height=max(180, 42 * len(frame))).configure_view(strokeOpacity=0).configure(background="transparent")
        st.altair_chart(chart, width="stretch")

    st.divider()
    if st.button("Rerun Benchmarks Now (20 iterations)"):
        with st.spinner("Executing post-quantum vs classical benchmarks..."):
            try:
                res = subprocess.run(
                    [sys.executable, "-m", "benchmarks.bench_pq_vs_classic", "--iterations", "20", "--output", str(BENCHMARKS_FILE)],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    timeout=30,
                )
                if res.returncode == 0:
                    st.success("Benchmarks completed and updated successfully!")
                    st.rerun()
                else:
                    st.error(f"Benchmark run failed: {res.stderr}")
            except Exception as exc:
                st.error(f"Error running benchmark: {exc}")


# -------------------- APPLICATION ENTRY --------------------
def run_dashboard() -> None:
    if not login():
        st.stop()

    with st.sidebar:
        st.markdown(
            '<div class="qs-brand"><div class="qs-mark">盾</div><div>'
            '<div class="qs-name">Q-SHIELD</div><div class="qs-caption">QUANTUM SECURITY CONSOLE</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )
        st.caption("WORKSPACE")
        selected_page = st.radio(
            "Navigate",
            [
                "Overview",
                "Threat Alerts",
                "Sessions",
                "Response Centre",
                "Evidence",
                "Cryptographic Benchmarks",
            ],
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("DATA DIRECTORY")
        st.code(str(DATA_DIR), language=None)
        if st.button("Sign out", width="stretch"):
            st.session_state["logged_in"] = False
            st.rerun()

    events, events_errors = read_jsonl(EVENTS_FILE)
    alert_records, alerts_errors = read_jsonl(ALERTS_FILE)
    session_records, sessions_errors = read_jsonl(SESSIONS_FILE)
    alerts_data = alerts_frame(alert_records)
    sessions_data = sessions_frame(session_records)
    blocklist_data = load_blocklist(BLOCKLIST_FILE)
    blocked_entries = blocklist_data.get("blocked_ips", [])

    if selected_page == "Overview":
        overview(events, alerts_data, sessions_data, blocked_entries)
    elif selected_page in ("Threat Alerts", "Alerts"):
        alerts_page(alerts_data)
    elif selected_page == "Sessions":
        sessions_page(sessions_data)
    elif selected_page in ("Response Centre", "Response"):
        response_page(sessions_data, blocked_entries)
    elif selected_page == "Evidence":
        evidence_page()
    elif selected_page in ("Cryptographic Benchmarks", "Benchmarks"):
        benchmarks_page()

    if events_errors or alerts_errors or sessions_errors:
        st.warning(f"Malformed JSONL records skipped: events={events_errors}, alerts={alerts_errors}, sessions={sessions_errors}.")

    st.markdown('<div class="qs-foot">Q-SHIELD STUDENT PROTOTYPE · SYNTHETIC DATA · AUTHORISED LAB USE ONLY</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    run_dashboard()
