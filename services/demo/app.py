"""
services/demo/app.py
─────────────────────
Layer 4 + 5: Streamlit Dashboard — Varaksha V2
"Analyst View" with real-time risk feed, graph visualisation,
and accessible fraud alert panel.

Run:
    streamlit run services/demo/app.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import random
import sys
import time

import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services"))

from agents.agent03_accessible_alert import (  # noqa: E402
    FlaggedTransaction,
    generate_alert,
)
from graph.graph_agent import build_demo_graph, run_detection  # noqa: E402

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title  = "Varaksha V2 — Fraud Intelligence Dashboard",
    page_icon   = "🛡️",
    layout      = "wide",
    initial_sidebar_state = "expanded",
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]

VERDICT_COLOR = {"ALLOW": "#28a745", "FLAG": "#fd7e14", "BLOCK": "#dc3545"}
TYPOLOGY_COLOR = {
    "FAN_OUT": "#e74c3c",
    "FAN_IN" : "#e67e22",
    "CYCLE"  : "#9b59b6",
    "SCATTER": "#3498db",
}

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/e/e1/UPI-Logo-vector.svg/320px-UPI-Logo-vector.svg.png", width=120)
    st.title("Varaksha V2")
    st.caption("Privacy-Preserving UPI Fraud Intelligence")
    st.divider()
    st.subheader("⚙️ Demo Controls")
    auto_refresh   = st.toggle("Auto-refresh feed (3 s)", value=False)
    n_feed_rows    = st.slider("Feed rows to display", 5, 50, 15)
    risk_threshold = st.slider("FLAG threshold", 0.30, 0.70, 0.40, 0.05)
    block_threshold= st.slider("BLOCK threshold", 0.60, 0.95, 0.75, 0.05)
    st.divider()
    st.caption("🏛️ Inspired by Nasdaq Verafin + BIS Project Aurora")

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ Varaksha V2 — UPI Fraud Intelligence Dashboard")
st.caption("Real-time risk cache · Money-mule graph · Accessible multilingual alerts")

col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)

# ── Section 1: Real-Time Risk Cache Feed ─────────────────────────────────────
st.divider()
st.subheader("📡 Section 1: Real-Time Consortium Risk Cache (Layer 2 — Rust DashMap)")

st.info(
    "**Architecture note:** This panel simulates the response stream from the Rust gateway "
    "(port 8082). In a live deployment, each row below represents one `POST /v1/tx` "
    "response — sub-5 ms per lookup via DashMap.",
    icon="ℹ️",
)

@st.cache_data(ttl=3)
def _generate_feed(n: int, flag_thresh: float, block_thresh: float) -> pd.DataFrame:
    """Generate a simulated risk cache response feed."""
    rng = np.random.default_rng(int(time.time()) if True else 42)
    merchant_cats = ["FOOD", "TRAVEL", "ECOM", "UTILITY", "P2P", "GAMBLING"]
    records = []
    for _ in range(n):
        score   = float(rng.beta(1.5, 8) if rng.random() > 0.15 else rng.beta(6, 2))
        verdict = "BLOCK" if score >= block_thresh else "FLAG" if score >= flag_thresh else "ALLOW"
        records.append({
            "trace_id"          : hashlib.md5(str(rng.integers(1e9)).encode()).hexdigest()[:10],
            "vpa_hash"          : f"{_hash(str(rng.integers(1e9)))}…",
            "amount (INR)"      : round(float(rng.exponential(3000)), 2),
            "merchant_category" : rng.choice(merchant_cats),
            "risk_score"        : round(score, 4),
            "verdict"           : verdict,
            "latency_µs"        : int(rng.integers(200, 4800)),
        })
    return pd.DataFrame(records)

feed_df = _generate_feed(n_feed_rows, risk_threshold, block_threshold)

# KPIs
total      = len(feed_df)
n_block    = (feed_df["verdict"] == "BLOCK").sum()
n_flag     = (feed_df["verdict"] == "FLAG").sum()
avg_lat    = feed_df["latency_µs"].mean()

col_kpi1.metric("Transactions",  total)
col_kpi2.metric("🔴 BLOCKED",   n_block, delta=f"{100*n_block/total:.1f}%")
col_kpi3.metric("🟠 FLAGGED",   n_flag,  delta=f"{100*n_flag/total:.1f}%")
col_kpi4.metric("Avg Latency",   f"{avg_lat:.0f} µs", delta="< 5 000 µs target" if avg_lat < 5000 else "⚠️ over target")

def _color_verdict(val: str) -> str:
    return f"background-color: {VERDICT_COLOR.get(val, '')}22; color: {VERDICT_COLOR.get(val, 'black')}; font-weight: bold"

styled = feed_df.style.applymap(_color_verdict, subset=["verdict"])
st.dataframe(styled, use_container_width=True, height=350)

if auto_refresh:
    time.sleep(3)
    st.rerun()

st.download_button(
    "⬇️ Export feed CSV",
    feed_df.to_csv(index=False).encode(),
    file_name="varaksha_risk_feed.csv",
    mime="text/csv",
)

# ── Section 2: Money-Mule Network Graph ───────────────────────────────────────
st.divider()
st.subheader("🕸️ Section 2: Money-Mule Network (Layer 3 — NetworkX / BIS Aurora model)")

st.info(
    "This graph is built **asynchronously** — outside the payment path. "
    "Detected clusters are pushed to the Rust cache via `POST /v1/webhook/update_cache`. "
    "Typologies: **Fan-out** (disbursement), **Fan-in** (aggregation), **Cycle** (layering).",
    icon="ℹ️",
)

@st.cache_data(ttl=30)
def _get_graph_data() -> tuple[list, list, list]:
    G        = build_demo_graph()
    clusters = run_detection(G)
    flagged  = {n: c for c in clusters for n in c.nodes}

    # Build Plotly node-link layout
    pos = nx.spring_layout(G, seed=42, k=0.6)

    edge_x, edge_y = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    node_x, node_y, node_color, node_text, node_size = [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        cluster = flagged.get(node)
        if cluster:
            node_color.append(TYPOLOGY_COLOR.get(cluster.typology, "#e74c3c"))
            node_text.append(f"{node[:8]}…<br>{cluster.typology}<br>score={cluster.risk_score:.2f}")
            node_size.append(18)
        else:
            node_color.append("#95a5a6")
            node_text.append(f"{node[:8]}… (legit)")
            node_size.append(8)

    return (edge_x, edge_y), (node_x, node_y, node_color, node_text, node_size), clusters

(edge_x, edge_y), (node_x, node_y, node_color, node_text, node_size), clusters = _get_graph_data()

fig = go.Figure()
fig.add_trace(go.Scatter(
    x=edge_x, y=edge_y,
    mode="lines",
    line=dict(color="#bdc3c7", width=0.8),
    hoverinfo="none",
))
fig.add_trace(go.Scatter(
    x=node_x, y=node_y,
    mode="markers",
    marker=dict(size=node_size, color=node_color, line=dict(width=1, color="#2c3e50")),
    text=node_text,
    hovertemplate="%{text}<extra></extra>",
))
fig.update_layout(
    title       = "Transaction Network — flagged nodes coloured by typology",
    showlegend  = False,
    height      = 500,
    margin      = dict(l=10, r=10, t=40, b=10),
    plot_bgcolor= "#0e1117",
    paper_bgcolor="#0e1117",
    font        = dict(color="#ecf0f1"),
    xaxis       = dict(showgrid=False, zeroline=False, showticklabels=False),
    yaxis       = dict(showgrid=False, zeroline=False, showticklabels=False),
)
st.plotly_chart(fig, use_container_width=True)

# Cluster summary table
if clusters:
    cluster_df = pd.DataFrame([{
        "Typology"   : c.typology,
        "Nodes"      : len(c.nodes),
        "Edges"      : c.edge_count,
        "Risk Score" : round(c.risk_score, 3),
    } for c in clusters])
    st.dataframe(cluster_df, use_container_width=True, hide_index=True)

# Typology legend
legend_cols = st.columns(4)
for i, (typology, color) in enumerate(TYPOLOGY_COLOR.items()):
    legend_cols[i].markdown(
        f'<span style="color:{color}; font-weight:bold">■ {typology}</span>',
        unsafe_allow_html=True,
    )

# ── Section 3: Accessible Alert Panel ────────────────────────────────────────
st.divider()
st.subheader("🔔 Section 3: Accessible Alert — Mock-Bhashini Layer (Layer 4)")

st.info(
    "When a transaction is BLOCKED, the system generates a **court-ready English legal warning** "
    "(citing BNS/IT Act laws), translates it to **Hindi via Mock-Bhashini NMT**, and produces "
    "an **MP3 audio alert** using `edge-tts` Neural TTS (hi-IN-SwaraNeural voice).",
    icon="ℹ️",
)

col_alert1, col_alert2 = st.columns([1, 1])

with col_alert1:
    st.subheader("🎯 Simulate a Blocked Transaction")
    sim_vpa    = st.text_input("VPA (will be hashed)", value="attacker@ybl")
    sim_amount = st.number_input("Amount (INR)", value=175_000.0, step=1000.0)
    sim_cat    = st.selectbox("Merchant Category", ["P2P", "GAMBLING", "ECOM", "TRAVEL"])
    sim_score  = st.slider("Risk Score", 0.75, 1.00, 0.92, 0.01)
    sim_flags  = st.multiselect("Graph Flags", ["FAN_OUT", "FAN_IN", "CYCLE", "SCATTER"], default=["FAN_OUT", "CYCLE"])
    run_alert  = st.button("🚨 Generate Alert", type="primary")

with col_alert2:
    if run_alert:
        tx = FlaggedTransaction(
            transaction_id    = f"TXN-DEMO-{int(time.time())}",
            vpa_hash          = hashlib.sha256(sim_vpa.encode()).hexdigest(),
            amount_inr        = sim_amount,
            merchant_category = sim_cat,
            risk_score        = sim_score,
            graph_flags       = sim_flags,
        )
        with st.spinner("Generating multilingual alert…"):
            result = asyncio.run(generate_alert(tx))

        risk_label = "🔴 CRITICAL" if result.risk_level == "CRITICAL" else "🟠 HIGH"
        st.markdown(f"### {risk_label} — Transaction Blocked")

        st.markdown("**📄 English Warning (Court-Ready)**")
        st.warning(result.english_warning)

        st.markdown("**🇮🇳 Hindi Warning (Mock-Bhashini NMT)**")
        st.error(result.hindi_warning)

        st.markdown("**⚖️ Laws Cited**")
        for law in result.laws_cited:
            st.markdown(f"- `{law}`")

        if result.audio_path and result.audio_path.exists():
            st.markdown("**🔊 Audio Alert (edge-tts · hi-IN-SwaraNeural)**")
            with open(result.audio_path, "rb") as f:
                st.audio(f.read(), format="audio/mp3")
            st.caption(f"File: `{result.audio_path.name}`")
        else:
            st.caption("⚠️ Audio not generated — run `pip install edge-tts` to enable.")
    else:
        st.markdown(
            """
            **How it works:**
            1. Fill in the transaction details on the left.
            2. Click **Generate Alert**.
            3. The system will cite applicable Indian laws, translate to Hindi,
               and generate a spoken audio warning.

            > *"Security is useless if the victim doesn't understand the warning."*
            > — Varaksha V2 Design Brief
            """
        )

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.caption(
    "Varaksha V2 · Secure AI Software & Systems Hackathon · "
    "Blue Team: NPCI UPI Fraud Detection · "
    "Inspired by Nasdaq Verafin + BIS Project Aurora + Bhashini API"
)
