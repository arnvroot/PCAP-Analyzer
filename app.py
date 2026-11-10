"""
app.py
======
Offline Streamlit SOC/DFIR dashboard.

Just the entry point now -- each page lives in dashboard/pages/, the
pdf/csv export logic lives in dashboard/export/. This file only sets
up the sidebar and calls whichever page function is selected.

This app NEVER opens the pcap directly -- it only reads the small JSON
files produced by analyzer.py. Run analyzer.py first.

Usage:
    streamlit run app.py -- --datadir ./output
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from dashboard.data import load_json, DATADIR
from dashboard.export import build_pdf_bytes, build_csv_bytes
from dashboard.pages import (
    overview, protocol_analysis, top_talkers, conversations, port_analysis,
    dns_page, http_page, tls_page, credential_leaks, beacon_detection,
    port_scan, alerts_page, timeline_page, search_page,
)

st.set_page_config(page_title="Pcap Trace : Packet File Inspector", layout="wide", page_icon="📦")

st.sidebar.title("📦 Pcap Trace : Packet File Inspector")
st.sidebar.caption(f"Data source: `{DATADIR}`")

summary = load_json("summary.json")
if not summary:
    st.error(
        f"No summary.json found in `{DATADIR}`. Run analyzer.py first:\n\n"
        f"`python analyzer.py --pcap capture.pcap --outdir {DATADIR}`"
    )
    st.stop()

PAGES = [
    "Overview",
    "Alerts",
    "Credential Leaks",
    "Conversations",
    "Top Talkers",
    "DNS",
    "HTTP",
    "TLS",
    "Beacon Detection",
    "Port Analysis",
    "Port Scan Detection",
    "Timeline",
    "Protocol Analysis",
    "Search",
]
page = st.sidebar.radio("Navigate", PAGES)

st.sidebar.divider()
st.sidebar.metric("Total Packets", f"{summary.get('total_packets', 0):,}")
st.sidebar.metric("Total Bytes", f"{summary.get('total_bytes', 0) / 1024 / 1024:.1f} MB")
st.sidebar.metric("Alerts", summary.get("alert_count", 0))
if summary.get("interrupted_partial_results"):
    st.sidebar.warning("Analysis was interrupted — results are partial.")

st.sidebar.divider()
st.sidebar.subheader("Export Report")
pcap_stem = Path(summary.get("pcap_file", "capture")).stem

try:
    pdf_bytes = build_pdf_bytes()
    st.sidebar.download_button(
        "⬇ Download PDF report",
        data=pdf_bytes,
        file_name=f"{pcap_stem}_triage_report.pdf",
        mime="application/pdf",
        use_container_width=True,
    )
except Exception as exc:
    st.sidebar.error(f"PDF export failed: {exc}")

try:
    csv_bytes = build_csv_bytes()
    st.sidebar.download_button(
        "⬇ Download CSV (alerts)",
        data=csv_bytes,
        file_name=f"{pcap_stem}_alerts.csv",
        mime="text/csv",
        use_container_width=True,
    )
except Exception as exc:
    st.sidebar.error(f"CSV export failed: {exc}")

# route to whichever page is selected
if page == "Overview":
    overview.render(summary)
elif page == "Protocol Analysis":
    protocol_analysis.render()
elif page == "Top Talkers":
    top_talkers.render()
elif page == "Conversations":
    conversations.render()
elif page == "Port Analysis":
    port_analysis.render()
elif page == "DNS":
    dns_page.render()
elif page == "HTTP":
    http_page.render()
elif page == "TLS":
    tls_page.render()
elif page == "Credential Leaks":
    credential_leaks.render()
elif page == "Beacon Detection":
    beacon_detection.render()
elif page == "Port Scan Detection":
    port_scan.render()
elif page == "Alerts":
    alerts_page.render()
elif page == "Timeline":
    timeline_page.render()
elif page == "Search":
    search_page.render()
