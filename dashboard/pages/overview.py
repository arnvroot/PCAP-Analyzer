import pandas as pd
import plotly.express as px
import streamlit as st

from ..data import load_json
from ..colors import severity_emoji


def render(summary: dict) -> None:
    st.title("Overview")
    stats = load_json("statistics.json")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Packets", f"{summary.get('total_packets', 0):,}")
    c2.metric("Total Bytes", f"{summary.get('total_bytes', 0)/1024/1024:.2f} MB")
    c3.metric("Duration (s)", f"{summary.get('duration_seconds', 0):.1f}")
    c4.metric("Flows", f"{summary.get('flow_count', 0):,}")

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Avg Packets/sec", f"{summary.get('avg_packets_per_sec', 0):.1f}")
    c6.metric("Avg Bytes/sec", f"{summary.get('avg_bytes_per_sec', 0):.1f}")
    c7.metric("Largest Packet", f"{stats.get('largest_packet', 0)} B")
    c8.metric("Smallest Packet", f"{stats.get('smallest_packet', 0)} B")

    dist = stats.get("packet_size_distribution", {})
    if dist:
        order = ["0-64", "64-128", "128-256", "256-512", "512-1024", "1024-1500", "1500+"]
        df = pd.DataFrame({"bucket": list(dist.keys()), "count": list(dist.values())})
        df["bucket"] = pd.Categorical(df["bucket"], categories=order, ordered=True)
        df = df.sort_values("bucket")
        fig = px.bar(df, x="bucket", y="count", title="Packet Size Distribution")
        st.plotly_chart(fig, use_container_width=True)

    alerts = load_json("alerts.json").get("alerts", [])
    if alerts:
        st.subheader("Recent Alerts")
        for a in alerts[:8]:
            st.write(f"{severity_emoji(a['severity'])} **{a['category']}** — {a['message']}")
