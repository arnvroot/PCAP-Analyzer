import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Packet Timeline")
    tl = load_json("timeline.json")
    pps = tl.get("packets_per_second", {})
    bps = tl.get("bytes_per_second", {})
    if pps:
        df = pd.DataFrame({"time": list(pps.keys()), "packets_per_sec": list(pps.values())})
        df["time"] = df["time"].astype(int)
        df["bytes_per_sec"] = df["time"].astype(str).map(bps).fillna(0)
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=df["time"], y=df["packets_per_sec"], name="Packets/sec"))
        fig.add_trace(go.Scatter(x=df["time"], y=df["bytes_per_sec"], name="Bytes/sec", yaxis="y2"))
        fig.update_layout(
            yaxis=dict(title="Packets/sec"),
            yaxis2=dict(title="Bytes/sec", overlaying="y", side="right"),
            title="Traffic Over Time",
        )
        st.plotly_chart(fig, use_container_width=True)

        mean_pps = df["packets_per_sec"].mean()
        spikes = df[df["packets_per_sec"] > mean_pps * 3]
        if not spikes.empty:
            st.subheader("Traffic Spikes (>3x average)")
            st.dataframe(spikes, use_container_width=True, hide_index=True)
    else:
        st.info("No timeline data available.")
