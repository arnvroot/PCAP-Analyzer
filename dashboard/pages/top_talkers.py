import pandas as pd
import plotly.express as px
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Top Talkers")
    flows = load_json("flows.json")
    talkers = flows.get("top_talkers", {})

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Top 10 Bytes Sent")
        d = talkers.get("bytes_sent", {})
        if d:
            df = pd.DataFrame({"ip": list(d.keys()), "bytes": list(d.values())}).sort_values("bytes", ascending=False)
            st.plotly_chart(px.bar(df, x="ip", y="bytes"), use_container_width=True)
        st.subheader("Top 10 Packets Sent")
        d = talkers.get("packets_sent", {})
        if d:
            df = pd.DataFrame({"ip": list(d.keys()), "packets": list(d.values())}).sort_values("packets", ascending=False)
            st.dataframe(df, use_container_width=True, hide_index=True)

    with col2:
        st.subheader("Top 10 Bytes Received")
        d = talkers.get("bytes_received", {})
        if d:
            df = pd.DataFrame({"ip": list(d.keys()), "bytes": list(d.values())}).sort_values("bytes", ascending=False)
            st.plotly_chart(px.bar(df, x="ip", y="bytes"), use_container_width=True)
        st.subheader("Top 10 Packets Received")
        d = talkers.get("packets_received", {})
        if d:
            df = pd.DataFrame({"ip": list(d.keys()), "packets": list(d.values())}).sort_values("packets", ascending=False)
            st.dataframe(df, use_container_width=True, hide_index=True)
