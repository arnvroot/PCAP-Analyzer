import pandas as pd
import plotly.express as px
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Port Analysis")
    ports = load_json("ports.json")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Top Destination Ports")
        d = ports.get("top_dst_ports", [])
        if d:
            df = pd.DataFrame(d, columns=["port", "count"])
            st.plotly_chart(px.bar(df, x="port", y="count"), use_container_width=True)
    with col2:
        st.subheader("Top Source Ports")
        d = ports.get("top_src_ports", [])
        if d:
            df = pd.DataFrame(d, columns=["port", "count"])
            st.plotly_chart(px.bar(df, x="port", y="count"), use_container_width=True)

    st.subheader("Uncommon Ports")
    up = ports.get("uncommon_ports", [])
    if up:
        st.warning(f"{len(up)} uncommon port(s) seen — worth a second look.")
        st.dataframe(pd.DataFrame({"port": up}), use_container_width=True, hide_index=True)
    else:
        st.success("No uncommon ports flagged.")
