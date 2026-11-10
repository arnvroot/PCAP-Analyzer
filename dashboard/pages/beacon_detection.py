import pandas as pd
import plotly.express as px
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Beacon Detection")
    beacons = load_json("flows.json").get("beacon_detection", [])
    if beacons:
        df = pd.DataFrame(beacons).sort_values("coefficient_of_variation")
        st.dataframe(df, use_container_width=True, hide_index=True)
        fig = px.scatter(df, x="mean_interval_s", y="coefficient_of_variation", size="samples",
                          hover_data=["src", "dst", "dst_port"], title="Beacon Candidates (lower CV = more regular)")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No regular beacon-like flows detected.")
