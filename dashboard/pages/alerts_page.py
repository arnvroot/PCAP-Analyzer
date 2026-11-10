import pandas as pd
import streamlit as st

from ..data import load_json
from ..colors import SEVERITY_COLORS_HEX


def render() -> None:
    st.title("Alerts")
    alerts = load_json("alerts.json").get("alerts", [])
    if alerts:
        df = pd.DataFrame(alerts)
        sev_filter = st.multiselect("Filter by severity", options=["high", "medium", "low"], default=["high", "medium", "low"])
        df = df[df["severity"].isin(sev_filter)]
        cat_filter = st.multiselect("Filter by category", options=sorted(df["category"].unique()), default=list(df["category"].unique()))
        df = df[df["category"].isin(cat_filter)]
        for _, row in df.iterrows():
            bg = SEVERITY_COLORS_HEX.get(row["severity"], "#888888")
            st.markdown(
                f"<div style='background-color:{bg}22; border-left:5px solid {bg}; "
                f"padding:8px 12px; margin-bottom:6px; border-radius:4px;'>"
                f"<b style='color:{bg};'>{row['severity'].upper()}</b> — "
                f"<b>{row['category']}</b> — {row['message']}</div>",
                unsafe_allow_html=True,
            )
    else:
        st.success("No alerts generated.")
