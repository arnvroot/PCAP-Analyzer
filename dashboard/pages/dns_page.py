import pandas as pd
import plotly.express as px
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("DNS Analysis")
    dns = load_json("dns.json")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Top Queried Domains")
        d = dns.get("top_queried_domains", [])
        if d:
            df = pd.DataFrame(d, columns=["domain", "count"])
            st.plotly_chart(px.bar(df, x="domain", y="count"), use_container_width=True)
    with col2:
        st.subheader("Query Types")
        d = dns.get("query_types", {})
        if d:
            df = pd.DataFrame({"type": list(d.keys()), "count": list(d.values())})
            st.plotly_chart(px.pie(df, names="type", values="count"), use_container_width=True)

    st.subheader("Suspicious DNS (high entropy / long domains / possible DGA-tunneling)")
    alerts = dns.get("alerts", [])
    if alerts:
        st.warning(f"{len(alerts)} suspicious DNS entries flagged.")
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.info("No suspicious DNS activity flagged.")

    with st.expander("All DNS Records"):
        recs = dns.get("records", [])
        if recs:
            st.dataframe(pd.DataFrame(recs), use_container_width=True, hide_index=True)
