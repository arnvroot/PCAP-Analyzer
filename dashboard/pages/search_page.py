import pandas as pd
import streamlit as st

from ..data import load_json


def _filtered(records: list, q: str):
    if not records:
        return None
    df = pd.DataFrame(records)
    mask = df.astype(str).apply(lambda col: col.str.lower().str.contains(q, na=False)).any(axis=1)
    return df[mask]


def render() -> None:
    st.title("Search anything")
    query = st.text_input("Search IP, domain, or port across all datasets")
    if not query:
        st.caption("Enter a search term above (IP address, domain, port number, etc.)")
        return

    q = query.strip().lower()

    st.subheader("Conversations")
    df = _filtered(load_json("flows.json").get("top_conversations", []), q)
    if df is not None:
        st.dataframe(df, use_container_width=True, hide_index=True)

    st.subheader("DNS Records")
    df = _filtered(load_json("dns.json").get("records", []), q)
    if df is not None:
        st.dataframe(df, use_container_width=True, hide_index=True)

    st.subheader("HTTP Records")
    df = _filtered(load_json("http.json").get("records", []), q)
    if df is not None:
        st.dataframe(df, use_container_width=True, hide_index=True)

    st.subheader("Alerts")
    df = _filtered(load_json("alerts.json").get("alerts", []), q)
    if df is not None:
        st.dataframe(df, use_container_width=True, hide_index=True)
