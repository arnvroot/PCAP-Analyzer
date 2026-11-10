import pandas as pd
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Port Scan Detection")
    ports = load_json("ports.json")

    st.subheader("Vertical Scans (many ports, one host)")
    v = ports.get("vertical_scans", [])
    if v:
        st.error(f"{len(v)} possible vertical scan(s) detected.")
        st.dataframe(pd.DataFrame(v), use_container_width=True, hide_index=True)
    else:
        st.success("None detected.")

    st.subheader("Horizontal Scans (one port, many hosts)")
    h = ports.get("horizontal_scans", [])
    if h:
        st.error(f"{len(h)} possible horizontal scan(s) detected.")
        st.dataframe(pd.DataFrame(h), use_container_width=True, hide_index=True)
    else:
        st.success("None detected.")

    st.subheader("SYN Scan Candidates")
    s = ports.get("syn_scan_candidates", [])
    if s:
        st.warning(f"{len(s)} SYN scan candidate(s) detected.")
        st.dataframe(pd.DataFrame(s), use_container_width=True, hide_index=True)
    else:
        st.success("None detected.")
