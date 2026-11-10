import pandas as pd
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("HTTP Analysis")
    http = load_json("http.json").get("records", [])
    if http:
        st.info(f"{len(http)} HTTP requests parsed.")
        df = pd.DataFrame(http)
        method_filter = st.multiselect("Filter by method", options=sorted(df["method"].unique()), default=list(df["method"].unique()))
        df = df[df["method"].isin(method_filter)]
        search = st.text_input("Search host/URI")
        if search:
            mask = df["host"].str.contains(search, case=False, na=False) | df["uri"].str.contains(search, case=False, na=False)
            df = df[mask]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No HTTP traffic parsed.")
