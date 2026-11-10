import pandas as pd
import plotly.express as px
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("TLS Analysis")
    tls = load_json("tls.json").get("records", [])
    if tls:
        st.info(f"{len(tls)} TLS ClientHello records parsed.")
        df = pd.DataFrame(tls)
        search = st.text_input("Search SNI")
        if search:
            df = df[df["sni"].str.contains(search, case=False, na=False)]
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.subheader("Top SNI Hostnames")
        if "sni" in df.columns:
            top_sni = df["sni"].value_counts().head(10)
            st.plotly_chart(px.bar(x=top_sni.index, y=top_sni.values, labels={"x": "SNI", "y": "count"}), use_container_width=True)
    else:
        st.info("No TLS ClientHello records parsed.")
