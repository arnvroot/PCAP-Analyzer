import pandas as pd
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Top Conversations")
    flows = load_json("flows.json")
    convs = flows.get("top_conversations", [])
    if convs:
        df = pd.DataFrame(convs)
        proto_filter = st.multiselect("Filter by protocol", options=sorted(df["proto"].unique()), default=list(df["proto"].unique()))
        df = df[df["proto"].isin(proto_filter)]
        sort_col = st.selectbox("Sort by", ["bytes", "packets", "duration_s"])
        df = df.sort_values(sort_col, ascending=False)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No conversation data available.")

    st.subheader("Large Transfers (>50MB)")
    lt = flows.get("large_transfers", [])
    if lt:
        st.warning(f"{len(lt)} large transfer(s) detected.")
        st.dataframe(pd.DataFrame(lt), use_container_width=True, hide_index=True)
    else:
        st.success("No large transfers detected.")
