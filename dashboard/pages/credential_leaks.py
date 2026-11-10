import pandas as pd
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Credential Leak Detection")
    creds = load_json("alerts.json").get("credential_leaks", [])
    if creds:
        st.error(f"{len(creds)} potential credential exposures detected.")
        st.dataframe(pd.DataFrame(creds), use_container_width=True, hide_index=True)
    else:
        st.success("No credential material detected in cleartext protocols.")
