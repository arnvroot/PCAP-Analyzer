import pandas as pd
import plotly.express as px
import streamlit as st

from ..data import load_json


def render() -> None:
    st.title("Protocol Analysis")
    proto = load_json("protocols.json")
    counts = proto.get("counts", {})
    pct = proto.get("percentages", {})

    if counts:
        df = pd.DataFrame({"protocol": list(counts.keys()), "count": list(counts.values())})
        df["percentage"] = df["protocol"].map(pct)
        col1, col2 = st.columns([2, 1])
        with col1:
            fig = px.pie(df, names="protocol", values="count", title="Protocol Distribution")
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.dataframe(df.sort_values("count", ascending=False), use_container_width=True, hide_index=True)

    st.subheader("Internal vs External Traffic")
    tclass = proto.get("traffic_classification", {})
    if tclass:
        df2 = pd.DataFrame({"class": list(tclass.keys()), "count": list(tclass.values())})
        st.plotly_chart(px.bar(df2, x="class", y="count", color="class"), use_container_width=True)

    st.subheader("TCP Flags")
    flags = proto.get("tcp_flags", {})
    if flags:
        df3 = pd.DataFrame({"flag": list(flags.keys()), "count": list(flags.values())})
        st.plotly_chart(px.bar(df3, x="flag", y="count"), use_container_width=True)

    st.subheader("ICMP")
    icmp = proto.get("icmp", {})
    ic1, ic2, ic3 = st.columns(3)
    ic1.metric("Echo Requests", icmp.get("echo_request", 0))
    ic2.metric("Echo Replies", icmp.get("echo_reply", 0))
    ic3.metric("Large ICMP Packets", icmp.get("large_packets", 0))
    if icmp.get("ping_sweep_candidates"):
        st.warning("Possible Ping Sweep sources:")
        st.dataframe(pd.DataFrame(icmp["ping_sweep_candidates"]), use_container_width=True, hide_index=True)

    st.subheader("ARP")
    arp = proto.get("arp", {})
    a1, a2 = st.columns(2)
    a1.metric("ARP Requests", arp.get("requests", 0))
    a2.metric("ARP Replies", arp.get("replies", 0))
    if arp.get("spoof_candidates"):
        st.error("Possible ARP Spoofing detected:")
        st.dataframe(pd.DataFrame(arp["spoof_candidates"]), use_container_width=True, hide_index=True)
