# every page pulls its data through load_json, nothing reads the pcap directly

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import streamlit as st


def resolve_datadir() -> Path:
    """supports `streamlit run app.py -- --datadir X`"""
    args = sys.argv[1:]
    if "--datadir" in args:
        idx = args.index("--datadir")
        if idx + 1 < len(args):
            return Path(args[idx + 1])
    return Path("./output")


DATADIR = resolve_datadir()


@st.cache_data(show_spinner=False)
def load_json(name: str) -> Dict[str, Any]:
    path = DATADIR / name
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
