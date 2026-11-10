# builds the "download csv" button's file. no color here since csv
# can't do that, so we lean on clear section headers instead

from __future__ import annotations

import csv
import io
from datetime import datetime

from ..data import load_json


def build_csv_bytes() -> bytes:
    summary = load_json("summary.json")
    alerts_doc = load_json("alerts.json")
    alerts = alerts_doc.get("alerts", [])
    creds = alerts_doc.get("credential_leaks", [])

    sev_order = {"high": 0, "medium": 1, "low": 2}
    alerts_sorted = sorted(alerts, key=lambda a: sev_order.get(a.get("severity", ""), 3))
    sev_counts = {"high": 0, "medium": 0, "low": 0}
    for a in alerts_sorted:
        sev_counts[a.get("severity", "low")] = sev_counts.get(a.get("severity", "low"), 0) + 1

    buf = io.StringIO()
    writer = csv.writer(buf)

    # report header
    writer.writerow(["PCAP SOC/DFIR Triage Report"])
    writer.writerow(["Capture File", summary.get("pcap_file", "unknown")])
    writer.writerow(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow(["Total Packets", f"{summary.get('total_packets', 0):,}"])
    writer.writerow(["Total Alerts", len(alerts_sorted)])
    writer.writerow(["High", sev_counts.get("high", 0), "Medium", sev_counts.get("medium", 0), "Low", sev_counts.get("low", 0)])
    writer.writerow([])

    # alerts section
    writer.writerow(["=== ALERTS ==="])
    writer.writerow(["#", "Severity", "Category", "Message"])
    for i, a in enumerate(alerts_sorted, start=1):
        writer.writerow([i, a.get("severity", "").upper(), a.get("category", ""), a.get("message", "")])
    writer.writerow([])

    # credential leaks section
    writer.writerow(["=== CREDENTIAL LEAKS ==="])
    writer.writerow(["#", "Src", "Dst", "Port", "Pattern", "Snippet"])
    for i, c in enumerate(creds, start=1):
        writer.writerow([i, c.get("src", ""), c.get("dst", ""), c.get("dport", ""), c.get("pattern", ""), c.get("snippet", "")])
    if not creds:
        writer.writerow(["(none detected)"])

    return buf.getvalue().encode("utf-8")
