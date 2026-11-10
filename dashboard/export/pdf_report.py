# builds the "download pdf report" file. plain tables, no fills/stripes
# only the severity column in the alerts table gets colored, since
# that's the actual point (red/orange/green), not decoration

from __future__ import annotations

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

from ..data import load_json
from ..colors import SEVERITY_COLORS_RL

PLAIN_GRID = ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb"))


def build_pdf_bytes() -> bytes:
    summary = load_json("summary.json")
    stats = load_json("statistics.json")
    protocols = load_json("protocols.json")
    alerts_doc = load_json("alerts.json")
    alerts = alerts_doc.get("alerts", [])
    creds = alerts_doc.get("credential_leaks", [])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h2 = styles["Heading2"]
    normal = styles["Normal"]
    cell_style = ParagraphStyle("cell", parent=normal, fontSize=8, leading=10)
    header_cell = ParagraphStyle("header_cell", parent=cell_style, fontName="Helvetica-Bold")

    story = []

    # title / metadata
    story.append(Paragraph("PCAP SOC/DFIR Triage Report", title_style))
    story.append(Paragraph(f"Capture file: {summary.get('pcap_file', 'unknown')}", normal))
    story.append(Paragraph(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal))
    if summary.get("interrupted_partial_results"):
        story.append(Paragraph(
            '<font color="#e67e22"><b>Warning: analysis was interrupted — results are partial.</b></font>',
            normal,
        ))
    story.append(Spacer(1, 14))

    # alerts go first, this is the part people actually care about
    story.append(Paragraph(f"Alerts ({len(alerts)} total)", h2))
    sev_order = {"high": 0, "medium": 1, "low": 2}
    alerts_sorted = sorted(alerts, key=lambda a: sev_order.get(a.get("severity", ""), 3))

    if not alerts_sorted:
        story.append(Paragraph("No alerts were generated for this capture.", normal))
    else:
        header = [Paragraph("Severity", header_cell), Paragraph("Category", header_cell), Paragraph("Message", header_cell)]
        alert_rows = [header]
        row_colors = []
        for a in alerts_sorted:
            sev = a.get("severity", "low")
            row_colors.append(SEVERITY_COLORS_RL.get(sev, colors.grey))
            alert_rows.append([
                Paragraph(sev.upper(), cell_style),
                Paragraph(a.get("category", ""), cell_style),
                Paragraph(a.get("message", ""), cell_style),
            ])

        t = Table(alert_rows, colWidths=[0.9 * inch, 1.6 * inch, 4.3 * inch], repeatRows=1)
        style_cmds = [
            PLAIN_GRID,
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]
        # only the severity text itself is colored, cell background stays white
        for i, c in enumerate(row_colors, start=1):
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), c))
            style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(style_cmds))
        story.append(t)
    story.append(Spacer(1, 14))

    # credential leaks, right under alerts since it's basically an alert detail view
    if creds:
        story.append(Paragraph(f"Credential Leak Detail ({len(creds)} total)", h2))
        cred_header = [Paragraph("Src", header_cell), Paragraph("Dst:Port", header_cell), Paragraph("Snippet", header_cell)]
        cred_rows = [cred_header]
        for c in creds[:100]:
            cred_rows.append([
                Paragraph(str(c.get("src", "")), cell_style),
                Paragraph(f"{c.get('dst', '')}:{c.get('dport', '')}", cell_style),
                Paragraph(str(c.get("snippet", "")), cell_style),
            ])
        t = Table(cred_rows, colWidths=[1.5 * inch, 1.5 * inch, 3.8 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            PLAIN_GRID,
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

    # capture summary
    story.append(Spacer(1, 10))
    story.append(Paragraph("Capture Summary", h2))
    summary_rows = [
        ["Total Packets", f"{summary.get('total_packets', 0):,}"],
        ["Total Bytes", f"{summary.get('total_bytes', 0) / 1024 / 1024:.2f} MB"],
        ["Duration (s)", f"{summary.get('duration_seconds', 0):.1f}"],
        ["Unique Flows", f"{summary.get('flow_count', 0):,}"],
        ["Largest Packet", f"{stats.get('largest_packet', 0)} B"],
        ["Smallest Packet", f"{stats.get('smallest_packet', 0)} B"],
        ["Total Alerts", f"{summary.get('alert_count', len(alerts)):,}"],
    ]
    t = Table(summary_rows, colWidths=[2.2 * inch, 3.5 * inch])
    t.setStyle(TableStyle([
        PLAIN_GRID,
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    # protocol breakdown
    counts = protocols.get("counts", {})
    if counts:
        story.append(Paragraph("Protocol Breakdown", h2))
        proto_rows = [["Protocol", "Count", "Percentage"]]
        pct = protocols.get("percentages", {})
        for proto, cnt in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
            proto_rows.append([proto, f"{cnt:,}", f"{pct.get(proto, 0):.1f}%"])
        t = Table(proto_rows, colWidths=[2.2 * inch, 1.8 * inch, 1.8 * inch])
        t.setStyle(TableStyle([
            PLAIN_GRID,
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)

    doc.build(story)
    return buf.getvalue()
