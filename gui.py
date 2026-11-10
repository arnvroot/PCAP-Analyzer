"""
gui.py
======
Next-Generation Modern CustomTkinter Dashboard for PCAP/PCAPNG Traffic & DFIR Analysis.

Features:
- Responsive background-threaded packet inspection (zero UI freeze).
- Executive metric cards with live packet rates & data volume.
- Interactive embedded Matplotlib charts (Protocol Donut & Top Ports / Activity).
- Live Real-Time Security Alerts with severity badges & keyword filter.
- Deep-dive Attack Detections: Credential Leaks, Port Scans, DGA/DNS, C2 Beacons, ARP Spoofs.
- Top Talkers & Conversations flow inspector.
- Built-in Executive PDF Threat Report export using ReportLab (no JSON file clutter needed).
"""

from __future__ import annotations

import io
import os
import sys
import time
import queue
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

# Matplotlib embedded backend
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ReportLab for direct executive PDF generation
from reportlab.lib import colors as rl_colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

# Ensure local package import works regardless of launch directory
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from pcap_analyzer import PcapAnalyzer
from pcap_analyzer.config import (
    PORT_SCAN_UNIQUE_PORTS_THRESHOLD,
    PORT_SCAN_UNIQUE_HOSTS_THRESHOLD,
    LARGE_TRANSFER_BYTES,
)

# Appearance configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Theme Palette Constants
BG_DARK = "#0F111A"
CARD_BG = "#1A1D27"
CARD_BORDER = "#2A3042"
ACCENT_CYAN = "#00D2FC"
ACCENT_PURPLE = "#7928CA"
ACCENT_GREEN = "#00E676"
ACCENT_RED = "#FF3366"
ACCENT_AMBER = "#FFAA00"
TEXT_MUTED = "#8E9AA8"


class GuiPcapAnalyzer(PcapAnalyzer):
    """
    Subclass of PcapAnalyzer that sends real-time progress, metrics, and security
    threat events to a thread-safe Queue for GUI consumption.
    """

    def __init__(self, pcap_path: str, outdir: str, event_queue: queue.Queue):
        super().__init__(pcap_path, outdir)
        self.event_queue = event_queue
        self._last_cred_count = 0
        self._last_dns_count = 0
        self._reported_scans = set()
        self._reported_sweeps = set()
        self._reported_arps = set()
        self._emitted_alerts = set()
        self.live_alerts: List[Dict[str, Any]] = []

    def _scan_credentials(self, payload: bytes, src: str, dst: str, sport: int, dport: int) -> None:
        super()._scan_credentials(payload, src, dst, sport, dport)
        if len(self.credential_hits) > self._last_cred_count:
            for hit in self.credential_hits[self._last_cred_count:]:
                msg = f"{hit['src']} -> {hit['dst']}:{hit['dport']} [matched '{hit.get('snippet', '')}']"
                alert_key = ("Credential Leak", msg)
                if alert_key not in self._emitted_alerts:
                    self._emitted_alerts.add(alert_key)
                    alert_item = {
                        "severity": "high",
                        "category": "Credential Leak",
                        "message": msg,
                        "src": hit["src"],
                        "dst": f"{hit['dst']}:{hit['dport']}",
                        "details": hit.get("snippet", ""),
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                    }
                    self.live_alerts.append(alert_item)
                    self.event_queue.put(("alert", alert_item))
            self._last_cred_count = len(self.credential_hits)

    def _parse_dns(self, buf: bytes, src: str, dst: str) -> None:
        super()._parse_dns(buf, src, dst)
        if len(self.dns_alerts) > self._last_dns_count:
            for d in self.dns_alerts[self._last_dns_count:]:
                msg = f"Query '{d.get('domain', '')}' ({d.get('reason', '')}, entropy={d.get('entropy', 0)}) from {d.get('src', src)}"
                alert_key = ("Suspicious DNS", msg)
                if alert_key not in self._emitted_alerts:
                    self._emitted_alerts.add(alert_key)
                    alert_item = {
                        "severity": "medium",
                        "category": "Suspicious DNS",
                        "message": msg,
                        "src": d.get("src", src),
                        "dst": dst,
                        "details": f"Entropy: {d.get('entropy', 0)}, Type: {d.get('reason', '')}",
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                    }
                    self.live_alerts.append(alert_item)
                    self.event_queue.put(("alert", alert_item))
            self._last_dns_count = len(self.dns_alerts)

    def _handle_tcp(self, ts: float, src: str, dst: str, tcp, size: int) -> None:
        super()._handle_tcp(ts, src, dst, tcp, size)
        target_pair = (src, dst)
        if (
            target_pair in self.src_dst_ports
            and len(self.src_dst_ports[target_pair]) >= PORT_SCAN_UNIQUE_PORTS_THRESHOLD
            and target_pair not in self._reported_scans
        ):
            self._reported_scans.add(target_pair)
            msg = f"{src} probed {len(self.src_dst_ports[target_pair])}+ unique ports on target {dst}"
            alert_item = {
                "severity": "high",
                "category": "Port Scan (vertical)",
                "message": msg,
                "src": src,
                "dst": dst,
                "details": f"{len(self.src_dst_ports[target_pair])} ports probed",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
            self._emitted_alerts.add(("Port Scan (vertical)", msg))
            self.live_alerts.append(alert_item)
            self.event_queue.put(("alert", alert_item))

    def _handle_icmp(self, ts: float, src: str, dst: str, icmp, size: int) -> None:
        super()._handle_icmp(ts, src, dst, icmp, size)
        if (
            len(self.icmp_src_targets[src]) >= PORT_SCAN_UNIQUE_HOSTS_THRESHOLD
            and src not in self._reported_sweeps
        ):
            self._reported_sweeps.add(src)
            msg = f"{src} initiated ping sweep touching {len(self.icmp_src_targets[src])}+ distinct hosts"
            alert_item = {
                "severity": "medium",
                "category": "Ping Sweep",
                "message": msg,
                "src": src,
                "dst": "Multiple hosts",
                "details": f"{len(self.icmp_src_targets[src])} targets pinged",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
            self._emitted_alerts.add(("Ping Sweep", msg))
            self.live_alerts.append(alert_item)
            self.event_queue.put(("alert", alert_item))

    def _handle_arp(self, arp) -> None:
        super()._handle_arp(arp)
        try:
            spa = socket.inet_ntoa(arp.spa)
            if len(self.ip_to_macs[spa]) > 1 and spa not in self._reported_arps:
                self._reported_arps.add(spa)
                mac_list = list(self.ip_to_macs[spa])
                msg = f"Duplicate IP detected! {spa} claimed by multiple MACs: {mac_list}"
                alert_item = {
                    "severity": "high",
                    "category": "ARP Spoofing",
                    "message": msg,
                    "src": spa,
                    "dst": "Broadcast",
                    "details": str(mac_list),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }
                self._emitted_alerts.add(("ARP Spoofing", msg))
                self.live_alerts.append(alert_item)
                self.event_queue.put(("alert", alert_item))
        except Exception:
            pass

    def run(self) -> None:
        self._install_signal_handler()
        self._start_time = time.time()
        last_progress_time = time.time()
        last_packet_update = 0

        try:
            with open(self.pcap_path, "rb") as f:
                reader = self._open_reader(f)

                for ts, buf in reader:
                    if self._interrupted:
                        break
                    try:
                        self._process_packet(ts, buf)
                    except Exception:
                        pass

                    self.total_packets += 1

                    now = time.time()
                    if (now - last_progress_time >= 0.25) or (self.total_packets - last_packet_update >= 500):
                        pos = f.tell()
                        pct = (pos / self._file_size * 100) if self._file_size > 0 else 0.0
                        duration = (self.last_ts - self.first_ts) if (self.first_ts and self.last_ts) else 0.0
                        pps = self.total_packets / duration if duration > 0 else 0.0

                        self.event_queue.put((
                            "progress",
                            {
                                "total_packets": self.total_packets,
                                "total_bytes": self.total_bytes,
                                "duration": duration,
                                "pps": pps,
                                "pct": min(pct, 100.0),
                                "protocol_counts": dict(self.protocol_counts),
                            },
                        ))
                        last_progress_time = now
                        last_packet_update = self.total_packets

        except Exception as exc:
            self.event_queue.put(("error", f"Error during parsing: {exc}"))
            return

        # Run post-processing for beacons, scans, conversations
        try:
            self._post_process()
            # Also write outputs gracefully
            self._write_outputs()
        except Exception as exc:
            self.event_queue.put(("error", f"Error during post-processing: {exc}"))
            return

        # Emit post-processed alerts (beacons, horizontal scans, large transfers)
        for a in self.alerts:
            cat = a.get("category", "")
            if cat in ("Credential Leak", "Suspicious DNS", "Port Scan (vertical)"):
                continue
            msg = a.get("message", "")
            if (cat, msg) not in self._emitted_alerts:
                self._emitted_alerts.add((cat, msg))
                alert_item = {
                    "severity": a.get("severity", "medium"),
                    "category": cat,
                    "message": msg,
                    "src": "-",
                    "dst": "-",
                    "details": msg,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }
                self.live_alerts.append(alert_item)
                self.event_queue.put(("alert", alert_item))

        duration = (self.last_ts - self.first_ts) if (self.first_ts and self.last_ts) else 0.0
        pps = self.total_packets / duration if duration > 0 else 0.0
        elapsed = time.time() - self._start_time

        # Package full dataset for dashboard graphs & PDF report
        complete_payload = {
            "pcap_file": str(self.pcap_path.name),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration": duration,
            "pps": pps,
            "elapsed": elapsed,
            "flow_count": len(self.flows),
            "alerts": list(self.live_alerts),
            "credential_hits": list(self.credential_hits),
            "dns_alerts": list(self.dns_alerts),
            "vertical_scans": list(getattr(self, "vertical_scans", [])),
            "horizontal_scans": list(getattr(self, "horizontal_scans", [])),
            "beacons": list(getattr(self, "beacons", [])),
            "top_conversations": list(getattr(self, "top_conversations", [])),
            "top_talkers_sent": self.bytes_sent.top()[:8],
            "top_talkers_recv": self.bytes_received.top()[:8],
            "protocol_counts": dict(self.protocol_counts),
            "dst_port_counts": dict(self.dst_port_counts.most_common(8)),
            "timeline_pps": dict(sorted(self.timeline_pps.items())),
            "interrupted": self._interrupted,
        }

        self.event_queue.put(("complete", complete_payload))


class PdfThreatReportBuilder:
    """
    Generates an executive PDF Threat & DFIR Report using ReportLab directly
    from the in-memory analyzer data without needing any intermediate JSON files.
    """

    @staticmethod
    def generate(data: Dict[str, Any], output_path: str) -> None:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=0.5 * inch,
            rightMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("RepTitle", parent=styles["Heading1"], fontSize=18, leading=22, textColor=rl_colors.HexColor("#0F172A"))
        subtitle_style = ParagraphStyle("RepSub", parent=styles["Normal"], fontSize=9, leading=12, textColor=rl_colors.HexColor("#64748B"))
        sec_h2 = ParagraphStyle("SecH2", parent=styles["Heading2"], fontSize=12, leading=15, textColor=rl_colors.HexColor("#1E293B"), spaceBefore=12, spaceAfter=6)
        normal = ParagraphStyle("RepNorm", parent=styles["Normal"], fontSize=8.5, leading=11)
        bold = ParagraphStyle("RepBold", parent=normal, fontName="Helvetica-Bold")
        cell_style = ParagraphStyle("RepCell", parent=normal, fontSize=8, leading=10)
        cell_bold = ParagraphStyle("RepCellBold", parent=cell_style, fontName="Helvetica-Bold")

        story = []

        # Title & Executive Header
        story.append(Paragraph("🛡️ PCAP Threat Intelligence & SOC Triage Report", title_style))
        pcap_name = data.get("pcap_file", "Capture")
        story.append(Paragraph(f"Capture: <b>{pcap_name}</b> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC | Offline DFIR Engine", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=rl_colors.HexColor("#2563EB"), spaceBefore=6, spaceAfter=10))

        # Executive Metrics Summary Table
        story.append(Paragraph("Executive Summary", sec_h2))
        total_b = data.get("total_bytes", 0)
        bytes_str = f"{total_b / (1024 * 1024):.2f} MB" if total_b >= 1024 * 1024 else f"{total_b / 1024:.1f} KB"
        alerts_list = data.get("alerts", [])
        high_cnt = sum(1 for a in alerts_list if a.get("severity") == "high")
        med_cnt = sum(1 for a in alerts_list if a.get("severity") == "medium")
        low_cnt = sum(1 for a in alerts_list if a.get("severity") == "low")

        exec_summary = [
            [Paragraph("Total Packets", cell_bold), Paragraph(f"{data.get('total_packets', 0):,}", cell_style),
             Paragraph("Total Data Volume", cell_bold), Paragraph(bytes_str, cell_style)],
            [Paragraph("Capture Duration", cell_bold), Paragraph(f"{data.get('duration', 0):.2f} s", cell_style),
             Paragraph("Average Rate", cell_bold), Paragraph(f"{data.get('pps', 0):,.1f} pps", cell_style)],
            [Paragraph("Unique Flows", cell_bold), Paragraph(f"{data.get('flow_count', 0):,}", cell_style),
             Paragraph("Total Security Alerts", cell_bold),
             Paragraph(f"<font color='#DC2626'><b>{len(alerts_list)}</b> ({high_cnt} High, {med_cnt} Med, {low_cnt} Low)</font>", cell_style)],
        ]
        t_exec = Table(exec_summary, colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
        t_exec.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), rl_colors.HexColor("#F8FAFC")),
            ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(t_exec)

        # Red Flags & Security Alerts Table
        story.append(Paragraph(f"Security Alerts & Red Flags ({len(alerts_list)} Total)", sec_h2))
        if not alerts_list:
            story.append(Paragraph("✅ No threat anomalies or credential leaks detected in this capture.", normal))
        else:
            alert_rows = [[Paragraph("Severity", cell_bold), Paragraph("Category", cell_bold), Paragraph("Detection Details", cell_bold), Paragraph("Time", cell_bold)]]
            for a in alerts_list[:40]:
                sev = a.get("severity", "low").upper()
                sev_color = "#DC2626" if sev == "HIGH" else "#D97706" if sev == "MEDIUM" else "#2563EB"
                alert_rows.append([
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", cell_style),
                    Paragraph(a.get("category", "-"), cell_style),
                    Paragraph(a.get("message", "-"), cell_style),
                    Paragraph(a.get("timestamp", "-"), cell_style),
                ])
            t_alerts = Table(alert_rows, colWidths=[0.8 * inch, 1.6 * inch, 4.1 * inch, 0.7 * inch], repeatRows=1)
            t_alerts.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#E2E8F0")),
                ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(t_alerts)

        # Credential Leaks Section
        creds = data.get("credential_hits", [])
        if creds:
            story.append(Paragraph(f"🚨 Plaintext Credential Leaks ({len(creds)} Detected)", sec_h2))
            cred_rows = [[Paragraph("Source IP", cell_bold), Paragraph("Target Destination", cell_bold), Paragraph("Leaked Snippet / Pattern", cell_bold)]]
            for c in creds[:25]:
                cred_rows.append([
                    Paragraph(str(c.get("src", "")), cell_style),
                    Paragraph(f"{c.get('dst', '')}:{c.get('dport', '')}", cell_style),
                    Paragraph(f"<font color='#DC2626'><code>{str(c.get('snippet', ''))}</code></font>", cell_style),
                ])
            t_creds = Table(cred_rows, colWidths=[1.8 * inch, 1.8 * inch, 3.6 * inch], repeatRows=1)
            t_creds.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#FEE2E2")),
                ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#FCA5A5")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t_creds)

        # Protocol Distribution Table
        proto_counts = data.get("protocol_counts", {})
        if proto_counts:
            story.append(Paragraph("Protocol Breakdown", sec_h2))
            total_p = sum(proto_counts.values()) or 1
            proto_rows = [[Paragraph("Protocol", cell_bold), Paragraph("Packets", cell_bold), Paragraph("Share", cell_bold)]]
            for proto, cnt in sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True):
                pct = (cnt / total_p) * 100
                proto_rows.append([Paragraph(proto, cell_style), Paragraph(f"{cnt:,}", cell_style), Paragraph(f"{pct:.1f}%", cell_style)])
            t_proto = Table(proto_rows, colWidths=[2.4 * inch, 2.4 * inch, 2.4 * inch])
            t_proto.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#F1F5F9")),
                ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t_proto)

        # Top Talkers
        talkers = data.get("top_talkers_sent", [])
        if talkers:
            story.append(Paragraph("Top Network Talkers (Bytes Transmitted)", sec_h2))
            talk_rows = [[Paragraph("Host IP", cell_bold), Paragraph("Bytes Sent", cell_bold), Paragraph("Volume (MB)", cell_bold)]]
            for ip, b in talkers[:8]:
                talk_rows.append([Paragraph(str(ip), cell_style), Paragraph(f"{b:,}", cell_style), Paragraph(f"{b / (1024 * 1024):.2f} MB", cell_style)])
            t_talk = Table(talk_rows, colWidths=[2.4 * inch, 2.4 * inch, 2.4 * inch])
            t_talk.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#F1F5F9")),
                ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t_talk)

        doc.build(story)
        with open(output_path, "wb") as f:
            f.write(buf.getvalue())


class PcapAnalyzerApp(ctk.CTk):
    """
    Main Modern CustomTkinter Application Window for PCAP Analyzer.
    """

    def __init__(self):
        super().__init__()

        self.title("PCAP SOC & DFIR Threat Dashboard")
        self.geometry("1240x800")
        self.minsize(1050, 680)

        # State variables
        self.pcap_path: Optional[Path] = None
        self.analyzer_instance: Optional[GuiPcapAnalyzer] = None
        self.analysis_thread: Optional[threading.Thread] = None
        self.event_queue = queue.Queue()
        self.is_running = False
        self.completed_data: Optional[Dict[str, Any]] = None

        # Alerts in memory
        self.all_alerts: List[Dict[str, Any]] = []
        self.high_alerts = 0
        self.med_alerts = 0
        self.low_alerts = 0

        # Build UI layout
        self._setup_layout()
        self._build_sidebar()
        self._build_main_dashboard()

        # Start periodic queue polling
        self.after(50, self._process_queue)

    def _setup_layout(self):
        self.configure(fg_color=BG_DARK)
        self.grid_columnconfigure(0, weight=0, minsize=290)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

    # -------------------------------------------------------------------------
    # Sidebar
    # -------------------------------------------------------------------------
    def _build_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, corner_radius=0, width=290, fg_color="#12151E")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.sidebar_frame.grid_columnconfigure(0, weight=1)

        # Branding
        title_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🛜PCAP Analyzer",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#FFFFFF",
        )
        title_label.grid(row=0, column=0, padx=22, pady=(22, 2), sticky="w")

        subtitle_label = ctk.CTkLabel(
            self.sidebar_frame,
            text=" SOC & DFIR Traffic Intelligence",
            font=ctk.CTkFont(size=12),
            text_color=ACCENT_CYAN,
        )
        subtitle_label.grid(row=1, column=0, padx=22, pady=(0, 18), sticky="w")

        self._add_sidebar_separator(row=2)

        # Capture File Section
        file_sec_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="CAPTURE SOURCE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_MUTED,
        )
        file_sec_label.grid(row=3, column=0, padx=22, pady=(14, 6), sticky="w")

        self.btn_browse = ctk.CTkButton(
            self.sidebar_frame,
            text="📁 Select PCAP / PCAPNG",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1E293B",
            hover_color="#334155",
            border_width=1,
            border_color=CARD_BORDER,
            command=self._on_browse_file,
            height=38,
        )
        self.btn_browse.grid(row=4, column=0, padx=22, pady=(0, 8), sticky="ew")

        self.lbl_selected_file = ctk.CTkLabel(
            self.sidebar_frame,
            text="No capture loaded",
            font=ctk.CTkFont(size=12),
            text_color="gray60",
            anchor="w",
            wraplength=245,
            justify="left",
        )
        self.lbl_selected_file.grid(row=5, column=0, padx=22, pady=(0, 14), sticky="w")

        self._add_sidebar_separator(row=6)

        # Controls Section
        ctrl_sec_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="ANALYSIS CONTROLS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_MUTED,
        )
        ctrl_sec_label.grid(row=7, column=0, padx=22, pady=(14, 6), sticky="w")

        self.btn_start = ctk.CTkButton(
            self.sidebar_frame,
            text="▶ Run Live Analysis",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self._start_analysis,
            height=38,
            state="disabled",
        )
        self.btn_start.grid(row=8, column=0, padx=22, pady=(0, 8), sticky="ew")

        self.btn_stop = ctk.CTkButton(
            self.sidebar_frame,
            text="⏹ Stop / Intercept",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#DC2626",
            hover_color="#B91C1C",
            command=self._stop_analysis,
            height=36,
            state="disabled",
        )
        self.btn_stop.grid(row=9, column=0, padx=22, pady=(0, 8), sticky="ew")

        # PDF Threat Report Export Button
        self.btn_pdf_report = ctk.CTkButton(
            self.sidebar_frame,
            text="📑 Export PDF Threat Report",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#4F46E5",
            hover_color="#4338CA",
            command=self._export_pdf_report,
            height=38,
            state="disabled",
        )
        self.btn_pdf_report.grid(row=10, column=0, padx=22, pady=(0, 8), sticky="ew")

        self.btn_reset = ctk.CTkButton(
            self.sidebar_frame,
            text="↺ Reset Dashboard",
            font=ctk.CTkFont(size=12),
            fg_color="#1E293B",
            hover_color="#334155",
            command=self._reset_dashboard,
            height=32,
        )
        self.btn_reset.grid(row=11, column=0, padx=22, pady=(0, 14), sticky="ew")

        self._add_sidebar_separator(row=12)

        # Progress Section
        prog_sec_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="STREAMING ENGINE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_MUTED,
        )
        prog_sec_label.grid(row=13, column=0, padx=22, pady=(14, 6), sticky="w")

        self.prog_bar = ctk.CTkProgressBar(self.sidebar_frame, mode="determinate", progress_color=ACCENT_CYAN)
        self.prog_bar.set(0.0)
        self.prog_bar.grid(row=14, column=0, padx=22, pady=(0, 6), sticky="ew")

        self.lbl_progress = ctk.CTkLabel(
            self.sidebar_frame,
            text="Engine Idle",
            font=ctk.CTkFont(size=12),
            text_color="gray70",
            anchor="w",
        )
        self.lbl_progress.grid(row=15, column=0, padx=22, pady=(0, 15), sticky="w")

        # Spacer to push settings to bottom
        self.sidebar_frame.grid_rowconfigure(16, weight=1)

        # Bottom theme toggle
        self.opt_theme = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["Dark", "Light", "System"],
            command=lambda m: ctk.set_appearance_mode(m),
            height=28,
            fg_color="#1E293B",
            button_color="#334155",
        )
        self.opt_theme.set("Dark")
        self.opt_theme.grid(row=17, column=0, padx=22, pady=(10, 20), sticky="ew")

    def _add_sidebar_separator(self, row: int):
        sep = ctk.CTkFrame(self.sidebar_frame, height=1, fg_color="#1E2433")
        sep.grid(row=row, column=0, sticky="ew", padx=22, pady=2)

    # -------------------------------------------------------------------------
    # Main Dashboard Workspace
    # -------------------------------------------------------------------------
    def _build_main_dashboard(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=16)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)  # Tabs expand fully

        # 1. Top Section: 4 Modern Metric Cards
        self._build_top_cards(row=0)

        # 2. Tabs Section (Full dashboard of all things on GUI itself)
        self._build_tabs(row=1)

        # 3. Bottom Status Bar
        self._build_status_bar(row=2)

    def _build_top_cards(self, row: int):
        cards_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        cards_container.grid(row=row, column=0, sticky="ew", pady=(0, 14))
        for i in range(4):
            cards_container.grid_columnconfigure(i, weight=1, uniform="stat_cards")

        # Card 1: Packets
        self.card_packets, self.lbl_stat_packets, self.lbl_stat_packets_sub = self._create_stat_card(
            parent=cards_container,
            title="TOTAL PACKETS",
            initial_val="0",
            subtitle="0 pps rate",
            col=0,
            accent_color=ACCENT_CYAN,
        )

        # Card 2: Bytes
        self.card_bytes, self.lbl_stat_bytes, self.lbl_stat_bytes_sub = self._create_stat_card(
            parent=cards_container,
            title="DATA VOLUME",
            initial_val="0.0 KB",
            subtitle="0 bytes payload",
            col=1,
            accent_color=ACCENT_PURPLE,
        )

        # Card 3: Duration
        self.card_duration, self.lbl_stat_duration, self.lbl_stat_duration_sub = self._create_stat_card(
            parent=cards_container,
            title="CAPTURE DURATION",
            initial_val="0.00 s",
            subtitle="0.0s elapsed",
            col=2,
            accent_color="#38BDF8",
        )

        # Card 4: Red Flags & Threats
        self.card_alerts, self.lbl_stat_alerts, self.lbl_stat_alerts_sub = self._create_stat_card(
            parent=cards_container,
            title="THREATS & RED FLAGS",
            initial_val="0",
            subtitle="0 High | 0 Med | 0 Low",
            col=3,
            accent_color=ACCENT_RED,
        )

    def _create_stat_card(self, parent, title: str, initial_val: str, subtitle: str, col: int, accent_color: str):
        card = ctk.CTkFrame(
            parent,
            corner_radius=12,
            fg_color=CARD_BG,
            border_width=1,
            border_color=CARD_BORDER,
        )
        card.grid(row=0, column=col, sticky="ew", padx=6, pady=0)
        card.grid_columnconfigure(0, weight=1)

        # Top indicator line
        top_line = ctk.CTkFrame(card, height=3, corner_radius=2, fg_color=accent_color)
        top_line.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 6))

        t_lbl = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_MUTED,
        )
        t_lbl.grid(row=1, column=0, padx=16, pady=(0, 2), sticky="w")

        v_lbl = ctk.CTkLabel(
            card,
            text=initial_val,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#FFFFFF",
        )
        v_lbl.grid(row=2, column=0, padx=16, pady=(0, 2), sticky="w")

        s_lbl = ctk.CTkLabel(
            card,
            text=subtitle,
            font=ctk.CTkFont(size=11),
            text_color="gray60",
        )
        s_lbl.grid(row=3, column=0, padx=16, pady=(0, 12), sticky="w")

        return card, v_lbl, s_lbl

    # -------------------------------------------------------------------------
    # Tabs: Graphs, Alerts, Talkers, Attack Detections
    # -------------------------------------------------------------------------
    def _build_tabs(self, row: int):
        self.tabview = ctk.CTkTabview(
            self.main_frame,
            corner_radius=12,
            fg_color=CARD_BG,
            segmented_button_fg_color="#12151E",
            segmented_button_selected_color="#2563EB",
            segmented_button_selected_hover_color="#1D4ED8",
        )
        self.tabview.grid(row=row, column=0, sticky="nsew", pady=(0, 10))

        # Define tabs
        self.tab_overview = self.tabview.add("📊 Live Graphs & Overview")
        self.tab_alerts = self.tabview.add("🚨 Red Flags & Live Alerts")
        self.tab_talkers = self.tabview.add("📡 Top Talkers & Flows")
        self.tab_attacks = self.tabview.add("🛡️ Deep Attack Detections")

        self._setup_overview_tab()
        self._setup_alerts_tab()
        self._setup_talkers_tab()
        self._setup_attacks_tab()

    # --- TAB 1: Overview & Graphs ---
    def _setup_overview_tab(self):
        tab = self.tab_overview
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Quick Protocol Pill Strip
        proto_pill_frame = ctk.CTkFrame(tab, fg_color="#141722", corner_radius=8)
        proto_pill_frame.grid(row=0, column=0, sticky="ew", padx=12, pady=(6, 8))
        proto_pill_frame.grid_columnconfigure(0, weight=1)

        self.lbl_proto_pills = ctk.CTkLabel(
            proto_pill_frame,
            text="Live Traffic Distribution:  TCP: 0  |  UDP: 0  |  IPv4: 0  |  IPv6: 0  |  ARP: 0  |  ICMP: 0",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#94A3B8",
            pady=8,
        )
        self.lbl_proto_pills.grid(row=0, column=0, sticky="ew")

        # Matplotlib Embedded Charts Frame
        self.chart_container = ctk.CTkFrame(tab, fg_color=CARD_BG, corner_radius=10)
        self.chart_container.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        self.chart_container.grid_columnconfigure(0, weight=1)
        self.chart_container.grid_rowconfigure(0, weight=1)

        # Initialize dark-styled Matplotlib Figure
        self.fig, (self.ax_pie, self.ax_bar) = plt.subplots(1, 2, figsize=(8.5, 3.8), facecolor=CARD_BG)
        self.fig.subplots_adjust(left=0.08, right=0.94, top=0.88, bottom=0.15, wspace=0.35)
        self._style_blank_axes()

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_container)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.configure(bg=CARD_BG, highlightthickness=0)
        self.canvas_widget.pack(fill="both", expand=True, padx=6, pady=6)

    def _style_blank_axes(self):
        self.ax_pie.clear()
        self.ax_bar.clear()
        self.ax_pie.set_facecolor(CARD_BG)
        self.ax_bar.set_facecolor(CARD_BG)

        # Placeholder vertical bars
        self.ax_pie.bar(["IPv4", "TCP", "UDP", "ARP"], [0, 0, 0, 0], color="#2A3042", width=0.5)
        self.ax_pie.set_title("Protocol Breakdown (Packets)", color="#E2E8F0", fontsize=11, fontweight="bold", pad=8)
        self.ax_pie.tick_params(colors="#94A3B8", labelsize=8)
        for spine in self.ax_pie.spines.values():
            spine.set_visible(False)
        self.ax_pie.grid(axis="y", color="#242B3B", linestyle="--", alpha=0.6)

        # Placeholder bar
        self.ax_bar.barh(["No Data"], [0], color="#2A3042")
        self.ax_bar.set_title("Top Destination Ports", color="#E2E8F0", fontsize=11, fontweight="bold", pad=8)
        self.ax_bar.tick_params(colors="#94A3B8", labelsize=8)
        for spine in self.ax_bar.spines.values():
            spine.set_visible(False)
        self.ax_bar.grid(axis="x", color="#242B3B", linestyle="--", alpha=0.6)

    def _update_overview_charts(self, data: Dict[str, Any]):
        try:
            self.ax_pie.clear()
            self.ax_bar.clear()
            self.ax_pie.set_facecolor(CARD_BG)
            self.ax_bar.set_facecolor(CARD_BG)

            # 1. Protocol Vertical Column Bar Chart
            protos = data.get("protocol_counts", {})
            plot_protos = {k: v for k, v in protos.items() if v > 0}

            if plot_protos:
                labels = list(plot_protos.keys())
                counts = list(plot_protos.values())
                palette = [ACCENT_CYAN, ACCENT_PURPLE, ACCENT_AMBER, "#38BDF8", ACCENT_GREEN, ACCENT_RED, "#C084FC"]
                bar_colors = [palette[i % len(palette)] for i in range(len(labels))]

                bars = self.ax_pie.bar(labels, counts, color=bar_colors, width=0.5, edgecolor="none")
                self.ax_pie.set_title("Protocol Breakdown (Packets)", color="#E2E8F0", fontsize=11, fontweight="bold", pad=8)
                self.ax_pie.tick_params(colors="#94A3B8", labelsize=8)
                for spine in self.ax_pie.spines.values():
                    spine.set_visible(False)
                self.ax_pie.grid(axis="y", color="#242B3B", linestyle="--", alpha=0.6)

                # Numbers above bars
                max_val = max(counts) if counts else 1
                self.ax_pie.set_ylim(0, max_val * 1.15)
                for bar in bars:
                    yval = bar.get_height()
                    if yval > 0:
                        lbl_str = f"{yval:,}" if yval < 10000 else f"{yval/1000:.0f}k"
                        self.ax_pie.text(
                            bar.get_x() + bar.get_width() / 2,
                            yval,
                            lbl_str,
                            ha="center",
                            va="bottom",
                            color="#FFFFFF",
                            fontsize=8,
                            fontweight="bold",
                        )
            else:
                self.ax_pie.bar(["None"], [0], color="#2A3042")
                self.ax_pie.set_title("Protocol Breakdown", color="#E2E8F0", fontsize=11, fontweight="bold", pad=8)
                self.ax_pie.tick_params(colors="#94A3B8", labelsize=8)
                for spine in self.ax_pie.spines.values():
                    spine.set_visible(False)

            # 2. Top Destination Ports Horizontal Bar
            ports = data.get("dst_port_counts", {})
            if ports:
                port_labels = [f"Port {p}" for p in list(ports.keys())[::-1]]
                port_vals = list(ports.values())[::-1]
                bars = self.ax_bar.barh(port_labels, port_vals, color=ACCENT_CYAN, height=0.55, edgecolor="none")
                self.ax_bar.set_title("Top Destination Ports (Probed)", color="#E2E8F0", fontsize=11, fontweight="bold", pad=8)
                self.ax_bar.tick_params(colors="#94A3B8", labelsize=8)
                for spine in self.ax_bar.spines.values():
                    spine.set_visible(False)
                self.ax_bar.grid(axis="x", color="#242B3B", linestyle="--", alpha=0.6)
            else:
                self.ax_bar.barh(["None"], [0], color="#2A3042")
                self.ax_bar.set_title("Top Destination Ports", color="#E2E8F0", fontsize=11, fontweight="bold", pad=8)
                self.ax_bar.tick_params(colors="#94A3B8", labelsize=8)
                for spine in self.ax_bar.spines.values():
                    spine.set_visible(False)

            self.fig.tight_layout()
            self.canvas.draw_idle()
        except Exception:
            pass

    # --- TAB 2: Red Flags & Live Alerts ---
    def _setup_alerts_tab(self):
        tab = self.tab_alerts
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Filter & Action Header Bar
        header_bar = ctk.CTkFrame(tab, fg_color="#141722", corner_radius=8)
        header_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 8))
        header_bar.grid_columnconfigure(1, weight=1)

        self.lbl_alert_stats = ctk.CTkLabel(
            header_bar,
            text="🚨 Live Threat Feed (0 Red Flags)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#F8FAFC",
        )
        self.lbl_alert_stats.grid(row=0, column=0, padx=12, pady=8, sticky="w")

        # Search / filter box
        self.entry_filter = ctk.CTkEntry(
            header_bar,
            placeholder_text="🔍 Filter alerts by IP, category, or keyword...",
            font=ctk.CTkFont(size=12),
            height=30,
            fg_color="#1E2433",
            border_color=CARD_BORDER,
        )
        self.entry_filter.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        self.entry_filter.bind("<KeyRelease>", lambda e: self._filter_alerts())

        # Severity Filter Dropdown
        self.opt_sev_filter = ctk.CTkOptionMenu(
            header_bar,
            values=["All Severities", "High Only", "Medium+", "Low"],
            command=lambda v: self._filter_alerts(),
            height=30,
            width=120,
            fg_color="#1E293B",
            button_color="#334155",
        )
        self.opt_sev_filter.set("All Severities")
        self.opt_sev_filter.grid(row=0, column=2, padx=6, pady=8)

        self.btn_clear_alerts = ctk.CTkButton(
            header_bar,
            text="Clear",
            width=65,
            height=30,
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            command=self._clear_alerts,
        )
        self.btn_clear_alerts.grid(row=0, column=3, padx=(0, 10), pady=8)

        # Scrollable Textbox for alerts
        self.txt_alerts = ctk.CTkTextbox(
            tab,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            corner_radius=8,
            fg_color="#0F121C",
            border_width=1,
            border_color=CARD_BORDER,
        )
        self.txt_alerts.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Color tags
        self.txt_alerts.tag_config("time", foreground="#64748B")
        self.txt_alerts.tag_config("high", foreground="#FF4D6D")
        self.txt_alerts.tag_config("med", foreground="#FBBF24")
        self.txt_alerts.tag_config("low", foreground="#38BDF8")
        self.txt_alerts.tag_config("info", foreground=ACCENT_GREEN)
        self.txt_alerts.tag_config("text", foreground="#E2E8F0")

        self.txt_alerts.insert("end", "[INFO] Ready for packet stream. Threat events will appear here in real time.\n", "info")

    def _clear_alerts(self):
        self.txt_alerts.delete("1.0", "end")

    def _filter_alerts(self):
        keyword = self.entry_filter.get().strip().lower()
        sev_choice = self.opt_sev_filter.get()

        self.txt_alerts.delete("1.0", "end")
        for a in self.all_alerts:
            sev = a.get("severity", "low").lower()
            if sev_choice == "High Only" and sev != "high":
                continue
            if sev_choice == "Medium+" and sev not in ("high", "medium"):
                continue

            full_line = f"{a.get('category', '')} {a.get('message', '')} {a.get('src', '')} {a.get('dst', '')}".lower()
            if keyword and keyword not in full_line:
                continue

            self._append_single_alert_to_box(a)

    def _append_single_alert_to_box(self, a: Dict[str, Any]):
        sev = a.get("severity", "medium").lower()
        cat = a.get("category", "General")
        msg = a.get("message", "")
        ts = a.get("timestamp", datetime.now().strftime("%H:%M:%S"))

        if sev == "high":
            badge = "🔴 [HIGH]"
            tag = "high"
        elif sev == "low":
            badge = "🔵 [LOW]"
            tag = "low"
        else:
            badge = "🟡 [MED]"
            tag = "med"

        self.txt_alerts.insert("end", f"[{ts}] ", "time")
        self.txt_alerts.insert("end", f"{badge} ", tag)
        self.txt_alerts.insert("end", f"[{cat}] ", tag)
        self.txt_alerts.insert("end", f"{msg}\n", "text")
        self.txt_alerts.see("end")

    # --- TAB 3: Top Talkers & Conversations ---
    def _setup_talkers_tab(self):
        tab = self.tab_talkers
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        # Left: Top Conversations Table / Text
        left_frame = ctk.CTkFrame(tab, fg_color="#12151E", corner_radius=10, border_width=1, border_color=CARD_BORDER)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(10, 6), pady=10)
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(1, weight=1)

        lbl_conv = ctk.CTkLabel(left_frame, text="Active Conversations (Top Flows)", font=ctk.CTkFont(size=13, weight="bold"), text_color=ACCENT_CYAN)
        lbl_conv.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="w")

        self.txt_conversations = ctk.CTkTextbox(
            left_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0F121C",
            border_width=0,
            wrap="none",
        )
        self.txt_conversations.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.txt_conversations.insert("end", "Flow data will populate once analysis completes.\n")

        # Right: Top Talkers Chart & List
        right_frame = ctk.CTkFrame(tab, fg_color="#12151E", corner_radius=10, border_width=1, border_color=CARD_BORDER)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=10)
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(1, weight=1)

        lbl_talk = ctk.CTkLabel(right_frame, text="Top Transmitting Hosts (Bytes Sent)", font=ctk.CTkFont(size=13, weight="bold"), text_color=ACCENT_PURPLE)
        lbl_talk.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="w")

        self.txt_top_talkers = ctk.CTkTextbox(
            right_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0F121C",
            border_width=0,
            wrap="none",
        )
        self.txt_top_talkers.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.txt_top_talkers.insert("end", "Top talker statistics will populate after inspection.\n")

    def _update_talkers_tab(self, data: Dict[str, Any]):
        # Populate Conversations
        convs = data.get("top_conversations", [])
        self.txt_conversations.delete("1.0", "end")
        if not convs:
            self.txt_conversations.insert("end", "No active conversations recorded.\n")
        else:
            header = f"{'Source':<18} {'Destination':<22} {'Proto':<6} {'Bytes':<10} {'Packets':<8}\n"
            self.txt_conversations.insert("end", header)
            self.txt_conversations.insert("end", "-" * 66 + "\n")
            for c in convs[:35]:
                dst_full = f"{c.get('dst', '')}:{c.get('dst_port', '')}"
                b_str = f"{c.get('bytes', 0) / 1024:.1f} KB" if c.get('bytes', 0) < 1024 * 1024 else f"{c.get('bytes', 0) / (1024*1024):.2f} MB"
                line = f"{c.get('src', ''):<18} {dst_full:<22} {c.get('proto', ''):<6} {b_str:<10} {c.get('packets', 0):<8}\n"
                self.txt_conversations.insert("end", line)

        # Populate Top Talkers
        talkers = data.get("top_talkers_sent", [])
        self.txt_top_talkers.delete("1.0", "end")
        if not talkers:
            self.txt_top_talkers.insert("end", "No host transmission data available.\n")
        else:
            header = f"{'Rank':<6} {'IP Address':<22} {'Volume (MB)':<14} {'Raw Bytes'}\n"
            self.txt_top_talkers.insert("end", header)
            self.txt_top_talkers.insert("end", "-" * 56 + "\n")
            for idx, (ip, b) in enumerate(talkers, start=1):
                mb_str = f"{b / (1024 * 1024):.2f} MB"
                line = f"#{idx:<5} {str(ip):<22} {mb_str:<14} {b:,}\n"
                self.txt_top_talkers.insert("end", line)

    # --- TAB 4: Deep Attack Detections ---
    def _setup_attacks_tab(self):
        tab = self.tab_attacks
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Category Selector Bar
        cat_bar = ctk.CTkFrame(tab, fg_color="#141722", corner_radius=8)
        cat_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 8))
        cat_bar.grid_columnconfigure(1, weight=1)

        lbl_cat = ctk.CTkLabel(cat_bar, text="Attack Vector Inspector:", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_MUTED)
        lbl_cat.grid(row=0, column=0, padx=12, pady=8, sticky="w")

        self.opt_attack_cat = ctk.CTkSegmentedButton(
            cat_bar,
            values=["Credential Leaks", "Port Scans", "Suspicious DNS / DGA", "C2 Beacons", "ARP & Sweeps"],
            command=self._render_attack_view,
            selected_color="#2563EB",
            selected_hover_color="#1D4ED8",
        )
        self.opt_attack_cat.set("Credential Leaks")
        self.opt_attack_cat.grid(row=0, column=1, padx=12, pady=6, sticky="ew")

        # Attack Detail Textbox
        self.txt_attacks = ctk.CTkTextbox(
            tab,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            corner_radius=8,
            fg_color="#0F121C",
            border_width=1,
            border_color=CARD_BORDER,
        )
        self.txt_attacks.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        self.txt_attacks.tag_config("red", foreground="#FF4D6D")
        self.txt_attacks.tag_config("yellow", foreground="#FBBF24")
        self.txt_attacks.tag_config("cyan", foreground=ACCENT_CYAN)
        self.txt_attacks.tag_config("norm", foreground="#E2E8F0")

        self.txt_attacks.insert("end", "[INFO] Attack detection modules will populate once capture analysis is run.\n", "cyan")

    def _render_attack_view(self, selected_category: str):
        if not self.completed_data:
            self.txt_attacks.delete("1.0", "end")
            self.txt_attacks.insert("end", f"No data loaded yet for {selected_category}. Run analysis first.\n")
            return

        self.txt_attacks.delete("1.0", "end")
        data = self.completed_data

        if selected_category == "Credential Leaks":
            creds = data.get("credential_hits", [])
            if not creds:
                self.txt_attacks.insert("end", "✅ No plaintext credentials or authentication tokens detected in payload streams.\n", "cyan")
            else:
                self.txt_attacks.insert("end", f"🚨 DETECTED {len(creds)} PLAINTEXT CREDENTIAL / AUTH HIT(S):\n\n", "red")
                for i, c in enumerate(creds, start=1):
                    self.txt_attacks.insert("end", f"[{i}] {c.get('src')} -> {c.get('dst')}:{c.get('dport')}\n", "yellow")
                    self.txt_attacks.insert("end", f"    Pattern: {c.get('pattern')}\n", "norm")
                    self.txt_attacks.insert("end", f"    Snippet: {c.get('snippet')}\n\n", "red")

        elif selected_category == "Port Scans":
            vert = data.get("vertical_scans", [])
            horiz = data.get("horizontal_scans", [])
            if not vert and not horiz:
                self.txt_attacks.insert("end", "✅ No vertical or horizontal port scans exceeded threshold detection.\n", "cyan")
            else:
                if vert:
                    self.txt_attacks.insert("end", f"🔴 VERTICAL PORT SCANS ({len(vert)} targets probed):\n", "red")
                    for s in vert:
                        self.txt_attacks.insert("end", f"  • Attacker {s.get('src')} probed {s.get('unique_dst_ports')} unique ports on {s.get('dst')}\n", "yellow")
                    self.txt_attacks.insert("end", "\n")
                if horiz:
                    self.txt_attacks.insert("end", f"🟠 HORIZONTAL PORT SCANS ({len(horiz)} detected):\n", "red")
                    for s in horiz:
                        self.txt_attacks.insert("end", f"  • Host {s.get('src')} contacted {s.get('unique_dst_hosts')} distinct IP addresses on identical port\n", "yellow")

        elif selected_category == "Suspicious DNS / DGA":
            dns_a = data.get("dns_alerts", [])
            if not dns_a:
                self.txt_attacks.insert("end", "✅ No high-entropy or DGA-like domain queries identified.\n", "cyan")
            else:
                self.txt_attacks.insert("end", f"⚠️ SUSPICIOUS DNS QUERIES ({len(dns_a)} flagged):\n\n", "yellow")
                for d in dns_a:
                    self.txt_attacks.insert("end", f"  • Domain: {d.get('domain')}\n", "red")
                    self.txt_attacks.insert("end", f"    Reason: {d.get('reason')} | Shannon Entropy: {d.get('entropy')} | Length: {d.get('length')}\n", "norm")
                    self.txt_attacks.insert("end", f"    Source IP: {d.get('src')}\n\n", "cyan")

        elif selected_category == "C2 Beacons":
            beacons = data.get("beacons", [])
            if not beacons:
                self.txt_attacks.insert("end", "✅ No periodic command-and-control beaconing flows detected.\n", "cyan")
            else:
                self.txt_attacks.insert("end", f"📡 C2 BEACON CANDIDATES ({len(beacons)} flows):\n\n", "red")
                for b in beacons:
                    self.txt_attacks.insert("end", f"  • Flow: {b.get('src')} -> {b.get('dst')}:{b.get('dst_port')} ({b.get('proto')})\n", "yellow")
                    self.txt_attacks.insert("end", f"    Mean Interval: {b.get('mean_interval_s')}s | Variance (CV): {b.get('coefficient_of_variation')} | Samples: {b.get('samples')}\n\n", "norm")

        elif selected_category == "ARP & Sweeps":
            self.txt_attacks.insert("end", "🔎 NETWORK LAYER ANOMALIES & SWEEPS:\n\n", "cyan")
            arp_spoofs = [a for a in data.get("alerts", []) if a.get("category") == "ARP Spoofing"]
            sweeps = [a for a in data.get("alerts", []) if a.get("category") == "Ping Sweep"]

            if arp_spoofs:
                self.txt_attacks.insert("end", "🚨 ARP Spoofing / Duplicate MACs:\n", "red")
                for a in arp_spoofs:
                    self.txt_attacks.insert("end", f"  • {a.get('message')}\n", "yellow")
                self.txt_attacks.insert("end", "\n")
            else:
                self.txt_attacks.insert("end", "✅ No ARP poisoning or IP conflict detected.\n\n", "norm")

            if sweeps:
                self.txt_attacks.insert("end", "⚠️ ICMP Ping Sweeps:\n", "yellow")
                for a in sweeps:
                    self.txt_attacks.insert("end", f"  • {a.get('message')}\n", "norm")
            else:
                self.txt_attacks.insert("end", "✅ No ICMP sweep scans exceeded alert threshold.\n", "norm")

    # -------------------------------------------------------------------------
    # Status Bar
    # -------------------------------------------------------------------------
    def _build_status_bar(self, row: int):
        self.status_frame = ctk.CTkFrame(self.main_frame, height=26, fg_color="transparent")
        self.status_frame.grid(row=row, column=0, sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)

        self.lbl_status = ctk.CTkLabel(
            self.status_frame,
            text="Status: Ready | Load a PCAP/PCAPNG file to inspect",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
            anchor="w",
        )
        self.lbl_status.grid(row=0, column=0, sticky="w")

    # -------------------------------------------------------------------------
    # Actions & Analysis Lifecycle
    # -------------------------------------------------------------------------
    def _on_browse_file(self):
        file_selected = filedialog.askopenfilename(
            title="Select PCAP or PCAPNG Capture File",
            filetypes=[
                ("Packet Captures", "*.pcap *.pcapng *.cap"),
                ("PCAP files (*.pcap)", "*.pcap"),
                ("PCAPNG files (*.pcapng)", "*.pcapng"),
                ("All files (*.*)", "*.*"),
            ],
        )
        if not file_selected:
            return

        p = Path(file_selected)
        if not p.exists():
            messagebox.showerror("Error", f"Selected file does not exist:\n{file_selected}")
            return

        self.pcap_path = p
        size_mb = p.stat().st_size / (1024 * 1024)
        size_str = f"{size_mb:.2f} MB" if size_mb >= 1.0 else f"{p.stat().st_size / 1024:.1f} KB"

        self.lbl_selected_file.configure(
            text=f"{p.name} ({size_str})",
            text_color="#FFFFFF",
        )
        self.btn_start.configure(state="normal")
        self.btn_pdf_report.configure(state="disabled")
        self.lbl_status.configure(text=f"Status: File loaded ({p.name}) | Ready to parse")

    def _start_analysis(self):
        if not self.pcap_path or not self.pcap_path.exists():
            messagebox.showerror("No File", "Please select a valid PCAP file first.")
            return

        if self.is_running:
            return

        self._reset_dashboard(keep_file=True)
        self.is_running = True

        self.btn_start.configure(state="disabled")
        self.btn_browse.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_pdf_report.configure(state="disabled")
        self.prog_bar.set(0.0)
        self.lbl_progress.configure(text="Streaming packets...")
        self.lbl_status.configure(text=f"Status: Parsing {self.pcap_path.name} in background thread...")

        self.txt_alerts.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] ", "time")
        self.txt_alerts.insert("end", f"[START] Streaming analysis started on {self.pcap_path.name}...\n", "info")

        # Create temporary working directory for any internal operations
        outdir = BASE_DIR / "output"
        outdir.mkdir(parents=True, exist_ok=True)

        self.analyzer_instance = GuiPcapAnalyzer(
            pcap_path=str(self.pcap_path),
            outdir=str(outdir),
            event_queue=self.event_queue,
        )

        self.analysis_thread = threading.Thread(
            target=self.analyzer_instance.run,
            daemon=True,
            name="PcapWorkerThread",
        )
        self.analysis_thread.start()

    def _stop_analysis(self):
        if self.analyzer_instance and self.is_running:
            self.lbl_status.configure(text="Status: Halting parser (wrapping up partial findings)...")
            self.lbl_progress.configure(text="Stopping...")
            self.analyzer_instance._interrupted = True
            self.btn_stop.configure(state="disabled")

    def _reset_dashboard(self, keep_file: bool = False):
        self.all_alerts = []
        self.high_alerts = 0
        self.med_alerts = 0
        self.low_alerts = 0
        self.completed_data = None

        self.lbl_stat_packets.configure(text="0")
        self.lbl_stat_packets_sub.configure(text="0 pps rate")
        self.lbl_stat_bytes.configure(text="0.0 KB")
        self.lbl_stat_bytes_sub.configure(text="0 bytes payload")
        self.lbl_stat_duration.configure(text="0.00 s")
        self.lbl_stat_duration_sub.configure(text="0.0s elapsed")
        self.lbl_stat_alerts.configure(text="0", text_color="#FFFFFF")
        self.lbl_stat_alerts_sub.configure(text="0 High | 0 Med | 0 Low")
        self.lbl_proto_pills.configure(
            text="Live Traffic Distribution:  TCP: 0  |  UDP: 0  |  IPv4: 0  |  IPv6: 0  |  ARP: 0  |  ICMP: 0"
        )
        self.lbl_alert_stats.configure(text="🚨 Live Threat Feed (0 Red Flags)")
        self.prog_bar.set(0.0)
        self.lbl_progress.configure(text="Engine Idle")
        self.btn_pdf_report.configure(state="disabled")

        self._style_blank_axes()
        self.canvas.draw_idle()

        if not keep_file:
            self.pcap_path = None
            self.lbl_selected_file.configure(
                text="No capture loaded",
                text_color="gray60",
            )
            self.btn_start.configure(state="disabled")
            self.lbl_status.configure(text="Status: Ready | Load a PCAP/PCAPNG file to inspect")

        self.txt_alerts.delete("1.0", "end")
        self.txt_conversations.delete("1.0", "end")
        self.txt_top_talkers.delete("1.0", "end")
        self.txt_attacks.delete("1.0", "end")

    def _export_pdf_report(self):
        if not self.completed_data:
            messagebox.showwarning("No Data", "Please run analysis on a capture file first.")
            return

        stem = Path(self.completed_data.get("pcap_file", "capture")).stem
        default_name = f"{stem}_DFIR_Threat_Report.pdf"

        save_path = filedialog.asksaveasfilename(
            title="Save Executive PDF Threat Report",
            initialfile=default_name,
            defaultextension=".pdf",
            filetypes=[("PDF Document (*.pdf)", "*.pdf")],
        )
        if not save_path:
            return

        try:
            PdfThreatReportBuilder.generate(self.completed_data, save_path)
            res = messagebox.askyesno(
                "PDF Report Generated",
                f"Executive PDF Threat Report successfully exported to:\n{save_path}\n\nWould you like to open it now?",
            )
            if res:
                if sys.platform == "win32":
                    os.startfile(save_path)
                else:
                    import subprocess
                    subprocess.Popen(["xdg-open", save_path])
        except Exception as exc:
            messagebox.showerror("Export Failed", f"Failed to generate PDF report:\n{exc}")

    # -------------------------------------------------------------------------
    # Main-Thread Queue Consumer
    # -------------------------------------------------------------------------
    def _process_queue(self):
        try:
            if not self.winfo_exists():
                return
            while not self.event_queue.empty():
                event_type, data = self.event_queue.get_nowait()
                if event_type == "progress":
                    self._handle_progress_event(data)
                elif event_type == "alert":
                    self._handle_alert_event(data)
                elif event_type == "complete":
                    self._handle_complete_event(data)
                elif event_type == "error":
                    self._handle_error_event(data)
        except Exception:
            pass
        finally:
            try:
                if self.winfo_exists():
                    self.after(50, self._process_queue)
            except Exception:
                pass

    def _handle_progress_event(self, data: Dict[str, Any]):
        pkts = data.get("total_packets", 0)
        total_b = data.get("total_bytes", 0)
        dur = data.get("duration", 0.0)
        pps = data.get("pps", 0.0)
        pct = data.get("pct", 0.0)
        protos = data.get("protocol_counts", {})

        self.lbl_stat_packets.configure(text=f"{pkts:,}")
        self.lbl_stat_packets_sub.configure(text=f"{pps:,.0f} pps rate")

        if total_b >= 1024 * 1024:
            self.lbl_stat_bytes.configure(text=f"{total_b / (1024 * 1024):.2f} MB")
        else:
            self.lbl_stat_bytes.configure(text=f"{total_b / 1024:.1f} KB")
        self.lbl_stat_bytes_sub.configure(text=f"{total_b:,} bytes payload")

        self.lbl_stat_duration.configure(text=f"{dur:.2f} s")

        self.prog_bar.set(pct / 100.0)
        self.lbl_progress.configure(text=f"{pct:.1f}% ({pkts:,} pkts)")
        self.lbl_status.configure(text=f"Status: Streaming packet stream ({pct:.1f}% parsed)...")

        proto_txt = (
            f"Live Traffic Distribution:  TCP: {protos.get('TCP', 0):,}  |  "
            f"UDP: {protos.get('UDP', 0):,}  |  "
            f"IPv4: {protos.get('IPv4', 0):,}  |  "
            f"IPv6: {protos.get('IPv6', 0):,}  |  "
            f"ARP: {protos.get('ARP', 0):,}  |  "
            f"ICMP: {protos.get('ICMP', 0):,}"
        )
        self.lbl_proto_pills.configure(text=proto_txt)

    def _handle_alert_event(self, alert: Dict[str, Any]):
        self.all_alerts.append(alert)
        sev = alert.get("severity", "medium").lower()

        if sev == "high":
            self.high_alerts += 1
        elif sev == "low":
            self.low_alerts += 1
        else:
            self.med_alerts += 1

        total_cnt = len(self.all_alerts)
        self.lbl_stat_alerts.configure(
            text=f"{total_cnt}",
            text_color=ACCENT_RED if self.high_alerts > 0 else ACCENT_AMBER,
        )
        self.lbl_stat_alerts_sub.configure(
            text=f"{self.high_alerts} High | {self.med_alerts} Med | {self.low_alerts} Low"
        )
        self.lbl_alert_stats.configure(
            text=f"🚨 Live Threat Feed ({total_cnt} Red Flags: {self.high_alerts} High, {self.med_alerts} Med)"
        )

        self._append_single_alert_to_box(alert)

    def _handle_complete_event(self, data: Dict[str, Any]):
        self.is_running = False
        self.completed_data = data

        self.btn_start.configure(state="normal")
        self.btn_browse.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_pdf_report.configure(state="normal")

        self.prog_bar.set(1.0)
        self.lbl_progress.configure(text="Scan Finished (100%)")

        pkts = data.get("total_packets", 0)
        total_b = data.get("total_bytes", 0)
        dur = data.get("duration", 0.0)
        pps = data.get("pps", 0.0)
        elapsed = data.get("elapsed", 0.0)
        interrupted = data.get("interrupted", False)
        protos = data.get("protocol_counts", {})

        # Ensure summary cards display exact final numbers
        self.lbl_stat_packets.configure(text=f"{pkts:,}")
        self.lbl_stat_packets_sub.configure(text=f"{pps:,.0f} pps rate")

        if total_b >= 1024 * 1024:
            self.lbl_stat_bytes.configure(text=f"{total_b / (1024 * 1024):.2f} MB")
        else:
            self.lbl_stat_bytes.configure(text=f"{total_b / 1024:.1f} KB")
        self.lbl_stat_bytes_sub.configure(text=f"{total_b:,} bytes payload")

        self.lbl_stat_duration.configure(text=f"{dur:.2f} s")
        self.lbl_stat_duration_sub.configure(text=f"{elapsed:.2f}s elapsed")

        proto_txt = (
            f"Live Traffic Distribution:  TCP: {protos.get('TCP', 0):,}  |  "
            f"UDP: {protos.get('UDP', 0):,}  |  "
            f"IPv4: {protos.get('IPv4', 0):,}  |  "
            f"IPv6: {protos.get('IPv6', 0):,}  |  "
            f"ARP: {protos.get('ARP', 0):,}  |  "
            f"ICMP: {protos.get('ICMP', 0):,}"
        )
        self.lbl_proto_pills.configure(text=proto_txt)

        status_msg = (
            f"Analysis complete in {elapsed:.2f}s ({pkts:,} packets parsed). "
            f"{'Partial results preserved.' if interrupted else 'All threat engines evaluated.'}"
        )
        self.lbl_status.configure(text=f"Status: {status_msg}")

        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_alerts.insert("end", f"[{ts}] ", "time")
        if interrupted:
            self.txt_alerts.insert("end", "[WARN] Analysis interrupted by user. Partial scan results preserved.\n", "med")
        else:
            self.txt_alerts.insert("end", f"[COMPLETE] {status_msg}\n", "info")
        self.txt_alerts.see("end")

        # Update Graphs & Other Tabs
        self._update_overview_charts(data)
        self._update_talkers_tab(data)
        self._render_attack_view(self.opt_attack_cat.get())

    def _handle_error_event(self, err_msg: str):
        self.is_running = False
        self.btn_start.configure(state="normal")
        self.btn_browse.configure(state="normal")
        self.btn_stop.configure(state="disabled")

        self.lbl_status.configure(text="Status: Analysis encountered an error.")
        self.lbl_progress.configure(text="Engine Error")

        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_alerts.insert("end", f"[{ts}] ", "time")
        self.txt_alerts.insert("end", f"[ERROR] {err_msg}\n", "high")
        self.txt_alerts.see("end")

        messagebox.showerror("Analysis Error", err_msg)


def main():
    app = PcapAnalyzerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
