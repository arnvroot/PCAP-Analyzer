# turns everything gathered during the run into the json files app.py
# reads, plus a quick colored summary printed to the terminal

from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any, List

from .config import TOP_N

log = logging.getLogger("pcap_analyzer")


class ReportWriterMixin:
    def _write_json(self, name: str, data: Any) -> None:
        path = self.outdir / name
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        log.info(f"Wrote {path} ({path.stat().st_size / 1024:.1f} KB)")

    def _write_outputs(self) -> None:
        duration = (self.last_ts - self.first_ts) if (self.first_ts and self.last_ts) else 0
        pps = self.total_packets / duration if duration > 0 else 0
        bps = self.total_bytes / duration if duration > 0 else 0

        summary = {
            "pcap_file": str(self.pcap_path.name),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "capture_start": self.first_ts,
            "capture_end": self.last_ts,
            "duration_seconds": round(duration, 3),
            "avg_packets_per_sec": round(pps, 2),
            "avg_bytes_per_sec": round(bps, 2),
            "flow_count": len(self.flows),
            "alert_count": len(self.alerts),
            "interrupted_partial_results": self._interrupted,
        }
        self._write_json("summary.json", summary)

        statistics_json = {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": round(duration, 3),
            "avg_packets_per_sec": round(pps, 2),
            "avg_bytes_per_sec": round(bps, 2),
            "largest_packet": self.max_pkt_size,
            "smallest_packet": self.min_pkt_size,
            "packet_size_distribution": dict(self.pkt_size_histogram),
        }
        self._write_json("statistics.json", statistics_json)

        total_proto = sum(self.protocol_counts.values()) or 1
        protocols_json = {
            "counts": dict(self.protocol_counts),
            "percentages": {k: round(v / total_proto * 100, 2) for k, v in self.protocol_counts.items()},
            "traffic_classification": dict(self.traffic_class_counts),
            "tcp_flags": dict(self.tcp_flags_totals),
            "icmp": {
                "echo_request": self.icmp_echo_request,
                "echo_reply": self.icmp_echo_reply,
                "large_packets": self.icmp_large,
                "ping_sweep_candidates": self.ping_sweep_candidates,
            },
            "arp": {
                "requests": self.arp_requests,
                "replies": self.arp_replies,
                "spoof_candidates": self.arp_spoof_candidates,
            },
        }
        self._write_json("protocols.json", protocols_json)

        flows_json = {
            "top_conversations": self.top_conversations,
            "large_transfers": self.large_transfers,
            "top_talkers": {
                "bytes_sent": self.bytes_sent.as_dict(),
                "bytes_received": self.bytes_received.as_dict(),
                "packets_sent": self.packets_sent.as_dict(),
                "packets_received": self.packets_received.as_dict(),
            },
            "beacon_detection": self.beacons,
        }
        self._write_json("flows.json", flows_json)

        ports_json = {
            "top_dst_ports": Counter(self.dst_port_counts).most_common(TOP_N),
            "top_src_ports": Counter(self.src_port_counts).most_common(TOP_N),
            "uncommon_ports": self.uncommon_ports,
            "vertical_scans": self.vertical_scans,
            "horizontal_scans": self.horizontal_scans,
            "syn_scan_candidates": self.syn_scan_candidates,
        }
        self._write_json("ports.json", ports_json)

        dns_json = {
            "top_queried_domains": Counter(self.dns_queries).most_common(TOP_N),
            "query_types": dict(self.dns_qtypes),
            "records": self.dns_records[:2000],
            "alerts": self.dns_alerts[:200],
        }
        self._write_json("dns.json", dns_json)

        self._write_json("http.json", {"records": self.http_records})
        self._write_json("tls.json", {"records": self.tls_records})

        alerts_json = {
            "alerts": self.alerts,
            "credential_leaks": self.credential_hits,
        }
        self._write_json("alerts.json", alerts_json)

        timeline_json = {
            "packets_per_second": dict(sorted(self.timeline_pps.items())),
            "bytes_per_second": dict(sorted(self.timeline_bps.items())),
        }
        self._write_json("timeline.json", timeline_json)

        log.info(f"All outputs written to {self.outdir.resolve()}")
        self._print_console_report()

    def _print_console_report(self) -> None:
        """quick colored terminal summary, right after streaming finishes.
        just ansi codes + box drawing chars, no extra deps. worst case
        (terminal doesn't support ansi) the codes just get ignored."""

        RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
        RED, YEL, GRN, CYA, MAG = "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[95m"
        WIDTH = 78

        def rule(char: str = "─") -> str:
            return char * WIDTH

        def header(title: str, color: str = CYA) -> str:
            pad = max(0, WIDTH - len(title) - 4)
            return f"\n{color}{BOLD}┌─ {title} " + "─" * pad + f"┐{RESET}"

        def kv_row(label: str, value: str, color: str = "") -> str:
            return f"  {DIM}{label:<28}{RESET} {color}{value}{RESET}"

        sev_color = {"high": RED, "medium": YEL, "low": GRN}
        sev_icon = {"high": "🔴", "medium": "🟠", "low": "🟡"}

        duration = (self.last_ts - self.first_ts) if (self.first_ts and self.last_ts) else 0
        pps = self.total_packets / duration if duration > 0 else 0
        bps = self.total_bytes / duration if duration > 0 else 0

        lines: List[str] = []
        lines.append(f"\n{BOLD}{MAG}{rule('═')}{RESET}")
        lines.append(f"{BOLD}{MAG}  SCAN COMPLETE — {self.pcap_path.name}{RESET}")
        lines.append(f"{BOLD}{MAG}{rule('═')}{RESET}")

        lines.append(header("CAPTURE SUMMARY"))
        lines.append(kv_row("Total Packets", f"{self.total_packets:,}"))
        lines.append(kv_row("Total Bytes", f"{self.total_bytes:,} ({self.total_bytes/1024/1024:.2f} MB)"))
        lines.append(kv_row("Duration", f"{duration:.2f} s"))
        lines.append(kv_row("Avg Packets/sec", f"{pps:.1f}"))
        lines.append(kv_row("Avg Bytes/sec", f"{bps:.1f}"))
        lines.append(kv_row("Unique Flows", f"{len(self.flows):,}"))

        lines.append(header("PROTOCOL BREAKDOWN"))
        total_proto = sum(self.protocol_counts.values()) or 1
        bar_width = 30
        for proto, cnt in self.protocol_counts.most_common():
            pct = cnt / total_proto * 100
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)
            lines.append(f"  {proto:<8} {CYA}{bar}{RESET} {pct:5.1f}%  ({cnt:,})")

        lines.append(header("TOP 5 TALKERS (by bytes sent)"))
        for ip, b in self.bytes_sent.top()[:5]:
            lines.append(kv_row(ip, f"{b/1024/1024:.2f} MB"))

        alert_counts = Counter(a["severity"] for a in self.alerts)
        title_color = RED if alert_counts.get("high") else (YEL if alert_counts.get("medium") else GRN)
        lines.append(header(f"ALERTS ({len(self.alerts)} total)", color=title_color))
        if not self.alerts:
            lines.append(f"  {GRN}✓ No suspicious activity detected.{RESET}")
        else:
            lines.append(
                f"  {RED}{alert_counts.get('high', 0)} high{RESET}   "
                f"{YEL}{alert_counts.get('medium', 0)} medium{RESET}   "
                f"{GRN}{alert_counts.get('low', 0)} low{RESET}\n"
            )
            order = {"high": 0, "medium": 1, "low": 2}
            sorted_alerts = sorted(self.alerts, key=lambda a: order.get(a["severity"], 3))
            for a in sorted_alerts[:15]:
                c = sev_color.get(a["severity"], "")
                icon = sev_icon.get(a["severity"], "•")
                lines.append(f"  {icon} {c}{BOLD}[{a['category']}]{RESET} {a['message']}")
            if len(self.alerts) > 15:
                lines.append(f"  {DIM}... and {len(self.alerts) - 15} more (see alerts.json / dashboard){RESET}")

        if self.credential_hits:
            lines.append(header("CREDENTIAL LEAKS", color=RED))
            for c in self.credential_hits[:5]:
                lines.append(f"  {RED}⚠ {c['src']} -> {c['dst']}:{c['dport']}{RESET}  {DIM}{c['snippet']}{RESET}")
            if len(self.credential_hits) > 5:
                lines.append(f"  {DIM}... and {len(self.credential_hits) - 5} more{RESET}")

        lines.append(f"\n{BOLD}{MAG}{rule('═')}{RESET}")
        lines.append(f"  {DIM}Full details: {self.outdir.resolve()}{RESET}")
        lines.append(f"  {DIM}Launch dashboard: streamlit run app.py -- --datadir {self.outdir}{RESET}")
        lines.append(f"{BOLD}{MAG}{rule('═')}{RESET}\n")

        print("\n".join(lines))
