# these only run once, after all packets are streamed, since they need
# the full picture (flow deltas, port sets, etc) to work out anything

from __future__ import annotations

import logging
import statistics
from collections import defaultdict
from typing import Any, Dict, List

from .config import (
    UNCOMMON_PORT_THRESHOLD, BEACON_MIN_SAMPLES, BEACON_CV_THRESHOLD,
    PORT_SCAN_UNIQUE_PORTS_THRESHOLD, PORT_SCAN_UNIQUE_HOSTS_THRESHOLD,
    LARGE_TRANSFER_BYTES, TOP_N,
)

log = logging.getLogger("pcap_analyzer")


class DetectorsMixin:
    def _post_process(self) -> None:
        log.info("Running post-processing detections (beaconing, scans, alerts)...")

        # uncommon ports = seen rarely overall
        self.uncommon_ports = [
            port for port, cnt in self.dst_port_counts.items()
            if cnt < UNCOMMON_PORT_THRESHOLD
        ][:50]

        self._detect_beacons()
        self._detect_port_scans()
        self._detect_arp_spoofing()
        self._detect_ping_sweeps()
        self._detect_large_transfers_and_conversations()
        self._build_alerts()

    def _detect_beacons(self) -> None:
        self.beacons: List[Dict[str, Any]] = []
        for key, flow in self.flows.items():
            if len(flow.deltas) >= BEACON_MIN_SAMPLES:
                mean_d = statistics.mean(flow.deltas)
                if mean_d <= 0:
                    continue
                stdev_d = statistics.pstdev(flow.deltas)
                cv = stdev_d / mean_d if mean_d else 0
                if cv < BEACON_CV_THRESHOLD:
                    self.beacons.append({
                        "src": flow.src_ip, "dst": flow.dst_ip,
                        "src_port": flow.src_port, "dst_port": flow.dst_port,
                        "proto": flow.proto, "samples": len(flow.deltas),
                        "mean_interval_s": round(mean_d, 3),
                        "stdev_s": round(stdev_d, 3),
                        "coefficient_of_variation": round(cv, 4),
                    })
        self.beacons.sort(key=lambda b: b["coefficient_of_variation"])
        self.beacons = self.beacons[:100]

    def _detect_port_scans(self) -> None:
        # vertical: many ports probed on the same target
        self.vertical_scans = [
            {"src": src, "dst": dst, "unique_dst_ports": len(ports)}
            for (src, dst), ports in self.src_dst_ports.items()
            if len(ports) >= PORT_SCAN_UNIQUE_PORTS_THRESHOLD
        ]
        self.vertical_scans.sort(key=lambda s: s["unique_dst_ports"], reverse=True)

        # horizontal: same port hit across many different hosts
        horizontal_agg: Dict[str, int] = defaultdict(int)
        for (src, port), hosts in self.src_port_dst_hosts.items():
            horizontal_agg[src] = max(horizontal_agg[src], len(hosts))
        self.horizontal_scans = [
            {"src": src, "unique_dst_hosts": n}
            for src, n in horizontal_agg.items()
            if n >= PORT_SCAN_UNIQUE_HOSTS_THRESHOLD
        ]

        self.syn_scan_candidates = [
            {"src": src, "syn_only_count": cnt}
            for src, cnt in self.syn_only_count.items()
            if cnt >= PORT_SCAN_UNIQUE_PORTS_THRESHOLD
        ]

    def _detect_arp_spoofing(self) -> None:
        self.arp_spoof_candidates = [
            {"ip": ip, "macs": list(macs)} for ip, macs in self.ip_to_macs.items() if len(macs) > 1
        ]

    def _detect_ping_sweeps(self) -> None:
        self.ping_sweep_candidates = [
            {"src": src, "unique_targets": len(dsts)}
            for src, dsts in self.icmp_src_targets.items()
            if len(dsts) >= PORT_SCAN_UNIQUE_HOSTS_THRESHOLD
        ]

    def _detect_large_transfers_and_conversations(self) -> None:
        sorted_flows = sorted(self.flows.values(), key=lambda fl: fl.bytes, reverse=True)
        self.large_transfers = [
            {
                "src": fl.src_ip, "dst": fl.dst_ip, "src_port": fl.src_port, "dst_port": fl.dst_port,
                "proto": fl.proto, "bytes": fl.bytes, "packets": fl.packets,
                "duration_s": round(fl.duration, 2),
            }
            for fl in sorted_flows[:25] if fl.bytes >= LARGE_TRANSFER_BYTES
        ]
        self.top_conversations = [
            {
                "src": fl.src_ip, "dst": fl.dst_ip, "src_port": fl.src_port, "dst_port": fl.dst_port,
                "proto": fl.proto, "bytes": fl.bytes, "packets": fl.packets,
                "duration_s": round(fl.duration, 2),
            }
            for fl in sorted_flows[:TOP_N]
        ]

    def _build_alerts(self) -> None:
        for b in self.beacons[:20]:
            self.alerts.append({
                "severity": "medium", "category": "Beaconing",
                "message": f"Regular beacon-like traffic {b['src']} -> {b['dst']}:{b['dst_port']} "
                           f"(interval~{b['mean_interval_s']}s, CV={b['coefficient_of_variation']})",
            })
        for c in self.credential_hits[:20]:
            self.alerts.append({
                "severity": "high", "category": "Credential Leak",
                "message": f"Possible credential material {c['src']} -> {c['dst']}:{c['dport']} "
                           f"matched pattern.",
            })
        for s in self.vertical_scans[:20]:
            self.alerts.append({
                "severity": "high", "category": "Port Scan (vertical)",
                "message": f"{s['src']} probed {s['unique_dst_ports']} unique ports on {s['dst']}.",
            })
        for s in self.horizontal_scans:
            self.alerts.append({
                "severity": "high", "category": "Port Scan (horizontal)",
                "message": f"{s['src']} contacted {s['unique_dst_hosts']} unique hosts on the same port.",
            })
        for d in self.dns_alerts[:20]:
            self.alerts.append({
                "severity": "medium", "category": "Suspicious DNS",
                "message": f"Domain '{d['domain']}' flagged ({d['reason']}, entropy={d['entropy']}).",
            })
        for lt in self.large_transfers[:10]:
            self.alerts.append({
                "severity": "low", "category": "Large Transfer",
                "message": f"{lt['bytes']/1024/1024:.1f}MB transferred {lt['src']} <-> {lt['dst']} "
                           f"over {lt['proto']}.",
            })
        for a in self.arp_spoof_candidates[:10]:
            self.alerts.append({
                "severity": "high", "category": "ARP Spoofing",
                "message": f"IP {a['ip']} seen with multiple MAC addresses: {a['macs']}.",
            })
        for p in self.ping_sweep_candidates[:10]:
            self.alerts.append({
                "severity": "medium", "category": "Ping Sweep",
                "message": f"{p['src']} pinged {p['unique_targets']} unique hosts.",
            })
