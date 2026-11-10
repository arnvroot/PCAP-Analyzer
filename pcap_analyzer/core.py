# this is the class everything else plugs into. init sets up all the
# counters/structures, run() does the actual streaming loop

from __future__ import annotations

import logging
import signal
import time
from collections import defaultdict, Counter
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import dpkt

from .packet_handlers import PacketHandlersMixin
from .protocol_parsers import ProtocolParsersMixin
from .detectors import DetectorsMixin
from .report_writer import ReportWriterMixin
from .utils import TopN

log = logging.getLogger("pcap_analyzer")


class PcapAnalyzer(PacketHandlersMixin, ProtocolParsersMixin, DetectorsMixin, ReportWriterMixin):
    def __init__(self, pcap_path: str, outdir: str):
        self.pcap_path = Path(pcap_path)
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)

        self._interrupted = False

        # global stats
        self.total_packets = 0
        self.total_bytes = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.min_pkt_size: Optional[int] = None
        self.max_pkt_size: Optional[int] = None
        self.pkt_size_histogram: Counter = Counter()

        # protocol stats
        self.protocol_counts: Counter = Counter()

        # top talkers
        self.bytes_sent = TopN()
        self.bytes_received = TopN()
        self.packets_sent = TopN()
        self.packets_received = TopN()

        # conversations / flows
        self.flows: Dict[Tuple, Any] = {}

        # ports
        self.dst_port_counts: Counter = Counter()
        self.src_port_counts: Counter = Counter()

        # internal/external
        self.traffic_class_counts: Counter = Counter()

        # dns
        self.dns_queries: Counter = Counter()
        self.dns_qtypes: Counter = Counter()
        self.dns_records: List[Dict[str, Any]] = []
        self.dns_alerts: List[Dict[str, Any]] = []

        # http
        self.http_records: List[Dict[str, Any]] = []

        # tls
        self.tls_records: List[Dict[str, Any]] = []

        # credential leaks
        self.credential_hits: List[Dict[str, Any]] = []

        # port scan detection
        self.src_dst_ports: Dict[Tuple[str, str], set] = defaultdict(set)  # (src,dst) -> ports touched
        self.src_port_dst_hosts: Dict[Tuple[str, int], set] = defaultdict(set)  # (src,port) -> hosts touched
        self.syn_only_count: Counter = Counter()

        # tcp
        self.tcp_flags_totals: Counter = Counter()

        # icmp
        self.icmp_echo_request = 0
        self.icmp_echo_reply = 0
        self.icmp_large = 0
        self.icmp_src_targets: Dict[str, set] = defaultdict(set)

        # arp
        self.arp_requests = 0
        self.arp_replies = 0
        self.ip_to_macs: Dict[str, set] = defaultdict(set)

        # large transfers
        self.large_transfers: List[Dict[str, Any]] = []

        # timeline
        self.timeline_pps: Counter = Counter()
        self.timeline_bps: Counter = Counter()

        # alerts
        self.alerts: List[Dict[str, Any]] = []

        # progress
        self._start_time = time.time()
        self._file_size = self.pcap_path.stat().st_size if self.pcap_path.exists() else 0

    def _install_signal_handler(self) -> None:
        def handler(signum, frame):
            log.warning("Interrupt received - finishing current packet and writing partial results...")
            self._interrupted = True
        try:
            signal.signal(signal.SIGINT, handler)
        except (ValueError, OSError):
            pass  # not in main thread / not supported

    def _open_reader(self, f) -> Iterator[Tuple[float, bytes]]:
        """returns a (ts, buf) iterator, works for both pcap and pcapng."""
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":  # pcapng magic
            log.info("PCAPNG format detected; using dpkt's built-in pcapng reader.")
            reader = dpkt.pcapng.Reader(f)
            for ts, buf in reader:
                yield ts, buf
        else:
            reader = dpkt.pcap.Reader(f)
            for ts, buf in reader:
                yield ts, buf

    def run(self) -> None:
        self._install_signal_handler()
        log.info(f"Opening capture: {self.pcap_path} ({self._file_size / 1024 / 1024:.1f} MB)")

        with open(self.pcap_path, "rb") as f:
            reader = self._open_reader(f)
            last_progress = time.time()

            for ts, buf in reader:
                if self._interrupted:
                    break
                try:
                    self._process_packet(ts, buf)
                except Exception as exc:  # keep streaming even on malformed packets
                    log.debug(f"Skipped malformed packet: {exc}")

                self.total_packets += 1
                if time.time() - last_progress > 2.0:
                    pos = f.tell()
                    pct = (pos / self._file_size * 100) if self._file_size else 0
                    log.info(f"Progress: {self.total_packets:,} packets | {pct:.1f}% of file")
                    last_progress = time.time()

        elapsed = time.time() - self._start_time
        log.info(f"Finished streaming {self.total_packets:,} packets in {elapsed:.1f}s")
        self._post_process()
        self._write_outputs()
