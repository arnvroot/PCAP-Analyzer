# this is the per-packet parsing layer. everything here just updates
# counters/flows on self, nothing gets stored raw

from __future__ import annotations

import socket
from typing import Tuple

import dpkt

from .utils import is_private_ip, safe_inet, FlowStats
from .config import ICMP_LARGE_PAYLOAD


class PacketHandlersMixin:
    def _bucket_size(self, size: int) -> str:
        for lo, hi, label in [
            (0, 64, "0-64"), (64, 128, "64-128"), (128, 256, "128-256"),
            (256, 512, "256-512"), (512, 1024, "512-1024"),
            (1024, 1500, "1024-1500"), (1500, 65535, "1500+"),
        ]:
            if lo <= size < hi:
                return label
        return "1500+"

    def _process_packet(self, ts: float, buf: bytes) -> None:
        size = len(buf)
        self.total_bytes += size
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        self.min_pkt_size = size if self.min_pkt_size is None else min(self.min_pkt_size, size)
        self.max_pkt_size = size if self.max_pkt_size is None else max(self.max_pkt_size, size)
        self.pkt_size_histogram[self._bucket_size(size)] += 1

        bucket = int(ts)
        self.timeline_pps[bucket] += 1
        self.timeline_bps[bucket] += size

        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            self.protocol_counts["Other"] += 1
            return

        # arp
        if isinstance(eth.data, dpkt.arp.ARP):
            self.protocol_counts["ARP"] += 1
            self._handle_arp(eth.data)
            return

        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            self.protocol_counts["IPv4"] += 1
            self._handle_ip(ts, ip, size, version=4)
        elif isinstance(ip, dpkt.ip6.IP6):
            self.protocol_counts["IPv6"] += 1
            self._handle_ip(ts, ip, size, version=6)
        else:
            self.protocol_counts["Other"] += 1

    def _handle_arp(self, arp: "dpkt.arp.ARP") -> None:
        try:
            spa = socket.inet_ntoa(arp.spa)
            sha = ":".join(f"{b:02x}" for b in arp.sha)
        except Exception:
            return
        if arp.op == dpkt.arp.ARP_OP_REQUEST:
            self.arp_requests += 1
        elif arp.op == dpkt.arp.ARP_OP_REPLY:
            self.arp_replies += 1
        self.ip_to_macs[spa].add(sha)

    def _handle_ip(self, ts: float, ip, size: int, version: int) -> None:
        src = safe_inet(ip.src, version) if version == 4 else socket.inet_ntop(socket.AF_INET6, ip.src)
        dst = safe_inet(ip.dst, version) if version == 4 else socket.inet_ntop(socket.AF_INET6, ip.dst)

        self.bytes_sent.add(src, size)
        self.bytes_received.add(dst, size)
        self.packets_sent.add(src)
        self.packets_received.add(dst)

        # internal/external classification
        src_priv, dst_priv = is_private_ip(src), is_private_ip(dst)
        if src_priv and dst_priv:
            self.traffic_class_counts["Internal -> Internal"] += 1
        elif src_priv and not dst_priv:
            self.traffic_class_counts["Internal -> External"] += 1
        elif not src_priv and dst_priv:
            self.traffic_class_counts["External -> Internal"] += 1
        else:
            self.traffic_class_counts["External -> External"] += 1

        proto = ip.p if version == 4 else ip.nxt
        data = ip.data

        if isinstance(data, dpkt.tcp.TCP):
            self.protocol_counts["TCP"] += 1
            self._handle_tcp(ts, src, dst, data, size)
        elif isinstance(data, dpkt.udp.UDP):
            self.protocol_counts["UDP"] += 1
            self._handle_udp(ts, src, dst, data, size)
        elif isinstance(data, dpkt.icmp.ICMP):
            self.protocol_counts["ICMP"] += 1
            self._handle_icmp(src, dst, data)
        else:
            self.protocol_counts["Other"] += 1

    def _flow_key(self, src: str, dst: str, sport: int, dport: int, proto: str) -> Tuple:
        # normalize direction so both sides of a conversation share one flow entry
        if (src, sport) <= (dst, dport):
            return (src, dst, sport, dport, proto)
        return (dst, src, dport, sport, proto)

    def _get_flow(self, src, dst, sport, dport, proto, ts, size) -> FlowStats:
        key = self._flow_key(src, dst, sport, dport, proto)
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowStats(proto=proto, src_ip=key[0], dst_ip=key[1], src_port=key[2], dst_port=key[3])
            self.flows[key] = flow
        flow.update(ts, size)
        return flow

    def _handle_tcp(self, ts: float, src: str, dst: str, tcp, size: int) -> None:
        self.dst_port_counts[tcp.dport] += 1
        self.src_port_counts[tcp.sport] += 1

        flow = self._get_flow(src, dst, tcp.sport, tcp.dport, "TCP", ts, size)

        flags = tcp.flags
        is_syn = bool(flags & dpkt.tcp.TH_SYN)
        is_ack = bool(flags & dpkt.tcp.TH_ACK)
        is_fin = bool(flags & dpkt.tcp.TH_FIN)
        is_rst = bool(flags & dpkt.tcp.TH_RST)
        is_psh = bool(flags & dpkt.tcp.TH_PUSH)
        is_urg = bool(flags & dpkt.tcp.TH_URG)

        if is_syn:
            self.tcp_flags_totals["SYN"] += 1
            flow.syn += 1
        if is_ack:
            self.tcp_flags_totals["ACK"] += 1
            flow.ack += 1
        if is_fin:
            self.tcp_flags_totals["FIN"] += 1
            flow.fin += 1
        if is_rst:
            self.tcp_flags_totals["RST"] += 1
            flow.rst += 1
        if is_psh:
            self.tcp_flags_totals["PSH"] += 1
            flow.psh += 1
        if is_urg:
            self.tcp_flags_totals["URG"] += 1
            flow.urg += 1

        # retransmission heuristic: same seq number seen twice on this flow
        if tcp.seq in flow._seq_seen:
            flow.retransmits += 1
            self.tcp_flags_totals["RETRANSMIT"] += 1
        elif len(flow._seq_seen) < 5000:  # cap memory for very long flows
            flow._seq_seen.add(tcp.seq)

        # port scan bookkeeping, keyed per (src, dst) so it's per-target
        if is_syn and not is_ack:
            self.src_dst_ports[(src, dst)].add(tcp.dport)
            self.syn_only_count[src] += 1

        # uncommon dest port check happens later, needs global counts first

        try:
            payload = tcp.data
        except Exception:
            payload = b""

        if payload:
            self._scan_credentials(payload, src, dst, tcp.sport, tcp.dport)
            if tcp.dport == 80 or tcp.sport == 80 or tcp.dport == 8080 or tcp.sport == 8080:
                self._parse_http(payload, src, dst, tcp.sport, tcp.dport)
            if tcp.dport == 443 or tcp.sport == 443:
                self._parse_tls(payload, src, dst, tcp.sport, tcp.dport)

        # large transfer tracking happens later, from flow.bytes

    def _handle_udp(self, ts: float, src: str, dst: str, udp, size: int) -> None:
        self.dst_port_counts[udp.dport] += 1
        self.src_port_counts[udp.sport] += 1
        self._get_flow(src, dst, udp.sport, udp.dport, "UDP", ts, size)

        if udp.sport == 53 or udp.dport == 53:
            try:
                self._parse_dns(udp.data, src, dst)
            except Exception:
                pass

    def _handle_icmp(self, src: str, dst: str, icmp) -> None:
        if icmp.type == dpkt.icmp.ICMP_ECHO:
            self.icmp_echo_request += 1
            self.icmp_src_targets[src].add(dst)
        elif icmp.type == dpkt.icmp.ICMP_ECHOREPLY:
            self.icmp_echo_reply += 1
        try:
            if len(icmp.data.data) > ICMP_LARGE_PAYLOAD:
                self.icmp_large += 1
        except Exception:
            pass
