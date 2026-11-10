# small reusable helpers + the two data structures that hold per-flow
# and top-N stats without ever storing raw packets

from __future__ import annotations

import ipaddress
import math
import socket
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Tuple


def shannon_entropy(s: str) -> float:
    """shannon entropy (bits/char) of a string, used for DGA-ish domain flagging."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def safe_inet(addr_bytes: bytes, version: int) -> str:
    try:
        if version == 4:
            return socket.inet_ntoa(addr_bytes)
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    except (OSError, ValueError):
        return "0.0.0.0" if version == 4 else "::"


class TopN:
    """bounded-memory 'top N by value' tracker, so we never keep full distributions."""

    def __init__(self, n: int = 10):
        self.n = n
        self._counter: Counter = Counter()

    def add(self, key: str, value: int = 1) -> None:
        self._counter[key] += value

    def top(self) -> List[Tuple[str, int]]:
        return self._counter.most_common(self.n)

    def as_dict(self) -> dict:
        return dict(self._counter.most_common(self.n))


@dataclass
class FlowStats:
    """aggregated, bounded-memory stats for one 5-tuple flow. no packets stored."""
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    proto: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    # for beacon detection we keep only inter-arrival deltas, capped in count
    _last_seen: float = field(default=0.0, repr=False)
    deltas: List[float] = field(default_factory=list)
    syn: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    urg: int = 0
    retransmits: int = 0
    _seq_seen: set = field(default_factory=set, repr=False)

    MAX_DELTAS = 200  # cap memory per flow

    def update(self, ts: float, size: int) -> None:
        if self.packets == 0:
            self.first_ts = ts
        else:
            delta = ts - self._last_seen
            if delta >= 0 and len(self.deltas) < self.MAX_DELTAS:
                self.deltas.append(delta)
        self._last_seen = ts
        self.last_ts = ts
        self.packets += 1
        self.bytes += size

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)
