# everything that looks inside the tcp/udp payload lives here

from __future__ import annotations

import dpkt

from .config import CREDENTIAL_PATTERNS, DNS_QTYPE_NAMES, DNS_ENTROPY_THRESHOLD, DNS_LONG_DOMAIN_THRESHOLD
from .utils import shannon_entropy


class ProtocolParsersMixin:
    def _parse_dns(self, buf: bytes, src: str, dst: str) -> None:
        try:
            dns = dpkt.dns.DNS(buf)
        except Exception:
            return
        for q in dns.qd:
            try:
                name = q.name
            except Exception:
                continue
            self.dns_queries[name] += 1
            qtype_name = DNS_QTYPE_NAMES.get(q.type, str(q.type))
            self.dns_qtypes[qtype_name] += 1

            entropy = shannon_entropy(name.split(".")[0] if "." in name else name)
            is_long = len(name) > DNS_LONG_DOMAIN_THRESHOLD
            is_high_entropy = entropy > DNS_ENTROPY_THRESHOLD

            if len(self.dns_records) < 5000:  # cap memory
                self.dns_records.append({
                    "query": name, "type": qtype_name, "src": src, "dst": dst,
                    "entropy": round(entropy, 2), "length": len(name),
                })

            if is_high_entropy or is_long:
                self.dns_alerts.append({
                    "domain": name, "entropy": round(entropy, 2), "length": len(name),
                    "src": src, "reason": "high_entropy" if is_high_entropy else "long_domain",
                })

    def _parse_http(self, payload: bytes, src: str, dst: str, sport: int, dport: int) -> None:
        if len(self.http_records) >= 3000:
            return
        try:
            if payload.startswith((b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS")):
                req = dpkt.http.Request(payload)
                self.http_records.append({
                    "src": src, "dst": dst, "sport": sport, "dport": dport,
                    "method": req.method, "uri": req.uri,
                    "host": req.headers.get("host", ""),
                    "user_agent": req.headers.get("user-agent", ""),
                    "cookie": req.headers.get("cookie", ""),
                    "authorization": req.headers.get("authorization", ""),
                    "content_type": req.headers.get("content-type", ""),
                })
        except Exception:
            pass  # not a clean http request, probably a mid-stream segment

    def _parse_tls(self, payload: bytes, src: str, dst: str, sport: int, dport: int) -> None:
        if len(self.tls_records) >= 3000:
            return
        try:
            if len(payload) < 6 or payload[0] != 0x16:  # not a tls handshake record
                return
            records, _ = dpkt.ssl.tls_multi_factory(payload)
            for record in records:
                if record.type != 22:  # handshake
                    continue
                try:
                    handshake = dpkt.ssl.TLSHandshake(record.data)
                except Exception:
                    continue
                if handshake.type == 1:  # clienthello
                    ch = handshake.data
                    sni = self._extract_sni(ch)
                    self.tls_records.append({
                        "src": src, "dst": dst, "sport": sport, "dport": dport,
                        "sni": sni, "tls_version": f"{record.version:#06x}",
                        "type": "ClientHello",
                    })
        except Exception:
            pass

    @staticmethod
    def _extract_sni(client_hello) -> str:
        try:
            for ext_type, ext_data in client_hello.extensions:
                if ext_type == 0:  # server_name
                    if len(ext_data) > 5:
                        name_len = int.from_bytes(ext_data[3:5], "big")
                        return ext_data[5:5 + name_len].decode(errors="ignore")
        except Exception:
            pass
        return ""

    def _scan_credentials(self, payload: bytes, src: str, dst: str, sport: int, dport: int) -> None:
        if len(self.credential_hits) >= 2000:
            return
        for pattern in CREDENTIAL_PATTERNS:
            m = pattern.search(payload)
            if m:
                snippet = m.group(0)[:80].decode(errors="ignore")
                self.credential_hits.append({
                    "src": src, "dst": dst, "sport": sport, "dport": dport,
                    "pattern": pattern.pattern.decode(errors="ignore"),
                    "snippet": snippet,
                })
                break  # one hit per packet payload is enough
