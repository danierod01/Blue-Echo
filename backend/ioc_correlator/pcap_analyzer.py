import asyncio
import logging
import os
import tempfile
import warnings
from collections import Counter

logger = logging.getLogger(__name__)

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap LE
    b"\xa1\xb2\xc3\xd4",  # pcap BE
    b"\x4d\x3c\xb2\xa1",  # nanosecond pcap LE
    b"\xa1\xb2\x3c\x4d",  # nanosecond pcap BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
}

MAX_PACKETS = 50_000


def is_pcap(content: bytes) -> bool:
    return len(content) >= 4 and content[:4] in _PCAP_MAGIC


def _extract_tls_sni(payload: bytes) -> str | None:
    """Extrae el SNI de un TLS ClientHello (best-effort)."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        if payload[5] != 0x01:  # HandshakeType.client_hello
            return None
        # TLS record(5) + Handshake header(4) + client_version(2) + random(32)
        offset = 5 + 4 + 2 + 32
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(payload):
            return None
        cipher_len = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2 + cipher_len
        if offset + 1 > len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2
        end = min(offset + ext_total, len(payload))
        while offset + 4 <= end:
            ext_type = int.from_bytes(payload[offset:offset + 2], "big")
            ext_len  = int.from_bytes(payload[offset + 2:offset + 4], "big")
            offset += 4
            if ext_type == 0 and offset + 5 <= end:  # SNI
                name_len = int.from_bytes(payload[offset + 3:offset + 5], "big")
                name = payload[offset + 5:offset + 5 + name_len]
                return name.decode("ascii", errors="ignore")
            offset += ext_len
    except Exception:
        pass
    return None


def _parse_pcap_sync(tmp_path: str) -> tuple[list, dict]:
    """Parseo síncrono del PCAP — se ejecuta en un thread pool."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw  # noqa

    packets = rdpcap(tmp_path)

    src_ips:     Counter = Counter()
    dst_ips:     Counter = Counter()
    connections: Counter = Counter()
    dns_queries: set = set()
    http_hosts:  set = set()
    tls_sni:     set = set()
    proto_counts: Counter = Counter()
    total_bytes = 0

    for pkt in packets[:MAX_PACKETS]:
        total_bytes += len(pkt)

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            proto_counts["OTHER"] += 1
            continue

        src_ips[src] += 1
        dst_ips[dst] += 1

        if TCP in pkt:
            proto_counts["TCP"] += 1
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            connections[(src, sport, dst, dport)] += 1
            if Raw in pkt:
                payload = bytes(pkt[Raw])
                if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE"):
                    for line in payload.split(b"\r\n"):
                        if line.lower().startswith(b"host:"):
                            host = line[5:].strip().decode("utf-8", errors="ignore").split(":")[0]
                            if host:
                                http_hosts.add(host)
                            break
                sni = _extract_tls_sni(payload)
                if sni:
                    tls_sni.add(sni)
        elif UDP in pkt:
            proto_counts["UDP"] += 1
            if DNS in pkt and DNSQR in pkt:
                try:
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore").rstrip(".")
                    if qname and len(qname) > 1:
                        dns_queries.add(qname)
                except Exception:
                    pass
        else:
            proto_counts["OTHER"] += 1

    from ioc_correlator.extractor import ExtractedIOC
    from ioc_correlator.utils.validators import IOCType, detect_ioc_type

    seen: set = set()
    iocs: list = []
    for value in (set(src_ips) | set(dst_ips) | dns_queries | http_hosts | tls_sni):
        if value in seen:
            continue
        seen.add(value)
        ioc_type = detect_ioc_type(value)
        if ioc_type != IOCType.UNKNOWN:
            iocs.append(ExtractedIOC(value=value, ioc_type=ioc_type))

    top_conns = [
        {"src": f"{s}:{sp}", "dst": f"{d}:{dp}", "packets": c}
        for (s, sp, d, dp), c in connections.most_common(15)
    ]

    stats = {
        "total_packets": min(len(packets), MAX_PACKETS),
        "total_bytes": total_bytes,
        "unique_src_ips": [ip for ip, _ in src_ips.most_common(20)],
        "unique_dst_ips": [ip for ip, _ in dst_ips.most_common(20)],
        "top_connections": top_conns,
        "dns_queries": sorted(dns_queries)[:50],
        "http_hosts": sorted(http_hosts)[:30],
        "tls_sni": sorted(tls_sni)[:30],
        "protocols": dict(proto_counts),
    }

    return iocs, stats


async def analyze_pcap(content: bytes) -> tuple[list, dict]:
    """Parsea un PCAP/PCAPNG y devuelve (iocs, stats).

    El parseo con scapy es CPU-bound, se ejecuta en un thread pool
    para no bloquear el event loop de asyncio.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            f.write(content)
            tmp_path = f.name
        return await asyncio.to_thread(_parse_pcap_sync, tmp_path)
    except Exception as exc:
        logger.error("pcap_analyzer: error al parsear — %s", exc)
        raise
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
