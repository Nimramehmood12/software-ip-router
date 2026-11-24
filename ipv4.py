"""F1 - IPv4 header builder / parser with RFC 1071 checksum (RFC 791)."""
import itertools
import socket
import struct

IPV4_FMT = "!BBHHHBBH4s4s"          # 20-byte header
IPV4_MIN_HDR = 20
PROTO_ICMP = 1

_ident_counter = itertools.count(1)


def compute_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum: one's complement sum of 16-bit words, inverted."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def verify_checksum(header: bytes) -> bool:
    """A header with a correct checksum field sums (and inverts) to 0."""
    return compute_checksum(header) == 0


def build_ipv4(src: str, dst: str, proto: int, payload: bytes = b"", ttl: int = 64,
               tos: int = 0, ident: int = None, flags: int = 0,
               frag_offset: int = 0) -> bytes:
    """Build a 20-byte-header IPv4 packet (IHL=5) with a valid checksum."""
    if ident is None:
        ident = next(_ident_counter) & 0xFFFF
    total_length = IPV4_MIN_HDR + len(payload)
    flags_frag = ((flags & 0x7) << 13) | (frag_offset & 0x1FFF)
    src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
    hdr = struct.pack(IPV4_FMT, (4 << 4) | 5, tos, total_length, ident,
                      flags_frag, ttl, proto, 0, src_b, dst_b)
    csum = compute_checksum(hdr)
    hdr = struct.pack(IPV4_FMT, (4 << 4) | 5, tos, total_length, ident,
                      flags_frag, ttl, proto, csum, src_b, dst_b)
    return hdr + payload


def parse_ipv4(raw: bytes) -> dict:
    """Parse an IPv4 packet. Raises ValueError if it is structurally malformed.

    The checksum is NOT enforced here; see the 'checksum_ok' key.
    """
    if len(raw) < IPV4_MIN_HDR:
        raise ValueError("packet shorter than 20 bytes")
    (ver_ihl, tos, total_length, ident, flags_frag, ttl, proto, csum,
     src_b, dst_b) = struct.unpack(IPV4_FMT, raw[:IPV4_MIN_HDR])
    version, ihl = ver_ihl >> 4, ver_ihl & 0xF
    if version != 4:
        raise ValueError("not IPv4 (version=%d)" % version)
    if ihl < 5:
        raise ValueError("bad IHL %d" % ihl)
    header_len = ihl * 4
    if len(raw) < header_len:
        raise ValueError("truncated header")
    if total_length < header_len or total_length > len(raw):
        raise ValueError("bad total length %d (got %d bytes)" % (total_length, len(raw)))
    header = raw[:header_len]
    return {
        "version": version, "ihl": ihl, "header_len": header_len, "tos": tos,
        "total_length": total_length, "ident": ident,
        "flags": flags_frag >> 13, "frag_offset": flags_frag & 0x1FFF,
        "ttl": ttl, "proto": proto, "checksum": csum,
        "src": socket.inet_ntoa(src_b), "dst": socket.inet_ntoa(dst_b),
        "dst_int": struct.unpack("!I", dst_b)[0],
        "header": header, "payload": raw[header_len:total_length],
        "checksum_ok": verify_checksum(header),
    }


def decrement_ttl(raw: bytes) -> bytes:
    """Return the packet with TTL-1 and a freshly recomputed header checksum."""
    ihl = (raw[0] & 0xF) * 4
    hdr = bytearray(raw[:ihl])
    if hdr[8] == 0:
        raise ValueError("TTL already 0")
    hdr[8] -= 1
    hdr[10:12] = b"\x00\x00"
    hdr[10:12] = struct.pack("!H", compute_checksum(bytes(hdr)))
    return bytes(hdr) + raw[ihl:]


if __name__ == "__main__":
    # Self test: RFC 1071-style known vector + round trip
    pkt = build_ipv4("10.0.1.1", "10.0.6.2", PROTO_ICMP, b"hello", ttl=64)
    p = parse_ipv4(pkt)
    assert p["checksum_ok"] and p["ttl"] == 64
    q = parse_ipv4(decrement_ttl(pkt))
    assert q["checksum_ok"] and q["ttl"] == 63
    bad = bytearray(pkt); bad[8] ^= 0xFF
    assert not parse_ipv4(bytes(bad))["checksum_ok"]
    print("ipv4.py self-test OK")
