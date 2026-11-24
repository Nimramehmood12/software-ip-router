"""Minimal ICMP helpers (RFC 792). Echo is used by ping; the generic builder is
there for Phase 2 (Time Exceeded type 11, Destination Unreachable type 3)."""
import struct

from ipv4 import compute_checksum

ECHO_REPLY = 0
DEST_UNREACHABLE = 3
ECHO_REQUEST = 8
TIME_EXCEEDED = 11


def build_icmp(icmp_type: int, code: int, rest: bytes, body: bytes = b"") -> bytes:
    """type, code, checksum, 4 bytes 'rest of header', body."""
    assert len(rest) == 4
    msg = struct.pack("!BBH", icmp_type, code, 0) + rest + body
    csum = compute_checksum(msg)
    return struct.pack("!BBH", icmp_type, code, csum) + rest + body


def build_echo(icmp_type: int, ident: int, seq: int, payload: bytes) -> bytes:
    return build_icmp(icmp_type, 0, struct.pack("!HH", ident, seq), payload)


def parse_icmp(data: bytes) -> dict:
    if len(data) < 8:
        raise ValueError("ICMP message too short")
    icmp_type, code, csum = struct.unpack("!BBH", data[:4])
    out = {"type": icmp_type, "code": code, "checksum": csum,
           "rest": data[4:8], "body": data[8:],
           "checksum_ok": compute_checksum(data) == 0}
    if icmp_type in (ECHO_REQUEST, ECHO_REPLY):
        out["ident"], out["seq"] = struct.unpack("!HH", data[4:8])
    return out
