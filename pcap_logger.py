"""F8 - tiny libpcap writer using LINKTYPE_RAW (101): each record is a bare
IPv4 packet, so Wireshark decodes the IP header directly (no Ethernet)."""
import struct
import time

LINKTYPE_RAW = 101


class PcapWriter:
    def __init__(self, path: str, snaplen: int = 65535):
        self.f = open(path, "wb")
        # magic, ver 2.4, thiszone, sigfigs, snaplen, network
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, LINKTYPE_RAW))
        self.f.flush()
        self.snaplen = snaplen

    def write(self, packet: bytes, ts: float = None):
        if ts is None:
            ts = time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        cap = packet[:self.snaplen]
        self.f.write(struct.pack("<IIII", sec, usec, len(cap), len(packet)) + cap)
        self.f.flush()      # flush each record so a killed router still leaves a valid file

    def close(self):
        if not self.f.closed:
            self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
