"""phase 1 oracle: reverse-engineer RIPv2 (RFC 2082) auth and recover the key.

parses a size-06 pcap, dumps the packet structure, then single-threaded brute
forces the key while testing BOTH digest constructions (keyed-MD5 vs HMAC-MD5)
and BOTH alphabets (hex first, base36 fallback). prints the recovered key.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (extract_auth_packets, crack_chunk, keyspace_size,
                    CONSTRUCTIONS, keyed_md5, hmac_md5)

KEY_LEN = 6


def hexs(b: bytes) -> str:
    return b.hex()


def dump_packet(p: dict):
    print("=" * 68)
    print("authenticated RIPv2 packet (RFC 2082, auth type 3)")
    print("=" * 68)
    raw = p["raw"]
    print(f"  RIP payload length : {len(raw)} bytes")
    print(f"  command/version    : {raw[0]}/{raw[1]}  (2=response, v2)")
    print(f"  auth header AFI     : 0x{int.from_bytes(raw[4:6],'big'):04x} (0xffff = auth)")
    print(f"  auth type           : {int.from_bytes(raw[6:8],'big')}  (3 = keyed message digest)")
    print(f"  RIP-2 packet length : {p['pktlen']} (header..last RTE, excl. trailer)")
    print(f"  key id              : {p['keyid']}")
    print(f"  auth data len       : {p['authlen']}")
    print(f"  sequence number     : {p['seq']} (0x{p['seq']:08x})")
    print(f"  captured digest     : {hexs(p['digest'])}")
    print(f"  MD5 input region    : {len(p['data'])} bytes (raw[:-16], through ffff0001 trailer hdr)")
    print(f"    data hex          : {hexs(p['data'])}")
    print()


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "pcaps/rip_passkey_size_06_01.pcap"
    print(f"[*] loading {pcap}")
    pkts = extract_auth_packets(pcap)
    if not pkts:
        print("[!] no authenticated RIPv2 packets found", file=sys.stderr)
        sys.exit(2)
    print(f"[*] found {len(pkts)} authenticated packet(s); using the first")
    target = pkts[0]
    dump_packet(target)

    data, digest = target["data"], target["digest"]

    # sanity: show what each construction produces for a sample key, so the
    # difference between the two is visible even before the search.
    sample = b"abc123"
    print("[*] construction demo with sample key 'abc123':")
    print(f"    keyed_md5 -> {hexs(keyed_md5(data, sample))}")
    print(f"    hmac_md5  -> {hexs(hmac_md5(data, sample))}")
    print()

    # search order: hex is cheap (16^6=16.7M), so test BOTH constructions over
    # hex before falling back to the far larger base36 space (36^6=2.2B).
    attempts = [
        ("hex", "keyed_md5"),
        ("hex", "hmac_md5"),
        ("base36", "keyed_md5"),
        ("base36", "hmac_md5"),
    ]
    for alphabet, construction in attempts:
        size = keyspace_size(alphabet, KEY_LEN)
        print(f"[*] brute force: alphabet={alphabet} ({size:,} keys) construction={construction}")
        t0 = time.time()
        last = {"n": 0, "t": t0}

        def cb(tried, _last=last, _size=size):
            now = time.time()
            rate = (tried - _last["n"]) / max(now - _last["t"], 1e-9)
            _last["n"], _last["t"] = tried, now
            print(f"      {tried:,}/{_size:,}  ({100*tried/_size:5.1f}%)  {rate/1e6:6.2f} Mkeys/s",
                  end="\r", flush=True)

        res = crack_chunk(data, digest, alphabet, KEY_LEN, construction,
                          0, size, progress_cb=cb)
        dt = time.time() - t0
        print()
        if res:
            key, idx = res
            rate = idx / max(dt, 1e-9)
            print()
            print("#" * 68)
            print(f"[+] KEY RECOVERED: {key.decode()!r}")
            print(f"    alphabet      : {alphabet}")
            print(f"    construction  : {construction}  (brief said HMAC-MD5)")
            print(f"    index         : {idx:,}")
            print(f"    time          : {dt:.2f}s   avg {rate/1e6:.2f} Mkeys/s")
            print("#" * 68)
            # independent re-verification against the captured trailer
            recomputed = CONSTRUCTIONS[construction](data, key)
            ok = recomputed == digest
            print(f"[{'+' if ok else '!'}] re-verify: recomputed digest {'MATCHES' if ok else 'DOES NOT MATCH'} capture")
            print(f"    recomputed : {hexs(recomputed)}")
            print(f"    captured   : {hexs(digest)}")
            if not ok:
                sys.exit(3)
            # robustness: the key must reproduce EVERY authenticated packet in
            # the capture (different data + sequence numbers), not just one.
            # a single-packet hit could be a fluke; N/N rules that out.
            fn = CONSTRUCTIONS[construction]
            allok = sum(fn(q["data"], key) == q["digest"] for q in pkts)
            print(f"[{'+' if allok == len(pkts) else '!'}] cross-check: {allok}/{len(pkts)} authenticated packets in this capture validate with '{key.decode()}'")
            if allok != len(pkts):
                sys.exit(3)
            # persist for later phases
            Path("results").mkdir(exist_ok=True)
            Path("results/phase1_key.txt").write_text(
                f"{key.decode()}\n{alphabet}\n{construction}\n")
            print("[*] wrote results/phase1_key.txt")
            return
        else:
            print(f"[-] exhausted {alphabet}/{construction} in {dt:.1f}s, no match")
    print("[!] no key found under any construction/alphabet", file=sys.stderr)
    sys.exit(4)


if __name__ == "__main__":
    main()
