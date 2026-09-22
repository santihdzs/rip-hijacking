"""shared rip/rfc2082 parsing and digest primitives for the tc2007b cracker.

references:
- RFC 2453 (RIPv2), RFC 2082 (RIP-2 MD5 authentication)
"""
import hashlib
import hmac as _hmac

# candidate alphabets. brief is contradictory ("hexadecimal" vs "lowercase
# letters and numbers"), so we try hex (16^6, fast) before base36 (36^6).
HEX = "0123456789abcdef"
BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
ALPHABETS = {"hex": HEX, "base36": BASE36}


def keyspace_size(alphabet: str, length: int) -> int:
    """total keys for an alphabet NAME (key into ALPHABETS) and length."""
    return len(ALPHABETS[alphabet]) ** length


def index_to_key(idx: int, alphabet: str, length: int) -> bytes:
    """map an integer index in [0, base**length) to a fixed-length key.

    `alphabet` is a NAME (key into ALPHABETS). little-endian positional
    encoding over the alphabet; contiguous index ranges therefore map to
    non-overlapping key chunks (used for partitioning).
    """
    chars = ALPHABETS[alphabet]
    b = len(chars)
    out = bytearray(length)
    for i in range(length):
        idx, r = divmod(idx, b)
        out[i] = ord(chars[r])
    return bytes(out)


# --- digest constructions -------------------------------------------------
# the brief SAYS "HMAC-MD5" but RFC 2082 specifies keyed-MD5 (key right-padded
# to 16 bytes, appended to the rip data, then plain MD5). we implement both and
# let the brute force decide which one actually reproduces the captured trailer.

def keyed_md5(data: bytes, key: bytes) -> bytes:
    """RFC 2082 keyed-MD5: MD5(data || key padded with zeros to 16 bytes)."""
    return hashlib.md5(data + key.ljust(16, b"\x00")).digest()


def hmac_md5(data: bytes, key: bytes) -> bytes:
    """standard HMAC-MD5 with the raw key (NOT what RFC 2082 uses)."""
    return _hmac.new(key, data, hashlib.md5).digest()


CONSTRUCTIONS = {"keyed_md5": keyed_md5, "hmac_md5": hmac_md5}


# --- pcap extraction ------------------------------------------------------

def extract_auth_packets(pcap_path: str):
    """return authenticated RIPv2 packets (auth type 3) from a pcap.

    each item is a dict with the raw RIP UDP payload plus the pre-sliced
    regions needed for digest reconstruction:
      raw     full RIP payload (header..trailer incl. 16-byte digest)
      data    everything up to but excluding the 16-byte digest field
              (== RFC 2082 MD5 input region, before the key is appended)
      digest  the captured 16-byte trailer digest
      seq     sequence number from the auth header
      keyid, authlen, pktlen  auth header fields
    """
    from scapy.all import rdpcap, UDP

    results = []
    for pkt in rdpcap(pcap_path):
        if not pkt.haslayer(UDP):
            continue
        udp = pkt[UDP]
        if udp.sport != 520 or udp.dport != 520:
            continue
        # scapy dissects RIP into its own layers, so re-serialize the UDP
        # payload back to raw bytes rather than looking for a Raw layer.
        payload = bytes(udp.payload)
        if len(payload) < 24:
            continue
        cmd, ver = payload[0], payload[1]
        # authenticated response: first RTE is AFI 0xffff, auth type 3
        afi = int.from_bytes(payload[4:6], "big")
        authtype = int.from_bytes(payload[6:8], "big")
        if not (cmd == 2 and ver == 2 and afi == 0xFFFF and authtype == 3):
            continue
        pktlen = int.from_bytes(payload[8:10], "big")
        keyid = payload[10]
        authlen = payload[11]
        seq = int.from_bytes(payload[12:16], "big")
        digest = payload[-16:]
        data = payload[:-16]  # through the trailer AFI(ffff)+type(0001)
        results.append({
            "raw": payload, "data": data, "digest": digest, "seq": seq,
            "keyid": keyid, "authlen": authlen, "pktlen": pktlen,
        })
    return results


def crack_chunk(data: bytes, target: bytes, alphabet: str, length: int,
                construction: str, start: int, end: int,
                progress_cb=None, progress_every: int = 200_000):
    """brute-force key indices in [start, end); return (key_bytes, idx) or None.

    construction/alphabet are looked up by name so this is reusable by the
    oracle and by distributed workers over identical semantics.
    """
    fn = CONSTRUCTIONS[construction]
    chars = ALPHABETS[alphabet].encode()
    b = len(chars)
    if start >= end:
        return None
    # odometer state for `start` (digit 0 = least significant), matching
    # index_to_key so chunk boundaries stay aligned with the global keyspace.
    digits = []
    x = start
    for _ in range(length):
        x, r = divmod(x, b)
        digits.append(r)
    key = bytearray(chars[d] for d in digits)
    tried = 0

    # fast path: keyed_md5 over a fixed data prefix -> reuse a primed md5 state.
    if construction == "keyed_md5":
        prime = hashlib.md5(data)
        pad = b"\x00" * (16 - length) if length < 16 else b""
        for idx in range(start, end):
            h = prime.copy()
            h.update(bytes(key) + pad)
            if h.digest() == target:
                return bytes(key), idx
            tried += 1
            if progress_cb and tried % progress_every == 0:
                progress_cb(tried)
            # increment odometer
            i = 0
            while i < length:
                d = digits[i] + 1
                if d < b:
                    digits[i] = d
                    key[i] = chars[d]
                    break
                digits[i] = 0
                key[i] = chars[0]
                i += 1
        return None

    for idx in range(start, end):
        if fn(data, bytes(key)) == target:
            return bytes(key), idx
        tried += 1
        if progress_cb and tried % progress_every == 0:
            progress_cb(tried)
        i = 0
        while i < length:
            d = digits[i] + 1
            if d < b:
                digits[i] = d
                key[i] = chars[d]
                break
            digits[i] = 0
            key[i] = chars[0]
            i += 1
    return None
