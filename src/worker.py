import argparse
import hashlib
import os
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ALPHABETS, CONSTRUCTIONS
from protocol import send_msg, MsgReader

# sub-batch size: crack this many keys, then emit PROGRESS and check for STOP.
# ~1M keys ~= 0.4s at ~2.4 Mkeys/s, so heartbeats land well inside any timeout.
BATCH = 1_000_000


def crack_batch(data, target, alphabet, length, construction, start, end):
    """crack [start,end); return (key, idx) or None. inlined for throughput."""
    chars = ALPHABETS[alphabet].encode()
    b = len(chars)
    digits = []
    x = start
    for _ in range(length):
        x, r = divmod(x, b)
        digits.append(r)
    key = bytearray(chars[d] for d in digits)
    if construction == "keyed_md5":
        prime = hashlib.md5(data)
        pad = b"\x00" * (16 - length) if length < 16 else b""
        for idx in range(start, end):
            h = prime.copy()
            h.update(bytes(key) + pad)
            if h.digest() == target:
                return bytes(key), idx
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
    fn = CONSTRUCTIONS[construction]
    for idx in range(start, end):
        if fn(data, bytes(key)) == target:
            return bytes(key), idx
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


def run(host, port, wid, die_after=None):
    sock = socket.create_connection((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    reader = MsgReader(sock)
    send_msg(sock, {"type": "HELLO", "worker": wid, "host": socket.gethostname(),
                    "pid": os.getpid(), "cores": os.cpu_count()})
    params = reader.read()
    if not params or params.get("type") != "PARAMS":
        print(f"[{wid}] no PARAMS, exiting", file=sys.stderr)
        return
    data = bytes.fromhex(params["data"])
    digest = bytes.fromhex(params["digest"])
    alphabet = params["alphabet"]
    length = params["length"]
    construction = params["construction"]
    print(f"[{wid}] joined: alphabet={alphabet} len={length} construction={construction}", flush=True)

    t_start = time.time()
    total_tried = 0
    # split wall time into compute (hashing) vs socket-wait (blocked on the
    # master) so phase 3 can classify the workload as CPU- or network-bound.
    t_compute = 0.0
    t_wait = 0.0
    while True:
        _s = time.perf_counter()
        send_msg(sock, {"type": "REQUEST"})
        msg = reader.read()
        t_wait += time.perf_counter() - _s
        if msg is None:
            break
        mt = msg.get("type")
        if mt == "STOP":
            print(f"[{wid}] STOP (key={msg.get('key')!r} by {msg.get('by')})", flush=True)
            break
        if mt == "NOWORK":
            # nothing free right now; brief wait then re-request. also send a
            # heartbeat so the master keeps us alive while we idle.
            send_msg(sock, {"type": "HEARTBEAT"})
            time.sleep(0.2)
            continue
        if mt != "ASSIGN":
            continue
        chunk, start, end = msg["chunk"], msg["start"], msg["end"]
        stop = False
        pos = start
        while pos < end:
            b_end = min(pos + BATCH, end)
            _c = time.perf_counter()
            res = crack_batch(data, digest, alphabet, length, construction, pos, b_end)
            t_compute += time.perf_counter() - _c
            total_tried += b_end - pos
            if res:
                key, idx = res
                send_msg(sock, {"type": "FOUND", "chunk": chunk,
                                "key": key.decode(), "idx": idx})
                print(f"[{wid}] FOUND key={key.decode()!r} idx={idx}", flush=True)
                stop = True
                break
            rate = total_tried / max(time.time() - t_start, 1e-9)
            _s = time.perf_counter()
            send_msg(sock, {"type": "PROGRESS", "chunk": chunk,
                            "tried": b_end - start, "rate": rate})
            m = reader.poll(0.0)
            t_wait += time.perf_counter() - _s
            # crash injection for node-death testing
            if die_after and total_tried >= die_after:
                print(f"[{wid}] simulated crash after {total_tried} keys", flush=True)
                os._exit(1)
            if m and m.get("type") == "STOP":
                print(f"[{wid}] STOP mid-chunk (key={m.get('key')!r})", flush=True)
                stop = True
                break
            pos = b_end
        if stop:
            break
        _s = time.perf_counter()
        send_msg(sock, {"type": "DONE", "chunk": chunk, "tried": end - start})
        t_wait += time.perf_counter() - _s

    wall = time.time() - t_start
    hps = total_tried / t_compute if t_compute else 0.0
    cpu_frac = t_compute / (t_compute + t_wait) if (t_compute + t_wait) else 0.0
    # machine-parseable summary line for the phase-3 benchmark harness
    print(f"SUMMARY {wid} tried={total_tried} compute_s={t_compute:.4f} "
          f"wait_s={t_wait:.4f} wall_s={wall:.4f} hps={hps:.1f} cpu_frac={cpu_frac:.4f}",
          flush=True)
    try:
        send_msg(sock, {"type": "SUMMARY", "worker": wid, "tried": total_tried,
                        "compute_s": t_compute, "wait_s": t_wait, "hps": hps})
        sock.close()
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9099)
    ap.add_argument("--id", default=f"w{os.getpid()}")
    ap.add_argument("--die-after", type=int, default=None,
                    help="simulate node death after N keys (for death-detection tests)")
    a = ap.parse_args()
    run(a.host, a.port, a.id, a.die_after)


if __name__ == "__main__":
    main()
