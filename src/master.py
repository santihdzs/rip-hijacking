"""phase 2 master: partition the keyspace and coordinate workers over TCP.

- extracts data+trailer from the target pcap (reusing the phase-1 oracle logic)
- splits the keyspace into fixed-size, non-overlapping chunks handed out on
  demand (dynamic load balancing -> no fast worker sits idle)
- detects dead nodes by heartbeat timeout and requeues their chunk so no block
  is ever skipped
- the master node also cracks: it launches local worker subprocesses so the
  coordinator host contributes CPU instead of sitting idle
- on FOUND it re-verifies the key against the captured digest, then broadcasts
  STOP to halt every worker immediately
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import extract_auth_packets, keyspace_size, CONSTRUCTIONS
from protocol import send_msg, MsgReader

HERE = Path(__file__).resolve().parent


class Master:
    def __init__(self, data, digest, alphabet, length, construction,
                 chunk_size, timeout, max_index=None):
        self.data = data
        self.digest = digest
        self.alphabet = alphabet
        self.length = length
        self.construction = construction
        self.chunk_size = chunk_size
        self.timeout = timeout

        self.keyspace = keyspace_size(alphabet, length)
        if max_index:  # cap the searched space (used for bounded benchmarks)
            self.keyspace = min(self.keyspace, max_index)
        self.num_chunks = (self.keyspace + chunk_size - 1) // chunk_size

        self.lock = threading.Lock()
        self.pending = deque(range(self.num_chunks))
        self.inflight = {}          # chunk_id -> {"wid", "last_seen", "start", "end"}
        self.completed = set()
        self.conns = {}             # wid -> socket
        self.workers = {}           # wid -> {"last_seen", "addr", "dead"}
        self.total_tried = 0
        self.found = None           # (key, wid, idx)
        self.exhausted = False
        self.done_evt = threading.Event()
        self.t0 = None
        # checkpoint/resume (set by main before serving)
        self.progress_path = None
        self.pcap_name = None
        self.packet_index = 0
        self.resume = True

    # --- chunk bookkeeping ------------------------------------------------
    def chunk_bounds(self, c):
        start = c * self.chunk_size
        return start, min(start + self.chunk_size, self.keyspace)

    def params_msg(self):
        return {"type": "PARAMS", "data": self.data.hex(),
                "digest": self.digest.hex(), "alphabet": self.alphabet,
                "length": self.length, "construction": self.construction,
                "keyspace": self.keyspace, "chunk_size": self.chunk_size}

    # --- checkpoint / resume ---------------------------------------------
    def _merged_completed_ranges(self):
        """completed chunk ids -> sorted, merged absolute [start,end) ranges."""
        ranges = []
        for c in sorted(self.completed):
            s, e = self.chunk_bounds(c)
            if ranges and ranges[-1][1] == s:
                ranges[-1][1] = e
            else:
                ranges.append([s, e])
        return ranges

    def save_checkpoint(self):
        """atomically persist searched ranges so an interrupted run can resume."""
        if not self.progress_path:
            return
        with self.lock:
            data = {
                "pcap": self.pcap_name, "packet_index": self.packet_index,
                "alphabet": self.alphabet, "length": self.length,
                "construction": self.construction, "keyspace": self.keyspace,
                "chunk_size": self.chunk_size,
                "completed_ranges": self._merged_completed_ranges(),
                "found": self.found[0] if self.found else None,
                "updated": time.time(),
            }
        os.makedirs(os.path.dirname(self.progress_path) or ".", exist_ok=True)
        tmp = self.progress_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.progress_path)  # atomic on POSIX

    def load_checkpoint(self):
        """on startup, skip ranges already searched by a previous run."""
        if not (self.resume and self.progress_path
                and os.path.exists(self.progress_path)):
            return
        try:
            with open(self.progress_path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        same = (data.get("pcap") == self.pcap_name
                and data.get("packet_index") == self.packet_index
                and data.get("alphabet") == self.alphabet
                and data.get("length") == self.length
                and data.get("construction") == self.construction
                and data.get("keyspace") == self.keyspace)
        if not same:
            print("[master] checkpoint present but params differ; ignoring it",
                  flush=True)
            return
        ranges = data.get("completed_ranges", [])
        if not ranges:
            return

        def covered(s, e):
            return any(rs <= s and e <= re_ for rs, re_ in ranges)

        remaining, skipped = deque(), 0
        for c in self.pending:
            s, e = self.chunk_bounds(c)
            if covered(s, e):
                self.completed.add(c)
                skipped += 1
            else:
                remaining.append(c)
        self.pending = remaining
        done_keys = sum(e - s for s, e in ranges)
        self.total_tried += done_keys
        print(f"[master] RESUME from {self.progress_path}: {skipped} chunks "
              f"already searched (~{done_keys:,} keys), {len(self.pending)} "
              f"chunks remaining", flush=True)

    def broadcast_stop(self, key, by):
        with self.lock:
            conns = list(self.conns.values())
        for c in conns:
            try:
                send_msg(c, {"type": "STOP", "key": key, "by": by})
            except OSError:
                pass

    def _finish_found(self, key, wid, idx):
        # re-verify before trusting a worker's claim
        recomputed = CONSTRUCTIONS[self.construction](self.data, key.encode())
        if recomputed != self.digest:
            print(f"[master] REJECTED bogus FOUND from {wid}: {key!r}", flush=True)
            return
        with self.lock:
            if self.found:
                return
            self.found = (key, wid, idx)
        # CRASH-SAFE: persist the recovered key to disk IMMEDIATELY, before any
        # STOP broadcast or cleanup, so it survives an interrupt right after find.
        self.save_found_key(key, idx)
        print(f"[master] verified key {key!r} from {wid} (idx {idx}); broadcasting STOP", flush=True)
        self.broadcast_stop(key, wid)
        self.done_evt.set()

    def save_found_key(self, key, idx):
        """write the recovered key to the ledger + per-file record, durably."""
        os.makedirs("results", exist_ok=True)
        stem = Path(self.pcap_name).stem if self.pcap_name else "unknown"
        # per-file record (overwrite)
        rec = (f"pcap={self.pcap_name}\nkey={key}\nidx={idx}\n"
               f"alphabet={self.alphabet}\nlength={self.length}\n"
               f"construction={self.construction}\n")
        with open(f"results/key_{stem}.txt", "w") as f:
            f.write(rec)
            f.flush()
            os.fsync(f.fileno())
        # master ledger (append once per pcap, deduped)
        line = (f"{self.pcap_name}\t{key}\tidx={idx}\talphabet={self.alphabet}"
                f"\tlength={self.length}\tconstruction={self.construction}\n")
        path = "results/all_keys.txt"
        try:
            with open(path) as f:
                existing = f.read()
        except FileNotFoundError:
            existing = ""
        if f"{self.pcap_name}\t" not in existing:
            with open(path, "a") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())

    # --- per-connection handler ------------------------------------------
    def handle(self, conn, addr):
        reader = MsgReader(conn)
        try:
            hello = reader.read()
        except (OSError, ValueError):
            return
        if not hello or hello.get("type") != "HELLO":
            return
        wid = hello.get("worker", f"{addr[0]}:{addr[1]}")
        with self.lock:
            self.conns[wid] = conn
            self.workers[wid] = {"last_seen": time.time(), "addr": addr, "dead": False}
        print(f"[master] worker {wid} joined from {addr} (cores={hello.get('cores')})", flush=True)
        try:
            send_msg(conn, self.params_msg())
        except OSError:
            return

        while True:
            try:
                msg = reader.read()
            except (OSError, ValueError):
                break
            if msg is None:
                break
            t = msg.get("type")
            now = time.time()
            with self.lock:
                if wid in self.workers:
                    self.workers[wid]["last_seen"] = now
                if t == "REQUEST":
                    if self.found or self.exhausted:
                        reply = {"type": "STOP",
                                 "key": self.found[0] if self.found else None,
                                 "by": self.found[1] if self.found else "exhausted"}
                    elif self.pending:
                        c = self.pending.popleft()
                        s, e = self.chunk_bounds(c)
                        self.inflight[c] = {"wid": wid, "last_seen": now, "start": s, "end": e}
                        reply = {"type": "ASSIGN", "chunk": c, "start": s, "end": e}
                    elif self.inflight:
                        # everything is out but not done; a requeue may appear
                        reply = {"type": "NOWORK"}
                    else:
                        self.exhausted = True
                        reply = {"type": "STOP", "key": None, "by": "exhausted"}
                        self.done_evt.set()
                    try:
                        send_msg(conn, reply)
                    except OSError:
                        break
                    continue
                elif t == "PROGRESS":
                    c = msg.get("chunk")
                    if c in self.inflight and self.inflight[c]["wid"] == wid:
                        self.inflight[c]["last_seen"] = now
                    continue
                elif t == "HEARTBEAT":
                    continue
                elif t == "DONE":
                    c = msg.get("chunk")
                    info = self.inflight.pop(c, None)
                    if info:
                        self.completed.add(c)
                        self.total_tried += info["end"] - info["start"]
                    continue
            if t == "FOUND":
                idx = msg.get("idx", -1)
                c = msg.get("chunk")
                with self.lock:
                    info = self.inflight.pop(c, None)
                    if info:
                        self.total_tried += max(0, idx - info["start"])
                self._finish_found(msg.get("key"), wid, idx)
                break

        # disconnect: requeue any chunk this worker still held so nothing is skipped
        with self.lock:
            requeued = []
            for c, info in list(self.inflight.items()):
                if info["wid"] == wid:
                    self.inflight.pop(c)
                    self.pending.appendleft(c)
                    requeued.append(c)
            self.conns.pop(wid, None)
            if wid in self.workers:
                self.workers[wid]["dead"] = True
        if requeued and not (self.found or self.exhausted):
            print(f"[master] worker {wid} disconnected; requeued chunks {requeued}", flush=True)
        try:
            conn.close()
        except OSError:
            pass

    # --- heartbeat / node-death monitor ----------------------------------
    def monitor(self):
        tick = 0
        while not self.done_evt.is_set():
            time.sleep(1.0)
            tick += 1
            now = time.time()
            with self.lock:
                for c, info in list(self.inflight.items()):
                    if now - info["last_seen"] > self.timeout:
                        wid = info["wid"]
                        self.inflight.pop(c)
                        self.pending.appendleft(c)
                        if wid in self.workers:
                            self.workers[wid]["dead"] = True
                        print(f"[master] TIMEOUT: worker {wid} silent >{self.timeout}s, "
                              f"requeued chunk {c}", flush=True)
                if tick % 3 == 0 and not self.found:
                    alive = sum(1 for w in self.workers.values() if not w["dead"])
                    print(f"[master] status: pending={len(self.pending)} "
                          f"inflight={len(self.inflight)} completed={len(self.completed)} "
                          f"tried~{self.total_tried:,} workers_alive={alive}", flush=True)
            # persist progress outside the lock (save_checkpoint takes it itself)
            if tick % 2 == 0:
                self.save_checkpoint()

    # --- server ----------------------------------------------------------
    def serve(self, host, port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(64)
        srv.settimeout(0.5)
        self.t0 = time.time()
        threading.Thread(target=self.monitor, daemon=True).start()
        print(f"[master] listening on {host}:{port} | keyspace={self.keyspace:,} "
              f"chunks={self.num_chunks} (size {self.chunk_size:,})", flush=True)
        while not self.done_evt.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
        srv.close()


def infer_length(pcap_path, override):
    if override:
        return override
    m = re.search(r"size_?(\d+)", Path(pcap_path).name)
    return int(m.group(1)) if m else 6


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9099)
    ap.add_argument("--chunk-size", type=int, default=5_000_000)
    ap.add_argument("--alphabet", default="base36")
    ap.add_argument("--length", type=int, default=None,
                    help="key length; inferred from filename (size_NN) if omitted")
    ap.add_argument("--construction", default="keyed_md5",
                    choices=list(CONSTRUCTIONS))
    ap.add_argument("--packet-index", type=int, default=0)
    ap.add_argument("--local-workers", type=int, default=1,
                    help="worker subprocesses launched on the master host (>=1 so master also cracks)")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="seconds of silence before a node is presumed dead")
    ap.add_argument("--max-index", type=int, default=None,
                    help="cap the searched keyspace to [0,N) for bounded benchmarks")
    ap.add_argument("--progress-file", default=None,
                    help="checkpoint path (default results/progress_<pcap>.json)")
    ap.add_argument("--no-resume", action="store_true",
                    help="ignore any existing checkpoint and start from index 0")
    a = ap.parse_args()

    pkts = extract_auth_packets(a.pcap)
    if not pkts:
        print("[master] no authenticated RIPv2 packets in pcap", file=sys.stderr)
        sys.exit(2)
    p = pkts[a.packet_index]
    length = infer_length(a.pcap, a.length)
    print(f"[master] target {a.pcap} pkt#{a.packet_index}: digest={p['digest'].hex()} "
          f"seq={p['seq']} | alphabet={a.alphabet} length={length} construction={a.construction}",
          flush=True)

    m = Master(p["data"], p["digest"], a.alphabet, length, a.construction,
               a.chunk_size, a.timeout, a.max_index)
    m.pcap_name = Path(a.pcap).name
    m.packet_index = a.packet_index
    m.resume = not a.no_resume
    m.progress_path = a.progress_file or f"results/progress_{Path(a.pcap).stem}.json"
    m.load_checkpoint()  # adjust pending BEFORE the server starts assigning

    srv_thread = threading.Thread(target=m.serve, args=(a.host, a.port), daemon=True)
    srv_thread.start()
    time.sleep(0.3)  # let the listener bind before launching local workers

    procs = []
    for i in range(a.local_workers):
        procs.append(subprocess.Popen(
            [sys.executable, str(HERE / "worker.py"), "--host", a.host,
             "--port", str(a.port), "--id", f"master-local-{i}"]))
    if a.local_workers:
        print(f"[master] launched {a.local_workers} local worker(s); master node is cracking too", flush=True)

    m.done_evt.wait()
    m.save_checkpoint()  # final flush (records completed ranges + found key)
    elapsed = time.time() - m.t0
    # make sure every worker gets STOP even if it was mid-request
    m.broadcast_stop(m.found[0] if m.found else None,
                     m.found[1] if m.found else "exhausted")
    time.sleep(0.3)
    for pr in procs:
        try:
            pr.terminate()
        except Exception:
            pass

    print("\n" + "#" * 68)
    if m.found:
        key, wid, idx = m.found
        rate = m.total_tried / max(elapsed, 1e-9)
        print(f"[master] KEY RECOVERED: {key!r}")
        print(f"    found by      : {wid} at index {idx:,}")
        print(f"    elapsed       : {elapsed:.2f}s")
        print(f"    keys tried    : ~{m.total_tried:,}")
        print(f"    aggregate rate: {rate/1e6:.2f} Mkeys/s across the cluster")
        print(f"    chunks done   : {len(m.completed)}/{m.num_chunks}")
        Path("results").mkdir(exist_ok=True)
        Path("results/phase2_result.txt").write_text(
            f"key={key}\nfound_by={wid}\nidx={idx}\nelapsed_s={elapsed:.3f}\n"
            f"total_tried={m.total_tried}\naggregate_mkeys_s={rate/1e6:.3f}\n"
            f"alphabet={m.alphabet}\nlength={m.length}\nconstruction={m.construction}\n")
        print("[master] wrote results/phase2_result.txt")
    else:
        print(f"[master] keyspace exhausted, no key found ({elapsed:.1f}s)")
    print("#" * 68)


if __name__ == "__main__":
    main()
