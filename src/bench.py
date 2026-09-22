"""phase 3 benchmarks: per-node HPS, aggregate cluster HPS, CPU vs socket bound.

three measurements, all against the real size-06 target digest:
  BM1  single-core raw hashing rate (pure compute baseline)
  BM2  multi-process scaling sweep -> per-core and aggregate HPS, saturation
  BM3  instrumented distributed run -> per-worker HPS, cluster HPS, and the
       compute-vs-socket-wait split that classifies the workload

results are written to results/benchmarks.json and results/benchmarks.txt.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from multiprocessing import Pool

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import extract_auth_packets, keyspace_size
from worker import crack_batch

PCAP = "pcaps/rip_passkey_size_06_01.pcap"
ALPHABET, LENGTH, CONSTRUCTION = "base36", 6, "keyed_md5"
_P = extract_auth_packets(PCAP)[0]
DATA, DIGEST = _P["data"], _P["digest"]


def _bm_work(args):
    """crack a [start,end) range that excludes the real key -> full work, no hit."""
    start, end = args
    t = time.perf_counter()
    crack_batch(DATA, DIGEST, ALPHABET, LENGTH, CONSTRUCTION, start, end)
    return end - start, time.perf_counter() - t


def bm1_single_core(n=5_000_000):
    print(f"[BM1] single-core raw HPS over {n:,} keys...")
    tried, dt = _bm_work((0, n))
    hps = tried / dt
    print(f"      {hps/1e6:.3f} Mkeys/s  ({dt:.2f}s)")
    return {"keys": n, "seconds": dt, "hps": hps}


def bm2_scaling(per_proc=3_000_000):
    cores = os.cpu_count()
    procs_list = sorted({1, 2, 4, 6, 8, cores})
    print(f"[BM2] scaling sweep (host has {cores} logical cores), {per_proc:,} keys/proc...")
    rows = []
    for p in procs_list:
        # give each process a disjoint range so no key is hashed twice
        ranges = [(i * per_proc, (i + 1) * per_proc) for i in range(p)]
        t0 = time.time()
        with Pool(p) as pool:
            res = pool.map(_bm_work, ranges)
        wall = time.time() - t0
        total = sum(r[0] for r in res)
        agg = total / wall
        per_core = agg / p
        rows.append({"procs": p, "total_keys": total, "wall_s": wall,
                     "aggregate_hps": agg, "per_core_hps": per_core})
        print(f"      procs={p:2d}  aggregate={agg/1e6:6.2f} Mkeys/s  "
              f"per-core={per_core/1e6:5.2f} Mkeys/s")
    return rows


def bm3_distributed(workers=8, max_index=120_000_000, chunk=2_000_000, port=9140):
    py = sys.executable
    print(f"[BM3] distributed run: {workers} workers, {max_index:,} keys, chunk {chunk:,}...")
    mp = subprocess.Popen(
        [py, str(HERE / "master.py"), PCAP, "--host", "127.0.0.1", "--port", str(port),
         "--local-workers", "0", "--chunk-size", str(chunk), "--max-index", str(max_index)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    t0 = time.time()
    wps = [subprocess.Popen(
        [py, str(HERE / "worker.py"), "--host", "127.0.0.1", "--port", str(port),
         "--id", f"bench-w{i}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for i in range(workers)]
    mp.wait()
    wall = time.time() - t0
    per_worker = []
    for w in wps:
        out, _ = w.communicate()
        for line in out.splitlines():
            if line.startswith("SUMMARY"):
                d = dict(kv.split("=") for kv in line.split()[2:])
                per_worker.append({k: float(v) for k, v in d.items()})
    total_tried = sum(w["tried"] for w in per_worker)
    agg = total_tried / wall if wall else 0
    mean_cpu_frac = sum(w["cpu_frac"] for w in per_worker) / len(per_worker) if per_worker else 0
    tot_compute = sum(w["compute_s"] for w in per_worker)
    tot_wait = sum(w["wait_s"] for w in per_worker)
    print(f"      cluster aggregate = {agg/1e6:.2f} Mkeys/s over {wall:.2f}s")
    print(f"      per-worker HPS    = {[round(w['hps']/1e6,2) for w in per_worker]} Mkeys/s")
    print(f"      compute/(compute+wait) = {mean_cpu_frac*100:.2f}%  -> "
          f"{'CPU-BOUND' if mean_cpu_frac > 0.9 else 'socket/network-bound'}")
    print(f"      aggregate compute={tot_compute:.2f}s  socket-wait={tot_wait:.2f}s")
    return {"workers": workers, "max_index": max_index, "wall_s": wall,
            "total_tried": total_tried, "aggregate_hps": agg,
            "mean_cpu_frac": mean_cpu_frac, "total_compute_s": tot_compute,
            "total_wait_s": tot_wait, "per_worker": per_worker}


def main():
    print("=" * 60)
    print("phase 3 benchmarks (target: size-06 keyed-MD5 / base36)")
    print("=" * 60)
    results = {
        "host_cores": os.cpu_count(),
        "keyspace": keyspace_size(ALPHABET, LENGTH),
        "bm1_single_core": bm1_single_core(),
        "bm2_scaling": bm2_scaling(),
        "bm3_distributed": bm3_distributed(),
    }
    Path("results").mkdir(exist_ok=True)
    Path("results/benchmarks.json").write_text(json.dumps(results, indent=2))

    lines = []
    b1, b3 = results["bm1_single_core"], results["bm3_distributed"]
    lines.append("RIP auth cracker benchmarks")
    lines.append(f"host logical cores : {results['host_cores']}")
    lines.append(f"keyspace (base36^6): {results['keyspace']:,}")
    lines.append("")
    lines.append(f"BM1 single-core HPS: {b1['hps']/1e6:.3f} Mkeys/s")
    lines.append("")
    lines.append("BM2 scaling (procs -> aggregate / per-core Mkeys/s):")
    for r in results["bm2_scaling"]:
        lines.append(f"  {r['procs']:2d} : {r['aggregate_hps']/1e6:6.2f} / {r['per_core_hps']/1e6:5.2f}")
    lines.append("")
    lines.append(f"BM3 distributed ({b3['workers']} workers):")
    lines.append(f"  cluster aggregate HPS : {b3['aggregate_hps']/1e6:.2f} Mkeys/s")
    lines.append(f"  wall time             : {b3['wall_s']:.2f}s for {b3['total_tried']:,} keys")
    lines.append(f"  compute fraction      : {b3['mean_cpu_frac']*100:.2f}%  "
                 f"({'CPU-bound' if b3['mean_cpu_frac']>0.9 else 'socket-bound'})")
    lines.append(f"  aggregate compute/wait: {b3['total_compute_s']:.2f}s / {b3['total_wait_s']:.2f}s")
    Path("results/benchmarks.txt").write_text("\n".join(lines) + "\n")
    print("\n[*] wrote results/benchmarks.json and results/benchmarks.txt")


if __name__ == "__main__":
    main()
