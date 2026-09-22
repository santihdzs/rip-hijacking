# plan: rip-hijacking distributed RIP auth cracker (TC2007B)

tier: high. autonomous, phased, commit after each phase. stop only if genuinely blocked.

## phase 1 — oracle (rip_oracle.py)
- parse size-06 pcap with scapy, isolate an authenticated RIPv2 response (auth type 3, RFC 2082).
- extract: raw RIP payload, sequence number, 16-byte auth trailer digest.
- reconstruct digest input two ways and TEST BOTH (brief claims HMAC-MD5, RFC 2082 is keyed-MD5):
  - keyed-MD5: MD5( RIP data through `ffff 0001` trailer header + key right-padded to 16 bytes )
  - HMAC-MD5: HMAC(key, RIP data), same data region
- alphabet: try hex (16^6 = 16.7M) first, fall back to base36 (36^6 = 2.2B). password length 6.
- single-thread brute force; a key reproducing the captured trailer confirms construction + alphabet.
- gate: must print recovered key before phase 2.

## phase 2 — cluster (master.py, worker.py, common.py)
- master-worker over raw TCP. 1 master (also cracks, never idle) + >=3 workers.
- master extracts data+trailer from target pcap, partitions keyspace into non-overlapping chunks.
- protocol messages: assign, progress, found, heartbeat.
- node-death detection (heartbeat/timeout) + reassignment so no block skipped.
- confirm same key as phase 1.

## phase 3 — benchmarks (bench.py)
- hashes/sec per node, aggregate cluster HPS, CPU-bound vs socket-bound (compute vs socket-wait).
- save to file (results/benchmarks.*).

## phase 4 — report scaffold (LaTeX via /loom-core:paper eng)
- max 4 pages. sections: TCP protocol + message types, keyspace partition, RIP+MD5 reverse-eng & validation,
  benchmark metrics, node-death detection. fill objective parts, leave prose placeholders for user.

## deferred — DO NOT DO
- scapy route-injection into live FRR (needs user's Mininet box). stub with clear TODO.

## verification
- every phase re-checks against the phase-1 recovered key.
