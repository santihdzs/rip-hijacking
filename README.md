# RIPv2 (RFC 2082) auth key recovery — distributed cluster

TC2007B network-security lab. Recovers the keyed-MD5 authentication key from
captured RIPv2 updates, using a master-worker brute-force cluster over TCP.

## key result
- **construction**: RFC 2082 keyed-MD5 `MD5(D || key_padded_to_16)`, NOT HMAC-MD5
- **alphabet**: base36 (lowercase + digits), NOT hex
- **recovered key (06_01)**: `ykusrq` (validated against all 21 auth packets)

## setup
```
uv sync            # installs scapy into .venv
```

## phase 1 — oracle (single-threaded)
Parses a pcap, reverse-engineers the auth, brute-forces the key.
```
uv run python src/rip_oracle.py pcaps/rip_passkey_size_06_01.pcap
```

## phase 2 — distributed cluster
Master partitions the keyspace and coordinates workers over TCP; master also
cracks via local worker subprocesses. Start the master, then >=3 workers.
```
uv run python src/master.py pcaps/rip_passkey_size_06_01.pcap --port 9099 --local-workers 4
# in other shells / on other hosts:
uv run python src/worker.py --host <master-ip> --port 9099 --id w1
```
Node-death: kill or freeze a worker; the master requeues its chunk (heartbeat
timeout or socket disconnect) so no block is skipped.

## phase 3 — benchmarks
```
uv run python src/bench.py     # writes results/benchmarks.{json,txt}
```

## phase 4 — report
```
cd paper/essay && latexmk -pdf main.tex     # 4-page report, main.pdf
```
Plotting notebook: `paper/notebooks/graphing.ipynb`.

## deferred (needs Mininet box)
`src/inject_route.py` forges a valid authenticated RIP update offline; live
FRR/Mininet injection is a guarded stub (`--i-have-mininet`). See its TODO.
