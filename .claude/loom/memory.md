# memory: rip-hijacking

Per-project memory. Curated, not hoarded. Save durable facts, decisions, constraints, and corrections. Not transient state, not re-derivable info.

Every fact carries a provenance tag:
- [stated] the user said it
- [derived] concluded from analysis or reasoning in-session
- [fetched] pulled from an external source (cite it)

Worth-remembering gate: would this matter in a later session, and is it not already recoverable from the code, the captures, or git? If no, do not write it here.

## facts
- [derived] project analyzes RIP hijacking; evidence is 6 pcaps under `pcaps/` named `rip_passkey_size_{06,07,08}_*.pcap`, suggesting the study varies the auth passkey size (6/7/8).

## phase 1-4 findings (2026-09-22)
- [derived] recovered key for `pcaps/rip_passkey_size_06_01.pcap` = `ykusrq` (base36, length 6, index 1,618,816,210 of 36^6). validated against all 21 auth packets in that capture.
- [derived] auth construction is RFC 2082 keyed-MD5: `digest = MD5(D || key_padded_to_16)`, where D = RIP payload from header through the trailer `ffff0001` (i.e. payload[:-16]). it is NOT HMAC-MD5, and the alphabet is base36 (lowercase+digits), NOT hex. the assignment brief was wrong on both counts (hex space and HMAC both exhaust with no match).
- [derived] each pcap is a distinct passkey: 06_01 != 06_02 (both length 6); 07_* are length 7, 08_* length 8. filename `size_NN` encodes key length. only 06_01 has been cracked.
- [derived] throughput: ~2.5 Mkeys/s single core; ~12.6 Mkeys/s on 8 TCP workers; workload is 99.96% compute -> strongly CPU-bound, coordination is not the bottleneck.
- [derived] scapy dissects RIP into layers, so extract the UDP payload via `bytes(udp.payload)`, not a Raw layer.
- [project] deferred: live scapy route-injection into FRR/Mininet is stubbed in `src/inject_route.py` (guarded by --i-have-mininet). needs the user's Mininet box, not done.
