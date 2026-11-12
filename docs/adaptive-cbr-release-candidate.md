# Adaptive CBR release candidate

The default transport can now evaluate startup after 500 ms when it has queued
payload, measured useful load, and authenticated delivery feedback. A full queue
of predominantly small packets can also justify a modest rate increase after two
clean epochs. A brief fall in useful throughput no longer ends startup if the
sender still has backlog and delivery feedback is clean. This change adds no
fixed maximum rate or new user-facing mode.

## Bench results

The November 12, 2026 fixture ran on Linux 7.3 (arm64), with 12 ms propagation in
each direction and a bounded 700 Mbit/s TBF on each WAN exit (393,216-byte burst,
786,432-byte limit). The direct and tunnel routes used the same offered load and
fixture. The configured 700 Mbit/s is a lab setting, not a protocol limit.

| Run | Duration | Direct TCP payload (Mbit/s) | SFERA TCP payload (Mbit/s) | SFERA ICMP received/sent | SFERA TUN TX drops (server/client) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Upload | 38 s | 658.47 | 304.59 | 379/380 | 1,674 / 1,521 |
| Download | 38 s | 663.39 | 316.11 | 379/380 | 1,525 / 1,225 |
| Duplex (upload/download) | 65 s | 656.61 / 653.15 | 203.31 / 128.34 | 650/650 | 2,496 / 1,834 |

Duplex ICMP p95 was 60.2 ms through SFERA versus 32.7 ms direct. The two
directional runs also recorded WAN queue drops. ICMP delivery and TCP completion
can coexist with packet drops and retransmissions.

A separate paired, instrumented 38 s duplex comparison isolated the startup
retention change. The control reached a 100 Mbit/s pacing target at 39.8 s on
the server and never reached it on the client. The candidate reached it at
about 7.7 s on the server and 8.2 s on the client. The uninstrumented candidate
repeat delivered 194.29 / 173.39 Mbit/s of TCP payload and 379/380 ICMP probes.

On a 56 s 200 → 60 → 200 Mbit/s capacity step, the paired candidate had 720
TUN TX drops versus 1,137 for its control. Both delivered 560/560 ICMP probes,
but candidate TCP payload throughput fell from 121.74 / 66.53 to 113.74 /
60.41 Mbit/s. A first run on a slower 12 → 3 → 12 Mbit/s step delivered 329/330
ICMP probes. These observations confirm response to bandwidth changes; the
regression on the faster step still needs investigation.

Fixture candidate SHA-256: pacing source
`4972f865f83d6f3056ab2b4dadd1c1561d56b8aae03c727fc259740e2a98bb66`,
Linux binary `0790b002c017abb41115db6f1f738790fad387a8c5448753b06d8a5fd33cef15`.

## Open before a stable release

- Reduce the throughput gap and TUN drops under sustained load. A prototype
  that applied TUN backpressure moved drops into the kernel queue on the test
  kernel, so the next comparison must count both queues along with TCP goodput
  and latency.
- Find why the rate overshoots after a sharp bandwidth drop. Repeat directional
  and duplex capacity steps, tracking WAN and TUN drops separately alongside
  recovery time and TCP goodput.
- Validate packet timing and rate against a complete, independent IP-camera
  WebRTC capture. A plain RTP camera trace and a webcam through a media server
  are different fixtures and do not establish equivalence.
- Repeat the same load and reconnect matrix on a second independent operator
  route once one is available. The available tests do not establish resistance
  to operator filtering or traffic classification.
