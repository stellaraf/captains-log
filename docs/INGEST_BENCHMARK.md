# Native listener benchmark

This is an opt-in development integration benchmark. It inserts explicit synthetic log records through the running application listeners into the real ClickHouse `events` table. Run it against a disposable development deployment with at least 5 GiB free on both the workspace filesystem and every ClickHouse disk. The script does not configure a firewall or remove existing events.

```sh
python3 scripts/ingest-benchmark.py --host 192.0.2.10
```

The collector host is required explicitly; `192.0.2.10` above is an RFC 5737 documentation address, so replace it with your disposable collector address. TCP/UDP default to port 5514, TLS to port 6514, the local development API to port 18080, and ClickHouse to port 28123. Arguments can override these endpoints. The script reads the current database credential from `.local/dev.env` and a browser-issued bearer token from `.local/test-access-token`. The token must have at least 180 seconds remaining at startup; refresh it through the normal authenticated browser flow. No secrets are written into the receipt or printed.

## Workload and verification

The script sends 15,900 TCP messages at 265 events/second over 60 seconds, followed by 26,500 TCP messages at 2,650 events/second over 10 seconds. These are LF-framed standard PAN-OS traffic records derived exclusively from the sanitized 130-field PAN-OS 12.1 fixture. Every run uses a unique rule marker, current US/Pacific legacy timestamps and UTC high-resolution timestamps, unique session IDs, RFC 5737 / RFC 3849 test addresses, and serial `BENCHMARK-INGEST`. This serial separates synthetic input from the real firewall inventory.

Each TCP stage records actual producer elapsed time and achieved rate, exact stored row count, distinct session count, parsed count, collector drop-counter change, and time until all submitted records are stored with an observed empty collector queue. Five records in each TCP stage also undergo exact raw payload and normalized field comparison. Client `sendall` completion alone is never considered proof of ingestion. A socket write can finish before the collector has read, fsynced, parsed, and stored its messages; the separate drain measurement captures this distinction.

Five additional UDP datagrams and five TLS records exercise the actual running listener ports. TLS uses RFC 5425 octet counting, validates the local certificate trust and its `localhost` DNS identity, and requires TLS 1.2 or newer. These ten events undergo exact raw payload, session, address, application, action, subtype and port checks. A deliberately invalid TCP message must be retained verbatim with a parser error and appear in the parsing-diagnostics API. The framing delimiter is not part of the original payload.

Counts are filtered by both the synthetic serial and unique per-stage rule, so concurrent live firewall events cannot satisfy the benchmark assertions. All stage counts are checked again after the complete run to detect late duplicates. Collector queue/drop/resource metrics include the concurrent live firewall and any other syslog senders; they are process-level measurements, not per-source counters.

## Measurement limits

The benchmark samples Docker CPU and memory approximately every seven seconds (five-second interval plus Docker sampling time), and captures host free space and ClickHouse active-part bytes before and after. CPU percentages may exceed 100% when multiple cores are used. Active-part size changes also include live firewall input and background merges. They are approximate deployment measurements, not isolated per-record compression measurements. The receipt preserves the samples and timestamps for inspection.

The TCP sender has a bounded expected-duration-plus-60-second write loop, 10-second socket timeout, at most 256 frames per send, and a default 90-second drain deadline per stage. Database requests have 10-second execution and 256 MiB memory limits. UDP/TLS sample counts are fixed at five. No production-rate, 100 million row query, outage survival, FIPS, or appliance hardening claim follows from this test. Separate package tests exercise spool outage/restart behavior; bulk database benchmarks have a separate workload and report.

## Observed results

Executed 2026-09-07 22:47:34–22:49:01 UTC against the real Docker application, ClickHouse, PostgreSQL, and Keycloak development stack while the PA-1410 continued forwarding. Host: Apple M2 Ultra with 64 GiB RAM; Docker reported 16 CPUs and 23.43 GiB available memory, with the ClickHouse container limited to 3 GiB. The independent bulk ClickHouse benchmark was paused throughout.

| TCP workload | Sent = stored = distinct = parsed | Producer elapsed / rate | Stored at sender completion | Drain to exact count and empty queue | End-to-end persisted rate |
|---|---:|---:|---:|---:|---:|
| 265 EPS for 60 s | 15,900 | 60.0005 s / 265.00 EPS | 15,832 | 1.978 s | 256.46 EPS over 61.9973 s |
| 2,650 EPS for 10 s | 26,500 | 10.0001 s / 2,649.98 EPS | 23,585 | 3.885 s | 1,905.73 EPS over 13.9054 s |

Both stages had zero collector drop-counter increase. The burst demonstrates acceptance and successful subsequent persistence at the offered rate; it does **not** demonstrate indefinitely sustained 2,650 EPS database throughput. Every stage reached an observed empty queue. Raw and normalized comparisons passed for five records from each TCP stage.

All five UDP and all five TLS messages were stored exactly once and passed raw-byte/normalized-field comparisons. TLS negotiated `TLSv1.3` with `TLS_AES_128_GCM_SHA256`, with certificate trust and DNS identity verified. The intentionally invalid TCP message was stored once, preserved verbatim, marked `failed`, carried a nonempty parser error, and appeared in the authenticated diagnostics API. The total explicit test input was 42,411 messages, including this one diagnostic.

Across 13 resource samples, application CPU peaked at 156.72% and memory at 71.91 MiB; ClickHouse CPU peaked at 24.29% and memory at 1.094 GiB. These are observed samples, not guaranteed absolute peaks. Maximum sampled collector queue was 5,395 events; maximum sampled spool usage was 17,609,464 bytes (16.79 MiB). Recent-EPS samples in this receipt used the collector's earlier coarse one-second buckets and are separate from the exact elapsed/count calculations above. A subsequent correctness fix uses a full window of completed 100 ms buckets to eliminate periodic rate underestimation; the recorded count/elapsed measurements remain the original run.

ClickHouse active event-part storage increased from 1,219,436 bytes / 9,957 rows to 5,307,618 bytes / 53,459 rows: approximately 3.90 MiB net growth for 43,502 additional rows, including ongoing non-benchmark input and merge effects. Host free space decreased from 63,035,711,488 to 62,951,034,880 bytes (80.75 MiB); this also includes the durable spool and unrelated host activity. Docker's ClickHouse filesystem reported more free space after the run, illustrating why filesystem deltas cannot be treated as per-event compression measurements.

Machine-readable receipt: `.local/ingest-benchmark-4967160de4054b3cba2060b2dbe7cbbd.json`, mode 0600. Synthetic benchmark events remain in the development database under the normal retention policy.
