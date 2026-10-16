# 100M query qualification continuation

Measured October 16, 2026. The isolated ClickHouse dataset contains exactly
**100,000,000 synthetic Traffic records**, including raw messages, Base64 and
field representations. A query-memory correction passed a focused diagnostic.
**The complete query matrix with that correction is not yet qualified.**

## Dataset and execution boundary

The retained table is `nebulalog.benchmark_events`, UUID
`d11e0290-b2d0-4018-8259-1be279d83e19`. The diagnostic checked 100,000,000 unique
ordinal suffixes covering 0 through 99,999,999, with no malformed IDs or foreign
rows, both before and after execution. The rows were generated directly in the
database. This does not measure Syslog, parsing, WAL or collector throughput.

ClickHouse 25.8.33.6 ran under a 3 GiB memory and 3 CPU container limit on the
shared Apple M2 Ultra development host. The actual Go store diagnostic worker
was built with Go 1.27.2 for macOS ARM64. It was not the Rocky x86_64 appliance
binary. The dataset occupied 21,525,431,161 active bytes across 272 parts at the
diagnostic's initial observation. Synthetic repetition and a Traffic-only
distribution limit any production sizing inference.

Event pages retained the 512 MiB query-memory cap, two query threads, 8,192-row
blocks, a 64 MiB sort-remerge threshold and 30-second execution limit. Lazy
materialization used the existing 1,001-row lookahead threshold. The diagnostic
changed only the page setting `read_in_order_use_buffering=0`; it did not raise
resource limits or replace the requested payload with a narrower one.

## Observed failure and correction

The preceding run completed 29 case pairs: 58 modes and 580 measured samples.
Their recorded medians met the declared targets. Case 29 (zero-based),
destination port 443 over seven days, then failed during its normalized mode
with native ClickHouse error 241, exceeding the 512 MiB query limit. Its full
payload mode and the final three case pairs were not measured. That run did
not complete its final dataset-prefix check and remains failed/incomplete.

The focused candidate reran that exact case through the Go store. Each mode
returned 200 rows in the expected order on all ten samples. The pinned worker
validated decoded fields against the deterministic dataset oracle.

| Projection | Samples | p50 | p95 |
| --- | ---: | ---: | ---: |
| Normalized columns | 10 | 52.8295 ms | 57.77735 ms |
| Full payload (`* EXCEPT expires_at`) | 10 | 81.6850 ms | 95.40760 ms |

Maximum native memory among the measured **page queries** was 53,797,040 bytes.
The diagnostic's overall native peak was 493,593,846 bytes, including its
separate narrow control query. The retained execution plans no longer contain
`BufferChunks`; this supports the correction but does not independently prove
that buffering was the sole cause of the preceding failure.

There were 49 worker HTTP requests linked to successful native query finishes
and 50 supervisor SELECTs. The host executor exited zero, was reaped, and was
not timed out or killed. The dataset checks matched before and after the run.
No cache reset occurred; a narrow control preceded the normalized and full
payload samples. The figures are warm/mixed-cache first-page measurements,
not cold-cache, pagination, aggregate, arbitrary-filter or concurrency results.

## Evidence and limits

Private T9 evidence retains request SQL, query IDs, native query-log results,
decoded response hashes, exact source/build identities and executor results.
Independent review checked those chains. The diagnostic did **not** retain the
20 actual HTTP response bodies, so an independent reviewer cannot reparse them;
field validation relies on execution of the pinned worker and oracle. The
planned full-matrix successor retains bounded response bodies once per SHA-256
and links each sample to its actual body.

| Retained receipt | SHA-256 |
| --- | --- |
| Failed preceding run result | `b6e55c22031b62e128f45f47efb786271a269135f13077eb92e38cd2bedee1a0` |
| Native error resolution | `f9c361a7259aa61002b60258b9fc00d9397e6c12220eb354122a0be503d2a572` |
| Focused candidate result | `2ca8ab318f6f49065b10d11de84b9323df3975d75a7f9d80284bb34198a00185` |
| Host terminal | `c75b23576d8a4048d6ae70223c3d7efd1007dad12d315a351989926095ccb225` |
| Independent terminal review | `9d5900d31c84e9429a2792e5bab72971feb509c9a97de0e51221a0ffc41fd013` |

The baseline source was `65433ffe478767be122c0d739ac37196208e17e8`.
The diagnostic candidate's binary SHA-256 was
`9337b5741c438e62ec6b1ab8bfbe40cfa27ff52cc11b5af1511df90f36dc4871`.
The production change applies the setting only to event-page profiles,
including the capability fallback; detail, export, aggregate and capability
probe profiles retain their existing settings.

All 33 case pairs, 66 modes and 660 samples still require fresh qualification
using the final production profile. The previous 29 passing pairs cannot be
combined with this diagnostic to claim a complete run under one profile.
The new setting also requires execution against the selected appliance
ClickHouse fork, separate from earlier compatibility checks. Mixed PAN-OS
families, the 265 EPS retention population, 30/90-day production-equivalent
scale, native Rocky/FIPS performance, OVA import and final acceptance remain
open. Earlier 10M results remain in [the original report](../BENCHMARKS.md).
