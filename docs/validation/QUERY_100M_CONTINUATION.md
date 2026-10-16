# 100M query qualification continuation

Measured October 16, 2026. The isolated ClickHouse dataset contains exactly
**100,000,000 synthetic Traffic records**, including raw messages, Base64 and
field representations. The final page profile completed **33 case pairs,
66 modes and 660 samples** through the actual Go store, with all declared
median targets met. This combines 31 accepted pairs from an interrupted run
with a separately bounded two-pair continuation; it was not one uninterrupted
run. Retained failures and their limits are described below.

A separate nine-query check passed on the selected Altinity 25.3 engine. That
check proves bounded fallback compatibility, not 100M performance on that engine.
A separate all-family ingestion test stopped on total-server-memory pressure.
Its at-least-once retry preserved all unique events with identical replay copies;
query completion does not close the sustained or burst acceptance gates.

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
destination port 443 over seven days, then failed in both projections with
native ClickHouse error 241, exceeding the 512 MiB query limit. It retained
one normalized sample before failure and no successful full-payload sample;
the final three pairs were not attempted. That run did not complete its final
dataset-prefix check and remains failed/incomplete.

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
subsequent final-profile matrix retained bounded response bodies once per
SHA-256 and linked each sample to its actual body.

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

## Final-profile matrix: 33 pairs across the retained run and continuation

The final-profile run used source commit
`09c60b2185076ef1f37cb4034a45df6b9d931333` and the same local ARM64 execution
boundary and query caps. Between 11:16:04 and 11:24:23 UTC it completed cases
0–30: **31 pairs, 62 modes and 620 samples**. All measured medians met the
declared targets. The 1,364 worker requests have matching successful native
finishes and retained response bodies; maximum native memory was 450,923,585
bytes. Independent review reparsed the body, request and native evidence.

The supervisor reached its **548-read limit** before dispatching case 31.
That same exhausted budget prevented its final dataset-prefix check. This was
a harness accounting failure, not a new page-query memory failure. Neither of
the remaining pairs was launched: seven-day **time range** (case 31) and
**denied/drop Traffic** (case 32). The original result remains held and has no
final dataset-prefix proof.

A separately bounded continuation attempted only the missing pairs with the
same binary, source, oracle and page profile. It stopped at 11:54:40 UTC after
three successful metadata queries and one failed **independent ID-control
query** for case 31. That `SELECT id` used the ordinary event-read profile,
without the page-specific buffering and remerge settings. Native error 241
reported a proposed allocation of 513.09 MiB against its unchanged 512 MiB cap.
The worker returned before either production-page mode; **zero new samples**
were measured and case 32 was never started. This is a control-query limit,
not a measured failure of the corrected production-page profile.

The continuation's reserved terminal proof succeeded: exactly 100,000,000
unique ordinal IDs, 0 through 99,999,999, with no foreign or malformed rows.
Its executor exited one and was reaped without timeout or forced kill. Both
held runs remain intact. A second continuation used generator-derived literal
ordered IDs for only the two unmeasured pairs. The derivation enumerates complete
timestamp ties and preserves descending ID order; its vectors were independently
checked against comparable successful controls. Production page settings and the
full-column oracle remained unchanged. This avoids repeating the memory-failing
native ID-control query; it does not weaken the page or payload assertions.

| Retained receipt | SHA-256 |
| --- | --- |
| Final-profile held result, 31 pairs | `b02b681c0fd6ba495ba07635ee9b38cde9042661f3afa2abc9e8d87d920ee32a` |
| Final-profile host terminal | `e42f893714b6bb444e42be2590e353a792d32a13f89c2033d06dc90ba6b53739` |
| Independent budget/failure diagnosis | `077231627b5d03a6f21102edd038644b03b6d13774d7aa5a2d75beeceef3d81e` |
| Two-case continuation held result, zero samples | `d306dfa31c617e5d0e4f0a4e9c7c6902212b2c08980ba34dc1f4f7d83c6449fd` |
| Two-case continuation host terminal | `a2c3ae884d05b04f9b5c611049577d29c82d652332deed4b106f3b9b5ae5260e` |

## Completed local 100M query measurements

The final continuation ran from **12:15:39 to 12:16:48 UTC** and completed both
remaining pairs: 40 new samples, 86 worker SELECTs with 86 successful native
finishes and no native errors, plus 75 supervisor reads. Its executor exited
zero and was reaped within its 20-minute authority. The initial and final checks
both found exactly 100,000,000 unique ordinal IDs, 0 through 99,999,999, with no
foreign or malformed rows. Its maximum native query memory was 70,922,687 bytes.

Combined with the preserved 620 samples, this establishes **33 pairs, 66 modes,
660 measured samples and 1,450 qualifying worker requests** on the same source
and page profile. The four requests from the failed ID-control attempt remain
separate; neither failed run has been relabeled successful. Independent review
revalidated the request/native/settings chains and reparsed 30 retained body
artifacts (26 distinct content hashes) referenced by the 660 samples against
the unchanged 44-column synthetic oracle.

Each cell below is the **normalized / full-payload median in milliseconds**,
from ten samples per mode. The declared median targets were 1,000 ms for the
recent-hour window, 2,000 ms for 24 hours and 5,000 ms for seven days. Every mode
met its target. These are first-page results, usually capped at 200 rows.

| Filter | Recent 1 hour | 24 hours | 7 days |
| --- | ---: | ---: | ---: |
| Source IP | 29.913 / 46.736 | 55.096 / 286.688 | 119.141 / 1016.484 |
| Destination IP | 41.785 / 143.972 | 35.659 / 140.445 | 50.814 / 160.089 |
| Source CIDR | 39.364 / 61.777 | 28.916 / 66.907 | 50.133 / 88.559 |
| Application | 42.951 / 76.090 | 45.005 / 67.655 | 50.348 / 86.192 |
| Rule | 39.977 / 66.922 | 28.977 / 71.682 | 46.709 / 88.541 |
| Action | 33.029 / 72.790 | 45.311 / 70.800 | 55.377 / 93.847 |
| Firewall | 39.064 / 54.332 | 26.247 / 55.807 | 45.434 / 71.403 |
| Destination port | 30.380 / 63.391 | 43.591 / 57.275 | 50.496 / 89.925 |
| Source + destination | 30.037 / 37.392 | 34.119 / 35.250 | 32.270 / 51.084 |
| Time range | 39.331 / 55.533 | 39.609 / 59.209 | 51.422 / 82.952 |
| Denied/drop Traffic | 35.561 / 66.329 | 36.324 / 71.445 | 64.669 / 91.913 |

The two final pairs retained these p50/p95 results:

| Seven-day case | Projection | p50 | p95 |
| --- | --- | ---: | ---: |
| Time range | Normalized | 51.422 ms | 63.553 ms |
| Time range | Full payload | 82.952 ms | 92.561 ms |
| Denied/drop Traffic | Normalized | 64.669 ms | 89.120 ms |
| Denied/drop Traffic | Full payload | 91.913 ms | 100.405 ms |

The p95 values interpolate only ten samples and are not stable tail-latency
estimates. No cache reset occurred. The initial 31 pairs ran a narrow database
control before page measurements; the final two used literal IDs and metadata
reads before page measurements. Both used the same page settings, but their
warm-up histories differ. The all-family producer had already stopped before
the final continuation; its services remained present. This shared development
host is not a controlled concurrency or native appliance performance result.

| Retained receipt | SHA-256 |
| --- | --- |
| Successful two-pair result and 33-pair aggregate | `b5f85a6ecad14d0a27a9a0f2abdb940e411fa76692831682c38b2e841a5fa017` |
| Successful continuation host terminal | `5b1f3c159d9b56fd1eec0527efd147beccd421996b0b7071e6cb61b0ff7621f6` |
| Independent actual native/body review | `eacd3222ce0042430dafa0071f660292722fbd8b108a506e64601e350fade3ac` |

## Altinity 25.3 fallback compatibility

The current Go store was also exercised against the pinned
**25.3.8.30001.altinityfips** image, using a small deterministic 4,096-row
synthetic source. The image and worker ran as amd64 containers on the shared
ARM64 development host. This is an engine compatibility check, not a native
x86 appliance or performance measurement.

The first attempt stopped after two successful native SELECTs, before any
event-page request. Its synthetic expression
`toUInt64('18446744073709551615') - number` produced an `Int64`: for ordinal
4,095 the value was −4,096, rather than the expected UInt64
18,446,744,073,709,547,520. The literal oracle correctly rejected that fixture.
Read-only reconciliation found both native finishes, no native errors or
active queries, and confirmed that `bitNot(toUInt64(number))` produces the
expected UInt64. The failed fixture and evidence were preserved, and its
container was stopped.

A new fixture changed only that synthetic expression, retaining the oracle
and production page code. It **passed at 11:40:13 UTC**: nine SELECTs, nine
native starts and finishes, and zero native errors. Three fallback pages
returned **200 ascending, 1,001 descending and 200 cursor-paginated rows**.
Their order and full decoded payloads matched the independent literal oracle,
including the large UInt64 values; retained raw bodies were independently
reparsed. Native settings explicitly reported `read_in_order_use_buffering=0`.
The new owned container was then stopped with all evidence retained.

This proves that the selected fork recognizes the setting and supports those
bounded fallback pages. It does **not** prove lazy materialization on 25.3,
native FIPS operation, appliance acceptance or performance at scale. The image
name alone is not a FIPS qualification result.

| Retained receipt | SHA-256 |
| --- | --- |
| First-attempt reconciliation and synthetic type proof | `a279b9bc24e419fd7da8c1b64be9eb3e0946c3bb20e739d62d0aee0f5d1f19e7` |
| Corrected compatibility terminal | `7f52a0685e42c490dd4eb8426db44b4c3ca9c5446b93f72d2c4c34beb1f17a3b` |

Mixed PAN-OS families, the 265 EPS retention population, 30/90-day
production-equivalent scale, native Rocky/FIPS performance, OVA import and
final acceptance remain open. Earlier 10M results remain in
[the original report](../BENCHMARKS.md).

## Separate ingestion workload failure

These query results do not establish ingestion reliability. A separate split-role
collector run covered 26 sanitized templates across 14 categories. Its 312-record
transport controls passed, but the sustained phase stopped at 12:06:46 UTC on a
ClickHouse total/server-memory exception 241. It did not complete the required two hours
or the five-minute burst.

The producer recorded 60,642 completed sends. Read-only reconciliation found
**61,071 stored rows and 60,642 unique IDs**: 429 IDs each had two identical
copies. Unique-event raw and bound SHA-256 checksum aggregates matched the sent
set; no missing or altered unique payload was detected by that reconciliation.
The failed INSERT reported `written_rows=555` in its native query log; that
counter is not a committed-row count. The collector retried the retained batch
and subsequently reported an empty queue and 60,642 inserted events. That counter
tracks logical events after database and WAL acknowledgment, not physical rows
written by all attempts; it does not measure or exclude replay copies.

Identical replay copies after partial or ambiguously acknowledged database writes
are permitted by the existing [at-least-once delivery contract](../SYSLOG.md#durable-buffering).
This observation does not establish an exactly-once guarantee or a violation of
that contract. The total-memory failure remains a failed sustained-load result;
resource sizing and a fresh complete sustained and burst workload require
qualification. The original rows, payloads, WAL and failure evidence remain
preserved. The independent query dataset and page timings are separate.

Retained duplicate/payload reconciliation SHA-256:
`6b9a0d1b57ec386efbca183dc7068d7b7966a89592bae97bc8ceba303687e02d`.
