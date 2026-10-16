# Bounded database scale benchmark

The September measurements below are historical. An isolated **100,000,000-row**
dataset was subsequently populated and queried on October 16. The broader run
exposed a page-memory failure; a focused correction passed, while qualification
of the complete matrix with that correction remains open. See the
[100M continuation report](validation/QUERY_100M_CONTINUATION.md) for the measured
results and their limits.

Measured on 2026-09-07 against ClickHouse 25.8.33.6. The representative synthetic table reached **10,000,000 events**. All 33 search cases completed three measured repetitions. **100 million events were not tested:** the measured active data projects to 21.39 GiB at 100M before merge reserve, or **32.08 GiB with 50% reserve**, exceeding the authorized 20 GiB benchmark budget. No search, retention, or capacity claim at 100M follows from these results.

## Environment and isolation

Apple M2 Ultra, 24 host logical CPUs, 64 GiB host RAM, ARM64 macOS 25.6.0, Docker development deployment. The ClickHouse container's actual Docker limits were verified as **3 CPU cores and 3 GiB RAM**. Each benchmark query was capped at **2 threads, 512 MiB query memory, and 120 seconds**. Final insert settings used one thread and 4,096-row blocks. Background merges share the container resources. The application continued receiving real firewall data, but the separate listener throughput benchmark had finished before database generation started; see [listener measurements](INGEST_BENCHMARK.md).

All scale records were inserted only into `nebulalog.benchmark_events`, cloned from the actual `events` schema, including codecs, indexes, partition key, ordering key, and TTL. A separate 10,000-row `benchmark_retention` table tested TTL. The live `events` table was never written, altered, or deleted by the scale script. Credentials were read from the private `.local/dev.env` file without printing them.

The script checked host physical free space >=30 GiB and benchmark table data <=20 GiB before and after every insert batch, with a projected per-batch allowance. It also required >=10 GiB free inside ClickHouse. After a shared-memory rejection, it additionally waited for resident memory below 1.8 GiB and benchmark merge memory below 384 MiB before each batch. The host had at least 51.82 GiB free at all recorded successful batch checkpoints. These are sampled guards, not a guarantee against unrelated concurrent host writes between checks.

## Dataset and reproducibility

Every row carries a 130-field PAN-style TRAFFIC CSV, its Base64 representation, the full CSV-field JSON array, and normalized core fields. All identifiers are synthetic: serial `BENCHMARK`, source subnet `10.20.0.0/16`, translated sender `192.0.2.10`, and destination subnet `198.51.100.0/24`. Applications, policies, users, ports, byte counters, sessions, and allow/deny/drop actions vary deterministically. Actual timestamps span **2026-08-08 22:50:46 through 2026-09-07 22:50:45 UTC**. IDs run from 0 through 9,999,999; the final count was exactly 10,000,000 and no row had a foreign serial or parse status.

Generation used server-side `INSERT SELECT numbers()` with batches no larger than one million. It bypassed syslog, parsing, the spool, and application writes. The 30-day timestamp distribution corresponds to only 3.86 events/second in row density; it is **not** the 265 EPS reference workload or proof of a production retention population. Repeated synthetic values and deterministic IDs compress better than many real mixes. Only TRAFFIC is represented; all other PAN log types and production cardinality/skew require separate scale tests.

The exact schema is preserved in `.local/benchmark-results.json`, SHA-256 `cd8d3c8cb3124efc5c1f8f229118d004a05333207f0649abac884bfc727adf9f`. It uses `MergeTree`, partitions `(log_type, toDate(ingested_at))`, sort key `(log_type, received_at, serial, id)`, ZSTD(3) on raw/fields/description, source/destination bloom indexes, and an action set index. Synthetic expiration was deliberately set a year into the future so the scale table was stable during measurement.

```sh
# Coordinate with other load tests first. Requires the bounded local Docker stack.
python3 scripts/benchmark.py --run --maximum-rows 100000000
# If an insertion returns an error, inspect the receipt before resuming.
python3 scripts/benchmark.py --run --resume --maximum-rows 100000000
# Removes only the marker-verified synthetic table after checkpoint evidence exists.
python3 scripts/benchmark.py --cleanup
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -q
```

The 8 guard tests cover private credential files, local-only endpoints, both independent disk budgets, cleanup ownership, foreign-row refusal, active-insert refusal, and evidence-before-cleanup. They make no network requests or database mutations.

## Storage and native generation

| Measurement | First ~1M checkpoint | 10M checkpoint |
|---|---:|---:|
| Exact rows | 1,000,001 | 10,000,000 |
| Active part bytes | 230,469,842 | 2,296,626,790 |
| Active storage GiB | 0.215 | 2.139 |
| All retained part bytes, including inactive merge inputs | 557,681,504 | 6,183,362,883 |
| Uncompressed column bytes | 2,455,696,510 | 24,608,898,190 |
| Active bytes/event | 230.47 | 229.66 |
| Uncompressed / active storage ratio | 10.66× | 10.72× |

The first checkpoint includes one preceding type-validation row. It is a storage/generation checkpoint; no search timings were recorded with only one million rows present. The 10M active footprint includes table data, indexes, and marks, but excludes WAL/application exports, system database logs, filesystem allocation overhead, OS, PostgreSQL, Keycloak, redundancy, and operational headroom. Inactive parts account for the difference between 2.139 GiB active and 5.759 GiB total table parts; merges can retain their inputs temporarily.

Successful million-row native inserts took 6.430–8.424 seconds per statement. Maximum tracked memory among successful insert statements was 442.96 MiB. These timings exclude cooldowns and failed/partially committed work; they are database generator measurements, not listener ingestion rates. The receipt contains per-statement user/system CPU counters and batch wall times.

## Search latency at 10M

Values are **p50 / p95 in milliseconds**, including localhost HTTP round trips and decoding up to 200 result rows. Each cell uses only three sequential samples; the p95 is linearly interpolated and is not a stable tail-latency estimate. Caches were not reset. The first and subsequent runs can benefit from warmed data and indexes, so these are **first-and-warm mixed** results, not cold-cache results. Every search explicitly selects TRAFFIC and applies its indicated time window, then sorts newest-first.

| Filter | Recent 1 hour | 24 hours | 7 days |
|---|---:|---:|---:|
| Source IP | 8.08 / 8.15 | 11.45 / 12.45 | 22.83 / 23.03 |
| Destination IP | 8.82 / 8.82 | 15.39 / 15.56 | 75.63 / 84.33 |
| Source CIDR | 12.27 / 12.93 | 10.15 / 11.33 | 18.50 / 19.28 |
| Application | 9.01 / 9.56 | 15.15 / 15.30 | 76.75 / 82.28 |
| Rule | 9.01 / 9.09 | 13.88 / 14.30 | 75.67 / 87.63 |
| Action | 10.09 / 10.65 | 15.41 / 15.99 | 78.88 / 82.66 |
| Firewall | 8.63 / 9.22 | 9.47 / 9.67 | 16.00 / 16.35 |
| Destination port | 11.16 / 11.66 | 15.67 / 16.25 | 105.05 / 105.81 |
| Source + destination | 9.26 / 9.52 | 10.68 / 11.33 | 10.58 / 11.62 |
| Time range | 10.08 / 10.15 | 19.27 / 22.89 | 107.71 / 130.56 |
| Denied/drop traffic | 9.87 / 11.14 | 15.09 / 16.20 | 83.96 / 89.81 |

Source-IP queries returned 2, 6, and 36 rows across the respective windows. Source-and-destination returned one row in each; the recent-hour destination query returned 58. Other cases reached the 200-row page limit. Thus these figures measure the first results page rather than full scans, total counts, deep pagination, concurrency, or arbitrary raw text search. Tracked memory peaked at 247.14 MiB across 198 successful searches (the original 99-query run and the retained 99-query rerun); their accumulated query thread CPU was 8.877 CPU-seconds. Client latency samples retained in the receipt are from the second run.

## TTL and CSV export

A separate table copied 10,000 synthetic rows with future expiration, then moved its TTL into the past and synchronously materialized it. Count changed **10,000 → 0** in **0.049 seconds**, and the empty test table was dropped. This proves that bounded TTL operation; it does not establish multi-day production TTL scheduling, large partition deletion latency, or all retention-policy flows.

The successful CSV stream returned **100,000 rows plus a header**, **11,125,265 bytes**, in **0.627 seconds**. It selected seven normalized columns and an explicit `log_type='traffic'` predicate, with a 512 MiB query cap and bounded external-sort allowance. The temporary local CSV was hashed and removed. SHA-256: `8941c9cdc7a5d94476b18e2e445e616f4b0abe7089e762f75b2070add72fca34`. This is a direct ClickHouse HTTP CSV measurement; authenticated asynchronous API exports are separate tests. Raw/field columns and CSV formula escaping are not exercised by this seven-column dataset.

## Failures, recovery, and the 100M boundary

1. The initial large insert block exceeded the 512 MiB query limit (521.27 MiB projected); no rows were committed. Smaller blocks allowed progress.
2. The sixth million-row statement was selected by ClickHouse's global memory overcommit tracker while RSS was 2.24 GiB and its tracked memory maximum was 2.25 GiB. **966,656 rows were committed before the error**. The runner resumed from the actual row count and maximum synthetic ID, preserving all committed rows instead of blindly replaying the batch. One insert thread, 4,096-row blocks, two-second cooldowns, and the shared-memory guard completed 10M without increasing any resource limit.
3. Two unfiltered 100,000-row CSV attempts exceeded the 512 MiB cap (513.40 and 515.92 MiB projected), including one with external sort configured. Their partial outputs were discarded. The explicit TRAFFIC filter allowed the equivalent single-type benchmark export to complete. Exporting across multiple log types at this scale remains a measured limitation of this query profile.
4. The first successful search and TTL run was followed by an export failure before its checkpoint had been saved. The script now persists each completed stage before starting the next one. Searches and TTL were repeated, and the second run's results are preserved.
5. At 10M, linear active-data projection alone exceeds 20 GiB for 100M; the required 50% merge reserve increases this to 32.08 GiB. The script therefore stopped without inserting further rows. No normalized-only substitute dataset was used to evade this boundary.

The host, disk, and memory limits remained unchanged. The database table guard never required deleting real data or disabling live collection. 90-day scale, 100M performance, concurrent user loads, mixed PAN log types, long-running steady ingestion, hardware appliance performance, and guest FIPS/security qualification remain unmeasured.

## Receipts and cleanup

Private local receipts (mode 0600) preserve the final schema, all retained latency samples, byte counters, successful statement CPU/memory, the partial-insert history, synthetic distribution, and failure descriptions:

- `.local/benchmark-results.json`
- `.local/benchmark-attempt-memory-limit.json`
- `.local/benchmark-attempt-overcommit.json`
- `.local/benchmark-attempt-export-memory.json`

Cleanup is restricted to the exact benchmark table after verifying its ownership marker, completed measurement receipt, zero foreign rows, and no active benchmark INSERT. Its before/after table state and absence verification are appended to the final receipt. No volume or live event data is removed.

Cleanup completed at 2026-09-07T22:59:53.528774+00:00: the ownership marker and all 10,000,000 rows were checked, no foreign rows or active synthetic inserts were found, and `benchmark_events` was dropped. A subsequent table lookup and part-state query verified absence and **zero benchmark table bytes**. Host physical free space at that observation was 53.13 GiB; host disk-image space reclamation can lag database file deletion. The live `events` table and its synthetic listener test records were preserved.
