# Storage sizing from measurements

Never infer retention from the shipped disk size. The manager's forecast consumes measured **newly written retained-data bytes** over a stated observation duration plus event counts, filesystem capacity and current use. Net filesystem growth after TTL deletion is not a reliable ingestion-storage estimate: a full steady-state database can have zero net growth while ingesting continuously.

For a sample of `H` hours, `B` new database bytes, `E` events, capacity `C`, used bytes `U` and reserve fraction `r`:

```text
daily growth = B × 24 / H
average EPS = E / (H × 3600)
bytes/event = B / E
usable capacity = C × (1 − r)
estimated retention = usable capacity / daily growth
days until reserve = max(0, usable capacity − U) / daily growth
required capacity for D days = daily growth × D / (1 − r)
```

Recommendations round up to 100 GB increments. Forecasts with less than 24 hours are marked insufficient; less than seven days preliminary. Missing or zero growth produces an unknown estimate, never infinite or zero promised retention. Use comparable compressed on-disk bytes and exclude temporary merge duplication; retain sample provenance and coverage. Retention changes, log mix and burst patterns invalidate historical assumptions.

Host expansion observations distinguish **usable filesystem capacity**, **filesystem geometry**, and **logical-volume length**. XFS `statvfs` capacity excludes the internal journal; it cannot be subtracted directly from LV length to detect unfinished growth. The read-only inspector parses the data/log/realtime sections of `xfs_info` with size/time bounds, requires an internal journal and no realtime device, and cross-checks geometry minus journal against `statvfs`. The growth planner compares LV length with the measured full data-section geometry. A fully expanded filesystem can therefore report no remaining stages while usable capacity remains smaller than its LV. [Linux 5.14 XFS statfs](https://github.com/torvalds/linux/blob/v5.14/fs/xfs/xfs_super.c#L756-L759), [xfs_info](https://man7.org/linux/man-pages/man8/xfs_info.8.html)

For a pool with multiple encrypted physical volumes, usable capacity, geometry and free VG space describe the whole pool, while presented/unallocated disk bytes describe only the designated data disk. Additional-disk resize geometry is not yet measured; a no-op on the designated disk cannot prove that no expansion exists elsewhere. The API leaves overall expansion unknown in that case. Missing growth fields remain unknown for older publishers; partial growth objects are rejected. These sanitized observations expire after 90 seconds and contain no device identities, unlock material or execution fingerprint. Real guest expansion/recovery qualification remains pending.

The specified reference profile, 265 EPS, is 22,896,000 events/day. If (and only if) measured growth is 34 GB/day, a 1 TB decimal capacity has approximately 25 days of usable retention with 15% reserve. This example is a mathematical test fixture, not a measured Captain’s Log benchmark.

```sh
PYTHONPATH=appliance python3 -m nebulalog_manager.cli storage sizing --measurements measurements.json
```

Example input format:

```json
{"capacity_bytes":1000000000000,"used_bytes":500000000000,"samples":[{"hours":24,"written_bytes":34000000000,"events":22896000}]}
```

## Read-only API inputs

`GET /api/storage` reads capacity/current event bytes from `system.disks` and
active `system.parts`. Its demand inputs come from successful `NewPart` entries
for `nebulalog.events` in `system.part_log`, using part-creation `event_time`.
The query excludes merge, mutation, download and failed-part records, unrelated
tables and future records. New-part bytes include compressed data and initial
part overhead. Final merged size can differ; raw payload length and query-log
uncompressed written bytes are not substituted for these measurements. ClickHouse
documents the event types and size columns in its
[part-log reference](https://clickhouse.com/docs/reference/system-tables/part_log).

The endpoint reports `write_measurements.windows.1h`, `.24h` and `.7d`, each with
the exact UTC `from`/`to`, seconds, newly written bytes, inserted rows, average EPS,
bytes/event, daily equivalent, coverage and quality. `as_of` is the beginning of
the previous UTC minute to allow time for asynchronous system-log flushing.
The timestamp describes durable database part creation, whereas per-device rates
in [INVENTORY.md](INVENTORY.md) use the event's appliance ingestion timestamp.
These related clocks are deliberately labeled separately.

Eight days of bounded part-log history are read. A whole-window rate requires an
observed record at or before the window's start. Missing/disabled/inaccessible
part logging yields `status:unavailable`; a short history yields null whole-window
rates. Recorded zero writes remain distinguishable from unavailable observations.
The endpoint does not create system logging or write PostgreSQL sample records.

The legacy `daily_growth_bytes` API field now means measured daily **new-part write
demand**, not net disk growth. Forecasts choose the seven-day input when available,
otherwise the full 24-hour input; an hour alone is not extrapolated into a qualified
day. Zero demand leaves retention unknown. All estimates are labeled
`forecast_status:preliminary`, because retained log extent cannot establish
continuous part-log recording, stable log mix or final merge compression. The
response says `observation_continuity:not_verified`; interrupted logging and
historical policy changes require review. A cleared part log cannot preserve a
previously measured forecast.

The API accounts for non-event usage on the same disk. Let `N=max(0,U−database
bytes)` and let `D` be measured daily write demand:

```text
event retention capacity = max(0, C × 0.85 − N)
estimated retention days = event retention capacity / D
days until reserve = max(0, C × 0.85 − U) / D
days until physical full = max(0, C − U) / D
required capacity for T days = (T × D + N) / 0.85
recommended capacity = ceil(required capacity / 100 GB) × 100 GB
```

Exact 100-GB recommendation boundaries are not rounded to an additional increment.
The current database bytes/event field remains a snapshot of retained active parts;
the window's written bytes/event is a separate ingestion measurement.

## Verification and remaining gates

Real ClickHouse 25.8 integration tests execute the production SQL over inline
records. They verify that merges, mutations, failed writes, other tables and
future entries do not inflate demand. Pure calculation tests cover 265 EPS,
reserve/non-event capacity, short/zero histories and exact recommendation rounding.
These checks insert no production event and change no retention policy.

The current development part log has less than a day of history, so its 24-hour
and seven-day demand/retention forecasts correctly remain unknown. Production
still requires retained metric continuity, measured merge/index behavior, reserve
alarms and 100M/1B query latency on representative hardware. See the release
acceptance record for executed benchmarks; these calculations do not close those
larger acceptance gates.
