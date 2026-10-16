# ClickHouse

Only firewall events belong in ClickHouse. The initial schema is
`migrations/clickhouse.sql`: one MergeTree table with category/day partitions,
category/receive-time/device/event-ID sort key, compressed raw evidence, and
source/destination bloom filters. Benchmark before changing indexes or claiming
billion-row latency. Never partition by device, source address or session.

The collector sends synchronous batches (up to 1,000 rows or two seconds), and
acknowledges its spool only after the server finishes. Retries use stable event
IDs; ambiguous acknowledgments can produce duplicates. This is at-least-once,
not exactly-once. Do not run `OPTIMIZE FINAL` as routine maintenance.

Requests enforce time ranges, page limits, memory and execution bounds. The
compiler emits typed parameters. Search errors are logged by the server but
database internals are not returned to the browser. DNS enrichment is held in a
separate bounded cache and never rewrites event rows.

Production must pin the qualified LTS release digest, leave ports private, place
all data/spool/exports on encrypted storage, and tune merges against measured
hardware. Development uses a 3 GiB / 3 CPU ClickHouse container. It does not
represent the reference production hardware.

The appliance and development profiles limit merge blocks to 1,024 rows and
1 MiB (`merge_max_block_size` and `merge_max_block_size_bytes`). These settings
reduce merge buffer sizes for wide PAN-OS records; they do not cap total memory
used by concurrent merges, input granules or compression buffers. Smaller blocks
can slow merges, so acceptance must check throughput and merge backlog as well
as memory. See the [ClickHouse merge settings](https://clickhouse.com/docs/reference/settings/merge-tree-settings/merge-max).

The October 16 all-family test exposed 85 background event-merge memory errors
under a 2.25 GiB server limit, even while collector delivery counters showed no
error. That run stopped at its aggregate test-storage allowance and did not
complete the two-hour soak. The block limits are a candidate correction, pending
a complete rerun with background merge errors included in the failure checks.
Keep part history, allocated disk measurements and inactive parts in the
evidence; collector acknowledgments alone do not establish database health.
