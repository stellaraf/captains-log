# Firewall inventory measurements

The authenticated inventory endpoints are `GET /api/firewalls` and
`GET /api/firewalls/{serial}`. All authenticated appliance roles retain read
access; metadata changes still require ADMINISTRATOR. A serial filter is bound
independently in both ClickHouse and PostgreSQL queries. The API never accepts
table names, SQL fragments, grouping intervals or arbitrary query scopes.

Inventory metadata is persisted by ingestion. Reads merge the latest retained
ClickHouse observation with saved friendly name, site, tags and notes without
writing PostgreSQL or running a query per device. A device observed in ClickHouse
but missing saved inventory metadata is returned with empty editable metadata;
the next successful ingestion metadata write persists its record.

## Rate windows

All rates count persisted events by **`ingested_at`**, the appliance timestamp.
Neither firewall-generated timestamps nor firewall receive clocks affect these
measurements. A request has one explicit UTC `as_of`; windows include their start
and exclude their end. Events at or after `as_of` are excluded.

| Field | Meaning |
| --- | --- |
| `rate_windows.averages.60s` | Retained events during the trailing 60 seconds divided by 60. |
| `rate_windows.averages.1h` | Trailing 3,600 seconds divided by 3,600. |
| `rate_windows.averages.24h` | Trailing 86,400 seconds divided by 86,400. |
| `rate_windows.averages.7d` | Trailing 604,800 seconds divided by 604,800. |
| `rate_windows.peaks.1m` | Maximum completed UTC minute-bucket count divided by 60, within the trailing seven days. |
| `rate_windows.peaks.5m` | Maximum completed UTC five-minute-bucket count divided by 300, within the trailing seven days. |
| `rate_windows.peaks.1h` | Maximum completed UTC hour-bucket count divided by 3,600, within the trailing seven days. |
| `events_today` | Retained events from UTC midnight through `as_of`; the day is explicitly UTC. |

Peaks are fixed, aligned buckets, not arbitrary sliding-window maxima. The
unfinished current bucket and any initial bucket that begins before the earliest
retained observation are excluded. Fractional-second first observations cannot
turn an incomplete bucket into a full one. A quieter completed bucket can therefore
be lower than the current trailing-60-second rate during a new burst.

For compatibility, `current_eps`, `average_eps` and `peak_eps` alias the 60-second
average, 24-hour average and one-minute peak respectively. They are nullable.
The detailed windows include `from`, `to`, duration, rate, coverage and quality.
Display those labels when comparing measurements instead of presenting every rate
as an unspecified “EPS.”

## Coverage and missing observations

The API reads at most eight days of event history: seven days of measurements plus
one day to establish the older temporal boundary. A complete average requires an
older retained observation at or before its start and a shortest configured
global/per-type retention at least as long as the window. Otherwise its `eps` is
null and quality is `insufficient_history`. A new device's few seconds of data
are never divided by a full day and presented as a measured day average.

For peaks, a completed bucket can supply an observed maximum before the full
seven-day lookback exists. Such a result has quality `partial_lookback` and
`history_covers_window:false`. A device with no usable completed buckets has a
null peak. A measured zero and an unavailable rate are distinct.

`history_covers_window` establishes retained temporal extent and the current
retention policy. **It does not establish uninterrupted collector availability,
lossless firewall forwarding or unchanged historical retention.** Each response
states `observation_continuity:not_verified` and
`historical_retention_changes:not_verified`. TTL deletions, earlier policy changes,
lost messages and manual deletion can remove evidence; these rates then describe
remaining retained events. Durable ingestion-rate rollups with coverage tracking
are still required to preserve historical rates independently of log deletion.
`quiet` means no retained event in the last minute, not a reachability diagnosis.

## Bounds and validation

One ClickHouse query groups all requested devices into the three peak widths and
an aggregate row. It has an eight-day timestamp bound, the existing interactive
30-second/512-MiB limits, a two-million-group ceiling and a 10,000-result ceiling.
Exceeding grouping/result limits throws an error instead of silently truncating
the peak population. PostgreSQL metadata is fetched in one scoped query. Query
scaling on 100 million and one billion rows remains an open acceptance gate.

`TestInventoryWindowCalculationsClickHouse` executes the actual SQL over inline
`values`/`numbers` data, including multi-device bursts, fractional first timestamps,
incomplete current buckets, future events, timestamp-selected metadata and serial
filter injection. It creates no table and writes no event. Set the private test
environment variables `NEBULALOG_TEST_CH_URL`, `NEBULALOG_TEST_CH_USER` and
`NEBULALOG_TEST_CH_PASSWORD` to run the opt-in ClickHouse tests. Do not put secrets
in shell history or committed fixtures.

The development ClickHouse 25.8 instance passed those calculations and an
additional read-only query against its existing events. This validates SQL and
window semantics; it does not close production query latency, continuity,
retention-independent metrics or the full release acceptance matrix.
