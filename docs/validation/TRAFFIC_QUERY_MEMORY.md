# Wide Traffic search memory regression

Observed and corrected on September 8, 2026 UTC in the local Docker development stack. This is application evidence; it does not qualify the frozen v7 Rocky build, a sealed OVA, or the required 100M-event benchmark.

## Failure and correction

The live category audit found that Traffic searches over one day and seven days returned HTTP 503, while the default one-hour view and seven-day Threat/DNS views worked. ClickHouse reported Code 241 when reading full event payloads, exceeding the existing 512 MiB per-query limit. A small output page does not necessarily imply a small intermediate read: this endpoint also returns raw text and the complete field map.

Interactive log pages and event details now use a dedicated ClickHouse event-read profile with `max_threads=2` and `max_block_size=8192`. The 512 MiB budget, 30-second limit, buffered completion/error handling, selected fields, filters, sorting and cursor rules are unchanged. Generic analytics and ingestion keep their existing settings; export settings and deadlines are unchanged. The implementation is in `internal/store/clickhouse.go` and the two event-read call sites in `internal/api/search.go`.

## Controlled database and source verification

The exact full-payload seven-day Traffic query succeeded with the bounded profile. Additional actual-table checks covered one-day descending time, seven-day descending time with 1,001 rows, ascending time, ascending source IP and descending byte count. All returned HTTP 200 and their ordered identity hashes matched lightweight identity-only control queries at the same fixed time bounds. Actual ClickHouse query-log peaks ranged from **121,981,077 to 337,485,097 bytes**, below the unchanged 536,870,912-byte limit. Server execution was 69–225 ms. These observations used approximately 178,000 Traffic records; they do not replace the larger release benchmark.

Profile-isolation, full raw/map/base64 and UInt64 decoding, handler wiring, limits, numeric/string/time cursors, event identity/time and late-error refusal have targeted tests. The final full Go run used the retained runtime's exact Go 1.25.14 compiler and `GOFIPS140=v1.0.0`, with local integration fixtures enabled: **135 top-level tests and 456 subtests passed, zero failures or skips**. `go vet -p 1 ./...` also passed with that exact compiler/module. An independent source review found no blocking issue. A separate real `numbers(1001)` fixture established result parity, not MergeTree memory relief.

## Development deployment

The backend binary was rebuilt for Linux ARM64 with Go 1.25.14, CGO disabled and the same frozen Go FIPS module. Its source inventory SHA-256 is `cbc0eae6e3301402d251353451bae41e3599d31f20b7caa1609d3d3367b9a70b`; binary SHA-256 is `75c4a8bdf7c41d13bca1083b7a7f9cee978ed7eb7096f077a265daae9dcfe4e2`. This identifies the backend build, not a committed full product source release or qualified FIPS operating environment.

A binary-only layer over the exact previous development image produced image `sha256:b74d7d89943bc448e344c9773b5ebeae646fd869723f71524cd053e352936f72`, version **`0.1.0-dev.query-memory-cbc0eae6e330`**. The existing `index-C0sr2okI.js` frontend and both migration files were preserved byte-for-byte. The later storage-plan panel is still source/preview work and is not deployed by this backend update.

The first replacement passed health checks but a comparison of environment-list order triggered an automatic rollback. The original environment's normalized key/value hash matched the restored container. The reviewed retry rejected duplicate keys and compared exact key/value maps, runtime settings, mounts, ports and other container identities. It succeeded at **10:34:51 UTC**; environment values matched and list ordering differed. No exports were queued or running before either replacement. The PostgreSQL, ClickHouse and Keycloak containers retained their original identities.

Post-cutover inspection confirmed the exact binary/frontend/migration hashes, healthy application/databases, all three UDP/TCP/TLS listeners and no restart, OOM or startup warning/error. Fresh native Traffic, DNS/THREAT and System records had ingestion timestamps after the new app started. This proves resumed ingestion, not uninterrupted delivery or zero UDP loss during replacement.

## Authenticated running-app verification

A fresh normal QA password/OTP login verified the deployed version and retained frontend. The original fixed seven-day window now succeeds at limits 1, 200 and 1,000; the one-day query succeeds as well. Two consecutive 1,000-row pages have correct time/ID ordering and no duplicate IDs. Ascending time, ascending source IP, descending bytes and a manual action filter pass. Two event-detail responses match every field from their corresponding page rows. The browser renders the wide Traffic page, opens Original payload and preserves exact raw content across direct detail reload.

All **19 category API requests** (18 categories plus one filtered Threat query) returned HTTP 200, and three category browser checks passed. The sampled Threat and DNS pages contain the same 200 retained events, reflecting the documented shared view. Configuration had no events in the tested window; its empty-state guidance and explicit 30-day expansion preserved the filter. A successful empty response does not prove native support or generation of every log family.

The unchanged refresh and application browser suites passed **all six cases**, with zero failures, skips or flaky results. This includes interval persistence, pause/manual/resume behavior, in-flight cancellation, mobile behavior, authentication, saved/graphical filters and layout persistence. Saved filters and the Traffic layout exactly matched their pre-test baselines afterward. Only the new QA session was deleted, and its absence was independently checked; the existing QA identity, OTP and human operator were preserved. All owned browsers closed. Final health remained HTTP 200 on the exact hotfix version at **10:44:47 UTC**.

## Private evidence and remaining boundary

Receipts retain aggregates, hashes and sanitized results; customer payloads and credentials are excluded from this document and source control:

- `.local/traffic-query-memory-experiments-20260908.json`
- `.local/traffic-query-memory-boundary-experiments-20260908.json`
- `.local/traffic-query-memory-parity-20260908.json`
- `.local/traffic-event-read-validation-20260908.json`
- `.local/traffic-query-hotfix/full-go-tests.json` and `go-vet.json`
- `.local/traffic-query-hotfix/build-binary.json` and `build-image.json`
- `.local/traffic-query-hotfix/deployment-result.json` (first rollback) and `deployment-v2-result.json` (successful retry)
- `.local/traffic-query-hotfix/runtime-post-cutover.json` and `ingestion-after-v2.json`
- `.local/qa-traffic-hotfix-live-20260908/validation.json` and its linked individual receipts

These checks establish the corrected running development behavior. All appliance, external identity, scale and final sign-off gates remain in [RELEASE_ACCEPTANCE](../RELEASE_ACCEPTANCE.md).
