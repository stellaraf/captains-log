# Application API contract

JSON keys use snake_case. Errors: `{ "error": "safe human-readable message" }`.
Every `/api/` endpoint requires a Keycloak bearer token except `/api/config`,
the minimal `/api/health` and a single-use expiring download capability.
Roles are ADMINISTRATOR, ANALYST, VIEWER.

- `GET /api/config`: `{auth:{url,realm,client_id},version}`.
- `GET /api/me`: `{id,name,role}`.
- `GET /api/preferences` and `PUT /api/preferences`: `{theme:"system"|"light"|"dark",density:"compact"|"comfortable",rail_collapsed:false}`. PostgreSQL persisted per authenticated subject; all roles can change their own preferences. The browser may cache display settings for pre-paint application but the server remains authoritative.
- `GET /api/logs?type=traffic&query=...&from=<RFC3339>&to=<RFC3339>&limit=200&cursor=...&sort=received_at&order=desc`: `{events:[],next_cursor:"",elapsed_ms}`. Default past hour, max limit 1000. `type=unified` includes all; `type=parsing` includes failed records.
- The Threat view includes stored `threat` records and DNS detections whose original `wire_type` is `THREAT`. DNS Security remains an overlapping view of stored `dns` records. URL, WildFire submissions and Data remain separate even when their wire format is THREAT. View membership does not rewrite records, duplicate storage or change their retention policy. A query-language `type eq ...` condition still filters the stored `log_type`, within the selected view.
- `type=alarms` is retained for route compatibility and displayed as **System alerts**: high/critical System records, not native PAN-OS Alarm logs. Authentication contains native Authentication Policy records; administrator authentication remains in System (`subtype eq auth`). Tunnel parsing is unsupported and explicitly labeled in the viewer; raw unrecognized records remain available through Parsing diagnostics.
- The log viewer offers automatic refresh every 5, 10, 30 or 60 seconds, Manual mode and Pause/Resume. Interval and pause preferences are stored per account in this browser, separately from server display preferences. Pause cancels an outstanding automatic refresh; manual refresh and explicit searches remain available. Resume immediately refreshes. Empty views identify the selected time/filter scope and offer an explicit 30-day search instead of implying that every category is waiting for forwarding.

This overlapping Threat/DNS behavior follows [PAN-OS DNS Security log guidance](https://docs.paloaltonetworks.com/dns-security/administration/monitor-dns-security/view-dns-security-logs). A read-only ClickHouse regression in `internal/api/search_clickhouse_test.go` verifies category, time and manual-filter behavior over inline records, plus the real sanitized DNS fixture's classification.
- Event fields: `id,ingested_at,generated_at,received_at,sender_ip,serial,device_name,vsys,log_type,subtype,schema_version,parser_version,parse_status,parse_error,raw,src_ip,dst_ip,src_port,dst_port,src_zone,dst_zone,src_user,dst_user,app,previous_app,action,rule,session_end_reason,bytes,bytes_sent,bytes_received,packets,session_id,nat_src_ip,nat_dst_ip,severity,description`.
- `GET /api/events/{id}?at=<received_at RFC3339>&type=<log_type>`: `{event}` or404 after expiry/not found. Stable detail links carry observed time/category for a bounded index-assisted lookup. Raw bytes remain available as `raw_base64` when the original payload contains invalid UTF-8.
- `POST /api/query/validate {query}`: `{valid:true}` or 400 safe syntax error.
- `GET /api/fields`: `{fields:[{alias,column,label,type,operators:[]}]}`.
- `GET /api/filters`: `{filters:[{id,name,description,query,log_type,columns:[],time_range,sort,favorite,builtin}]}`.
- `POST /api/filters` and `PUT /api/filters/{id}`: the filter object; return saved object. `DELETE /api/filters/{id}`. Owner scoped. Built-ins are read-only; duplicate creates a new object without id.
- `GET /api/layouts/{type}` and `PUT /api/layouts/{type}`: `{columns:[],widths:{},sort,order}`. PostgreSQL persisted per subject.
- `GET /api/firewalls`: `{firewalls:[{serial,device_name,sender_ip,friendly_name,site,tags:[],notes,panos_version,first_seen,last_seen,events_today,current_eps,average_eps,peak_eps,status}]}`. `PUT /api/firewalls/{serial}` accepts friendly_name/site/tags/notes (admin).
- `GET /api/firewalls/{serial}`: `{firewall}` with the same metadata and recent statistics, or404. Peak EPS is null until measured.
- `GET /api/stats`: `{messages_received,messages_parsed,parse_failures,events_inserted,queue_depth,spool_bytes,messages_dropped,events_per_second,bytes_per_second,last_event_received,listeners:[]}`.
- `GET /api/storage`: measured ClickHouse disk/parts information with `capacity_bytes,used_bytes,available_bytes,database_bytes,events,bytes_per_event,daily_growth_bytes,estimated_retention_days,reserve_percent,requirements:[],status`. Unknown projections are null. Host expansion capability is separately reported, never fabricated.
- `GET /api/retention`: `{revision,global_days,per_type:{},legacy_alarms_days?,engine:{schema,mode,table_uuid?,message?},status:{state,message,observed_at?,...}}`. All values are whole days (1–3650); presets30/60/90/180/365 and custom values remain supported. The optional legacy Alarms value was ineffective and is shown for review, not silently applied.
- `PUT /api/retention` (Administrator): `{expected_revision,global_days,per_type:{},apply_existing:true}`. Atomically audits before/after and applies to all retained and future events by UTC ingestion age. HTTP409 for stale revision, migration/maintenance or unresolved removal. System alerts share `system`; `alarms` is an alias only if it agrees with any `system` value. Unified/Parsing overrides are rejected. Extensions cannot restore physically deleted data. Legacy arrival-time TTL must pass the explicit held migration first; no row rewrite or save-triggered DDL occurs.
- Event reads bind current retention; a changed policy revision invalidates old search cursors (409) and export downloads/tickets. In-flight reads and exports use a snapshot; exported files retain their existing 24-hour lifetime. Physical storage accounting can include expired rows awaiting whole-day cleanup. See [retention semantics and migration](RETENTION.md).
- `POST /api/dns/resolve {ips:[]}`: `{results:{"ip":{hostname,status}}}` immediately returns cache/pending and queues bounded background work. `DELETE /api/dns/cache` admin.
- `POST /api/exports {query,log_type,from,to,columns:[],sort,order}`: `{id,status}`. `GET /api/exports/{id}`: `{id,status,rows,bytes,error}`; `GET /api/exports/{id}/download` streams completed CSV. ANALYST/admin only, jobs owner scoped. Visible-row export may run in the browser.
- `POST /api/exports/{id}/download-ticket`: `{url,expires_in}` for a completed owned job; the returned `/api/downloads/{token}` capability expires after60seconds and is redeemed once. Browser-native downloads avoid buffering the complete file in frontend memory. Export jobs cap output at512MiB, two concurrent jobs,2GiB retained exports. Database sorting spills at128MiB and caps temporary query disk use at1GiB; oversize work fails visibly and should be narrowed.
- `GET /api/security`: actual configured/observed security capability and unverified host status. UI must not show green hardening claims for development.
- `GET /api/updates`: actual update service status/capability; pending appliance validation must be visible.

## Identity provider administration

Only ADMINISTRATOR can access `/api/identity/` routes. Guides remain available
when the optional scoped Keycloak manager is not configured. The manager uses a
separate confidential service client with identity-provider management and realm
read privileges; it never receives the bootstrap administrator password.

- `GET /api/identity/providers`: `{available,providers:[]}`; exactly Entra/Okta supported. Unconfigured provider entries carry derived SP URLs and `configured:false`.
- `GET /api/identity/providers/{alias}`: `{provider}`. Existing public certificates include validity dates and `currently_valid`; expired trust can be inspected and replaced.
- `POST /api/identity/providers/{alias}/preview`: `{metadata_xml,groups:{viewer,analyst,administrator},enabled:false}` → `{preview}`. Parses one uploaded IdP descriptor of at most256KiB, rejects DTD/entities/external resources, validates HTTPS endpoints/signing keys and three distinct exact group values. It makes no provider changes and fetches no metadata URLs.
- `PUT /api/identity/providers/{alias}`: same input → `{provider}`. An audited operation disables the owned provider while replacing its settings/mappers, verifies required OTP and explicit role mappings, then enables it only if requested. Unrelated aliases/mappers are refused; a failed save leaves the owned provider disabled when that state can be verified. The error states any uncertainty.
- `PATCH /api/identity/providers/{alias}/state {enabled}`: `{provider}`. Disable without reuploading metadata, including when a certificate has expired. Enable requires a fresh strict configuration/MFA check. Existing sessions/tokens are not revoked by either operation.
- `POST /api/identity/providers/{alias}/test`: `{status}` with `configuration_valid`, `external_login_tested:false`, checked time and a safe message. This checks saved settings, mappers and required broker OTP; it does not perform an external login.

Provider writes record durable PostgreSQL audit intent before Keycloak changes
and completion/failure afterward. Keycloak is an external transaction boundary;
an interrupted operation may require inspection. A single manager serializes its
own writes. Do not perform concurrent manual Keycloak edits or run multiple
configuration managers because Keycloak's provider API has no compare-and-swap.
See [SAML setup](SAML.md) for provider-side steps and pilot acceptance.

The browser logs in through keycloak-js, PKCE S256, with tokens kept only in
memory, and refreshes the token before each API request. A 401 triggers login.
