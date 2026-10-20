CREATE DATABASE IF NOT EXISTS nebulalog;
CREATE TABLE IF NOT EXISTS nebulalog.events
(
 id String, ingested_at DateTime64(6, 'UTC'), received_at DateTime64(6, 'UTC'),
 generated_at Nullable(DateTime64(6, 'UTC')), expires_at DateTime('UTC'),
 sender_ip String, serial LowCardinality(String), device_name LowCardinality(String),
 vsys LowCardinality(String), log_type LowCardinality(String), wire_type LowCardinality(String),
 subtype LowCardinality(String), schema_version LowCardinality(String), schema_id LowCardinality(String),
 panos_version LowCardinality(String), timestamp_timezone LowCardinality(String),
 parser_version LowCardinality(String), parse_status LowCardinality(String), parse_error String,
 raw String CODEC(ZSTD(3)), raw_base64 String CODEC(ZSTD(3)), fields String CODEC(ZSTD(3)), extra_fields String CODEC(ZSTD(3)),
 src_ip String, dst_ip String, src_port UInt16, dst_port UInt16,
 src_zone LowCardinality(String), dst_zone LowCardinality(String), src_user String, dst_user String,
 app LowCardinality(String), previous_app LowCardinality(String), action LowCardinality(String), rule LowCardinality(String),
 session_end_reason LowCardinality(String), bytes UInt64, bytes_sent UInt64, bytes_received UInt64,
 packets UInt64, session_id String, nat_src_ip String, nat_dst_ip String,
 severity LowCardinality(String), description String CODEC(ZSTD(3)),
 INDEX src_bloom src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
 INDEX dst_bloom dst_ip TYPE bloom_filter(0.01) GRANULARITY 4,
 INDEX action_set action TYPE set(64) GRANULARITY 4
)
ENGINE=MergeTree
PARTITION BY (log_type, toDate(ingested_at))
ORDER BY (log_type, received_at, serial, id)
SETTINGS index_granularity=8192;
