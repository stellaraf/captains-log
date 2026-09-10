# Retention

Administration → Storage stores a global and per-category policy in PostgreSQL.
Each value is 1–3,650 days. The collector loads the durable policy for each batch
and stamps event expiry relative to ingestion time. PostgreSQL policy failures
hold work in the durable spool instead of inventing a retention period.

The current implementation applies policy changes to **new arrivals**. Existing
records retain their original expiry. The interface states this explicitly;
retroactive retention changes are an outstanding release feature.

ClickHouse removes expired data during TTL merges, not exactly at midnight or
the instant expiry is reached. Category/day partitions support efficient whole
part expiry. An expired record can remain physically present until merge work
occurs. Do not use row-by-row deletion or manually delete database files.

Storage thresholds are 70% informational, 80% warning, 90% critical and 95%
emergency. Development reports thresholds and bounds spool/export disk use;
automatic emergency Traffic partition purging is not enabled or qualified yet.
An appliance release must connect its audited emergency policy and protect
configured minimum retention before this acceptance gate can be checked.
