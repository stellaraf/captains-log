CREATE TABLE IF NOT EXISTS saved_filters (
 id uuid PRIMARY KEY, owner_id text NOT NULL, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 description text NOT NULL DEFAULT '', query text NOT NULL, log_type text NOT NULL DEFAULT 'traffic',
 columns jsonb NOT NULL DEFAULT '[]', time_range text NOT NULL DEFAULT '1h', sort text NOT NULL DEFAULT 'received_at',
 favorite boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saved_filters_owner ON saved_filters(owner_id);
CREATE TABLE IF NOT EXISTS layouts (owner_id text NOT NULL, log_type text NOT NULL, layout jsonb NOT NULL, PRIMARY KEY(owner_id,log_type));
CREATE TABLE IF NOT EXISTS firewalls (
 serial text PRIMARY KEY, device_name text NOT NULL DEFAULT '', sender_ip text NOT NULL DEFAULT '',
 friendly_name text NOT NULL DEFAULT '', site text NOT NULL DEFAULT '', tags jsonb NOT NULL DEFAULT '[]', notes text NOT NULL DEFAULT '',
 panos_version text NOT NULL DEFAULT '', first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS settings (key text PRIMARY KEY, value jsonb NOT NULL);
INSERT INTO settings(key,value) VALUES('retention','{"global_days":90,"per_type":{"traffic":60,"threat":365,"url":90,"authentication":365,"configuration":365,"system":365}}') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS audit_events(id bigserial PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, action text NOT NULL, target text NOT NULL, detail jsonb NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS export_jobs (
 id uuid PRIMARY KEY, owner_id text NOT NULL, status text NOT NULL, rows bigint NOT NULL DEFAULT 0, bytes bigint NOT NULL DEFAULT 0,
 error text NOT NULL DEFAULT '', request jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours'
);
CREATE TABLE IF NOT EXISTS storage_samples(sampled_at timestamptz NOT NULL DEFAULT now(), database_bytes bigint NOT NULL, events bigint NOT NULL, PRIMARY KEY(sampled_at));

ALTER TABLE saved_filters ADD COLUMN IF NOT EXISTS sort_order text NOT NULL DEFAULT 'desc' CHECK(sort_order IN ('asc','desc'));

CREATE TABLE IF NOT EXISTS user_preferences (
 owner_id text PRIMARY KEY,
 theme text NOT NULL DEFAULT 'system' CHECK(theme IN ('system','light','dark')),
 density text NOT NULL DEFAULT 'compact' CHECK(density IN ('compact','comfortable')),
 rail_collapsed boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now()
);

-- Emergency retention is separate from expiry assigned to future arrivals.
INSERT INTO settings(key,value) VALUES('storage_emergency','{"revision":1,"enabled":true,"trigger_percent":95,"recover_percent":90,"minimum_days":{"traffic":1,"url":7,"threat":30,"wildfire":30,"dns":30,"data":30,"hip":30,"globalprotect":30,"iptag":30,"userid":30,"decryption":30,"tunnel":30,"configuration":30,"system":30,"authentication":30}}') ON CONFLICT DO NOTHING;
INSERT INTO settings(key,value) VALUES('storage_emergency_maintenance','{"schema":1,"held":false,"delivery_held":false,"operation":null}') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS storage_emergency_state (
 singleton boolean PRIMARY KEY CHECK(singleton), value jsonb NOT NULL
);
INSERT INTO storage_emergency_state(singleton,value) VALUES(true,'{"state":"not_observed","observed_at":null,"message":"Waiting for the first verified ClickHouse disk observation","emergency_active":false,"insert_exclusions":0}') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS storage_emergency_actions (
 id uuid PRIMARY KEY, state text NOT NULL CHECK(state IN ('prepared','executing','uncertain','awaiting_cleanup','completed','cancelled')),
 plan jsonb NOT NULL, message text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS storage_emergency_one_pending ON storage_emergency_actions((true)) WHERE completed_at IS NULL;
CREATE TABLE IF NOT EXISTS storage_emergency_inserts (
 id uuid PRIMARY KEY, table_uuid uuid NOT NULL, partitions jsonb NOT NULL, query_id uuid NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now()
);

-- The engine remains unavailable until the explicit migration verifies the
-- events table identity and absence of legacy TTL. No event rows are rewritten.
INSERT INTO settings(key,value) VALUES('retention_engine','{"schema":1,"mode":"uninitialized"}') ON CONFLICT DO NOTHING;
INSERT INTO settings(key,value) VALUES('retention_status','{"state":"not_observed","message":"Waiting for retention engine verification"}') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS retention_actions (
 id uuid PRIMARY KEY, state text NOT NULL CHECK(state IN ('prepared','executing','uncertain','awaiting_cleanup','completed','cancelled')),
 plan jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS retention_one_pending ON retention_actions((true)) WHERE completed_at IS NULL;
