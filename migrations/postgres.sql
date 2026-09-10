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
