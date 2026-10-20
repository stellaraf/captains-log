-- Explicit version 2 migration, applied separately from immutable application
-- schema 1/2/3. The existing host_stepup_pending table stays inert; never copy
-- its rows or infer missing host challenges. Invalidation clears both tables.
-- Short-lived server-only OAuth transactions with mandatory host authority
-- bindings. State is hashed; nonce/verifier/tokens never enter audit/job JSON.
-- No default schema or challenge values can promote legacy inserts.
CREATE TABLE IF NOT EXISTS host_stepup_pending_v2 (
 record_schema integer NOT NULL CHECK (record_schema = 2),
 state_hash text PRIMARY KEY CHECK (state_hash ~ '^[a-f0-9]{64}$'),
 nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
 pkce_verifier text NOT NULL CHECK (pkce_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),
 policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
 actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048 AND actor_issuer !~ '[[:cntrl:]]'),
 actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 512 AND actor_subject !~ '[[:cntrl:]]'),
 actor_client_id text NOT NULL CHECK (octet_length(actor_client_id) BETWEEN 1 AND 512 AND actor_client_id !~ '[[:cntrl:]]'),
 actor_session_digest text NOT NULL CHECK (actor_session_digest ~ '^[a-f0-9]{64}$'),
 installation_id text NOT NULL CHECK (installation_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),
 operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_.]{0,127}$'),
 plan_id text NOT NULL CHECK (plan_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),
 plan_digest text NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
 resource_revision text NOT NULL CHECK (resource_revision ~ '^[a-f0-9]{64}$'),
 binding_expires_at timestamptz NOT NULL CHECK (isfinite(binding_expires_at)),
 created_at timestamptz NOT NULL CHECK (isfinite(created_at) AND created_at >= '1970-01-01T00:00:00Z'),
 expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
 challenge_schema integer NOT NULL CHECK (challenge_schema = 1),
 challenge_id text NOT NULL CHECK (challenge_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),
 challenge_subject_digest text NOT NULL CHECK (challenge_subject_digest ~ '^[a-f0-9]{64}$'),
 challenge_operation_schema integer NOT NULL CHECK (challenge_operation_schema = 1),
 challenge_action text NOT NULL CHECK (challenge_action IN ('job.accept', 'job.cancel')),
 challenge_request_digest text NOT NULL CHECK (challenge_request_digest ~ '^[a-f0-9]{64}$'),
 challenge_policy_generation text NOT NULL CHECK (challenge_policy_generation ~ '^[a-f0-9]{64}$'),
 challenge_issued_at bigint NOT NULL CHECK (challenge_issued_at BETWEEN 1 AND 253402300799),
 challenge_expires_at bigint NOT NULL CHECK (challenge_expires_at BETWEEN 1 AND 253402300799),
 CHECK (expires_at > created_at AND expires_at <= created_at + interval '120 seconds'),
 CHECK (expires_at <= binding_expires_at),
 CHECK (challenge_expires_at > challenge_issued_at AND challenge_expires_at <= challenge_issued_at + 120),
 CHECK (created_at >= to_timestamp(challenge_issued_at)),
 CHECK (expires_at <= to_timestamp(challenge_expires_at) AND to_timestamp(challenge_expires_at) <= binding_expires_at)
);
CREATE INDEX IF NOT EXISTS host_stepup_pending_v2_expiry ON host_stepup_pending_v2 (expires_at, state_hash);
