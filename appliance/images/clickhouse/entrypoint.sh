#!/bin/bash
set +x
set -Eeuo pipefail
umask 077

fail() { printf '%s\n' "Captain’s Log ClickHouse refused: $1" >&2; exit 78; }
trap 'fail "a required startup check failed; inspect protected appliance diagnostics"' ERR

# No sourceable external configuration, optional crypto mode, secret argv or arbitrary server flags.
[[ $# -le 1 && ${1:-server} == server || $# -eq 1 && $1 == health ]] || fail 'only server and health commands are supported'
[[ -r /proc/sys/crypto/fips_enabled && $(</proc/sys/crypto/fips_enabled) == 1 ]] || fail 'an actual FIPS-enabled host kernel is required'
[[ -r /etc/crypto-policies/config && $(</etc/crypto-policies/config) == FIPS ]] || fail 'the host crypto policy must be FIPS'
[[ $(id -u) == 101 && $(id -g) == 101 ]] || fail 'the fixed service identity 101:101 is required'
for option in OPENSSL_CONF OPENSSL_MODULES OPENSSL_CONF_INCLUDE OPENSSL_ENGINES OPENSSL_FORCE_FIPS_MODE LD_PRELOAD LD_LIBRARY_PATH BORINGSSL_FIPS_BREAK_TEST CLICKHOUSE_PASSWORD CLICKHOUSE_CONFIG CLICKHOUSE_ALWAYS_RUN_INITDB_SCRIPTS; do
    [[ -z ${!option:-} ]] || fail 'cryptographic, initializer or inline credential overrides are refused'
done
[[ ${CLICKHOUSE_PASSWORD_FILE:-/run/secrets/nebulalog-ch-password} == /run/secrets/nebulalog-ch-password ]] || fail 'the fixed password-file location is required'
[[ ${CLICKHOUSE_USER:-nebulalog} == nebulalog && ${CLICKHOUSE_DB:-nebulalog} == nebulalog ]] || fail 'only the fixed appliance database/account is supported'
[[ ${CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT:-0} == 0 ]] || fail 'application account management cannot be enabled'

readonly data=/var/lib/clickhouse runtime=/run/nebulalog-clickhouse
readonly format='nebulalog-clickhouse-fips:1:25.3.8.30001.altinityfips'
[[ ! -L $data && -d $data && $(stat -c '%u:%g:%a' "$data") == 101:101:700 ]] || fail 'the data directory must be private and owned by 101:101'
source /opt/nebulalog/storage-gate.sh
nebulalog_require_encrypted_storage || fail 'the data mount must resolve entirely through LUKS2'
[[ ! -L $runtime && -d $runtime && $(stat -c '%u:%g:%a' "$runtime") == 101:101:700 ]] || fail 'a private service-owned runtime tmpfs is required'
mountpoint -q "$runtime" || fail 'runtime credentials require a dedicated tmpfs mount'
[[ $(stat -f -c %T "$runtime") == tmpfs ]] || fail 'runtime credentials require tmpfs'
source /opt/nebulalog/data-state.sh

if [[ ${1:-server} == health ]]; then
    nebulalog_data_state "$data" "$format" || fail 'invalid persistent ownership or format state'
    [[ $nebulalog_data_phase == ready ]] || fail 'the candidate has not completed initialization'
    [[ -f $runtime/ready.json && ! -L $runtime/ready.json ]] || fail 'this process has not completed crypto and TLS readiness'
    /usr/bin/clickhouse client --config-file "$runtime/client.xml" --query 'SELECT 1' >/dev/null 2>&1 || fail 'verified native TLS authentication failed'
    cat "$runtime/ready.json"
    exit 0
fi

# Lock the existing directory inode without creating a file on unclaimed data.
# Descendant engine processes inherit this lock until they stop.
exec 9<"$data"
flock -n 9 || fail 'another initializer or server still owns this datastore'
nebulalog_data_state "$data" "$format" || fail 'invalid persistent ownership or format state'
rm -f "$runtime/ready.json"
[[ ! -L /run/secrets/nebulalog-ch-password && -f /run/secrets/nebulalog-ch-password && $(stat -c '%u:%a' /run/secrets/nebulalog-ch-password) == 101:400 ]] || fail 'the password file must be a regular UID101 mode0400 secret'
for file in server.crt ca.crt server.key; do
    [[ -f /etc/nebulalog/tls/$file && ! -L /etc/nebulalog/tls/$file && -r /etc/nebulalog/tls/$file ]] || fail 'required per-install TLS material is unavailable'
done
[[ $(stat -c '%u:%g:%a' /etc/nebulalog/tls/server.key) == 0:20001:640 ]] || fail 'the server key must be root:20001 mode0640'
# The exact vendor binary executes AWS-LC startup integrity/CAST checks before main.
# A loopback-only TLS preflight additionally requires full KAT and clean shutdown.
# The immutable OCI image identity is verified by the host bundle/lifecycle manager;
# do not substitute Ubuntu's unrelated sha256sum/openssl implementations at runtime.
/usr/bin/clickhouse local --path "$runtime/identity" --max_threads 1 --query "SELECT name,value FROM system.build_options WHERE name IN ('FIPS_CLICKHOUSE','OPENSSL_VERSION','VERSION_FULL') ORDER BY name FORMAT TSV" > "$runtime/build-options.tsv" 2> "$runtime/identity.stderr"
[[ $(<"$runtime/build-options.tsv") == $'FIPS_CLICKHOUSE\t1\nOPENSSL_VERSION\tAWS-LC-FIPS-2.0.0\nVERSION_FULL\tClickHouse 25.3.8.30001.altinityfips' ]] || fail 'the expected FIPS-enabled vendor module was not identified'

# No account-specific password is used by the preflight. Its dummy hash is SHA256("abc").
# The TLS key was generated on this FIPS guest and is only used after host/storage gates.
server_pid=''
probe_pid=''
shutdown() {
    rm -f "$runtime/ready.json"
    for pid in "$probe_pid" "$server_pid"; do
        if [[ -n $pid ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            for ((stop_attempt=0; stop_attempt<30; stop_attempt++)); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap shutdown EXIT
trap 'exit 143' TERM INT
rm -rf "$runtime/probe-data"
sed 's/@PASSWORD_SHA256@/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad/' /opt/nebulalog/users.xml.in > "$runtime/probe-users.xml"
sed 's/@PASSWORD@/abc/' /opt/nebulalog/client.xml.in > "$runtime/probe-client.xml"
sed -e 's#<listen_host>0.0.0.0</listen_host>#<listen_host>127.0.0.1</listen_host>#' \
    -e 's#/var/lib/clickhouse/#/run/nebulalog-clickhouse/probe-data/#g' \
    -e 's#/run/nebulalog-clickhouse/users.xml#/run/nebulalog-clickhouse/probe-users.xml#g' \
    /opt/nebulalog/server.xml > "$runtime/probe.xml"
/usr/bin/clickhouse server --config-file "$runtime/probe.xml" > "$runtime/probe.log" 2>&1 &
probe_pid=$!
probe_ready=false
for ((attempt=0; attempt<30; attempt++)); do
    kill -0 "$probe_pid" 2>/dev/null || fail 'the loopback TLS preflight exited before readiness'
    if grep -Fq 'Starting in FIPS mode, KAT test result: 1, Integrity check: 1' "$runtime/probe-data/logs/server.log" 2>/dev/null &&
       /usr/bin/clickhouse client --config-file "$runtime/probe-client.xml" --query 'SELECT 1' >/dev/null 2>&1; then probe_ready=true; break; fi
    sleep 1
done
[[ $probe_ready == true ]] || fail 'the loopback TLS preflight did not pass KAT/integrity and authenticated readiness'
kill -TERM "$probe_pid"
for ((attempt=0; attempt<30; attempt++)); do
    kill -0 "$probe_pid" 2>/dev/null || break
    sleep 1
done
if kill -0 "$probe_pid" 2>/dev/null; then
    kill -KILL "$probe_pid" 2>/dev/null || true
    fail 'the loopback TLS preflight did not stop within 30 seconds'
fi
probe_status=0
wait "$probe_pid" || probe_status=$?
probe_pid=''
[[ $probe_status == 0 ]] || fail 'the loopback TLS preflight did not shut down cleanly'

# First read of the per-install account secret occurs only after host/storage/module tests.
password=$(</run/secrets/nebulalog-ch-password)
[[ $password =~ ^[0-9a-f]{64}$ ]] || fail 'a per-install 256-bit lowercase hexadecimal service secret is required'
password_hash=$(printf "SELECT lower(hex(SHA256('%s'))) FORMAT TSVRaw\n" "$password" | /usr/bin/clickhouse local --path "$runtime/hash" --max_threads 1 --queries-file /dev/stdin 2> "$runtime/hash.stderr")
[[ $password_hash =~ ^[0-9a-f]{64}$ ]] || fail 'the vendor-module SHA256 password operation failed'
nebulalog_claim_data "$data" "$format" "$password_hash" || fail 'persistent initialization ownership could not be verified'
if [[ $nebulalog_data_phase == initializing ]]; then
    printf '%s\n' "Captain’s Log ClickHouse: starting or resuming this installation's owned initialization; engine recovery must succeed before readiness."
fi
# Shell expansion stays in memory/stdin, never process arguments or diagnostics.
users_template=$(</opt/nebulalog/users.xml.in)
printf '%s\n' "${users_template//@PASSWORD_SHA256@/$password_hash}" > "$runtime/users.xml"
client_template=$(</opt/nebulalog/client.xml.in)
printf '%s\n' "${client_template//@PASSWORD@/$password}" > "$runtime/client.xml"
unset password users_template client_template
rm -f "$runtime/hash.stderr" "$runtime/identity.stderr"

mkdir -p "$data/logs"
/usr/bin/clickhouse server --config-file /opt/nebulalog/server.xml > "$runtime/server-startup.log" 2>&1 &
server_pid=$!
ready=false
for ((attempt=0; attempt<120; attempt++)); do
    kill -0 "$server_pid" 2>/dev/null || fail 'server exited before readiness; see protected startup log'
    if /usr/bin/clickhouse client --config-file "$runtime/client.xml" --query 'SELECT 1' >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
done
[[ $ready == true ]] || fail 'verified TLS/crypto readiness timed out'
nebulalog_mark_data_ready "$data" "$format" "$password_hash" || fail 'persistent readiness record could not be synchronized'
unset password_hash nebulalog_data_owner_digest
printf '%s\n' '{"schema":1,"state":"runtime-ready","host_fips":true,"encrypted_storage":true,"module":"AWS-LC-FIPS-2.0.0","kat":true,"integrity":true,"native_tls_authenticated":true,"guest_qualification":"pending"}' > "$runtime/ready.json.tmp"
mv "$runtime/ready.json.tmp" "$runtime/ready.json"
printf '%s\n' 'Captain’s Log ClickHouse FIPS candidate: TLS and module readiness complete; release qualification remains separate.'
server_status=0
wait "$server_pid" || server_status=$?
server_pid=''
exit "$server_status"
