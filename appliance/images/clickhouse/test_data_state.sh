#!/bin/bash
# Run in the candidate image with a private tmpfs and UID101. No engine or FIPS bypass.
set -Eeuo pipefail
umask 077
source /opt/nebulalog/data-state.sh
readonly format='nebulalog-clickhouse-fips:1:25.3.8.30001.altinityfips'
readonly digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
readonly other=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
root=$(mktemp -d /run/nebulalog-clickhouse/data-state-tests.XXXXXXXX)
trap 'rm -rf "$root"' EXIT
checks=0
new_case() { data="$root/$1"; mkdir -m 0700 "$data"; }
accept() { "$@"; checks=$((checks + 1)); }
reject() { if "$@" > "$root/rejection.stdout" 2> "$root/rejection.stderr"; then printf 'Unexpected acceptance: %s\n' "$1" >&2; exit 1; fi; checks=$((checks + 1)); }

new_case fresh
accept nebulalog_data_state "$data" "$format"
[[ $nebulalog_data_phase == empty && -z $(ls -A "$data") ]]
accept nebulalog_claim_data "$data" "$format" "$digest"
[[ $nebulalog_data_phase == initializing && ! -e $data/.nebulalog-fips-format ]]
# Interrupted initial engine writes remain intact through an owned retry.
mkdir "$data/store"
printf 'fixture metadata\n' > "$data/store/part"
accept nebulalog_claim_data "$data" "$format" "$digest"
[[ $(<"$data/store/part") == 'fixture metadata' ]]
reject nebulalog_claim_data "$data" "$format" "$other"
[[ ! -e $data/.nebulalog-fips-format ]]
accept nebulalog_mark_data_ready "$data" "$format" "$digest"
accept nebulalog_data_state "$data" "$format"
[[ $nebulalog_data_phase == ready ]]
accept nebulalog_claim_data "$data" "$format" "$digest"
accept nebulalog_mark_data_ready "$data" "$format" "$digest"
reject nebulalog_claim_data "$data" "$format" "$other"

new_case foreign
mkdir "$data/store"
reject nebulalog_claim_data "$data" "$format" "$digest"
[[ -d $data/store && ! -e $data/.nebulalog-fips-owner ]]
new_case inspection_failure
find() { return 1; }
reject nebulalog_claim_data "$data" "$format" "$digest"
unset -f find
[[ ! -e $data/.nebulalog-fips-owner ]]
new_case marker_only
printf '%s\n' "$format" > "$data/.nebulalog-fips-format"
reject nebulalog_claim_data "$data" "$format" "$digest"
new_case broken_owner_link
ln -s "$data/absent" "$data/.nebulalog-fips-owner"
reject nebulalog_claim_data "$data" "$format" "$digest"

for variation in empty truncated extra_line no_newline embedded_nul mode directory hardlink wrong_version invalid_digest; do
    new_case "$variation"
    owner="$data/.nebulalog-fips-owner"
    printf '%s:owner:%s\n' "$format" "$digest" > "$owner"
    case $variation in
        empty) : > "$owner" ;;
        truncated) printf '%s:owner:aaaa\n' "$format" > "$owner" ;;
        extra_line) printf '\n' >> "$owner" ;;
        no_newline) printf '%s:owner:%s' "$format" "$digest" > "$owner" ;;
        embedded_nul) printf '%s:owner:%s\0' "$format" "$digest" > "$owner" ;;
        mode) chmod 0640 "$owner" ;;
        directory) rm "$owner"; mkdir "$owner" ;;
        hardlink) ln "$owner" "$data/alias" ;;
        wrong_version) printf '%s:owner:%s\n' "${format/25.3/25.8}" "$digest" > "$owner" ;;
        invalid_digest) printf '%s:owner:%s\n' "$format" "${digest/a/z}" > "$owner" ;;
    esac
    reject nebulalog_claim_data "$data" "$format" "$digest"
    [[ ! -e $data/.nebulalog-fips-format ]]
done

new_case interrupted_marker_write
accept nebulalog_claim_data "$data" "$format" "$digest"
printf 'incomplete\n' > "$data/.nebulalog-fips-format.pending.fixture"
accept nebulalog_claim_data "$data" "$format" "$digest"
accept nebulalog_mark_data_ready "$data" "$format" "$digest"
[[ $(<"$data/.nebulalog-fips-format.pending.fixture") == incomplete ]]

new_case marker_symlink
accept nebulalog_claim_data "$data" "$format" "$digest"
printf '%s\n' "$format" > "$data/foreign-marker"
ln -s "$data/foreign-marker" "$data/.nebulalog-fips-format"
reject nebulalog_mark_data_ready "$data" "$format" "$digest"
[[ -L $data/.nebulalog-fips-format ]]

# Verify a failed durability barrier stops before persistent engine initialization.
new_case sync_failure
sync() { return 1; }
reject nebulalog_claim_data "$data" "$format" "$digest"
unset -f sync
[[ ! -e $data/.nebulalog-fips-format ]]
accept nebulalog_claim_data "$data" "$format" "$digest"

# The production entrypoint takes an inode lock with no pre-claim data write.
new_case lock
exec 9<"$data"
accept flock -n 9
reject bash -c 'exec 9<&-; exec 8<"$1"; flock -n 8' fixture "$data"
[[ -z $(ls -A "$data") ]]
exec 9<&-
accept bash -c 'exec 8<"$1"; flock -n 8' fixture "$data"
printf '{"data_state_checks_passed":%d,"engine_started":false,"guest_qualified":false}\n' "$checks"
