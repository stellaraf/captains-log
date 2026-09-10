#!/bin/bash
# Called only after the fixed entrypoint's host, storage and service-identity gates.
# Function arguments provide isolated fixture paths; they are not runtime overrides.

_nebulalog_data_error() {
    printf '%s\n' "Captain’s Log ClickHouse data refused: $1" >&2
    return 1
}

_nebulalog_read_record() {
    local file=$1 size=$2
    [[ ! -L $file && -f $file && $(stat -c '%u:%g:%a:%h:%s' "$file") == "101:101:600:1:$size" ]] || return 1
    IFS= read -r nebulalog_data_record < "$file" || return 1
    # Reject extra lines, embedded NULs and a missing final newline as well as links.
    printf '%s\n' "$nebulalog_data_record" | cmp -s - "$file"
}

nebulalog_data_state() {
    local state_data=$1 expected_format=$2 owner="$1/.nebulalog-fips-owner" marker="$1/.nebulalog-fips-format"
    local prefix="$2:owner:" owner_size first_entry
    owner_size=$((${#prefix} + 65))
    nebulalog_data_phase=''
    nebulalog_data_owner_digest=''
    if [[ -e $owner || -L $owner ]]; then
        _nebulalog_read_record "$owner" "$owner_size" || { _nebulalog_data_error 'invalid ownership record; preserve the datastore for explicit recovery review'; return 1; }
        [[ $nebulalog_data_record == "$prefix"* ]] || { _nebulalog_data_error 'ownership record belongs to another candidate version'; return 1; }
        nebulalog_data_owner_digest=${nebulalog_data_record#"$prefix"}
        [[ $nebulalog_data_owner_digest =~ ^[0-9a-f]{64}$ ]] || { _nebulalog_data_error 'malformed ownership record; automatic adoption is forbidden'; return 1; }
        nebulalog_data_phase=initializing
        if [[ -e $marker || -L $marker ]]; then
            _nebulalog_read_record "$marker" "$((${#expected_format} + 1))" && [[ $nebulalog_data_record == "$expected_format" ]] || { _nebulalog_data_error 'unrecognized data format/version; automatic downgrade is forbidden'; return 1; }
            nebulalog_data_phase=ready
        fi
    else
        first_entry=$(find "$state_data" -mindepth 1 -maxdepth 1 -print -quit) || { _nebulalog_data_error 'cannot inspect the datastore; an empty directory cannot be assumed'; return 1; }
        [[ -z $first_entry ]] || { _nebulalog_data_error 'nonempty storage has no valid ownership record; preserve it for explicit recovery review or provision a separate fresh encrypted datastore'; return 1; }
        nebulalog_data_phase=empty
    fi
    unset nebulalog_data_record
}

nebulalog_claim_data() {
    local state_data=$1 expected_format=$2 expected_digest=$3 owner="$1/.nebulalog-fips-owner"
    [[ $expected_digest =~ ^[0-9a-f]{64}$ ]] || return 1
    # Recheck after the bounded crypto probe. The entrypoint holds a directory flock.
    nebulalog_data_state "$state_data" "$expected_format" || return 1
    if [[ $nebulalog_data_phase == empty ]]; then
        # Exclusive creation plus filesystem sync precede all persistent engine writes.
        # An incomplete record remains refused; it is never silently repaired/adopted.
        (umask 077; set -o noclobber; printf '%s:owner:%s\n' "$expected_format" "$expected_digest" > "$owner") || return 1
        sync -f "$owner" || return 1
        nebulalog_data_state "$state_data" "$expected_format" || return 1
    fi
    [[ $nebulalog_data_owner_digest == "$expected_digest" ]] || { _nebulalog_data_error 'the datastore ownership record does not match this installation credential; restore the original credential or request explicit recovery review'; return 1; }
    # Also cover a retry after a previously failed sync; never infer durability.
    sync -f "$owner"
}

nebulalog_mark_data_ready() {
    local state_data=$1 expected_format=$2 expected_digest=$3 temporary
    nebulalog_data_state "$state_data" "$expected_format" || return 1
    [[ $nebulalog_data_phase != empty && $nebulalog_data_owner_digest == "$expected_digest" ]] || return 1
    [[ $nebulalog_data_phase != ready ]] || return 0
    # A crash may leave a private temporary record. Do not follow or overwrite it.
    temporary=$(mktemp "$state_data/.nebulalog-fips-format.pending.XXXXXXXX") || return 1
    printf '%s\n' "$expected_format" > "$temporary" && sync -f "$temporary" || return 1
    mv -T "$temporary" "$state_data/.nebulalog-fips-format" && sync -f "$state_data"
}
