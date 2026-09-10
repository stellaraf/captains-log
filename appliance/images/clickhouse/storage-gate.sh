#!/bin/bash
# Read-only storage prerequisite. The public entry point accepts no overrides.

_ch_storage_fail() {
    printf '%s\n' "ClickHouse storage refused: $*" >&2
    return 1
}

_ch_storage_line() {
    local value
    [[ -f "$1" && -r "$1" && ! -L "$1" ]] || return 1
    value=$(head -c 257 -- "$1") || return 1
    [[ ${#value} -le 256 && -n "$value" && "$value" != *$'\n'* ]] || return 1
    printf '%s' "$value"
}

_ch_storage_device_type() {
    local content line found='' count=0
    [[ -f "$1/uevent" && -r "$1/uevent" && ! -L "$1/uevent" ]] || return 1
    content=$(head -c 4097 -- "$1/uevent") || return 1
    [[ ${#content} -le 4096 ]] || return 1
    while IFS= read -r line; do
        case "$line" in
            DEVTYPE=*) found=${line#DEVTYPE=}; count=$((count + 1)) ;;
        esac
    done <<< "$content"
    [[ $count -eq 1 && ( "$found" == disk || "$found" == partition ) ]] || return 1
    printf '%s' "$found"
}

_ch_storage_walk() {
    local device=$1 encrypted=$2 depth=$3 node metadata type uuid slave child target index
    local -a children
    [[ "$device" =~ ^[0-9]{1,10}:[0-9]{1,10}$ ]] || { _ch_storage_fail 'invalid block device number'; return 1; }
    [[ $depth -le 16 ]] || { _ch_storage_fail 'block graph depth limit exceeded'; return 1; }
    _ch_nodes=$((_ch_nodes + 1))
    [[ $_ch_nodes -le 128 ]] || { _ch_storage_fail 'block graph node limit exceeded'; return 1; }
    [[ -L "$_ch_sysroot/dev/block/$device" ]] || { _ch_storage_fail 'missing block device index'; return 1; }
    node=$(cd -P -- "$_ch_sysroot/dev/block/$device" 2>/dev/null && pwd -P) || { _ch_storage_fail 'unresolvable block device'; return 1; }
    case "$node" in "$_ch_sysroot"/devices/*) ;; *) _ch_storage_fail 'block device escapes sysfs devices'; return 1 ;; esac
    for ((index = 0; index < depth; index++)); do
        [[ "${_ch_ancestry[index]}" != "$node" ]] || { _ch_storage_fail 'block graph cycle'; return 1; }
    done
    _ch_ancestry[depth]=$node
    metadata=$(_ch_storage_line "$node/dev") || { _ch_storage_fail 'missing block device metadata'; return 1; }
    [[ "$metadata" == "$device" ]] || { _ch_storage_fail 'inconsistent block device metadata'; return 1; }
    type=$(_ch_storage_device_type "$node") || { _ch_storage_fail 'unknown block device type'; return 1; }

    children=()
    if [[ -e "$node/slaves" || -L "$node/slaves" ]]; then
        [[ -d "$node/slaves" && ! -L "$node/slaves" ]] || { _ch_storage_fail 'invalid slaves directory'; return 1; }
        children=("$node/slaves"/*)
    fi
    [[ ${#children[@]} -le 16 ]] || { _ch_storage_fail 'block graph branch limit exceeded'; return 1; }

    if [[ -e "$node/dm" || -L "$node/dm" ]]; then
        [[ -d "$node/dm" && ! -L "$node/dm" && "$type" == disk && ${#children[@]} -gt 0 ]] || { _ch_storage_fail 'incomplete device-mapper metadata'; return 1; }
        uuid=$(_ch_storage_line "$node/dm/uuid") || { _ch_storage_fail 'missing device-mapper UUID'; return 1; }
        [[ "$uuid" =~ ^[a-zA-Z0-9_.:+-]+$ ]] || { _ch_storage_fail 'invalid device-mapper UUID'; return 1; }
        case "$uuid" in
            CRYPT-LUKS2-?*) encrypted=1 ;;
            LVM-?*) ;;
            *) _ch_storage_fail 'unsupported device-mapper type'; return 1 ;;
        esac
    else
        [[ ${#children[@]} -eq 0 ]] || { _ch_storage_fail 'unsupported intermediate block device'; return 1; }
        if [[ "$type" == partition ]]; then
            metadata=$(_ch_storage_line "$node/partition") || { _ch_storage_fail 'missing partition metadata'; return 1; }
            [[ "$metadata" =~ ^[1-9][0-9]{0,9}$ ]] || { _ch_storage_fail 'invalid partition metadata'; return 1; }
        else
            [[ -d "$node/slaves" && ! -e "$node/partition" && ! -L "$node/partition" ]] || { _ch_storage_fail 'incomplete disk metadata'; return 1; }
        fi
        [[ $encrypted -eq 1 ]] || { _ch_storage_fail 'unencrypted backing-device branch'; return 1; }
        return 0
    fi

    for slave in "${children[@]}"; do
        [[ -L "$slave" ]] || { _ch_storage_fail 'invalid slave link'; return 1; }
        target=$(cd -P -- "$slave" 2>/dev/null && pwd -P) || { _ch_storage_fail 'unresolvable slave link'; return 1; }
        case "$target" in "$_ch_sysroot"/devices/*) ;; *) _ch_storage_fail 'slave escapes sysfs devices'; return 1 ;; esac
        child=$(_ch_storage_line "$target/dev") || { _ch_storage_fail 'missing slave device number'; return 1; }
        [[ "$child" =~ ^[0-9]{1,10}:[0-9]{1,10}$ ]] || { _ch_storage_fail 'invalid slave device number'; return 1; }
        node=$(cd -P -- "$_ch_sysroot/dev/block/$child" 2>/dev/null && pwd -P) || { _ch_storage_fail 'missing slave block index'; return 1; }
        [[ "$node" == "$target" ]] || { _ch_storage_fail 'inconsistent slave block index'; return 1; }
        _ch_storage_walk "$child" "$encrypted" "$((depth + 1))" || return 1
    done
}

# Internal fixture seam. Production callers use nebulalog_require_encrypted_storage.
_nebulalog_check_luks2_tree() (
    [[ $# -eq 2 ]] || { _ch_storage_fail 'invalid tree-check arguments'; return 1; }
    local _ch_sysroot _ch_nodes=0
    local -a _ch_ancestry
    _ch_sysroot=$(cd -P -- "$1" 2>/dev/null && pwd -P) || { _ch_storage_fail 'sysfs unavailable'; return 1; }
    shopt -s nullglob dotglob
    _ch_ancestry=()
    _ch_storage_walk "$2" 0 0
)

_nebulalog_clickhouse_mount_device() (
    [[ $# -eq 1 ]] || { _ch_storage_fail 'invalid mount-check arguments'; return 1; }
    local line count=0 matches=0 device='' separator index
    local -a fields
    [[ -r "$1" ]] || { _ch_storage_fail 'mount metadata unavailable'; return 1; }
    while IFS= read -r -n 8193 line || [[ -n "$line" ]]; do
        count=$((count + 1))
        [[ $count -le 4096 && ${#line} -le 8192 ]] || { _ch_storage_fail 'mount metadata limit exceeded'; return 1; }
        read -r -a fields <<< "$line"
        [[ ${#fields[@]} -ge 6 ]] || { _ch_storage_fail 'malformed mount metadata'; return 1; }
        [[ "${fields[4]}" == /var/lib/clickhouse ]] || continue
        matches=$((matches + 1))
        [[ $matches -eq 1 ]] || { _ch_storage_fail 'ambiguous data mount'; return 1; }
        separator=0
        for ((index = 6; index < ${#fields[@]}; index++)); do
            if [[ "${fields[index]}" == - ]]; then separator=$index; break; fi
        done
        [[ $separator -ge 6 && ${#fields[@]} -eq $((separator + 4)) && "${fields[separator + 1]}" == xfs ]] || { _ch_storage_fail 'data must have an explicit XFS mount'; return 1; }
        device=${fields[2]}
        [[ "$device" =~ ^[0-9]{1,10}:[0-9]{1,10}$ ]] || { _ch_storage_fail 'invalid data mount device'; return 1; }
    done < "$1"
    [[ $matches -eq 1 ]] || { _ch_storage_fail 'explicit data mount missing'; return 1; }
    printf '%s\n' "$device"
)

nebulalog_require_encrypted_storage() {
    [[ $# -eq 0 ]] || { _ch_storage_fail 'runtime storage overrides are refused'; return 1; }
    [[ -d /var/lib/clickhouse && ! -L /var/lib/clickhouse ]] || { _ch_storage_fail 'data path must be a directory, not a symlink'; return 1; }
    local device
    device=$(_nebulalog_clickhouse_mount_device /proc/self/mountinfo) || return 1
    _nebulalog_check_luks2_tree /sys "$device"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    nebulalog_require_encrypted_storage "$@"
fi
