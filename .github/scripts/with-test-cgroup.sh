#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'with-test-cgroup: %s\n' "$*" >&2
    exit 1
}

[[ "$(uname -s)" == Linux ]] || fail 'Linux is required; no privileged action was attempted.'
caller_uid=$(id -u)
caller_gid=$(id -g)
[[ "$caller_uid" =~ ^[0-9]+$ && "$caller_uid" -gt 0 &&
   "$caller_gid" =~ ^[0-9]+$ && "$caller_gid" -gt 0 ]] ||
    fail 'A non-root caller UID and GID are required.'

uid_checked=false
gid_checked=false
while read -r key real effective saved filesystem rest; do
    case "$key" in
        Uid:)
            [[ "$real" == "$caller_uid" && "$effective" == "$caller_uid" &&
               "$saved" == "$caller_uid" && "$filesystem" == "$caller_uid" ]] ||
                fail 'Real, effective, saved and filesystem UIDs must match the non-root caller.'
            uid_checked=true
            ;;
        Gid:)
            [[ "$real" == "$caller_gid" && "$effective" == "$caller_gid" &&
               "$saved" == "$caller_gid" && "$filesystem" == "$caller_gid" ]] ||
                fail 'Real, effective, saved and filesystem GIDs must match the caller.'
            gid_checked=true
            ;;
    esac
done < /proc/self/status
[[ "$uid_checked" == true && "$gid_checked" == true ]] ||
    fail 'Could not verify the caller identity.'
(( $# > 0 )) || fail 'Usage: with-test-cgroup.sh COMMAND [ARGS...]'
[[ -n "${HOME:-}" && -n "${PATH:-}" ]] || fail 'HOME and PATH are required.'
work_dir=$(pwd -P)

cgroup_root=/sys/fs/cgroup
[[ "$(stat -fc %T -- "$cgroup_root")" == cgroup2fs &&
   -r "$cgroup_root/cgroup.controllers" ]] || fail '/sys/fs/cgroup must be cgroup v2.'
for tool in /usr/bin/env /bin/bash /usr/bin/setpriv /usr/bin/mktemp \
    /usr/bin/mkdir /usr/bin/chown /usr/bin/chmod /usr/bin/find \
    /usr/bin/rmdir /usr/bin/sleep /usr/bin/cat; do
    [[ -x "$tool" ]] || fail "Required runner tool is missing: $tool"
done
command -v sudo >/dev/null || fail 'sudo is required on the hosted Linux runner.'

command_environment=(
    "HOME=$HOME"
    "PATH=$PATH"
    "PWD=$work_dir"
    'LANG=C.UTF-8'
    'CARGO_BUILD_JOBS=1'
    'RUST_TEST_THREADS=1'
)
for name in CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC RUSTDOC \
    CARGO_TARGET_DIR CC CXX AR RANLIB TMPDIR; do
    if [[ "${!name+x}" == x ]]; then
        command_environment+=("$name=${!name}")
    fi
done

parent=''
bootstrap_pid=''
output_pid=''
pending_signal=0
cleanup() {
    [[ -n "$parent" ]] || return 0
    sudo -n /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -c '
        set -euo pipefail
        parent=$1
        [[ "$parent" =~ ^/sys/fs/cgroup/korei-code-mode-ci-[[:alnum:]]{8}$ ]] || exit 1
        populated() {
            local key value rest
            while read -r key value rest; do
                if [[ "$key" == populated ]]; then
                    [[ "$value" == 0 || "$value" == 1 ]] && [[ -z "$rest" ]] || return 1
                    printf "%s\n" "$value"
                    return 0
                fi
            done < "$parent/cgroup.events"
            return 1
        }
        state=$(populated)
        if [[ "$state" == 1 ]]; then
            printf "1\n" > "$parent/cgroup.kill"
            deadline=$((SECONDS + 10))
            while [[ "$state" == 1 ]]; do
                if (( SECONDS >= deadline )); then
                    printf "with-test-cgroup: cleanup timed out; retained %s\n" "$parent" >&2
                    exit 1
                fi
                /usr/bin/sleep 0.1
                state=$(populated)
            done
        fi
        # cgroupfs rejects rmdir while a group contains live processes.
        /usr/bin/find "$parent" -depth -type d -exec /usr/bin/rmdir -- {} +
    ' cleanup "$parent"
}

finish() {
    local status=$? cleanup_status=0 launcher_status=0
    trap - EXIT
    trap '' HUP INT TERM
    cleanup || cleanup_status=$?
    if (( cleanup_status != 0 )); then
        printf 'with-test-cgroup: cleanup failed (status %s); inspect retained tree %s\n' \
            "$cleanup_status" "$parent" >&2
        (( status != 0 )) || status=1
    elif [[ -n "$bootstrap_pid" ]]; then
        if wait "$bootstrap_pid"; then
            launcher_status=0
        else
            launcher_status=$?
        fi
        (( status != 0 )) || status=$launcher_status
    fi
    if (( cleanup_status == 0 )) && [[ -n "$output_pid" ]]; then
        if ! wait "$output_pid"; then
            printf 'with-test-cgroup: command output forwarding failed.\n' >&2
            (( status != 0 )) || status=1
        fi
    fi
    exit "$status"
}
trap finish EXIT
trap 'pending_signal=129' HUP
trap 'pending_signal=130' INT
trap 'pending_signal=143' TERM

parent=$(sudo -n /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    /usr/bin/mktemp -d -- "$cgroup_root/korei-code-mode-ci-XXXXXXXX")
[[ "$parent" =~ ^/sys/fs/cgroup/korei-code-mode-ci-[[:alnum:]]{8}$ ]] ||
    fail 'The runner did not return a unique cgroup path.'
command_environment+=("KOREI_TEST_CGROUP_PARENT=$parent")

sudo -n /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -c '
    set -euo pipefail
    parent=$1 uid=$2 gid=$3
    [[ "$(<"$parent/cgroup.type")" == domain ]]
    [[ -w "$parent/cgroup.kill" && -r "$parent/cgroup.events" ]]
    /usr/bin/mkdir -- "$parent/host"
    [[ "$(<"$parent/host/cgroup.type")" == domain ]]
    [[ -w "$parent/host/cgroup.kill" && -r "$parent/host/cgroup.events" ]]
    /usr/bin/chown -- "$uid:$gid" "$parent" "$parent/cgroup.procs"
    /usr/bin/chmod u+rwx -- "$parent"
    /usr/bin/chmod u+rw -- "$parent/cgroup.procs"
' setup "$parent" "$caller_uid" "$caller_gid"
(( pending_signal == 0 )) || exit "$pending_signal"

exec 3< <(exec sudo -n /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -c '
    set -euo pipefail
    parent=$1 uid=$2 gid=$3 work_dir=$4 count=$5
    shift 5
    environment=("${@:1:count}")
    shift "$count"
    printf "%s\n" "$$" > "$parent/host/cgroup.procs"
    printf "korei-cgroup-ready\n"
    cd -- "$work_dir"
    exec /usr/bin/env -i -- "${environment[@]}" /usr/bin/setpriv \
        --reuid "$uid" --regid "$gid" --init-groups -- "$@"
' bootstrap "$parent" "$caller_uid" "$caller_gid" "$work_dir" \
    "${#command_environment[@]}" "${command_environment[@]}" "$@")
bootstrap_pid=$!
# Defer cancellation until migration completes, so cleanup cannot race a late join.
while true; do
    if IFS= read -r readiness <&3; then
        [[ "$readiness" == korei-cgroup-ready ]] || fail 'Invalid bootstrap readiness response.'
        break
    else
        read_status=$?
        if (( pending_signal != 0 && read_status > 128 )); then
            continue
        fi
        fail 'The privileged bootstrap exited before confirming cgroup migration.'
    fi
done
/usr/bin/cat <&3 &
output_pid=$!
exec 3<&-
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
(( pending_signal == 0 )) || exit "$pending_signal"
if wait "$bootstrap_pid"; then
    command_status=0
else
    command_status=$?
fi
bootstrap_pid=''
exit "$command_status"
