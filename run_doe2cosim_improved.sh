#!/bin/bash

# DOE relay path for named pipes shared between thin-server and doe-emu
PIPE_DIR="${CXL_RELAY_SERVER_PATH:-/tmp/cxl_relay_pipes}"

LOG_DIR="/var/log/doe2cosim"
RUN_TS=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="$LOG_DIR/run_${RUN_TS}.log"

log() { echo "[$(date '+%H:%M:%S.%3N')] $*" | tee -a "$LOG_FILE"; }

# ------------------------------------------------------------
# Service registry
# Each service has: a command, a space-separated list of deps,
# and a readiness probe function name.
# ------------------------------------------------------------
declare -A SVC_CMD       # command to run
declare -A SVC_DEPS      # space-separated dep names
declare -A SVC_READY_FN  # name of bash function that returns 0 when service is up
declare -A SVC_PID       # populated at runtime
declare -A SVC_LOG       # per-service log file path

register_svc() {
    local name=$1 cmd=$2 deps=$3 ready_fn=$4
    SVC_CMD[$name]="$cmd"
    SVC_DEPS[$name]="$deps"
    SVC_READY_FN[$name]="$ready_fn"
    SVC_LOG[$name]="$LOG_DIR/${name}_${RUN_TS}.log"
}

# ------------------------------------------------------------
# Readiness probes
# Each function returns 0 (true) when the service is considered up.
# ------------------------------------------------------------

# doe-emu creates named pipes in $PIPE_DIR — wait for them to appear
ready_doe_emu() {
    ls "$PIPE_DIR"/*_server_pipe 2>/dev/null | grep -q .
}

# thin-server opens pipes then listens on TCP :5555 — wait for LISTEN state
ready_thin_srv() {
    grep -q ":15B3 .* 0A " /proc/net/tcp
}

# daemon-doe connects to thin-server — wait for ESTABLISHED on :5555
ready_daemon() {
    grep -q ":15B3 .* 01 " /proc/net/tcp
}

# ------------------------------------------------------------
# Start one service, enforcing declared dependencies first.
# Blocks until the service's readiness probe passes.
# ------------------------------------------------------------
start_svc() {
    local name=$1

    for dep in ${SVC_DEPS[$name]}; do
        if [[ -z ${SVC_PID[$dep]} ]]; then
            log "ERROR: cannot start '$name' — dependency '$dep' is not running"
            exit 1
        fi
    done

    ln -sf "${name}_${RUN_TS}.log" "$LOG_DIR/${name}.log"
    log "Starting $name  cmd='${SVC_CMD[$name]}'  log=${SVC_LOG[$name]}"

    CXL_LOG_FILE="${SVC_LOG[$name]}" CXL_RELAY_SERVER_PATH="$PIPE_DIR" ${SVC_CMD[$name]} &
    SVC_PID[$name]=$!
    log "  $name pid=${SVC_PID[$name]}, waiting for ready ..."

    local probe="${SVC_READY_FN[$name]}"
    local t0=$SECONDS
    until $probe; do sleep 0.2; done

    log "  $name ready  elapsed=$((SECONDS - t0))s"
}

# Stop all registered services in reverse start order
stop_all() {
    log "Stopping processes"
    pkill -f "daemon-doe"  2>/dev/null
    pkill -f "thin-server" 2>/dev/null
    pkill -f "doe-emu"     2>/dev/null
}

# ------------------------------------------------------------
# Main redirect flow
# ------------------------------------------------------------
run_redirect() {
    local mechanism=$1

    mkdir -p "$LOG_DIR"
    ln -sf "run_${RUN_TS}.log" "$LOG_DIR/run.log"

    log "=== doe2cosim start  mechanism=$mechanism  PIPE_DIR=$PIPE_DIR ==="

    # Fix interpreter for linux-cxl-apps built with a foreign toolchain
    ( mkdir -p /lib64; cd /lib64; ln -sf /lib/ld-linux-x86-64.so.2 ld-linux-x86-64.so.2 )

    log "Redirect DOE to Remote RC"
    echo 1 > /proc/avery_doe_redirect
    log "  avery_doe_redirect=$(cat /proc/avery_doe_redirect)"

    log "Set DOE backend: $mechanism"
    if [[ $mechanism == netlink ]]; then
        echo netlink > /proc/avery_doe_backend
        local daemon_cmd="./daemon-doe-netlink"
    elif [[ $mechanism == chardev ]]; then
        echo chardev > /proc/avery_doe_backend
        local daemon_cmd="./daemon-doe"
    else
        log "Unknown mechanism '$mechanism' — use netlink or chardev"
        exit 1
    fi
    log "  avery_doe_backend=$(cat /proc/avery_doe_backend)"

    mkdir -p "$PIPE_DIR"

    # Dependency order:
    #   doe_emu  (no deps, creates named pipes)
    #     └─ thin_srv  (opens pipes, listens on :5555)
    #          └─ daemon  (connects to :5555)
    register_svc doe_emu  "./doe-emu"     ""          ready_doe_emu
    register_svc thin_srv "./thin-server" "doe_emu"   ready_thin_srv
    register_svc daemon   "$daemon_cmd"   "thin_srv"  ready_daemon

    trap stop_all EXIT

    start_svc doe_emu
    start_svc thin_srv
    start_svc daemon

    local DEV="0000:00:04.0"
    log "Remove native rootport  DEV=$DEV"
    echo 1 > /sys/bus/pci/devices/${DEV}/remove

    sleep 1

    log "Rescan PCI bus"
    echo 1 > /sys/bus/pci/rescan

    stop_all
    log "=== done ==="
}

# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------
if [[ $1 == native ]]; then
    echo "Remove native rootport"
    DEV="0000:00:04.0"
    echo 1 > /sys/bus/pci/devices/${DEV}/remove
    sleep 1
    echo "Rescan PCI bus"
    echo 1 > /sys/bus/pci/rescan
elif [[ $1 == redirect ]]; then
    run_redirect "$2"
else
    echo "Usage: $0 native | redirect <netlink|chardev>"
    exit 1
fi
