#!/bin/bash

# Enum relay path for named pipes shared between thin-server-enum and emu-enum
PIPE_DIR="${CXL_RELAY_SERVER_PATH:-/tmp/cosim_enum_pipes}"
LOG_DIR="/var/log/enum2cosim"
TRIGGER="/proc/cosim_enum_trigger"

# Log levels: 0=error 1=info (default) 2=debug.
#   error -- only failures, printed to stderr, always
#   info  -- high-level milestones and results
#   debug -- step-by-step trace, daemon output to the terminal
LEVEL=1

err()  { echo "ERROR: $*" 1>&2; }
info() { if [ "$LEVEL" -ge 1 ]; then echo "$*"; fi; }
dbg()  { if [ "$LEVEL" -ge 2 ]; then echo "$*"; fi; }

# Start a daemon in its own session (see setsid rationale below).  Its
# stdout/stderr reach the terminal only at debug level; the daemons always
# write their own logs via CXL_LOG_FILE regardless.
launch() {
	if [ "$LEVEL" -ge 2 ]; then
		setsid "$@" &
	else
		setsid "$@" >/dev/null 2>&1 &
	fi
}

# Phase 1: bring up the userspace endpoint (emu-enum + thin-server-enum +
# daemon-enum) and keep it running.  Run this in its own terminal first; it
# blocks until Ctrl-C, then tears the stack down.  The kernel has not scanned
# anything yet -- it only does so once "run_enum.sh enum" fires the trigger.
run_endpoint() {
	# Fix interpreter for linux-cxl-apps
	# Reason behind: I build these apps using a different toolchain.
	# If I used Yocto toolchain all would work just fine.
	dbg "Fix interpreter"
	( mkdir -p /lib64; cd /lib64; ln -s /lib/ld-linux-x86-64.so.2 ld-linux-x86-64.so.2 ) 2>/dev/null

	mkdir -p "$LOG_DIR"
	mkdir -p "$PIPE_DIR"
	export CXL_RELAY_SERVER_PATH="$PIPE_DIR"

	# Each daemon is started with setsid so it lands in its own session /
	# process group.  Ctrl-C delivers SIGINT to the script's foreground process
	# group only; without setsid the daemons would share that group and die
	# immediately on Ctrl-C, before the EXIT trap can remove the bus.  Bus
	# removal (echo 0 > trigger -> pci_remove_root_bus) may issue config-space
	# writes that need a live daemon-enum, so the daemons must outlive the
	# trigger-0 step and be killed only afterwards.
	dbg "Start emu-enum (opens named pipes, replaces simv / remote endpoint)"
	export CXL_LOG_FILE="$LOG_DIR/emu_enum.log"
	launch ./emu-enum
	emu_enum_pid=$!

	dbg "Start thin-server-enum (creates named pipes, bridges daemon-enum TCP to emu-enum)"
	export CXL_LOG_FILE="$LOG_DIR/thin_server_enum.log"
	launch ./thin-server-enum
	thin_server_pid=$!

	# Wait until thin-server-enum is listening on :5556 (0x15B4, state 0A=LISTEN)
	# before starting daemon-enum, otherwise daemon-enum's connect() races and
	# fails with "Connection refused".
	dbg "Waiting for thin-server-enum to listen on :5556..."
	until grep -q ":15B4 .* 0A " /proc/net/tcp; do sleep 0.2; done

	dbg "Start daemon-enum (bridges /dev/cosim_enum_chardev0 to thin-server-enum)"
	export CXL_LOG_FILE="$LOG_DIR/daemon_enum.log"
	launch ./daemon-enum
	daemon_pid=$!

	# Ordered teardown, run exactly once (guard against INT+EXIT double-fire):
	#   1. echo 0 > trigger  -- remove the bus while daemon-enum is still alive
	#                           to service any config access during removal
	#   2. kill the daemons  -- enum chain torn down only after the bus is gone
	endpoint_cleanup() {
		[ -n "$cleaned" ] && return
		cleaned=1
		info ""
		info "Tearing down: removing virtual bus, then stopping daemons"
		echo 0 > "$TRIGGER" 2>/dev/null
		kill "$daemon_pid" "$thin_server_pid" "$emu_enum_pid" 2>/dev/null
	}
	trap endpoint_cleanup EXIT
	trap 'exit 130' INT TERM

	dbg "Waiting for daemon-enum to connect to thin-server-enum..."
: << 'EOM'
	Example real /proc/net/tcp line
	sl  local_address rem_address   st
	0:  0100007F:15B4 0100007F:8A42  01
	where
	0x0100007F is 127.0.0.1
	0x15B4 is 5556
	01 is TCP_ESTABLISHED
EOM
	until grep -q ":15B4 .* 01 " /proc/net/tcp; do sleep 0.2; done

	# Sanity: all three daemons must still be alive once connected.
	for pid in "$emu_enum_pid" "$thin_server_pid" "$daemon_pid"; do
		if ! kill -0 "$pid" 2>/dev/null; then
			err "endpoint daemon (pid $pid) died during startup -- see $LOG_DIR"
			exit 1
		fi
	done

	info "Endpoint is up. Now run './run_enum.sh enum' in another terminal"
	info "to start kernel enumeration.  Press Ctrl-C here to tear down."
	# Keep the daemons alive until interrupted; trap cleans up on exit.
	wait
}

# Phase 2: tell the kernel to scan the virtual bus.  Run this in a second
# terminal after "run_enum.sh endpoint" is up.  Config-space traffic starts
# here and flows through the endpoint daemons to emu-enum.
# Exit code: 0 if at least one virtual device enumerated, 1 otherwise.
run_enum() {
	if [ ! -e "$TRIGGER" ]; then
		err "$TRIGGER not found -- is cosim_enum_bus loaded?"
		exit 1
	fi

	dbg "Trigger the virtual bus scan (config-space traffic starts here)"
	echo 1 > "$TRIGGER"
	dbg "trigger = $(cat "$TRIGGER")"

	sleep 1

	ndev=$(lspci -D 2>/dev/null | grep -c '^0001:')
	if [ "$ndev" -eq 0 ]; then
		err "no virtual devices enumerated -- check $LOG_DIR/*.log"
		exit 1
	fi

	info "Virtual device(s): $ndev"
	if [ "$LEVEL" -ge 1 ]; then lspci -D 2>/dev/null | grep '^0001:'; fi
	return 0
}

stop_enum() {
	dbg "Removing virtual bus"
	echo 0 > "$TRIGGER" 2>/dev/null
	dbg "trigger = $(cat "$TRIGGER" 2>/dev/null)"

	dbg "Stopping enum daemons"
	pkill -f '\./emu-enum'         2>/dev/null
	pkill -f '\./thin-server-enum' 2>/dev/null
	pkill -f '\./daemon-enum'      2>/dev/null
	info "Done"
}


if [[ $1 == -h || $1 == --help || -z $1 ]]; then
	echo "Usage: $0 endpoint | enum | stop"
	echo ""
	echo "  ./run_enum.sh endpoint   # Terminal 1: brings up emu-enum + thin-server-enum + daemon-enum,"
	echo "                           #             holds the terminal alive (Ctrl-C tears it all down)"
	echo ""
	echo "  ./run_enum.sh enum       # Terminal 2: echo 1 > $TRIGGER -> kernel scans,"
	echo "                           #             then lists the discovered device(s)"
	echo ""
	echo "  ./run_enum.sh stop       # remove the bus + kill daemons (from anywhere)"
	echo "  ./run_enum.sh -h         # help"
	exit 0
elif [[ $1 == endpoint ]]; then
	run_endpoint
elif [[ $1 == enum ]]; then
	run_enum
elif [[ $1 == stop ]]; then
	stop_enum
else
	err "unknown command '$1' (try -h)"
	exit 1
fi
