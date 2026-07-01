#!/bin/bash

# Enum relay path for named pipes shared between thin-server-enum and enum-emu
PIPE_DIR="${CXL_RELAY_SERVER_PATH:-/tmp/cosim_enum_pipes}"
LOG_DIR="/var/log/enum2cosim"
TRIGGER="/proc/cosim_enum_trigger"

# Phase 1: bring up the userspace endpoint (enum-emu + thin-server-enum +
# daemon-enum) and keep it running.  Run this in its own terminal first; it
# blocks until Ctrl-C, then tears the stack down.  The kernel has not scanned
# anything yet -- it only does so once "run_enum.sh enum" fires the trigger.
run_endpoint() {
	# Fix interpreter for linux-cxl-apps
	# Reason behind: I build these apps using a different toolchain.
	# If I used Yocto toolchain all would work just fine.
	echo "Fix interpreter"
	( mkdir -p /lib64; cd /lib64; ln -s /lib/ld-linux-x86-64.so.2 ld-linux-x86-64.so.2 )

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
	echo "Start enum-emu (opens named pipes, replaces simv / remote endpoint)"
	export CXL_LOG_FILE="$LOG_DIR/enum_emu.log"
	setsid ./enum-emu &
	enum_emu_pid=$!

	echo "Start thin-server-enum (creates named pipes, bridges daemon-enum TCP to enum-emu)"
	export CXL_LOG_FILE="$LOG_DIR/thin_server_enum.log"
	setsid ./thin-server-enum &
	thin_server_pid=$!

	# Wait until thin-server-enum is listening on :5556 (0x15B4, state 0A=LISTEN)
	# before starting daemon-enum, otherwise daemon-enum's connect() races and
	# fails with "Connection refused".
	echo "Waiting for thin-server-enum to listen on :5556..."
	until grep -q ":15B4 .* 0A " /proc/net/tcp; do sleep 0.2; done

	echo "Start daemon-enum (bridges /dev/cosim_enum_chardev0 to thin-server-enum)"
	export CXL_LOG_FILE="$LOG_DIR/daemon_enum.log"
	setsid ./daemon-enum &
	daemon_pid=$!

	# Ordered teardown, run exactly once (guard against INT+EXIT double-fire):
	#   1. echo 0 > trigger  -- remove the bus while daemon-enum is still alive
	#                           to service any config access during removal
	#   2. kill the daemons  -- enum chain torn down only after the bus is gone
	endpoint_cleanup() {
		[ -n "$cleaned" ] && return
		cleaned=1
		echo ""
		echo "Tearing down: removing virtual bus, then stopping daemons"
		echo 0 > "$TRIGGER" 2>/dev/null
		kill "$daemon_pid" "$thin_server_pid" "$enum_emu_pid" 2>/dev/null
	}
	trap endpoint_cleanup EXIT
	trap 'exit 130' INT TERM

	echo "Waiting for daemon-enum to connect to thin-server-enum..."
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

	echo ""
	echo "Endpoint is up. Now run './run_enum.sh enum' in another terminal"
	echo "to start kernel enumeration.  Press Ctrl-C here to tear down."
	# Keep the daemons alive until interrupted; trap cleans up on exit.
	wait
}

# Phase 2: tell the kernel to scan the virtual bus.  Run this in a second
# terminal after "run_enum.sh endpoint" is up.  Config-space traffic starts
# here and flows through the endpoint daemons to enum-emu.
run_enum() {
	if [ ! -e "$TRIGGER" ]; then
		echo "ERROR: $TRIGGER not found -- is cosim_enum_bus loaded?"
		exit 1
	fi

	echo "Trigger the virtual bus scan (config-space traffic starts here)"
	echo 1 > "$TRIGGER"
	echo "trigger = $(cat "$TRIGGER")"

	sleep 1

	echo "Virtual device(s):"
	lspci -D 2>/dev/null | grep '^0001:' || echo "  (none -- check $LOG_DIR/*.log)"
}

stop_enum() {
	echo "Removing virtual bus"
	echo 0 > "$TRIGGER" 2>/dev/null
	echo "trigger = $(cat "$TRIGGER" 2>/dev/null)"

	echo "Stopping enum daemons"
	pkill -f '\./enum-emu'         2>/dev/null
	pkill -f '\./thin-server-enum' 2>/dev/null
	pkill -f '\./daemon-enum'      2>/dev/null
	echo "Done"
}


if [[ $1 == -h || $1 == --help || -z $1 ]]; then
	echo "Usage: $0 endpoint | enum | stop"
	echo ""
	echo "  ./run_enum.sh endpoint   # Terminal 1: brings up enum-emu + thin-server-enum + daemon-enum,"
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
fi
