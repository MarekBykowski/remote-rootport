#!/bin/bash

# DOE relay path for named pipes shared between thin-server and doe-emu
PIPE_DIR="${CXL_RELAY_SERVER_PATH:-/tmp/cxl_relay_pipes}"
LOG_DIR=`dirname $0`/logs

run_redirect() {
	echo "Redirect DOE to Remote RC"
	echo 1 > /proc/avery_doe_redirect
	cat /proc/avery_doe_redirect

	mkdir -p "$LOG_DIR"
	mkdir -p "$PIPE_DIR"
	export CXL_RELAY_SERVER_PATH="$PIPE_DIR"

	echo "Start thin-server (creates named pipes, bridges daemon-doe TCP to doe-emu)"
	export CXL_LOG_FILE="$LOG_DIR/thin_server.log"
	./thin-server &
	thin_server_pid=$!

	echo "Start doe-emu (opens named pipes, replaces simv / remote root port)"
	export CXL_LOG_FILE="$LOG_DIR/doe_emu.log"
	./doe-emu &
	doe_emu_pid=$!

	echo "Start daemon"
	export CXL_LOG_FILE="$LOG_DIR/daemon.log"
	if [[ $1 == netlink ]]; then
		echo "Using netlink"
		echo netlink > /proc/avery_doe_backend
		cat /proc/avery_doe_backend
		./daemon-doe-netlink &
	elif [[ $1 == chardev ]]; then
		echo "Using chardev"
		echo chardev > /proc/avery_doe_backend
		cat /proc/avery_doe_backend
		./daemon-doe &
	fi
	daemon_pid=$!

	cleanup() {
		echo "Stopping processes"
		kill $doe_emu_pid $thin_server_pid $daemon_pid 2>/dev/null
		wait $doe_emu_pid $thin_server_pid $daemon_pid 2>/dev/null
		echo "Done"
	}
	trap cleanup EXIT INT TERM

	echo "Running (Ctrl+C to stop)..."
	wait
}


if [[ $1 == -h || $1 == --help || -z $1 ]]; then
	echo "Usage: $0 native | redirect <netlink|chardev>"
	echo ""
	echo "  native               remove native rootport and rescan PCI bus"
	echo "  redirect netlink     redirect DOE via netlink backend to doe-emu"
	echo "  redirect chardev     redirect DOE via chardev backend to doe-emu"
	exit 0
elif [[ $1 == native ]]; then
	echo "Remove native rootport"
	DEV="0000:00:04.0"
	echo 1 > /sys/bus/pci/devices/${DEV}/remove
	sleep 1
	echo "Rescan PCI bus"
	echo 1 > /sys/bus/pci/rescan
elif [[ $1 == redirect ]]; then
	mechanism=$2
	run_redirect $mechanism
fi
