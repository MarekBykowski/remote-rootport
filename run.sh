#!/bin/bash

run_redirect() {
# Fix interpreter for linux-cxl-apps
# Reason behind: I build these apps using a different toolchain.
# If I used Yocto toolchain all would work just fine.
echo "Fix interpreter"
( mkdir -p /lib64; cd /lib64; ln -s /lib/ld-linux-x86-64.so.2 ld-linux-x86-64.so.2 )

echo "Redirect DOE to Remote RC"
echo 1 > /proc/avery_doe_redirect
cat /proc/avery_doe_redirect

./remote-rc &
rc_pid=$!

echo "Start Remote RC and daemon"
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

#Make cleanup reliable if the script crashes
trap "kill $rc_pid $daemon_pid 2>/dev/null" EXIT

echo "Waiting for daemon to connect to remote RC..."
: << 'EOM'
Example real /proc/net/tcp line
sl  local_address rem_address   st
0:  0100007F:15B3 0100007F:8A42  01
where
0x0100007F is 127.0.0.1
0x15B3 is 5555
EOM
until grep -q ":15B3 .* 01 " /proc/net/tcp; do sleep 0.2; done
#until ss -nt | grep 5555 >/dev/null; do sleep 0.2; done

sleep 1

echo "Remove native rootport"
DEV="0000:00:04.0"
echo 1 > /sys/bus/pci/devices/${DEV}/remove

sleep 1

echo "Rescan PCI bus"
echo 1 > /sys/bus/pci/rescan

echo "Stopping processes"
kill $rc_pid $daemon_pid

echo "Done"
}


if [[ $1 == native ]]; then
	echo "Remove netive rootport"
	DEV="0000:00:04.0"
	echo 1 > /sys/bus/pci/devices/${DEV}/remove
	sleep 1
	echo "Rescan PCI bus"
	echo 1 > /sys/bus/pci/rescan
elif [[ $1 == redirect ]]; then
	mechanism=$2
	run_redirect $mechanism
fi
