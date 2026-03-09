#!/bin/bash

echo "Redirect DOE to Remote RC"
echo 1 > /proc/avery_doe_redirect
cat /proc/avery_doe_redirect

echo "Start Remote RC and daemon"
./remote-rc &
rc_pid=$!
./daemon-doe &
daemon_pid=$!

sleep 1

echo "Remove Native RC root port"
DEV="0000:00:04.0"
echo 1 > /sys/bus/pci/devices/${DEV}/remove

sleep 1

echo "Rescan PCI bus"
echo 1 > /sys/bus/pci/rescan

kill $rc_pid $daemon_pid
echo "Done"
