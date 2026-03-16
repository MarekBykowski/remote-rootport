#!/bin/bash

mount -t tracefs tracefs /sys/kernel/tracing

# Clear the trace
#echo > /sys/kernel/tracing/trace

echo 1 > /sys/kernel/tracing/events/pci_config/enable
echo 1 > /sys/kernel/tracing/tracing_on

cat /sys/kernel/tracing/trace
# trace_pipe does runtime but consumes output
#cat /sys/kernel/tracing/trace_pipe

# When done disable
#echo 0 > /sys/kernel/tracing/events/pci_config/enable



