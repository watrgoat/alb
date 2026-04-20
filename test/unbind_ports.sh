#!/bin/bash
# Restore interfaces previously bound by bind_ports.sh back to their original driver.
# Usage: sudo ./test/unbind_ports.sh <pci> [pci...]
#   or:  sudo ./test/unbind_ports.sh  (restores everything tracked in /run/alb-test)
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root" >&2
    exit 1
fi

targets=()
if [ $# -gt 0 ]; then
    targets=("$@")
elif [ -d /run/alb-test ]; then
    for f in /run/alb-test/*.driver; do
        [ -e "$f" ] || continue
        targets+=("$(basename "${f%.driver}")")
    done
fi

if [ ${#targets[@]} -eq 0 ]; then
    echo "Nothing to restore" >&2
    exit 0
fi

for pci in "${targets[@]}"; do
    orig_driver=""
    if [ -f "/run/alb-test/$pci.driver" ]; then
        orig_driver=$(cat "/run/alb-test/$pci.driver")
    fi

    cur_driver=""
    if [ -e "/sys/bus/pci/devices/$pci/driver" ]; then
        cur_driver=$(basename "$(readlink "/sys/bus/pci/devices/$pci/driver")")
    fi

    if [ -n "$cur_driver" ]; then
        echo "$pci" > "/sys/bus/pci/drivers/$cur_driver/unbind" || true
    fi

    # Clear override first so drivers_probe respects the original driver
    echo "" > "/sys/bus/pci/devices/$pci/driver_override" || true

    if [ -n "$orig_driver" ]; then
        echo "$pci" > "/sys/bus/pci/drivers/$orig_driver/bind" || true
    else
        echo "$pci" > /sys/bus/pci/drivers_probe || true
    fi

    rm -f "/run/alb-test/$pci.driver" "/run/alb-test/$pci.iface"
    echo "Restored $pci -> ${orig_driver:-auto}"
done
