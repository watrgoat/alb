#!/bin/bash
# Bind an ethernet interface to vfio-pci so DPDK can own it.
# Usage: sudo ./test/bind_ports.sh <iface> [iface...]
# On success the PCI addresses are printed, one per line, in the order given.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root" >&2
    exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: $0 <iface> [iface...]" >&2
    exit 1
fi

if ! lsmod | grep -q '^vfio_pci'; then
    modprobe vfio-pci || {
        echo "Failed to load vfio-pci module" >&2
        exit 1
    }
fi

# Allow unsafe no-IOMMU mode (required on hosts without iommu=pt)
if [ -f /sys/module/vfio/parameters/enable_unsafe_noiommu_mode ]; then
    echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode || true
fi

for iface in "$@"; do
    if [ ! -e "/sys/class/net/$iface" ]; then
        echo "Interface $iface not found" >&2
        exit 1
    fi

    pci=$(basename "$(readlink "/sys/class/net/$iface/device")")
    if [ -z "$pci" ]; then
        echo "Could not resolve PCI address for $iface" >&2
        exit 1
    fi

    # Bring the link down before unbinding to avoid stuck carrier state
    ip link set "$iface" down || true

    cur_driver=""
    if [ -e "/sys/bus/pci/devices/$pci/driver" ]; then
        cur_driver=$(basename "$(readlink "/sys/bus/pci/devices/$pci/driver")")
    fi

    # Record original driver in /run so unbind_ports.sh can restore it
    mkdir -p /run/alb-test
    echo "$cur_driver" > "/run/alb-test/$pci.driver"
    echo "$iface" > "/run/alb-test/$pci.iface"

    if [ "$cur_driver" = "vfio-pci" ]; then
        echo "$pci  # $iface already bound to vfio-pci" >&2
        echo "$pci"
        continue
    fi

    if [ -n "$cur_driver" ]; then
        echo "$pci" > "/sys/bus/pci/drivers/$cur_driver/unbind"
    fi

    echo "vfio-pci" > "/sys/bus/pci/devices/$pci/driver_override"
    echo "$pci" > /sys/bus/pci/drivers_probe

    new_driver=$(basename "$(readlink "/sys/bus/pci/devices/$pci/driver")" 2>/dev/null || echo "")
    if [ "$new_driver" != "vfio-pci" ]; then
        echo "Failed to bind $pci ($iface) to vfio-pci (now: $new_driver)" >&2
        exit 1
    fi

    echo "$pci"
done
