# traffic-generator

DPDK-based UDP packet generator for load testing. Uses multiple TX queues across cores with a dedicated stats core and RX drain core.

## Build

```bash
bazel build //packages/traffic-generator:traffic-generator
```

## Run

```bash
./build/packet-forwarder --vdev=net_ring0 -l 0,1,2
```

Requires minimum 3 lcores: main (stats), workers 1..n-1 (TX), worker n (RX drain).
