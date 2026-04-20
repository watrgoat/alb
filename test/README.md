# ALB test harness

Two end-to-end tests live here:

1. **`run_test.sh`** — single-host functional test using DPDK TAP devices.
2. **`run_4port_test.sh`** — throughput/loss test over four physical NIC ports.

## 4-port loopback test

### Topology

```
  [gen]  P1 --cable--> P2  [ALB]  P3 --cable--> P4  [XDP collector]
     │                      │                         │
     └── TX pps → CSV       └── DPDK: RX P2, TX P3    └── eBPF XDP → CSV
          (input metric)        (port ^ 1 forwarding)     (output metric)
```

| Port | Default iface | Role                       | Driver   |
| ---- | ------------- | -------------------------- | -------- |
| P1   | `enp4s0f0np0` | traffic-generator TX       | vfio-pci |
| P2   | `enp4s0f1np1` | ALB ingress                | vfio-pci |
| P3   | `enp4s0f2np2` | ALB egress                 | vfio-pci |
| P4   | `enp4s0f3np3` | XDP collector (kernel RX)  | kernel   |

Cable **P1↔P2** and **P3↔P4**. P4 stays on the kernel driver so XDP can
attach; P1/P2/P3 are taken over by DPDK.

### Prerequisites

- Hugepages (the script reserves 512×2M if fewer are available).
- `vfio-pci` kernel module. The script loads it and enables unsafe no-IOMMU
  mode if needed.
- All four binaries built:
  ```bash
  bazel build //src:alb \
              //packages/traffic-generator:traffic-generator \
              //packages/traffic-collector:traffic-collector
  ```

### Running

```bash
sudo ./test/run_4port_test.sh [duration_seconds]      # default 30s
```

Override interface names via env:

```bash
sudo P1=ens1f0 P2=ens1f1 P3=ens1f2 P4=ens1f3 ./test/run_4port_test.sh 60
```

Results land in `test/results/<timestamp>/`:

| File                 | Meaning                                                        |
| -------------------- | -------------------------------------------------------------- |
| `tx-stats.csv`       | **Input metric**: generator TX pps (one row per second).       |
| `traffic-stats.csv`  | **Output metric**: XDP `packets_delta` per backend IP, 5s bucket. |
| `metrics.png`        | Plot of input vs. output pps (produced by `plot_metrics.py`).  |
| `alb.log`, `gen.log`, `col.log` | stdout/stderr of each process.                      |

### Plot

```bash
python3 test/plot_metrics.py test/results/<timestamp>
```

Requires `matplotlib` for the PNG — summary stats print regardless.

### What the config does

[`config-4port.yaml`](config-4port.yaml) lists three backends, all with P4's
MAC (`f8:f2:1e:08:64:94`) but distinct IPs. The ALB rewrites each packet to
one of those (MAC, IP, port) triples. Because all frames end up on P4, the
kernel receives them all; XDP keys by destination IP so the collector
still produces a per-backend breakdown for graphing.

### Cleanup

The trap in `run_4port_test.sh` restores P1/P2/P3 to their original drivers.
If the script is hard-killed and leaves them on `vfio-pci`, restore manually:

```bash
sudo ./test/unbind_ports.sh              # restores everything tracked in /run/alb-test
sudo ./test/unbind_ports.sh 0000:04:00.0 # or one at a time
```
