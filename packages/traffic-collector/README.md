clang -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c traffic-collector.bpf.c -o traffic-collector.bpf.o

bpftool gen skeleton traffic-collector.bpf.o > traffic-collector.skel.hpp

g++ -o traffic-collector traffic-collector.cpp -lbpf -lelf -lz


Bazel:

```
bazel build //packages/traffic-collector:traffic-collector

bazel-bin/packages/traffic-collector/traffic-collector

sudo cat /sys/kernel/debug/tracing/trace_pipe
```
