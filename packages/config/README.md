# config

YAML configuration parser for backend server definitions. Loads IP, port, and MAC addresses for up to 64 backends.

## Usage

```c
#include "config.h"

struct alb_config config;
alb_config_load("backends.yaml", &config);
alb_config_print(&config);
```

## Config Format

```yaml
backends:
  - ip: 192.168.1.10
    port: 8080
    mac: aa:bb:cc:dd:ee:ff
```

## Build

```bash
bazel build //packages/config:config
```
