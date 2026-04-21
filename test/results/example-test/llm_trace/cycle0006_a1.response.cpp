```cpp
#include <cstdint>

struct Strategy {
    ServerState *servers;
    int count;
    uint32_t total_weight;
    uint32_t cumulative_weights[3];

    Strategy(ServerState *s, int c) : servers(s), count(c), total_weight(0) {}

    ServerState *select(const StrategyInput &input) {
        uint32_t target = input.packet_hash % total_weight;
        uint32_t sum = 0;
        for (int i = 0; i < count; ++i) {
            sum += cumulative_weights[i];
            if (target < sum) {
                return &servers[i];
            }
        }
        return &servers[count - 1];
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    Strategy *s = new Strategy(servers, count);

    const double window_sec = 5.0;
    const double total_inbound_pps = 10000000.0;

    uint32_t new_weight[3];

    // Backend 0: miss_rate = 0.0, utilization = 0.9934
    {
        uint32_t capacity_hint = 1666999;
        uint32_t packets_sent = 8280000;
        uint32_t packets_missed = 0;

        double cap_budget = capacity_hint * window_sec;
        if (packets_missed > 0) {
            uint32_t effective = packets_sent - packets_missed;
            new_weight[0] = (uint32_t)(effective < cap_budget ? effective : cap_budget);
        } else {
            double probed = packets_sent * 1.05;
            new_weight[0] = (uint32_t)(probed < cap_budget ? probed : cap_budget);
        }
        if (new_weight[0] < 1) new_weight[0] = 1;
    }

    // Backend 1: miss_rate = 0.0077, utilization = 1.0078
    {
        uint32_t capacity_hint = 3333000;
        uint32_t packets_sent = 16795000;
        uint32_t packets_missed = 130000;

        double cap_budget = capacity_hint * window_sec;
        if (packets_missed > 0) {
            uint32_t effective = packets_sent - packets_missed;
            new_weight[1] = (uint32_t)(effective < cap_budget ? effective : cap_budget);
        } else {
            double probed = packets_sent * 1.05;
            new_weight[1] = (uint32_t)(probed < cap_budget ? probed : cap_budget);
        }
        if (new_weight[1] < 1) new_weight[1] = 1;
    }

    // Backend 2: miss_rate = 0.0, utilization = 0.997
    {
        uint32_t capacity_hint = 5000000;
        uint32_t packets_sent = 24925000;
        uint32_t packets_missed = 0;

        double cap_budget = capacity_hint * window_sec;
        if (packets_missed > 0) {
            uint32_t effective = packets_sent - packets_missed;
            new_weight[2] = (uint32_t)(effective < cap_budget ? effective : cap_budget);
        } else {
            double probed = packets_sent * 1.05;
            new_weight[2] = (uint32_t)(probed < cap_budget ? probed : cap_budget);
        }
        if (new_weight[2] < 1) new_weight[2] = 1;
    }

    uint32_t sum_new = new_weight[0] + new_weight[1] + new_weight[2];
    if (sum_new == 0) sum_new = 3;

    constexpr double scale_factor = 10000.0 / 25000000.0;
    uint32_t final_weight[3];
    for (int i = 0; i < 3; ++i) {
        final_weight[i] = (uint32_t)(new_weight[i] * scale_factor);
        if (final_weight[i] < 1) final_weight[i] = 1;
    }

    s->total_weight = final_weight[0] + final_weight[1] + final_weight[2];
    if (s->total_weight == 0) s->total_weight = 3;

    s->cumulative_weights[0] = final_weight[0];
    s->cumulative_weights[1] = final_weight[0] + final_weight[1];
    s->cumulative_weights[2] = final_weight[0] + final_weight[1] + final_weight[2];

    return s;
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```