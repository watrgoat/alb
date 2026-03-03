#include "strategy.h"

class RoundRobinBasic : public Strategy{
    int current = 0;
    ServerState* servers;
    int count;

public:
    RoundRobinBasic(ServerState* s, int n) : servers(s), count(n) {}

    ServerState* select(const StrategyInput& s){
        ServerState* picked = &servers[current];
        current = (current + 1) % count;
        return picked;
    }

};

extern "C" Strategy* create_strategy(ServerState* servers, int count) {
    return new RoundRobinBasic(servers, count);
};

extern "C" void destroy_strategy(Strategy* s) {
    delete s;
};