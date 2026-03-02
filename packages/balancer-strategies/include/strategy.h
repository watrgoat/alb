#pragma once

/* 
 StrategyInput is an abstract class that handles the inputs. It should include all possible needed parameters for every implementation.
- packet_hash
- packet_index
*/
struct StrategyInput;

/* 
ServerState can have
- address
- active connections
- weight
*/
struct ServerState;

class Strategy {
public:
    virtual ServerState* select(const StrategyInput& s) = 0;
    virtual ~Strategy() = default;
};

extern "C" Strategy* create_strategy();
extern "C" void destroy_strategy(StrategyInput* s);