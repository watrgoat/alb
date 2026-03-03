## Running

`g++ -shared -fPIC -o build/libteststrategy.so strategies/test-strategy-impl.cpp -I include`

### Test

`g++ -o build/test_main test/main.cpp -I include -ldl`

`./build/test_main`