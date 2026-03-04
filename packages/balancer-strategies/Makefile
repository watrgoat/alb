CXX = g++
CXXFLAGS = -I include
BUILD = build

all: $(BUILD)/libteststrategy.so $(BUILD)/test_main

$(BUILD)/libteststrategy.so: strategies/test-strategy-impl.cpp
	mkdir -p $(BUILD)
	$(CXX) -shared -fPIC $(CXXFLAGS) -o $@ $<

$(BUILD)/test_main: test/main.cpp
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< -ldl

test: all
	./$(BUILD)/test_main

clean:
	rm -rf $(BUILD)

.PHONY: all test clean