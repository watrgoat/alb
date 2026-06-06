#!/bin/bash

ip link set enp5s0f0 up
ip link set enp5s0f1 up
ip link set enp5s0f2 up
ip link set enp5s0f3 up

sudo ip addr add 10.0.0.0/24 dev enp5s0f0
sudo ip addr add 10.0.1.1/24 dev enp5s0f1
sudo ip addr add 10.0.2.2/24 dev enp5s0f2
sudo ip addr add 10.0.3.3/24 dev enp5s0f3

sysctl -w net.ipv4.ip_forward=1



