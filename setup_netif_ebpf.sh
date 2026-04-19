#!/bin/bash

ip link set enp4s0f0np0 up
ip link set enp4s0f1np1 up
ip link set enp4s0f2np2 up
ip link set enp4s0f3np3 up

sudo ip addr add 10.0.0.0/24 dev enp4s0f0np0
sudo ip addr add 10.0.1.1/24 dev enp4s0f1np1
sudo ip addr add 10.0.2.2/24 dev enp4s0f2np2
sudo ip addr add 10.0.3.3/24 dev enp4s0f3np3

sysctl -w net.ipv4.ip_forward=1



