### Running commands

`make`

``` ./build/packet-forwarder --vdev=net_ring0 --vdev=net_ring0 -l 0,1,2``` 

Requires at minimum 3 lcores: 1 -> stats, 2..n-1 -> tx, n -> rx)
