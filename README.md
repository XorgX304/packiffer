# Demo
this is a demo program that capture TCP and UDP packets on two different interfaces. each capture run on it's own thread.
# Usage
```
gcc -pthread -o demo demo.c
./demo [-t tcp interface] [-u udp interface] [-c number of packets to capture]
```
below command lists all of your interfaces.

```ifconfig -a```

## example
```./demo -t eth0 -u eth1 -c 1000```
## enviroment and compiler
i use vim editor and gcc compiler.
