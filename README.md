# Demo
this is a demo program that capture TCP and UDP packets on two different interfaces. each capture runs on its own thread and thread dump captured traffic in a separate file in 'pcap' format.

# Usage
```
gcc -pthread -o demo demo.c
./demo [-t tcp interface] [-u udp interface] [-c number of packets to capture]
```

we also need libpcap to compile program.

####Ubuntu

```sudo apt-get install libpcap-dev``` 

####FreeBSD

```
cd /usr/ports/net/libpcap/ && make install clean
pkg install libpcap
```

below command lists all of your interfaces.

```ifconfig -a```

# example
```./demo -t eth0 -u eth1 -c 1000```
# enviroment and compiler
i use vim editor and gcc compiler.
