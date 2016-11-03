# About
Packiffer is a packet sniffer program for linux that capture TCP and UDP packets on two different interfaces. each capture runs on its own thread and each thread dump captured traffic in a separate file in 'pcap' format in program directory. captured files are named as interfaces names and interfaces are not in promiscuous mode.

# Usage
```
# gcc -pthread -o packiffer packiffer.c -lpcap
# ./packiffer [-t tcp interface] [-u udp interface] [-c number of packets to capture]
```

we also need libpcap to compile program.

####Ubuntu

```# apt-get install libpcap-dev```

####Fedora 22+

```# dnf install libpcap-dev```

####FreeBSD [via Ports]

```
cd /usr/ports/net/libpcap/ && make install clean
pkg install libpcap
```

below command lists all of your interfaces.

```ifconfig -a```

# Example
```# ./packiffer -t eth0 -u eth1 -c 1000```

# Enviroment and Compiler
vim editor and gcc compiler.
