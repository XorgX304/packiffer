
<p align="center"><img align="center" src="/image.png" alt="packiffer"></p>


# About
Packiffer is a packet sniffer program for Unix-like Operating Systems that capture TCP and UDP packets on two different interfaces. each capture runs on its own thread and each thread dump captured traffic in a separate file in 'pcap' format in program directory. captured files are named as interfaces names and interfaces are not in promiscuous mode.

# Usage

### Build by using makefile (CLI)
```
# mkdir packiffer
# cd packiffer
# make
```

### Packiffer (CLI)
```
# gcc -pthread -o packiffer packiffer.c -lpcap
# ./packiffer -t [tcp interface] -u [udp interface] -c [number of packets to capture]
```
note that you can compile program with clang on FreeBSD.

```
# clang -pthread -o packiffer packiffer.c -lpcap
```

### Packiffer (GUI)
```
gcc `pkg-config --cflags gtk+-3.0` -pthread -o packiffergui packiffergui.c `pkg-config --libs gtk+-3.0` -lpcap
```


#### Packiffer needs libpcap to be compiled.

#### Ubuntu

```# apt-get install libpcap-dev```

#### Fedora 22+

```# dnf install libpcap-dev```

#### FreeBSD [via Ports]

```
# cd /usr/ports/net/libpcap/ && make install clean
# pkg install libpcap
```

below command lists all of available interfaces.

```$ ifconfig -a```

# Example
```# ./packiffer -t eth0 -u eth1 -c 1000```

# Tools
vim, gcc, clang, valgrind, gtk+, libpcap, GNU/Linux and FreeBSD.

# GUI Version (GTK+)
GUI works now! 
just type ./packiffergui and enjoy!
