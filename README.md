# poem-lwip: using lwIP over the socket API

poem-lwip allows users to **transparently** use the [lwIP](https://savannah.nongnu.org/projects/lwip/) network stack over TCP sockets.

It means that users can use lwIP without modifying the source code and binaries of applications.

To achieve transparent replacement, poem-lwip leverages [zpoline](https://github.com/yasukata/zpoline), a lightweight system call hook mechanism, to hook the socket-relevant system calls and converts them into lwIP operations.

Current version of poem-lwip only supports TCP, and does not support UDP.

## Note

This implementation is experimental, and some emulation may not work properly.

## Overview

The meaning of poem is **po**rtable **em**ulation; poem-lwip offers a portable emulation layer that absorbs differences between the socket and lwIP APIs.

Like microkernel services, poem-lwip launches a dedicated thread for executing the lwIP services (here, we call it the lwIP server).
poem-lwip hooks system calls executed by the application thread, and they are redirected to the lwIP server.

To simplify the implementation, poem-lwip leverages UNIX domain sockets as the communication channel between the application thread and the lwIP server thread.

## How to build

First, please select a directory where you wish to locate poem-lwip. In this example, we choose ```$HOME/lwip-over-socket``` and it is exported as ```MY_WORKDIR```.

```
export MY_WORKDIR="$HOME/lwip-over-socket"
```
```
mkdir $MY_WORKDIR
```

Then, please download poem-lwip and zpoline source code by git clone.

```
git clone https://github.com/yasukata/poem-lwip.git $MY_WORKDIR/poem-lwip
```
```
git clone https://github.com/yasukata/zpoline.git $MY_WORKDIR/zpoline
```

The following command, make, does:
- download lwIP source code from ```http://download.savannah.nongnu.org/releases/lwip/lwip-$(LWIP_VER).zip``` to $MY_WORKDIR/poem-lwip/lwip.
- download lwIP's contrib package from ```http://download.savannah.nongnu.org/releases/lwip/contrib-$(CONTRIB_VER).zip``` to $MY_WORKDIR/poem-lwip/lwip.
- unzip the downloaded zip files of lwip and contrib
- compile all, including lwip and poem-lwip implementations, and generate a library file ```$MY_WORKDIR/poem-lwip/libpoem-lwip.so```.

```
make -C $MY_WORKDIR/poem-lwip
```

The following command compiles zpoline and generates ```$MY_WORKDIR/zpoline/libzpoline.so```.

```
make -C $MY_WORKDIR/zpoline
```

## Setup

Before starting to run poem-lwip, please type the following command that is necessary for zpoline.

```
sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
```

For details, please refer to [https://github.com/yasukata/zpoline](https://github.com/yasukata/zpoline).

## Quick Example

This example uses two scripts:

1. ```launch-lwip-server.sh``` launches a lwip server thread in a dedicated process.
2. ```launch-app-with-lwip-hook.sh``` launches an application process while applying the system call hooks.

### Interface setup used in this example

poem-lwip can run lwIP on a physical network interface. However, this example uses virtual (non-physical) interfaces so that users, who do not have an extra physical network interface, can also try.

This example uses a pair of virtual interfaces named veth1 and veth2: veth1 is for us, and veth2 is for lwIP. We configure the following topology.

```
app --(Linux net. stack : 10.0.0.1/24)--[ veth1 ]
                                            |
                                            |
app --(lwIP net. stack  : 10.0.0.2/24)--[ veth2 ]
```

The command below creates veth1 and veth2.

```
sudo ip link add veth1 type veth peer name veth2
```

The following assigns an IP address (10.0.0.1/24) to veth1, and turns it on.

```
sudo ifconfig veth1 10.0.0.1 netmask 255.255.255.0 up
```

Please turn on veth2 by the following command, without giving an IP address.

```
sudo ifconfig veth2 up
```

Following commands disable rx/tx checksum offloading of the veth pair.

```
sudo ethtool -K veth1 rx off tx off
```
```
sudo ethtool -K veth2 rx off tx off
```

### lwIP server launcher script

Please save the following as  ```launch-lwip-server.sh```.

**WARNING: ```launch-lwip-server.sh``` launches a process using ```sudo``` so that it can bind the raw socket to a network interface.**

```
#!/bin/bash

if [ "${MY_WORKDIR}x" = "x" ]; then
	echo "please export the work directory for \$MY_WORKDIR"
	exit 0
fi

if [ "${1}x" = "x" ]; then
	echo "usage: $0 [unix socket path]"
	exit 0
fi

sudo \
LWIP_SERVER_ARGS="-a 10.0.0.2 -g 10.0.0.1 -m 255.255.255.0 -i veth2 -u $1" \
LIBZPHOOK=$MY_WORKDIR/poem-lwip/libpoem-lwip.so \
LD_PRELOAD=$MY_WORKDIR/zpoline/libzpoline.so \
sleep infinity
```

In the script above, ```LWIP_SERVER_ARGS``` specifies:

- ip address: 10.0.0.2
- gateway: 10.0.0.1
- netmask: 255.255.255.0
- interface: veth2

So, please change them accordingly.

### Application launcher script

Please save the following as  ```launch-app-with-lwip-hook.sh```.

```
#!/bin/bash

if [ "${MY_WORKDIR}x" = "x" ]; then
	echo "please export the work directory for \$MY_WORKDIR"
	exit 0
fi

if [ "${1}x" = "x" ] || [ "${2}x" != "--x" ]; then
	echo "usage: $0 [unix socket path] -- [command]"
	exit 0
fi

LWIP_HOOK_ARGS="-q 2,1,0 -q 2,1,6 -u $1" \
LIBZPHOOK=$MY_WORKDIR/poem-lwip/libpoem-lwip.so \
LD_PRELOAD=$MY_WORKDIR/zpoline/libzpoline.so \
${@:3:($#-1)}
```

### Testing with nc and telnet

Please open three consoles, and type the following each. ( Please respect the order from 1 to 3 )

1. launch the quicly server
```
bash launch-lwip-server.sh /tmp/lwip-server.sock
```
2. execute nc
```
bash launch-app-with-lwip-hook.sh /tmp/lwip-server.sock -- nc -l 10000
```
3. execute telnet
```
telnet 10.0.0.2 10000
```

What the commands above do are:

1. launches a lwIP server process that waits for UNIX domain socket connection at ```/tmp/lwip-server.sock```.
2. executes nc command that listens on port 10000 while specifying ```/tmp/lwip-server.sock``` for the UNIX domain socket path to communicate with the lwIP server.
3. executes telnet command that connects to 10.0.0.2 port 10000 that is managed by lwIP.

Supposedly, you will find nc and telnet are connected.

### Other examples

iperf3

2. launch an iperf3 server
```
bash launch-app-with-lwip-hook.sh /tmp/lwip-server.sock -- iperf3 -s4
```
3. execute an iperf3 client
```
iperf3 -c 10.0.0.2
```

curl

2. execute nc
```
echo "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: keep-alive\r\n\r\nmessage from nc" | bash launch-app-with-lwip-hook.sh /tmp/lwip-server.sock -- nc -l 10000
```
3. execute curl
```
curl 10.0.0.2:10000
```

## Known issue

lwIP, current version 2.1.3, does not implement the ```SO_REUSEPORT``` option yet. Therefore, ```tcp_bind``` may fail due to ERR_USE when a listening socket is not properly closed. If you encounter this issue, please restart the lwIP server.
