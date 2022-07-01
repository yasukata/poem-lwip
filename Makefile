PROGS = libpoem-lwip.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

LWIP_VER=2.1.3
CONTRIB_VER=2.1.0

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -g -rdynamic
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -shared -fPIC

LDFLAGS += -lpthread

C_SRCS = main.c

C_OBJS = $(C_SRCS:.c=.o)

# for lwip
LWIP_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))lwip
LWIP_SRC_DIR = $(LWIP_DIR)/lwip-$(LWIP_VER)
CONTRIB_SRC_DIR = $(LWIP_DIR)/contrib-$(CONTRIB_VER)
CFLAGS += -I$(LWIP_SRC_DIR)/src/include -I$(CONTRIB_SRC_DIR) -I$(CONTRIB_SRC_DIR)/ports/unix/port/include
LWIP_OBJS = $(LWIP_SRC_DIR)/src/api/api_lib.o \
			$(LWIP_SRC_DIR)/src/api/api_msg.o \
			$(LWIP_SRC_DIR)/src/api/err.o \
			$(LWIP_SRC_DIR)/src/api/if_api.o \
			$(LWIP_SRC_DIR)/src/api/netbuf.o \
			$(LWIP_SRC_DIR)/src/api/netdb.o \
			$(LWIP_SRC_DIR)/src/api/netifapi.o \
			$(LWIP_SRC_DIR)/src/api/sockets.o \
			$(LWIP_SRC_DIR)/src/api/tcpip.o \
			$(LWIP_SRC_DIR)/src/core/altcp_alloc.o \
			$(LWIP_SRC_DIR)/src/core/altcp.o \
			$(LWIP_SRC_DIR)/src/core/altcp_tcp.o \
			$(LWIP_SRC_DIR)/src/core/def.o \
			$(LWIP_SRC_DIR)/src/core/dns.o \
			$(LWIP_SRC_DIR)/src/core/inet_chksum.o \
			$(LWIP_SRC_DIR)/src/core/init.o \
			$(LWIP_SRC_DIR)/src/core/ip.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/autoip.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/dhcp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/etharp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/icmp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/igmp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/ip4_addr.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/ip4.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/ip4_frag.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/dhcp6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ethip6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/icmp6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/inet6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ip6_addr.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ip6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ip6_frag.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/mld6.o  \
			$(LWIP_SRC_DIR)/src/core/ipv6/nd6.o   \
			$(LWIP_SRC_DIR)/src/core/mem.o \
			$(LWIP_SRC_DIR)/src/core/memp.o \
			$(LWIP_SRC_DIR)/src/core/netif.o \
			$(LWIP_SRC_DIR)/src/core/pbuf.o \
			$(LWIP_SRC_DIR)/src/core/raw.o \
			$(LWIP_SRC_DIR)/src/core/stats.o \
			$(LWIP_SRC_DIR)/src/core/sys.o \
			$(LWIP_SRC_DIR)/src/core/tcp.o \
			$(LWIP_SRC_DIR)/src/core/tcp_in.o \
			$(LWIP_SRC_DIR)/src/core/tcp_out.o \
			$(LWIP_SRC_DIR)/src/core/timeouts.o \
			$(LWIP_SRC_DIR)/src/core/udp.o \
			$(LWIP_SRC_DIR)/src/netif/ethernet.o \
			$(CONTRIB_SRC_DIR)/ports/unix/port/sys_arch.o

OBJS = $(C_OBJS) $(LWIP_OBJS)

CLEANFILES += $(LWIP_OBJS)

.PHONY: all
all: $(PROGS)

$(CONTRIB_SRC_DIR).zip:
	wget -P $(LWIP_DIR) http://download.savannah.nongnu.org/releases/lwip/contrib-$(CONTRIB_VER).zip

$(LWIP_SRC_DIR).zip:
	wget -P $(LWIP_DIR) http://download.savannah.nongnu.org/releases/lwip/lwip-$(LWIP_VER).zip

$(CONTRIB_SRC_DIR): $(CONTRIB_SRC_DIR).zip
	unzip -n $< -d $(LWIP_DIR)

$(LWIP_SRC_DIR): $(LWIP_SRC_DIR).zip
	unzip -n $< -d $(LWIP_DIR)

$(OBJS): $(CONTRIB_SRC_DIR) $(LWIP_SRC_DIR)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
