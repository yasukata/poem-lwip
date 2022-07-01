/*
 *
 * Copyright 2022 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <lwip/opt.h>
#include <lwip/init.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/etharp.h>
#include <lwip/tcpip.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>

#include <lwip/prot/tcp.h>

#include <netif/ethernet.h>

#define PACKET_BUF_SIZE (1518)

struct __server_fd {
	char close_posted;
	char lwip_close_requested;
	long listen_sock_id;

	char is_connected;
	char is_bound;
	char is_accepted;
	int st;

	struct tcp_pcb *tpcb;
};

static int epoll_fd;

static int close_post_cnt = 0;
static int close_post_queue[MAX_FD] = { 0 };

static struct __server_fd sfds[MAX_FD] = { 0 };

static const char *ip_addr_str = NULL, *gateway_str = NULL, *netmask_str = NULL;
static const char *netdev_name = NULL, *server_unix_sock_path = NULL;

static err_t low_level_output(struct netif *netif __attribute__((unused)), struct pbuf *p)
{
	char buf[4096];
	void *bufptr, *largebuf = NULL;
	if (sizeof(buf) < p->tot_len) {
		largebuf = (char *) malloc(p->tot_len);
		assert(largebuf);
		bufptr = largebuf;
	} else
		bufptr = buf;
	pbuf_copy_partial(p, bufptr, p->tot_len, 0);
	assert(send((int)((uintptr_t) netif->state), bufptr, p->tot_len, MSG_NOSIGNAL) == p->tot_len);
	if (largebuf)
		free(largebuf);
	return ERR_OK;
}

static err_t if_init(struct netif *netif)
{
	int fd;
	struct ifreq ifr = { 0 };

	assert((fd = socket(AF_PACKET, SOCK_RAW, lwip_htons(ETH_P_ALL))) != -1);

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", netdev_name);
	assert(!ioctl(fd, SIOCGIFINDEX, &ifr));

	/* bind socket to the interface */
	{
		struct sockaddr_ll sll = { .sll_family = AF_PACKET,
					   .sll_protocol = lwip_htons(ETH_P_ALL),
					   .sll_ifindex = ifr.ifr_ifindex, };
		assert(!bind(fd, (struct sockaddr *) &sll, sizeof(sll)));
	}

	/* get mac address */
	assert(!ioctl(fd, SIOCGIFHWADDR, &ifr));
	for (int i = 0; i < 6; i++)
		netif->hwaddr[i] = ifr.ifr_hwaddr.sa_data[i];

	D("mac addr: %02x:%02x:%02x:%02x:%02x:%02x",
			netif->hwaddr[0],
			netif->hwaddr[1],
			netif->hwaddr[2],
			netif->hwaddr[3],
			netif->hwaddr[4],
			netif->hwaddr[5]);

	netif->state = (void *)((uintptr_t) fd);
	netif->output = etharp_output;
	netif->linkoutput = low_level_output;
	netif->mtu = 1518;
	netif->hwaddr_len = 6;
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

	return ERR_OK;
}

static void lwip_netif_init(struct netif *netif)
{
	ip4_addr_t _addr, _mask, _gate;

	inet_pton(AF_INET, ip_addr_str, &_addr);
	inet_pton(AF_INET, netmask_str, &_mask);
	inet_pton(AF_INET, gateway_str, &_gate);

	netif_add(netif, &_addr, &_mask, &_gate, NULL, if_init, ethernet_input);

	netif_set_default(netif);

	netif_set_link_up(netif);
	netif_set_up(netif);
}

static void post_close_fd(int fd)
{
	if (!sfds[fd].close_posted) {
		assert(!epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL));
		close_post_queue[close_post_cnt++] = fd;
		sfds[fd].close_posted = 1;
	}
}

static void tcp_destroy_handeler(u8_t id __attribute__((unused)),
				 void *data __attribute__((unused)))
{
	int fd = (int) ((uintptr_t) data);
	memset(&sfds[fd], 0, sizeof(sfds[fd]));
	asm volatile ("" ::: "memory");
	close(fd);
}

static const struct tcp_ext_arg_callbacks tcp_ext_arg_cbs =  {
	.destroy = tcp_destroy_handeler,
};

static void tcp_destroy_handeler_dummy(u8_t id __attribute__((unused)),
				       void *data __attribute__((unused)))
{

}

static const struct tcp_ext_arg_callbacks tcp_ext_arg_cbs_dummy =  {
	.destroy = tcp_destroy_handeler_dummy,
};

static err_t tcp_recv_handler(void *arg, struct tcp_pcb *tpcb,
			      struct pbuf *p, err_t err __attribute__((unused)))
{
	int fd = (int) ((uintptr_t) arg);
	assert(sfds[fd].tpcb == tpcb);
	if (p) {
		ssize_t tx;
		char buf[4096] = { 0 }, *bufptr = buf;
		if (sizeof(buf) < p->tot_len)
			assert((bufptr = (void *) malloc(p->tot_len)) != NULL);
		assert(pbuf_copy_partial(p, bufptr, p->tot_len, 0) == p->tot_len);
		tx = send(fd, bufptr, p->tot_len, MSG_NOSIGNAL);
		if (tx != -1) {
			assert(tx == (ssize_t) p->tot_len);
			tcp_recved(sfds[fd].tpcb, tx);
		} else { // closed by peer process
			assert(errno == ECONNRESET || errno == EPIPE);
			post_close_fd(fd);
		}
		if ((uintptr_t) buf != (uintptr_t) bufptr)
			free(bufptr);
		pbuf_free(p);
	} else // closed by remote host
		post_close_fd(fd);
	return ERR_OK;
}

static err_t sent_handler(void *arg __attribute__((unused)),
			  struct tcp_pcb *tpcb __attribute__((unused)),
			  uint16_t len __attribute__((unused)))
{
	return ERR_OK;
}

static void err_handler(void *arg __attribute__((unused)),
			err_t err __attribute__((unused)))
{
	int fd = (int) ((uintptr_t) arg);
	if (err == ERR_RST) {
		if (sfds[fd].tpcb && !sfds[fd].lwip_close_requested)
			post_close_fd(fd);
	}
}

static err_t poll_handler(void *arg __attribute__((unused)),
			  struct tcp_pcb *tpcb __attribute__((unused)))
{
	return ERR_OK;
}

static err_t connected_handler(void *arg, struct tcp_pcb *tpcb __attribute__((unused)), err_t err)
{
	unsigned long val = 0;
	int fd = (int) ((uintptr_t) arg);

	assert(!sfds[fd].is_connected);

	tcp_recv(tpcb, tcp_recv_handler);
	tcp_sent(tpcb, sent_handler);
	tcp_err(tpcb, err_handler);
	tcp_poll(tpcb, poll_handler, 100 /* POLL_INTERVAL */);
	tcp_setprio(tpcb, TCP_PRIO_MAX);

	tpcb->so_options |= SOF_KEEPALIVE;
	tpcb->keep_intvl = (60 * 1000);
	tpcb->keep_idle = (60 * 1000);
	tpcb->keep_cnt = 1;

	sfds[fd].is_connected = 1;
	assert(send(fd, &val, sizeof(val), MSG_NOSIGNAL) == sizeof(val));
	return err;
}

static err_t accept_handler(void *arg, struct tcp_pcb *tpcb, err_t err)
{
	int newfd, fd = (int) ((uintptr_t) arg);
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = tpcb->remote_ip.u_addr.ip4.addr,
		.sin_port = tpcb->remote_port,
	};

	if (err != ERR_OK) {
		D("accept failed %s", lwip_strerr(err));
		return err;
	}

	assert((newfd = socket(AF_LOCAL, SOCK_STREAM, 0)) != -1);

	{
		struct sockaddr_un sun = { .sun_family = AF_LOCAL, };
		snprintf(sun.sun_path, sizeof(sun.sun_path), "%s-accept-%ld", server_unix_sock_path, sfds[fd].listen_sock_id);
		assert(!connect(newfd, (const struct sockaddr *) &sun, sizeof(sun)));
	}

	sfds[newfd].tpcb = tpcb;

	tcp_arg(tpcb, (void *) ((uintptr_t) newfd));
	tcp_ext_arg_set_callbacks(tpcb, 0, &tcp_ext_arg_cbs);
	tcp_ext_arg_set(tpcb, 0, (void *) ((uintptr_t) newfd));
	tcp_recv(tpcb, tcp_recv_handler);
	tcp_sent(tpcb, sent_handler);
	tcp_err(tpcb, err_handler);
	tcp_poll(tpcb, poll_handler, 100 /* POLL_INTERVAL */);
	tcp_setprio(tpcb, TCP_PRIO_MAX);

	tpcb->so_options |= SOF_KEEPALIVE;
	tpcb->keep_intvl = (60 * 1000);
	tpcb->keep_idle = (60 * 1000);
	tpcb->keep_cnt = 1;

	sfds[newfd].st = SOCK_STREAM;
	sfds[newfd].is_accepted = 1;

	{
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = newfd,
		};
		assert(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev));
	}

	assert(send(fd, &sin, sizeof(sin), MSG_NOSIGNAL) == sizeof(sin));

	return err;
}

#define BATCH_SIZE (32)

static void *lwip_thread_fn(void *data)
{
	int fd;
	struct netif netif = { 0 };
	char *rx_buf;

	assert((rx_buf = malloc(BATCH_SIZE * PACKET_BUF_SIZE)) != NULL);

	assert(tcp_ext_arg_alloc_id() == 0);

	assert((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) != -1);

	unlink_unixsock_file(server_unix_sock_path);

	{
		struct sockaddr_un sun = { .sun_family = AF_LOCAL, };
		snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", server_unix_sock_path);
		assert(!bind(fd, (const struct sockaddr *) &sun, sizeof(sun)));
	}

	D("!!! configure permission of %s to be 0777", server_unix_sock_path);
	assert(!chmod(server_unix_sock_path, 0777));

	assert(!listen(fd, MAX_FD));

	/* lwip */
	lwip_init();

	/* lwip netif */
	lwip_netif_init(&netif);

	assert((epoll_fd = epoll_create1(EPOLL_CLOEXEC)) != -1);

	{
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = (int)((uintptr_t) netif.state),
		};
		assert(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev));
	}

	{
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = fd,
		};
		assert(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev));
	}

	asm volatile ("" ::: "memory");

	*((volatile bool *) data) = true;

	/* loop */
	while (1) {
		struct epoll_event evts[64];
		int i, nfd = epoll_wait(epoll_fd, evts, 64, 50);
		if (nfd < 0)
			assert(errno == EAGAIN);
		sys_check_timeouts();
		for (i = 0; i < nfd; i++) {
			if (evts[i].data.fd == (int)((uintptr_t) netif.state)) {
				struct mmsghdr msgvec[BATCH_SIZE] = { 0 };
				struct iovec iov[BATCH_SIZE] = { 0 };
				int i, c;
				for (i = 0; i < BATCH_SIZE; i++) {
					iov[i].iov_base = &rx_buf[i * PACKET_BUF_SIZE];
					iov[i].iov_len = PACKET_BUF_SIZE;
					msgvec[i].msg_hdr.msg_iov = &iov[i];
					msgvec[i].msg_hdr.msg_iovlen = 1;
					msgvec[i].msg_len = 0;
				}
				c = recvmmsg((int)((uintptr_t) netif.state), msgvec, BATCH_SIZE, MSG_DONTWAIT, NULL);
				if (c < 0)
					assert(errno == EAGAIN || errno == EBUSY);
				for (i = 0; i < c; i++) {
					struct pbuf *p;
					assert((p = pbuf_alloc(PBUF_RAW, msgvec[i].msg_len, PBUF_POOL)) != NULL);
					pbuf_take(p, iov[i].iov_base, msgvec[i].msg_len);
					p->len = p->tot_len = msgvec[i].msg_len;
					if (netif.input(p, &netif) != ERR_OK) {
						E("netif input failed");
						pbuf_free(p);
						assert(0);
					}
				}
			} else if (evts[i].data.fd == fd) {
				/* new socket creation */
				int newfd;
				{
					struct sockaddr_un sun;
					socklen_t addrlen = sizeof(sun);
					assert((newfd = accept(evts[i].data.fd, (struct sockaddr *) &sun, &addrlen)) != -1);
				}
				assert(newfd < MAX_FD);
				assert(!sfds[newfd].close_posted);
				assert(read(newfd, &sfds[newfd].st, sizeof(sfds[newfd].st)) == sizeof(sfds[newfd].st));
				assert((sfds[newfd].tpcb = tcp_new()) != NULL);
				tcp_arg(sfds[newfd].tpcb, (void *) ((uintptr_t) newfd));
				tcp_ext_arg_set_callbacks(sfds[newfd].tpcb, 0, &tcp_ext_arg_cbs);
				tcp_ext_arg_set(sfds[newfd].tpcb, 0, (void *) ((uintptr_t) newfd));
				{
					struct epoll_event ev = {
						.events = EPOLLIN,
						.data.fd = newfd,
					};
					assert(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev));
				}
			} else {
				ssize_t rx;
				if (sfds[evts[i].data.fd].close_posted) {
					// pass
				} else if (sfds[evts[i].data.fd].is_connected || sfds[evts[i].data.fd].is_accepted) {
					size_t l = tcp_sndbuf(sfds[evts[i].data.fd].tpcb);
					char b[PACKET_BUF_SIZE];
					if (sizeof(b) < l)
						l = sizeof(b);
					if (l) {
						rx = recv(evts[i].data.fd, b, l, MSG_DONTWAIT);
						if (rx > 0) {
							err_t e = tcp_write(sfds[evts[i].data.fd].tpcb, b, rx, TCP_WRITE_FLAG_COPY);
							assert(e == ERR_OK || e == ERR_CONN);
							if (e == ERR_OK)
								assert(tcp_output(sfds[evts[i].data.fd].tpcb) == ERR_OK);
						} else if (errno != EAGAIN)
							goto sock_error;
					}
				} else {
					/* operations requested through syscalls */
					long op;
					rx = read(evts[i].data.fd, &op, sizeof(op));
					if (rx <= 0) {
sock_error:
						/* socket is closed */
						if (rx == -1)
							assert(errno == ECONNRESET);
						else
							assert(!rx);

						post_close_fd(evts[i].data.fd);
					} else {
						switch (op) {
						case __NR_connect:
							{
								struct sockaddr_in sin;
								socklen_t addrlen;
								ip_addr_t ipaddr = { 0 };
								assert(!sfds[evts[i].data.fd].is_connected);
								assert(read(evts[i].data.fd, &addrlen, sizeof(addrlen)) == sizeof(addrlen));
								assert(addrlen <= sizeof(struct sockaddr_storage));
								assert(read(evts[i].data.fd, &sin, addrlen) == addrlen);
								ipaddr.u_addr.ip4.addr = sin.sin_addr.s_addr;
								assert(tcp_connect(sfds[evts[i].data.fd].tpcb, &ipaddr, lwip_ntohs(sin.sin_port), connected_handler) == ERR_OK);
							}
							break;
						case __NR_bind:
							{
								long ret = 0;
								struct sockaddr_in sin;
								socklen_t addrlen;
								ip_addr_t ipaddr = { 0 };
								assert(!sfds[evts[i].data.fd].is_bound);
								assert(read(evts[i].data.fd, &addrlen, sizeof(addrlen)) == sizeof(addrlen));
								assert(addrlen <= sizeof(struct sockaddr_in));
								assert(read(evts[i].data.fd, &sin, addrlen) == addrlen);
								ipaddr.u_addr.ip4.addr = sin.sin_addr.s_addr;
								assert(tcp_bind(sfds[evts[i].data.fd].tpcb, &ipaddr, lwip_ntohs(sin.sin_port)) == ERR_OK); /* TODO: cope with reuse port */
								sfds[evts[i].data.fd].is_bound = 1;
								assert(write(evts[i].data.fd, &ret, sizeof(ret)) == sizeof(ret));
							}
							break;
						case __NR_listen:
							{
								assert(!sfds[evts[i].data.fd].listen_sock_id);
								assert(read(evts[i].data.fd, &sfds[evts[i].data.fd].listen_sock_id, sizeof(sfds[evts[i].data.fd].listen_sock_id)) == sizeof(sfds[evts[i].data.fd].listen_sock_id));
								tcp_ext_arg_set_callbacks(sfds[evts[i].data.fd].tpcb, 0, &tcp_ext_arg_cbs_dummy); // set dummy to avoid fd is closed in tcp_listen
								assert((sfds[evts[i].data.fd].tpcb = tcp_listen(sfds[evts[i].data.fd].tpcb)) != NULL);
								tcp_arg(sfds[evts[i].data.fd].tpcb, (void *) ((uintptr_t) evts[i].data.fd));
								tcp_accept(sfds[evts[i].data.fd].tpcb, accept_handler);
								tcp_ext_arg_set_callbacks(sfds[evts[i].data.fd].tpcb, 0, &tcp_ext_arg_cbs);
								tcp_ext_arg_set(sfds[evts[i].data.fd].tpcb, 0, (void *) ((uintptr_t) evts[i].data.fd));
							}
							break;
						default:
							E("unknown op %ld", op);
							assert(0);
							break;
						}
					}
				}
			}
		}
		{
			int i, close_post_cnt_prev = close_post_cnt;
			for (i = 0; i < close_post_cnt; i++) {
				if (!sfds[close_post_queue[i]].lwip_close_requested) {
					sfds[close_post_queue[i]].lwip_close_requested = 1;
					tcp_close(sfds[close_post_queue[i]].tpcb);
				}
			}
			assert(close_post_cnt == close_post_cnt_prev);
			close_post_cnt = 0;
		}
	}

	close((int)((uintptr_t) netif.state));
	close(epoll_fd);
	close(fd);

	unlink_unixsock_file(server_unix_sock_path);

	pthread_exit(NULL);
}

static int lwip_server_init(void)
{
	int argc;
	char **argv;
	char *arg_str;

	parse_arg(SERVER_ENV_PATH, &argc, &argv, &arg_str);

	{
		int ch;
		while ((ch = getopt(argc, argv, "a:g:hi:m:u:")) != -1) {
			switch (ch) {
			case 'a':
				ip_addr_str = optarg;
				break;
			case 'g':
				gateway_str = optarg;
				break;
			case 'h':
				goto print_usage;
			case 'i':
				netdev_name = optarg;
				break;
			case 'm':
				netmask_str = optarg;
				break;
			case 'u':
				server_unix_sock_path = optarg;
				break;
			default:
				assert(0);
				break;
			}
		}
	}

	D("lwip-server: ip: %s", ip_addr_str);
	D("lwip-server: netmask: %s", netmask_str);
	D("lwip-server: gateway: %s", gateway_str);
	D("lwip-server: netdev: %s", netdev_name);

	if (!ip_addr_str || !netmask_str || !gateway_str || !netdev_name || !server_unix_sock_path) {
		printf("please specify ip address, netmask, gateway, net device name, and path for the unix socket\n");
print_usage:
		printf("usage:\n\t-a ip addr\n\t-g gateway\n\t-i net device name\n\t-m netmask\n\t-u server_unix_sock_path\n");
		exit(1);
	}

	{
		pthread_t lwip_th;
		volatile bool thread_ready = false;
		assert(!pthread_create(&lwip_th, NULL, lwip_thread_fn, (void *) &thread_ready));
		while (!thread_ready)
			usleep(10000);
	}

	return 0;
}
