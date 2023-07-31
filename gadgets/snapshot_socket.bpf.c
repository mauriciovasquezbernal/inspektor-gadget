// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/*
 * Inspired by the BPF selftests in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c
 */

/*
 * This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "types.h"

#define AF_INET         2

#define inet_daddr      sk.__sk_common.skc_daddr
#define inet_rcv_saddr  sk.__sk_common.skc_rcv_saddr
#define inet_dport      sk.__sk_common.skc_dport

#define ir_loc_addr     req.__req_common.skc_rcv_saddr
#define ir_num          req.__req_common.skc_num
#define ir_rmt_addr     req.__req_common.skc_daddr
#define ir_rmt_port     req.__req_common.skc_dport

#define sk_family       __sk_common.skc_family
#define sk_state        __sk_common.skc_state
#define sk_proto        __sk_common.sk_protocol

#define tw_daddr        __tw_common.skc_daddr
#define tw_rcv_saddr    __tw_common.skc_rcv_saddr
#define tw_dport        __tw_common.skc_dport

struct socket_entry {
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	__u32 state;
	__u32 ino;
};

// Describes the type produced the by iterator program. It's only used to get the BTF information of
// such type.
const struct socket_entry *GADGET_ITER_TYPE_VAR_NAME __attribute__((unused));

/**
 * sock_i_ino - Returns the inode identifier associated to a socket.
 * @sk: The socket whom inode identifier will be returned.
 *
 * Returns the inode identifier corresponding to the given as parameter socket.
 *
 * Returns:
 * * The inode identifier associated to the socket.
 */
static unsigned long sock_i_ino(const struct sock *sk)
{
	const struct socket *sk_socket = sk->sk_socket;
	const struct inode *inode;
	unsigned long ino;

	if (!sk_socket)
		return 0;

	inode = &container_of(sk_socket, struct socket_alloc, socket)->vfs_inode;
	bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
	return ino;
}

char _license[] SEC("license") = "GPL";

/*
 * This function receives arguments as they are stored
 * in the different socket structure, i.e. network-byte order.
 */
static __always_inline void socket_bpf_seq_write(struct seq_file *seq,
                __u16 proto, const __be32 src,
                const __u16 srcp, const __be32 dest,
                const __u16 destp, const unsigned char state, long ino)
{
	struct socket_entry entry = {};

	entry.src.l3.version = entry.dst.l3.version = 4;
	entry.src.proto = entry.dst.proto = proto;
	entry.src.l3.addr.v4 = src;
	entry.src.port = bpf_htons(srcp);
	entry.dst.l3.addr.v4 = dest;
	entry.dst.port = bpf_htons(destp);
	entry.state = state;
	entry.ino = ino;

	bpf_seq_write(seq, &entry, sizeof(entry));
}


static int dump_tcp_sock(struct seq_file *seq, struct tcp_sock *tp)
{
	const struct inet_connection_sock *icsk = &tp->inet_conn;
	const struct inet_sock *inet = &icsk->icsk_inet;
	const struct sock *sp = &inet->sk;

	socket_bpf_seq_write(seq, IPPROTO_TCP, inet->inet_rcv_saddr,
		inet->inet_sport, inet->inet_daddr,
		inet->inet_dport, sp->sk_state, sock_i_ino(sp));

	return 0;
}

static int dump_tw_sock(struct seq_file *seq, struct tcp_timewait_sock *ttw)
{
	struct inet_timewait_sock *tw = &ttw->tw_sk;

	socket_bpf_seq_write(seq, IPPROTO_TCP, tw->tw_rcv_saddr,
		tw->tw_sport, tw->tw_daddr,
		/*
		 * tcp_timewait_sock represents socket in TIME_WAIT state.
		 * Socket is this particular state are not associated with a
		 * struct sock:
		 * https://elixir.bootlin.com/linux/v5.15.12/source/include/linux/tcp.h#L442
		 * https://elixir.bootlin.com/linux/v5.15.12/source/include/net/inet_timewait_sock.h#L33
		 * Hence, they do not have an underlying file and, as a
		 * consequence, no inode.
		 *
		 * Like /proc/net/tcp, we print 0 as inode number for TIME_WAIT
		 * (state 6) socket:
		 * https://elixir.bootlin.com/linux/v5.15.12/source/include/net/tcp_states.h#L18
		 */
		tw->tw_dport, tw->tw_substate, 0);

	return 0;
}

static int dump_req_sock(struct seq_file *seq, struct tcp_request_sock *treq)
{
	struct inet_request_sock *irsk = &treq->req;

	socket_bpf_seq_write(seq, IPPROTO_TCP, irsk->ir_loc_addr,
		irsk->ir_num, irsk->ir_rmt_addr, irsk->ir_rmt_port,
		TCP_SYN_RECV, sock_i_ino(treq->req.req.sk));

	return 0;
}

SEC("iter/tcp")
int ig_snap_tcp4(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk_common = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	struct tcp_timewait_sock *tw;
	struct tcp_request_sock *req;
	struct tcp_sock *tp;

	if (sk_common == (void *)0)
		return 0;

	/* Filter out IPv6 for now */
	if (sk_common->skc_family != AF_INET)
		return 0;

	tp = bpf_skc_to_tcp_sock(sk_common);
	if (tp)
		return dump_tcp_sock(seq, tp);

	tw = bpf_skc_to_tcp_timewait_sock(sk_common);
	if (tw)
		return dump_tw_sock(seq, tw);

	req = bpf_skc_to_tcp_request_sock(sk_common);
	if (req)
		return dump_req_sock(seq, req);

	return 0;
}

SEC("iter/udp")
int ig_snap_udp4(struct bpf_iter__udp *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct udp_sock *udp_sk = ctx->udp_sk;
	struct inet_sock *inet;

	if (udp_sk == (void *)0)
		return 0;

	inet = &udp_sk->inet;

	/* Filter out IPv6 for now */
	if (inet->sk.sk_family != AF_INET)
		return 0;

	socket_bpf_seq_write(seq, IPPROTO_UDP, inet->inet_rcv_saddr,
		inet->inet_sport, inet->inet_daddr,
		inet->inet_dport, inet->sk.sk_state, sock_i_ino(&inet->sk));

	return 0;
}
