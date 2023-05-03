// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2023 The Inspektor Gadget authors */

/*
 * Inspired by the BPF selftests in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_iter_udp4.c
 */

/*
 * This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "socket-common.h"
#include "mntns_filter.h"

char _license[] SEC("license") = "GPL";

static const char tcp_proto[] = "TCP";
static const char udp_proto[] = "UDP";

const volatile __u64 socket_file_ops_addr = 0;

const volatile bool skip_tcp = false;
const volatile bool skip_udp = false;

static int dump_sock(struct seq_file *seq,
                         struct task_struct *task,
                         struct sock *sock,
                         const char *proto,
                         int ipversion)
{
	const struct inet_sock *inet = (struct inet_sock *)sock;
	__u32 netns = BPF_CORE_READ(sock, __sk_common.skc_net.net, ns.inum);

	socket_bpf_seq_print(seq, task, proto, ipversion,
		BPF_CORE_READ(inet, inet_rcv_saddr),
		BPF_CORE_READ(inet, inet_sport),
		BPF_CORE_READ(inet, inet_daddr),
		BPF_CORE_READ(inet, inet_dport),
		BPF_CORE_READ(sock, sk_state),
		sock_i_ino(sock), netns);

	return 0;
}

// This iterates on all the sockets (from all tasks) and updates the sockets
// map. This is useful to get the initial sockets that were already opened
// before the socket enricher was attached.
SEC("iter/task_file")
int ig_sockets_it(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	u64 mntns_id;

	if (!file || !task)
		return 0;

	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	// Check that the file descriptor is a socket.
	// TODO: cilium/ebpf doesn't support .ksyms, so we get the address of
	// socket_file_ops from userspace.
	// See: https://github.com/cilium/ebpf/issues/761
	if (socket_file_ops_addr == 0 || (__u64)(file->f_op) != socket_file_ops_addr)
		return 0;

	// file->private_data is a struct socket because we checked f_op.
	struct socket *socket = BPF_CORE_READ(file, private_data);
	struct sock *sock = BPF_CORE_READ(socket, sk);
	if (!sock) {
		return 0;
	}

	__u16 family = BPF_CORE_READ(sock, __sk_common.skc_family);
	int ipversion;
	switch (family) {
	case AF_INET:
		ipversion = 4;
		break;
	case AF_INET6:
		ipversion = 6;
		break;
	default:
		return 0;
	}

	__u16 proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	switch (proto) {
	case IPPROTO_TCP:
		if (skip_tcp)
			return 0;

		return dump_sock(seq, task, sock, tcp_proto, ipversion);

	case IPPROTO_UDP:
		if (skip_udp)
			return 0;

		return dump_sock(seq, task, sock, udp_proto, ipversion);
	}


	return 0;
}
