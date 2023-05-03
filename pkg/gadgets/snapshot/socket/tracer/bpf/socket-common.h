// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/*
 * Inspired by the BPF selftests in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.13/tools/testing/selftests/bpf/progs/bpf_tracing_net.h
 */

#ifndef __GADGET_SOCKET_COMMON_H__
#define __GADGET_SOCKET_COMMON_H__

#ifndef AF_INET
#define AF_INET		2	/* Internet IP Protocol 	*/
#endif

#ifndef AF_INET6
#define AF_INET6 10      /* IP version 6                 */
#endif

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
	const struct socket *sk_socket = BPF_CORE_READ(sk, sk_socket);
	const struct inode *inode;
	unsigned long ino;

	if (!sk_socket)
		return 0;

	inode = &container_of(sk_socket, struct socket_alloc, socket)->vfs_inode;
	bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
	return ino;
}

/*
 * This function receives arguments as they are stored
 * in the different socket structure, i.e. network-byte order.
 */
static __always_inline void socket_bpf_seq_print(struct seq_file *seq,
                struct task_struct *task,
                const char* protocol,
                int ipversion,
                const __be32 src, const __u16 srcp,
                const __be32 dest, const __u16 destp,
                const unsigned char state, long ino,
                __u32 netns)
{
	u64 mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	struct task_struct *parent = task->real_parent;
	pid_t parent_pid;
	if (!parent)
		parent_pid = -1;
	else
		parent_pid = parent->pid;

	__u32 uid = task->cred->uid.val;
	__u32 gid = task->cred->gid.val;

    /*
     * Notice that client side program is expecting socket information exactly
     * in this format:
     *
     * protocol: "TCP" or "UDP"
     * family: 4 or 6
     * IP addresses and ports: Hexadecimal in host-byte order.
     * state: Hexadecimal of https://github.com/torvalds/linux/blob/v5.13/include/net/tcp_states.h#L12-L24
     * ino: unsigned long.
     * netns: unsigned int.
     * mntns_id: unsigned long long.
     * parent_pid: int.
     * pid: int.
     * uid: unsigned int.
     * gid: unsigned int.
     * comm: string.
     */
    BPF_SEQ_PRINTF(seq, "%s %d ",
        protocol, ipversion);
    BPF_SEQ_PRINTF(seq, "%08X %04X %08X %04X ",
        bpf_ntohl(src), bpf_ntohs(srcp),
        bpf_ntohl(dest), bpf_ntohs(destp));
    BPF_SEQ_PRINTF(seq, "%02X %lu %u %llu ",
        state, ino, netns, mntns_id);
    BPF_SEQ_PRINTF(seq, "%d %d %u %u %s\n",
        parent_pid, task->tgid, uid, gid, task->comm);
}

#endif /* __GADGET_SOCKET_COMMON_H__ */
