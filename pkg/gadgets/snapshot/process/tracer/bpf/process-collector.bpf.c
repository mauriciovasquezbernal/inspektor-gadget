// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/* Inspired by the BPF iterator in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/bpf/progs/bpf_iter_task.c
 */

/* This BPF program uses the GPL-restricted function bpf_seq_printf().
 */

#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "mntns_filter.h"

const volatile bool show_threads = false;

SEC("iter/task")
int ig_snap_proc(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	__u64 session_id = ctx->meta->session_id;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;
	pid_t parent_pid;

	if (task == NULL)
		return 0;

	if (!show_threads && task->tgid != task->pid)
		return 0;

	__u64 mntns_id = task->nsproxy->mnt_ns->ns.inum;

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	parent = task->real_parent;
	if (!parent)
		parent_pid = -1;
	else
		parent_pid = parent->pid;

	__u32 uid = task->cred->uid.val;
	__u32 gid = task->cred->gid.val;

	BPF_SEQ_PRINTF(seq, "%d %d %d %llu %d %d %s\n", task->tgid, task->pid,
		       parent_pid, mntns_id, uid, gid, task->comm);

	return 0;
}

char _license[] SEC("license") = "GPL";
