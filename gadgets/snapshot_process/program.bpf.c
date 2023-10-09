// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

/* Copyright (c) 2021 The Inspektor Gadget authors */

/* Inspired by the BPF iterator in the Linux tree:
 * https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/bpf/progs/bpf_iter_task.c
 */

/* This BPF program uses the GPL-restricted function bpf_seq_write(). */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

const volatile bool show_threads = false;

struct process_entry {
	__u32 tgid;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	mnt_ns_id_t mntns_id;
	__u8 comm[TASK_COMM_LEN];
};

// Describes the type produced by the iterator program.
GADGET_ITER_TYPE(process_entry);

SEC("iter/task")
int ig_snap_proc(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;
	pid_t ppid;

	struct process_entry process = {};

	if (task == NULL)
		return 0;

	if (!show_threads && task->tgid != task->pid)
		return 0;

	__u64 mntns_id = task->nsproxy->mnt_ns->ns.inum;

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	parent = task->real_parent;
	ppid = parent ? parent->pid : -1;
	__u32 uid = task->cred->uid.val;
	__u32 gid = task->cred->gid.val;

	process.tgid = task->tgid;
	process.pid = task->pid;
	process.ppid = ppid;
	process.mntns_id = mntns_id;
	process.uid = uid;
	process.gid = gid;
	__builtin_memcpy(process.comm, task->comm, TASK_COMM_LEN);

	bpf_seq_write(seq, &process, sizeof(process));

	return 0;
}

char _license[] SEC("license") = "GPL";
