// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
#include <vmlinux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "execruntime.h"

const volatile int max_args = DEFAULT_MAXARGS;

static const struct record empty_record = {};

// configured by userspace
const volatile u64 fanotify_fops_addr = 0;
const volatile u64 tracer_fanotify_fd = 0;

// initialized by the iterator
volatile u64 tracer_group = 0;

// ig_fa_pick_ctx keeps context for kprobe/kretprobe fsnotify_remove_first_event
struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__uint(max_entries, 64);
		__type(key, u64); // tgid_pid
		__type(value, u64); // dummy
} ig_fa_pick_ctx SEC(".maps");

// ig_fa_records is consumed by userspace
struct {
		__uint(type, BPF_MAP_TYPE_QUEUE);
		__uint(max_entries, 64);
		__type(value, struct record);
} ig_fa_records SEC(".maps");

struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__uint(max_entries, 128);
		__type(key, u32); // tgid (fanotify will need to lookup by tgid)
		__type(value, struct record);
} exec_args SEC(".maps");

// Iterator used to initialize tracer_group.
//
// Unfortunately, all fanotify files are created with anon_inode_getfd() and
// they will use the same singleton inode.
// We cannot use bpf_get_ns_current_pid_tgid() because it requires kernel 5.7+.
// We cannot use bpf_get_current_pid_tgid() because the tracer might run in a non-init pidns.
SEC("iter/task_file")
int ig_fa_it(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	struct task_struct *current_task;

	if (!file || !task)
		return 0;

	// Initialization should only be done once
	if (tracer_group != 0)
		return 0;

	// The current file is not a fanotify file
	if (fanotify_fops_addr == 0 || (__u64)(file->f_op) != fanotify_fops_addr)
		return 0;

	// The current process is the one running the iterator
	current_task = (struct task_struct *) bpf_get_current_task();
	current_task = BPF_CORE_READ(current_task, group_leader);
	if (task != current_task)
		return 0;

	if (tracer_fanotify_fd == ctx->fd) {
		// found it!
		tracer_group = (u64) BPF_CORE_READ(file, private_data);
		return 0;
	}

	return 0;
}

SEC("kprobe/fsnotify_remove_first_event")
int BPF_KPROBE(ig_fa_pick, struct fsnotify_group *group)
{
	u64 pid_tgid;
	u64 dummy = 0;

	if (tracer_group != (u64)group)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();

	// Keep context for kretprobe/fsnotify_remove_first_event
	bpf_map_update_elem(&ig_fa_pick_ctx, &pid_tgid, &dummy, 0);

	return 0;
}

SEC("kretprobe/fsnotify_remove_first_event")
int BPF_KRETPROBE(ig_fa_pick_x, struct fanotify_event *ret)
{
	struct record *record;
	u32 pid;
	u64 pid_tgid;
	u64 *exists;

	pid_tgid = bpf_get_current_pid_tgid();

	exists = bpf_map_lookup_elem(&ig_fa_pick_ctx, &pid_tgid);
	if (!exists)
		return 0;

	pid = BPF_CORE_READ(ret, pid, numbers[0].nr);

	record = bpf_map_lookup_elem(&exec_args, &pid);
	if (!record) {
		// no record found but we need to push an empty record in the queue to
		// ensure userspace understands that there is no record for this event
		goto add_empty_record;
	}

	bpf_map_push_elem(&ig_fa_records, record, 0);

	bpf_map_delete_elem(&ig_fa_pick_ctx, &pid_tgid);
	return 0;

add_empty_record:
	bpf_map_push_elem(&ig_fa_records, &empty_record, 0);
	bpf_map_delete_elem(&ig_fa_pick_ctx, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct trace_event_raw_sys_enter* ctx)
{
	u64 pid_tgid;
	u32 tgid;
	struct record *record;
	struct task_struct *task;
	uid_t uid = (u32)bpf_get_current_uid_gid();

	unsigned int ret;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;
	int i;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;

	// Add new entry but not from the stack due to size limitations
	if (bpf_map_update_elem(&exec_args, &tgid, &empty_record, 0))
		return 0;
	record = bpf_map_lookup_elem(&exec_args, &tgid);
	if (!record)
		return 0;

	task = (struct task_struct*)bpf_get_current_task();

	record->timestamp = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(&record->caller_comm, sizeof(record->caller_comm));
	record->pid = tgid;
	record->uid = uid;
	record->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
	record->args_count = 0;
	record->args_size = 0;

	ret = bpf_probe_read_user_str(record->args, ARGSIZE, (const char*)ctx->args[0]);
	if (ret <= ARGSIZE) {
		record->args_size += ret;
	} else {
		// write an empty string
		record->args[0] = '\0';
		record->args_size++;
	}

	record->args_count++;
	#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (!argp)
			return 0;

		if (record->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&record->args[record->args_size], ARGSIZE, argp);
		if (ret > ARGSIZE)
			return 0;

		record->args_count++;
		record->args_size += ret;
	}
	/* try to read one more argument to check if there is one */
	bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, assume we have more arguments */
	record->args_count++;
	return 0;
}

#ifdef __TARGET_ARCH_arm64
SEC("kretprobe/do_execveat_common.isra.0")
int BPF_KRETPROBE(ig_execve_x)
#else /* !__TARGET_ARCH_arm64 */
SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct trace_event_raw_sys_exit* ctx)
#endif /* !__TARGET_ARCH_arm64 */
{
	u64 pid_tgid;
	u32 tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)pid_tgid;

	bpf_map_delete_elem(&exec_args, &tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
