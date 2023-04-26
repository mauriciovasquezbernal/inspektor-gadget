/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef MNTNS_FILTER_H
#define MNTNS_FILTER_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

const volatile bool filter_by_mnt_ns = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 1024);
} mount_ns_filter SEC(".maps");

static __always_inline bool should_filter_mntns_id(__u64 mntns_id) {
	return filter_by_mnt_ns && !bpf_map_lookup_elem(&mount_ns_filter, &mntns_id);
}

static __always_inline __u64 get_mntns_id() {
	struct task_struct *task;
	__u64 mntns_id;

	task = (struct task_struct*) bpf_get_current_task();
	mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	return mntns_id;
}

#endif