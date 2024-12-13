// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct syscall_trace_enter *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
