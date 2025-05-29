//go:build ignore

// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "header_host.h"

SEC("tracepoint/syscalls/sys_enter_execveat")
int ig_execveat_e(struct syscall_trace_enter *ctx)
{
	//const char *pathname = (const char *)ctx->args[1];
	//const char **args = (const char **)(ctx->args[2]);
	//return enter_execve(pathname, args);

	struct key k = {
		.key = 0,
	};

	struct value v = {	};
	//bpf_get_current_comm(v.task, sizeof(v.task));
	v.field1 = 7878;
	v.field2 = 1234;

	bpf_map_update_elem(&gadget_map, &k, &v, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";
