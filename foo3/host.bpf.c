//go:build ignore

// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "header_host.h"

SEC("tracepoint/syscalls/sys_enter_execveat")
int ig_execveat_e(struct syscall_trace_enter *ctx)
{
	struct key k = {
		.key = 0,
	};

	struct value v = {};
	if (bpf_core_field_exists((&v)->field1)) {
		v.field1 = 111111;
	}
	if (bpf_core_field_exists((&v)->field2)) {
		v.field2 = 222222;
	}
	if (bpf_core_field_exists((&v)->field3)) {
		v.field3 = 333333;
	}
	if (bpf_core_field_exists((&v)->field4)) {
		bpf_get_current_comm(v.field4, sizeof(v.field4));
	}

	bpf_map_update_elem(&gadget_map, &k, &v, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";
