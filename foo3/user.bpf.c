//go:build ignore

// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "header_user.h"

SEC("tracepoint/syscalls/sys_enter_execveat")
int ig_user(struct syscall_trace_enter *ctx)
{
	struct key k = {
		.key = 0,
	};

	struct value *v = bpf_map_lookup_elem(&gadget_map, &k);
	if (!v) {
		return 0; // If no entry found, exit early
	}

	bpf_printk("ig_user: field1: %llu", v->field1);
	bpf_printk("ig_user: field2: %llu", v->field2);

	return 0;
}

char _license[] SEC("license") = "GPL";
