//go:build ignore

// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <bpf/bpf_helpers.h>

struct key {
	__u32 key;
};

#define TASK_COMM_LEN 16

#define __map(name, val) void *name##__##val

//struct tracer_def {
//	char name[32];
//};
//static struct tracer_def mytracer_def = {
//	.name = "mytracer",
//};

//struct {
//	int type;
//	int max_entries;
//	int *key;
//	struct my_value *value;
//} btf_map SEC(".maps") = {
//	.type = BPF_MAP_TYPE_ARRAY,
//	.max_entries = 16,
//};

struct myvalue {
	__u64 field1;
	__u64 field2;
	__u64 field3;
	char field4[TASK_COMM_LEN];
};

// TODO: force the compiler to emit BTF for this

const struct myvalue *__foo_var_foo __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10);
} output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, int);
	//__type(value, struct myvalue);
} gadget_map SEC(".maps");

struct {
	__type(type, struct myvalue);
	__type(map, output);
} mytracer SEC(".tracers");

SEC("tracepoint/syscalls/sys_enter_execveat")
int ig_execveat_e(struct syscall_trace_enter *ctx)
{
	//int zero = 0;
	//bpf_map_lookup_elem(&gadget_map, &zero);

	return 0;
}

char _license[] SEC("license") = "GPL";
