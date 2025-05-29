#ifndef SOCKETS_MAP_H
#define SOCKETS_MAP_H

#include <bpf/bpf_helpers.h>

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct key {
	__u32 key;
};

#define TASK_COMM_LEN 16

struct value {
	char chunk[250];
	char field4[TASK_COMM_LEN];
	__u64 field2;
	__u64 field1;
	__u64 field3;

};

#define MAX_SOCKETS 16384
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SOCKETS);
	__type(key, struct key);
	__type(value, struct value);
} gadget_map SEC(".maps");


#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif
