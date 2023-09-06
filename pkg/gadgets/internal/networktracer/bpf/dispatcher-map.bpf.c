// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "dispatcher-map.h"

char _license[] SEC("license") = "GPL";
