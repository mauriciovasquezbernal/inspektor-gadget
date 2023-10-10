/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __MACROS_H
#define __MACROS_H

// Keep this aligned with pkg/gadgets/consts.go

// GADGET_TRACE_MAP is used to indicate that a given perf event array or ring buffer eBPF map is
// used to send events. Inspektor Gadget automatically polls the events from the map, enriches them
// and sends them to the user.
#define GADGET_TRACE_MAP(name) \
	const void * gadget_trace_map_##name __attribute__((unused));

// GADGET_STATS_MAP is used to indicate that a given hash eBPF map is used to send statistics.
#define GADGET_STATS_MAP(type) \
	const void * gadget_stats_map_##name __attribute__((unused));

// TODO: description
// Tells Inspektor Gadget that "type" is produced by the iterator program.
#define GADGET_ITER_TYPE(type) \
	const struct type *gadget_iter_type __attribute__((unused));

#endif /* __MACROS_H */
