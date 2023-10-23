/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __MACROS_H
#define __MACROS_H

// Keep this aligned with pkg/gadgets/run/types/metadata.go

// GADGET_TRACER is used to define a tracer.
#define GADGET_TRACER(name, map_name, event_type) \
	const void * gadget_tracer_##name##___##map_name##___##event_type __attribute__((unused)); \
	const struct event_type * gadget_trace_type_##name __attribute__((unused));

// GADGET_PARAM is used to indicate that a given variable is used as a parameter.
// Users of Inspektor Gadget can set these values from userspace
#define GADGET_PARAM(name) \
	const void * gadget_param_##name __attribute__((unused));

// GADGET_SNAPSHOTTER is used to mark a struct as being produced by a snapshotter gadget.
#define GADGET_SNAPSHOTTER(name, type) \
	const void *gadget_snapshotter_##name##___##type __attribute__((unused)); \
	const struct type *unusedevent_##name##___##type __attribute__((unused));

#endif /* __MACROS_H */
