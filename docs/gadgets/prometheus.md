---
title: 'Using prometheus'
weight: 30
description: >
  Expose metrics using prometheus
---

The Prometheus gadget collects and exposes metrics in Prometheus format. It's available in both, for Kubernetes (`ig-k8s`) and in Linux hosts (`ig`).


```bash
$ kubectl gadget prometheus --config @<path> --listen-address $IP:$PORT --metrics-path /metrics
$ ig prometheus --config @<path> --listen-address $IP:$PORT --metrics-path /metrics
```

## Configuration File

The configuration files defines the metrics to be exposed and their settings. The structure of this file is:

```yaml
metrics:
  - name: metric_name
    type: counter,gauge or histogram
    category: foo # category of the gadget to collect the metric. trace, snapshot, etc.
    gadget: bar # gadget used to collect the metric. exec,open, etc.
    selector:
      # defines which events to take into consideration when updating the metrics.
      # See more information below.
    labels:
      # defines the granularity of the labels to capture. See below.
```

### Filtering (aka Selectors)

It's possible to configure Inspektor Gadget to only update metrics for some specific labels. This is
useful to keep the cardinality of the labels low.

TODO: should we support other operators?

```yaml
  selector:
  - "columnName:value" # matches if the content of the column is equals to value
  - "columnName:!value" # matches if the content of the column is not equal to value
  - "columnName:>=value" # matches if the content of the column is greater and equal to value
  - "columnName:>value" # matches if the content of columnName is greater than the value
  - "columnName:<=value" # matches, if the content of columnName is lower or equal to the value
  - "columnName:<value" # matches, if the content of columnName is lower than the value
  - "columnName:~value" # matches if the content of column matches the regular expression 'value'.
                        # see https://github.com/google/re2/wiki/Syntax for more information on the syntax.
```

Some examples are:

Only metrics for default namespace

```yaml
selector:
  - k8s.namespace: default
```

Only events with retval != 0

```yaml
selector:
  - "retval:!0"
```

Only events executed by pid 1 by non root users

```yaml
selector:
  - "pid:0"
  - "uid:>=1"
```

### Counters

This is probably the most intuitive metric: "A _counter_ is a cumulative metric that represents a
single [monotonically increasing counter](https://en.wikipedia.org/wiki/Monotonic_function) whose
value can only increase or be reset to zero on restart. For example, you can use a counter to
represent the number of requests served, tasks completed, or errors." from
[https://prometheus.io/docs/concepts/metric_types/#counter](https://prometheus.io/docs/concepts/metric_types/#counter).

The following are examples of counters we can support with the existing gadgets. The first one
counts the number of executed processes by namespace, pod and container.

```yaml
metrics:
  - name: executed_processes
    type: counter
    category: trace
    gadget: exec
    labels:
      - namespace
      - pod
      - container
```

By default, a counter is increased by one each time there is an event, however it's possible to
increase a counter using a field on the event:

TODO: Find example

Executed processes by pod and container in the default namespace

```yaml
- name: executed_processes
  type: counter
  category: trace
  gadget: exec
  labels:
    - pod
    - container
  selector:
    - "namespace:default"
```

Or only count events for a given command:

`cat` executions by namespace, pod and container

```yaml
- name: executed_cats # ohno!
  type: counter
  category: trace
  gadget: exec
  labels:
    - namespace
    - pod
    - container
  selector:
    - "comm:cat"
```

DNS requests aggregated by namespace and pod

```yaml
- name: dns_requests
  type: counter
  category: trace
  gadget: dns
  labels:
    - namespace
    - pod
  selector:
    - "qr:Q" # Only count query events
```

### Gauges

"A _gauge_ is a metric that represents a single numerical value that can arbitrarily go up and down"
from
[https://prometheus.io/docs/concepts/metric_types/#gauge](https://prometheus.io/docs/concepts/metric_types/#gauge).

Right now only snapshotters are supported.

Examples of gauges are:

Number of processes by namespace, pod and container.

```yaml
- name: number_of_processes
  type: gauge
  category: snapshot
  gadget: process
  labels:
    - namespace
    - pod
    - container
```

Number of sockets in `CLOSE_WAIT` state

```yaml
- name: number_of_sockets_close_wait
  type: gauge
  category: snapshot
  gadget: socket
  labels:
    - namespace
    - pod
    - container
  selector:
    - "status:CLOSE_WAIT"
```

### Guide

Let's see how we can use this gadget in different environments.

#### On kubernetes

Create a file with the configuration for the metrics. The initial file only configures a counter:

```yaml
metrics:
  - name: executed_processes
    type: counter
    category: trace
    gadget: exec
    labels:
      - namespace
      - pod
      - container
```

Start the gadget

```bash
$ kubectl gadget prometheus --config @myconfig.yaml
INFO[0000] ubuntu-hirsute       | metrics server listening on 127.0.0.1:2223
```

Metrics are accessible on `127.0.0.1:2223/metrics`:

```bash
$ curl http://127.0.0.1:2223/metrics
# HELP executed_processes_total
# TYPE executed_processes_total counter
executed_processes_total{container="calico-node",namespace="kube-system",otel_scope_name="inspektor-gadget",otel_scope_version="",pod="calico-node-nqdpg"} 4
executed_processes_total{container="gadget",namespace="gadget",otel_scope_name="inspektor-gadget",otel_scope_version="",pod="gadget-fr9v8"} 2
# HELP otel_scope_info Instrumentation Scope metadata
# TYPE otel_scope_info gauge
otel_scope_info{otel_scope_name="inspektor-gadget",otel_scope_version=""} 1
# HELP target_info Target metadata
# TYPE target_info gauge
target_info{service_name="unknown_service:gadgettracermanager",telemetry_sdk_language="go",telemetry_sdk_name="opentelemetry",telemetry_sdk_version="1.14.0"} 1
```

You can see that the counters are already going up for some containers.

Let's create a pod to execute from more processes:

```bash
$ kubectl run -n mauricio mypod -it --image ubuntu -- bash
If you don't see a command prompt, try pressing enter.
root@mypod:/#
```

If we check the counter again, we can see that it shows that our pod has executed 3 processes:

```bash
$ curl http://127.0.0.1:2223/metrics
...
executed_processes_total{container="mypod",namespace="mauricio",otel_scope_name="inspektor-gadget",otel_scope_version="",pod="mypod"} 3
...
```

Those three processes were executed while creating the container, probably `runc` and `bash` itself.

Let's run some process in the pod we created:

```bash
root@mypod:/# for i in 1 {0..100}; do cat /dev/null; done
```

We can see that the counter was increased:

```bash
$ curl http://127.0.0.1:2223/metrics
...
executed_processes_total{container="mypod",namespace="mauricio",otel_scope_name="inspektor-gadget",otel_scope_version="",pod="mypod"} 105
...
```

Now, update the configuration file to only take into considerations executions of the `cat` binary:

```yaml
metrics:
  - name: executed_processes
    type: counter
    category: trace
    gadget: exec
    labels:
      - namespace
      - pod
      - container
    selector:
     - "comm:cat"
```

Restart the gadget

```bash
$ kubectl gadget prometheus --config @myconfig.yaml --listen-address 127.0.0.1:2223 --metrics-path /metrics
INFO[0000] ubuntu-hirsute       | metrics server listening on 127.0.0.1:2223
```

We can see that none pod is executing cat.

```bash
$ curl http://127.0.0.1:2223/metrics
# HELP target_info Target metadata
# TYPE target_info gauge
target_info{service_name="unknown_service:gadgettracermanager",telemetry_sdk_language="go",telemetry_sdk_name="opentelemetry",telemetry_sdk_version="1.14.0"} 1
```

Execute cat and ping quite a few times on the pod we created:

```
Let's run some process in the pod we created:

```bash
root@mypod:/# for i in 1 {0..100}; do cat /dev/null && sh -c "echo foo" ; done
```

The counter only takes into consideration the cat commands now:

```bash
$ curl http://127.0.0.1:2223/metrics
...
executed_processes_total{container="mypod",namespace="mauricio",otel_scope_name="inspektor-gadget",otel_scope_version="",pod="mypod"} 102
...
```

#### With `ig`

TODO
