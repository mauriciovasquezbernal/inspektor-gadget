---
# Code generated by 'make generate-documentation'. DO NOT EDIT.
title: Gadget filetop
---

filetop shows reads and writes by file, with container details.

The following parameters are supported:
 - interval: Output interval, in seconds. (default 1)
 - max_rows: Maximum rows to print. (default 20)
 - sort_by: The field to sort the results by (runtime.runtimeName,runtime.containerId,runtime.containerName,runtime.containerImageName,runtime.containerImageDigest,runtime.containerStartedAt,k8s.node,k8s.namespace,k8s.podName,k8s.labels,k8s.containerName,k8s.hostnetwork,mntns,pid,tid,comm,reads,writes,rbytes,wbytes,T,file). (default -reads,-writes,-rbytes,-wbytes)
 - all-files: Show all files. (default false, i.e. show regular files only)

### Example CR

```yaml
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: filetop
  namespace: gadget
spec:
  node: ubuntu-hirsute
  gadget: filetop
  runMode: Manual
  outputMode: Stream
  filter:
    namespace: default
```

### Operations


#### start

Start filetop gadget

```bash
$ kubectl annotate -n gadget trace/filetop \
    gadget.kinvolk.io/operation=start
```
#### stop

Stop filetop gadget

```bash
$ kubectl annotate -n gadget trace/filetop \
    gadget.kinvolk.io/operation=stop
```

### Output Modes

* Stream