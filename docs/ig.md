---
title: ig
weight: 80
description: >
  Description of the ig tool.
---

Inspektor Gadget relies on the Kubernetes API server to work. However, there are
[some cases](#use-cases) where it is necessary, or preferred, to trace
containers without passing through Kubernetes. In such scenarios, you can use
the `ig` tool, as it allows you to collect insights from the nodes to
debug your Kubernetes containers without relying on Kubernetes itself, but on
the container runtimes. It is important to remark that `ig` can also
be used to trace containers that were not created via Kubernetes.

Some characteristics of `ig`:

- It uses eBPF as its underlying core technology.
- Enriches the collected data with the Kubernetes metadata.
- Easy to install as it is a single binary (statically linked).

The architecture of `ig` is described in the main
[architecture](architecture.md#ig) document.

## Use cases

- In a Kubernetes environment, when the Kubernetes API server is not working
  properly, we cannot deploy Inspektor Gadget. Therefore, we still need a way to
  debug the containers of the cluster.
- In some cases, you might have root SSH access to the Kubernetes nodes of a
  cluster, but not to the `kubeconfig`.
- If you are implementing an application that needs to get insights from the
  Kubernetes node, you could include the `ig` binary in your container
  image, and your app simply execs it. In such a case, it is suggested to use
  the JSON output format to ease the parsing.
- Outside a Kubernetes environment, for observing and debugging standalone
  containers.

## Installation

The instruction to install `ig` are available in the main
[installation](install.md#installing-ig) guide.

## Usage

Currently, `ig` can trace containers managed by Docker regardless
of whether they were created via Kubernetes or not. In addition, it can also
use the CRI to trace containers managed by containerd and CRI-O, meaning only
the ones created via Kubernetes. Support for non-Kubernetes containers with
containerd is coming, see issue
[#734](https://github.com/inspektor-gadget/inspektor-gadget/issues/734).

By default, `ig` will try to communicate with the Docker Engine
API and the CRI API of containerd and CRI-O:

```bash
$ docker run -d --name myContainer nginx:1.21
95b814bb82b9e30dd935b03d04a7b00b6978ce018a6f55d6a9c7a824b31ec6b5

$ sudo ig list-containers
RUNTIME.RUNTIMENAME RUNTIME.CONTAINERID                                              RUNTIME.CONTAINERNAME
containerd          c7dfa4c92fec235626157417bf45745969006bd3bfd2607e87fdd0a176547603 konnectivity-agent
containerd          cd8ce885c115adbc87da5243630b90935e5bf1c2af96b00154ec475fd9b393b0 nsenter
containerd          b436a9886ee6e59ac7d38d1b76f8a306e2efeb3f1b6679ea1a58028edb198db3 azure-ip-masq-agent
containerd          642fc58b15fbaf578340f4bd656b427db51be63a94a7b6eb663388486e73d855 azuredisk
containerd          466a9d7e7b2087966621eacd792cc492f48f08f741f9dc82d88ef62a9d7d3e0f liveness-probe
containerd          f79db0f2ea6518869c89e1d0a0892221047b23e04e4dab59dc7e42d6808e2530 azurefile
containerd          85d74aeb6d29aaa38b282f3e51202bb648f7ba16a681d0d39dda684e724bb8a3 node-driver-registrar
containerd          a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46 kube-proxy
containerd          428c933882f1e4459c397da20bd89bbe7df7d437880a254472879d33b125b4da node-driver-registrar
containerd          cd75a08ea2e69756cd7b1de5935c49f5ba08ba7495b0589567dcd9493193d712 cloud-node-manager
containerd          d4bdf83ba71c7b22ee339ae5bb6fa7359f8a6bc7cd2f35ccd5681c728869cd39 liveness-probe
docker              b72558e589cb95e835c4840de19f0306d4081091c34045246d62b6efed3549f4 myContainer
```

To check which paths `ig` is using, you can use the `--help` flag:

```bash
$ sudo ig list-containers --help
List all containers

Usage:
  ig list-containers [flags]

Flags:
  ...
      --containerd-socketpath string   containerd CRI Unix socket path (default "/run/containerd/containerd.sock")
      --crio-socketpath string         CRI-O CRI Unix socket path (default "/run/crio/crio.sock")
      --docker-socketpath string       Docker Engine API Unix socket path (default "/run/docker.sock")
      --podman-socketpath string       Podman Unix socket path (default "/run/podman/podman.sock")
  ...
  -r, --runtimes string                Container runtimes to be used separated by comma. Supported values are: docker, containerd, cri-o, podman (default "docker,containerd,cri-o,podman")
  -w, --watch                          After listing the containers, watch for new containers
  ...
```

If needed, we can also specify the runtimes to be used and their UNIX socket
path:

```bash
$ sudo ig list-containers --runtimes docker --docker-socketpath /some/path/docker.sock
RUNTIME.RUNTIMENAME RUNTIME.CONTAINERID                                              RUNTIME.CONTAINERNAME
docker              b72558e589cb95e835c4840de19f0306d4081091c34045246d62b6efed3549f4 myContainer
```

### Common features

Notice that most of the commands support the following features even if, for
simplicity, they are not demonstrated in each command guide:

- JSON format and `custom-columns` output mode are supported through the
  `--output` flag.
- It is possible to filter events by container name using the `--containername`
  flag.
- It is possible to trace events from all the running processes, even though
  they were not generated from containers, using the `--host` flag.

For instance, for the `list-containers` command:

```bash
$ sudo ig list-containers -o json --containername kube-proxy
[
  {
    "runtime": {
      "runtimeName": "containerd",
      "containerId": "a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46",
      "containerName": "kube-proxy"
    },
    "k8s": {
      "namespace": "kube-system",
      "podName": "kube-proxy-tcbn4",
      "containerName": "kube-proxy",
      "podUID": "87c52d60-fefd-45a9-a420-895256fc03b5"
    },
    "pid": 454674,
    "mntns": 4026532232,
    "netns": 4026531840,
    "hostNetwork": true,
    "cgroupPath": "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod87c52d60_fefd_45a9_a420_895256fc03b5.slice/cri-containerd-a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46.scope",
    "cgroupID": 41286,
    "cgroupV2": "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod87c52d60_fefd_45a9_a420_895256fc03b5.slice/cri-containerd-a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46.scope"
  }
]
```

For example, with `--host`, you can get the following output:

```bash
$ sudo ig trace exec --host
CONTAINER                                               PID        PPID       COMM             RET ARGS

# Open another terminal.
$ cat /dev/null
$ docker run --name test-host --rm -t debian sh -c 'ls > /dev/null'
# Go back to first terminal.
CONTAINER                                               PID        PPID       COMM             RET ARGS
                               24640            4537             cat              0   /usr/bin/cat /dev/null
test-host                      24577            24553            sh               0   /bin/sh -c cat /dev/null
test-host                      24598            24577            cat              0   /bin/cat /dev/null
```

Events generated from containers have their container field set, while events which are generated from the host do not.
