// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestListContainers(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-list-containers")

	listContainersCmd := &Command{
		Name: "RunListContainers",
		Cmd:  fmt.Sprintf("ig list-containers -o json --runtimes=%s", *containerRuntime),
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: "test-pod",
						PodName:       "test-pod",
						Namespace:     ns,
					},
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						RuntimeName: types.String2RuntimeName(*containerRuntime),
					},
				},
			}

			normalize := func(c *containercollection.Container) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					c.K8s.ContainerName = "test-pod"
				}

				c.Runtime.ContainerID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.K8s.PodLabels = nil
				c.K8s.PodUID = ""
			}

			return ExpectEntriesInArrayToMatch(output, normalize, expectedContainer)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "sleep inf"),
		WaitUntilTestPodReadyCommand(ns),
		listContainersCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestFilterByContainerName(t *testing.T) {
	t.Parallel()
	cn := "test-filtered-container"
	ns := GenerateTestNamespaceName(cn)

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestFilterByContainerName on docker since we don't propagate the Kubernetes pod container name")
	}

	listContainersCmd := &Command{
		Name: "RunFilterByContainerName",
		Cmd:  fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s", *containerRuntime, cn),
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: cn,
						PodName:       cn,
						Namespace:     ns,
					},
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						RuntimeName: types.String2RuntimeName(*containerRuntime),
					},
				},
			}

			normalize := func(c *containercollection.Container) {
				c.Runtime.ContainerID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.K8s.PodLabels = nil
				c.K8s.PodUID = ""
			}

			return ExpectAllInArrayToMatch(output, normalize, expectedContainer)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, cn),
		listContainersCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestWatchCreatedContainers(t *testing.T) {
	t.Parallel()
	cn := "test-created-container"
	ns := GenerateTestNamespaceName(cn)

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestWatchContainers on docker since we don't propagate the Kubernetes pod container name")
	}

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s --watch", *containerRuntime, cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeAddContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							ContainerName: cn,
							PodName:       cn,
							Namespace:     ns,
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							RuntimeName: types.String2RuntimeName(*containerRuntime),
						},
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.Runtime.ContainerID = ""
				e.Container.Pid = 0
				e.Container.OciConfig = nil
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Container.K8s.PodLabels = nil
				e.Container.K8s.PodUID = ""
				e.Timestamp = ""
			}

			return ExpectAllToMatch(output, normalize, expectedEvent)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		watchContainersCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, cn),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestWatchDeletedContainers(t *testing.T) {
	t.Parallel()
	cn := "test-deleted-container"
	ns := GenerateTestNamespaceName(cn)

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestWatchContainers on docker since we don't propagate the Kubernetes pod container name")
	}

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s --watch", *containerRuntime, cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeRemoveContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							ContainerName: cn,
							PodName:       cn,
							Namespace:     ns,
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							RuntimeName: types.String2RuntimeName(*containerRuntime),
						},
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.Runtime.ContainerID = ""
				e.Container.Pid = 0
				e.Container.OciConfig = nil
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Container.K8s.PodLabels = nil
				e.Container.K8s.PodUID = ""
				e.Timestamp = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEvent)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand(cn, "busybox", ns, `["sleep", "inf"]`, ""),
		WaitUntilPodReadyCommand(ns, cn),
		watchContainersCmd,
		{
			Name: "DeletePod",
			Cmd:  fmt.Sprintf("kubectl delete pod %s -n %s", cn, ns),
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestPodWithSecurityContext(t *testing.T) {
	t.Parallel()
	cn := "test-security-context"
	po := cn
	ns := GenerateTestNamespaceName(cn)

	// TODO: Handle it once we support getting K8s container name for docker
	// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
	if *containerRuntime == ContainerRuntimeDocker {
		t.Skip("Skip TestPodWithSecurityContext on docker since we don't propagate the Kubernetes pod container name")
	}

	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("ig list-containers -o json --runtimes=%s --containername=%s --watch", *containerRuntime, cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvent := &containercollection.PubSubEvent{
				Type: containercollection.EventTypeAddContainer,
				Container: &containercollection.Container{
					K8s: containercollection.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							ContainerName: cn,
							PodName:       po,
							Namespace:     ns,
						},
					},
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							RuntimeName: types.RuntimeName(*containerRuntime),
						},
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.Pid = 0
				e.Container.OciConfig = nil
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Timestamp = ""

				e.Container.Runtime.ContainerID = ""
				e.Container.K8s.PodLabels = nil
				e.Container.K8s.PodUID = ""
			}

			return ExpectAllToMatch(output, normalize, expectedEvent)
		},
	}

	securityContextPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1001
    fsGroup: 1002
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: %s
    image: busybox
    command: ["sleep", "inf"]
`, po, ns, cn)

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		watchContainersCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		{
			Name:           "RunTestPodWithSecurityContext",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", securityContextPodYaml),
			ExpectedRegexp: fmt.Sprintf("pod/%s created", po),
		},
		WaitUntilPodReadyCommand(ns, po),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
