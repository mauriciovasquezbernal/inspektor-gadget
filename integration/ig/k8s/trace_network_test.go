// Copyright 2022-2023 The Inspektor Gadget authors
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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceNetwork(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-network")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	nginxIP, err := GetTestPodIP(ns, "nginx-pod")
	if err != nil {
		t.Fatalf("failed to get pod ip %s", err)
	}

	traceNetworkCmd := &Command{
		Name:         "TraceNetwork",
		Cmd:          fmt.Sprintf("ig trace network -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			testPodIP, err := GetTestPodIP(ns, "test-pod")
			if err != nil {
				return fmt.Errorf("getting pod ip: %w", err)
			}

			expectedEntries := []*networkTypes.Event{
				{
					Event:   BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:    "wget",
					Uid:     0,
					Gid:     0,
					PktType: "OUTGOING",
					Proto:   "tcp",
					Port:    80,
					DstEndpoint: eventtypes.L3Endpoint{
						Addr: nginxIP,
					},
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									Namespace:     ns,
									PodName:       "nginx-pod",
									ContainerName: "nginx-pod",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerName: "nginx-pod",
								RuntimeName:   eventtypes.String2RuntimeName(*containerRuntime),
							},
						},
					},
					Comm:    "nginx",
					Uid:     101, // default nginx user
					Gid:     101,
					PktType: "HOST",
					Proto:   "tcp",
					Port:    80,
					DstEndpoint: eventtypes.L3Endpoint{
						Addr: testPodIP,
					},
				},
			}

			normalize := func(e *networkTypes.Event) {
				// Docker and CRI-O uses a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				if *containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO {
					cn := e.K8s.ContainerName
					if strings.HasPrefix(e.Runtime.ContainerName, fmt.Sprintf("k8s_%s_%s_%s_", cn, cn, ns)) {
						e.Runtime.ContainerName = cn
					}
				}

				e.Timestamp = 0
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				e.Runtime.ContainerID = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		traceNetworkCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", nginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
