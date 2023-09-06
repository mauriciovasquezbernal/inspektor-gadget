// Copyright 2023 The Inspektor Gadget authors
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

package grpcruntime

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runType "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const (
	ParamNode = "node"

	// ConnectTimeout is the time in seconds we wait for a connection to the pod to
	// succeed
	ConnectTimeout = 30

	// ResultTimeout is the time in seconds we wait for a result to return from the gadget
	// after sending a Stop command
	ResultTimeout = 30
)

type Runtime struct {
	info          *deployinfo.DeployInfo
	defaultValues map[string]string
}

// New instantiates the runtime and loads the locally stored gadget info. If no info is stored locally,
// it will try to fetch one from one of the gadget nodes and store it locally. It will issue warnings on
// failures.
func New(skipInfo bool) *Runtime {
	r := &Runtime{
		defaultValues: map[string]string{},
	}

	if skipInfo {
		return r
	}

	// Initialize info
	info, err := deployinfo.Load()
	if err == nil {
		r.info = info
		return r
	}

	info, err = loadRemoteDeployInfo()
	if err != nil {
		log.Warnf("could not load gadget info from remote: %v", err)
		return r
	}
	r.info = info

	err = deployinfo.Store(info)
	if err != nil {
		log.Warnf("could not store gadget info: %v", err)
	}

	return r
}

func (r *Runtime) UpdateDeployInfo() error {
	info, err := loadRemoteDeployInfo()
	if err != nil {
		return fmt.Errorf("loading remote gadget info: %w", err)
	}

	return deployinfo.Store(info)
}

func (r *Runtime) Init(runtimeGlobalParams *params.Params) error {
	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ParamNode,
			Description: "Comma-separated list of nodes to run the gadget on",
			Validator: func(value string) error {
				nodes := strings.Split(value, ",")
				nodeMap := make(map[string]struct{})
				for _, node := range nodes {
					if _, ok := nodeMap[node]; ok {
						return fmt.Errorf("duplicated node: %s", node)
					}
					nodeMap[node] = struct{}{}
				}
				return nil
			},
		},
	}
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return nil
}

type gadgetPod struct {
	name string
	node string
}

func getGadgetPods(ctx context.Context, nodes []string) ([]gadgetPod, error) {
	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("creating RESTConfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("setting up trace client: %w", err)
	}

	opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
	pods, err := client.CoreV1().Pods("gadget").List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("getting pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no gadget pods found. Is Inspektor Gadget deployed?")
	}

	if len(nodes) == 0 {
		res := make([]gadgetPod, 0, len(pods.Items))

		for _, pod := range pods.Items {
			res = append(res, gadgetPod{name: pod.Name, node: pod.Spec.NodeName})
		}

		return res, nil
	}

	res := make([]gadgetPod, 0, len(nodes))
nodesLoop:
	for _, node := range nodes {
		for _, pod := range pods.Items {
			if node == pod.Spec.NodeName {
				res = append(res, gadgetPod{name: pod.Name, node: node})
				continue nodesLoop
			}
		}
		return nil, fmt.Errorf("node %q does not have a gadget pod", node)
	}

	return res, nil
}

func (r *Runtime) InitRunGadget(gadgetParams *params.Params, args []string) (string, error) {
	ctx, cancelDial := context.WithTimeout(context.Background(), time.Second*ConnectTimeout)
	defer cancelDial()

	// Get a random gadget pod and get the info from there
	pods, err := getGadgetPods(ctx, []string{})
	if err != nil {
		return "", fmt.Errorf("get gadget pods: %w", err)
	}
	if len(pods) == 0 {
		return "", fmt.Errorf("no valid pods found to get info from")
	}

	pod := pods[0]
	dialOpt := grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
		return NewK8SExecConn(ctx, pod, time.Second*ConnectTimeout)
		// return NewK8SPortForwardConn(ctx, s, time.Second*30)
	})

	conn, err := grpc.DialContext(ctx, "", dialOpt, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return "", fmt.Errorf("dialing gadget pod on node %q: %w", pod.node, err)
	}
	client := pb.NewGadgetManagerClient(conn)
	defer conn.Close()

	allParams := make(map[string]string)
	gadgetParams.CopyToMap(allParams, "")

	in := &pb.InitRunGadgetRequest{
		Params: allParams,
		Args:   args,
	}

	out, err := client.InitRunGadget(ctx, in)
	if err != nil {
		return "", fmt.Errorf("get info from gadget pod: %w", err)
	}

	return out.Payload, nil
}

func (r *Runtime) RunGadget(gadgetCtx runtime.GadgetContext) (runtime.CombinedGadgetResult, error) {
	// Get nodes to run on
	nodes := gadgetCtx.RuntimeParams().Get(ParamNode).AsStringSlice()
	pods, err := getGadgetPods(gadgetCtx.Context(), nodes)
	if err != nil {
		return nil, fmt.Errorf("get gadget pods: %w", err)
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("get gadget pods: Inspektor Gadget is not running on the requested node(s): %v", nodes) //nolint:all
	}

	if gadgetCtx.GadgetDesc().Type() == gadgets.TypeTraceIntervals {
		gadgetCtx.Parser().EnableSnapshots(
			gadgetCtx.Context(),
			time.Duration(gadgetCtx.GadgetParams().Get(gadgets.ParamInterval).AsInt32())*time.Second,
			2,
		)
		defer gadgetCtx.Parser().Flush()
	}

	if gadgetCtx.GadgetDesc().Type() == gadgets.TypeOneShot {
		gadgetCtx.Parser().EnableCombiner()
		defer gadgetCtx.Parser().Flush()
	}

	results := make(runtime.CombinedGadgetResult)
	var resultsLock sync.Mutex

	allParams := make(map[string]string)
	gadgets.ParamsToMap(
		allParams,
		gadgetCtx.GadgetParams(),
		gadgetCtx.RuntimeParams(),
		gadgetCtx.OperatorsParamCollection(),
	)

	gadgetCtx.Logger().Debugf("Params")
	for k, v := range allParams {
		gadgetCtx.Logger().Debugf("- %s: %q", k, v)
	}

	wg := sync.WaitGroup{}
	for _, pod := range pods {
		wg.Add(1)
		go func(pod gadgetPod) {
			gadgetCtx.Logger().Debugf("running gadget on node %q", pod.node)
			res, err := r.runGadget(gadgetCtx, pod, allParams)
			resultsLock.Lock()
			results[pod.node] = &runtime.GadgetResult{
				Payload: res,
				Error:   err,
			}
			resultsLock.Unlock()
			wg.Done()
		}(pod)
	}

	wg.Wait()
	return results, results.Err()
}

func (r *Runtime) runGadget(gadgetCtx runtime.GadgetContext, pod gadgetPod, allParams map[string]string) ([]byte, error) {
	// Notice that we cannot use gadgetCtx.Context() here, as that would - when cancelled by the user - also cancel the
	// underlying gRPC connection. That would then lead to results not being received anymore (mostly for profile
	// gadgets.)
	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialOpt := grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
		return NewK8SExecConn(ctx, pod, time.Second*ConnectTimeout)
	})

	dialCtx, cancelDial := context.WithTimeout(gadgetCtx.Context(), time.Second*ConnectTimeout)
	defer cancelDial()

	conn, err := grpc.DialContext(dialCtx, "", dialOpt, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("dialing gadget pod on node %q: %w", pod.node, err)
	}
	defer conn.Close()
	client := pb.NewGadgetManagerClient(conn)

	runRequest := &pb.GadgetRunRequest{
		GadgetName:     gadgetCtx.GadgetDesc().Name(),
		GadgetCategory: gadgetCtx.GadgetDesc().Category(),
		Params:         allParams,
		Args:           gadgetCtx.Args(),
		Nodes:          nil,
		FanOut:         false,
		LogLevel:       uint32(gadgetCtx.Logger().GetLevel()),
		Timeout:        int64(gadgetCtx.Timeout()),
	}

	runClient, err := client.RunGadget(connCtx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	controlRequest := &pb.GadgetControlRequest{Event: &pb.GadgetControlRequest_RunRequest{RunRequest: runRequest}}
	err = runClient.Send(controlRequest)
	if err != nil {
		return nil, err
	}

	parser := gadgetCtx.Parser()

	jsonHandler := func([]byte) {}
	jsonArrayHandler := func([]byte) {}

	if parser != nil {
		var enrichers []func(any) error
		ev := gadgetCtx.GadgetDesc().EventPrototype()
		if _, ok := ev.(operators.NodeSetter); ok {
			enrichers = append(enrichers, func(ev any) error {
				ev.(operators.NodeSetter).SetNode(pod.node)
				return nil
			})
		}

		jsonHandler = parser.JSONHandlerFunc(enrichers...)
		jsonArrayHandler = parser.JSONHandlerFuncArray(pod.node, enrichers...)
	}

	doneChan := make(chan error)

	var result []byte
	expectedSeq := uint32(1)

	// TODO: cleanup, polish, find right place
	//isRunGadget := gadgetCtx.GadgetDesc().Name() == "run"

	//	//var runParser func([]byte) error
	//	var nodeEnricher func(any) error
	//	var ebpfColNames []string
	//	if isRunGadget {
	//		ev := gadgetCtx.GadgetDesc().EventPrototype()
	//		if _, ok := ev.(operators.NodeSetter); ok {
	//			nodeEnricher = func(ev any) error {
	//				ev.(operators.NodeSetter).SetNode(pod.node)
	//				return nil
	//			}
	//		}
	//	}
	// fmt.Printf("\n\n\n")
	// for key, val := range parser.GetColumns().(columns.ColumnMap[runtype.Event]) {
	// 	fmt.Printf("%q: %+v", key, val)
	// 	if val.GetStart() != nil {
	// 		fmt.Printf("\npotential dynamic field")
	// 	}

	// 	fmt.Printf("\n\n")
	// }

	// fmt.Printf("\n\n\n")
	// panic("fasd")
	// ------

	go func() {
		for {
			ev, err := runClient.Recv()
			if err != nil {
				gadgetCtx.Logger().Debugf("%-20s | runClient returned with %v", pod.node, err)
				if !errors.Is(err, io.EOF) {
					doneChan <- err
					return
				}
				doneChan <- nil
				return
			}
			switch ev.Type {
			//			case pb.EventTypeColAttr:
			//				ebpfColAttrs := make(map[string]columns.Attributes)
			//				err := json.Unmarshal(ev.Payload, &ebpfColAttrs)
			//				if err != nil {
			//					gadgetCtx.Logger().Warnf("error parsing column attributes: %v", pod.node, err)
			//					continue
			//				}
			//
			//				cols := runType.GetColumns()
			//				for colName, colAttr := range ebpfColAttrs {
			//					colName := colName
			//					ebpfColNames = append(ebpfColNames, colName)
			//					cols.MustAddColumn(colAttr, func(ev *runType.Event) string {
			//						ebpfVals, ok := ev.Data.(map[string]string)
			//						if !ok {
			//							gadgetCtx.Logger().Warnf("error parsing column attributes: %v", pod.node, err)
			//							return ""
			//						}
			//						return ebpfVals[colName]
			//					})
			//				}
			//
			//				// Create right output formatter + print header
			//				parser = pkgParser.NewParser(cols)
			//				// TODO: handle options
			//				parser.GetTextColumnsFormatter().FormatHeader()
			//				fmt.Println(parser.GetTextColumnsFormatter().FormatHeader())
			case pb.EventTypeGadgetPayload:
				fallthrough
			case pb.EventTypeRunGadget:
				if expectedSeq != ev.Seq {
					gadgetCtx.Logger().Warnf("%-20s | expected seq %d, got %d, %d messages dropped", pod.node, expectedSeq, ev.Seq, ev.Seq-expectedSeq)
				}
				expectedSeq = ev.Seq + 1

				if ev.Type == pb.EventTypeRunGadget {
					//// TODO: move somewhere else
					//jsonToBaseEventStruct := func(j []byte) (runType.Event, error) {
					//	var eventHelper struct {
					//		Runtime struct {
					//			RuntimeName        string `json:"runtimeName"`
					//			ContainerId        string `json:"containerId"`
					//			ContainerName      string `json:"containerName"`
					//			ContainerImageName string `json:"containerImageName"`
					//		} `json:"runtime"`
					//		Node        string    `json:"node"`
					//		Namespace   string    `json:"namespace"`
					//		Pod         string    `json:"pod"`
					//		Container   string    `json:"container"`
					//		Hostnetwork bool      `json:"hostnetwork"`
					//		Timestamp   time.Time `json:"timestamp"`
					//		Mntns       uint64    `json:"mntns"`
					//	}
					//
					//	err := json.Unmarshal(j, &eventHelper)
					//	if err != nil {
					//		return runType.Event{}, err
					//	}
					//
					//	var event runType.Event
					//	event.Event.K8s.Node = eventHelper.Node
					//	event.Event.K8s.Namespace = eventHelper.Namespace
					//	event.Event.K8s.PodName = eventHelper.Pod
					//	event.Event.K8s.ContainerName = eventHelper.Container
					//	event.Event.K8s.HostNetwork = eventHelper.Hostnetwork
					//
					//	event.Event.Timestamp = types.TimeFromString(eventHelper.Timestamp.String())
					//	event.MountNsID = eventHelper.Mntns
					//
					//	event.Event.Runtime.RuntimeName = types.RuntimeName(eventHelper.Runtime.RuntimeName)
					//	event.Event.Runtime.ContainerID = eventHelper.Runtime.ContainerId
					//	event.Event.Runtime.ContainerName = eventHelper.Runtime.ContainerName
					//	event.Event.Runtime.ContainerImageName = eventHelper.Runtime.ContainerImageName
					//
					//	return event, nil
					//}
					//
					//event, err := jsonToBaseEventStruct(ev.Payload)
					//if err != nil {
					//	gadgetCtx.Logger().Errorf("error parsing event: %v", err)
					//	continue
					//}
					//if nodeEnricher != nil {
					//	nodeEnricher(&event)
					//}

					var event runType.Event

					//var jsonObj map[string]any
					if err := json.Unmarshal(ev.Payload, &event.Data); err != nil {
						fmt.Printf("error parsing event: %v", err)
						return
					}
					//ebpfCols := make(map[string]string)
					//for _, colName := range ebpfColNames {
					//	ebpfCols[colName] = fmt.Sprint(jsonObj[colName])
					//}
					//event.Data = ebpfCols

					// TODO: move somewhere else
					//formatter := parser.GetTextColumnsFormatter()
					//formatter.SetEventCallback(func(line string) {
					//	fmt.Println(line)
					//})
					//parser.SetEventCallback(formatter.EventHandlerFunc())
					//parser.EventHandlerFunc().(func(*runType.Event))(&event)
				}

				if len(ev.Payload) > 0 && ev.Payload[0] == '[' {
					jsonArrayHandler(ev.Payload)
					continue
				}
				jsonHandler(ev.Payload)

			case pb.EventTypeGadgetResult:
				gadgetCtx.Logger().Debugf("%-20s | got result from server", pod.node)
				result = ev.Payload
			case pb.EventTypeGadgetJobID: // not needed right now
			default:
				if ev.Type >= 1<<pb.EventLogShift {
					gadgetCtx.Logger().Log(logger.Level(ev.Type>>pb.EventLogShift), fmt.Sprintf("%-20s | %s", pod.node, string(ev.Payload)))
					continue
				}
				gadgetCtx.Logger().Warnf("unknown payload type %d: %s", ev.Type, ev.Payload)
			}
		}
	}()

	var runErr error
	select {
	case doneErr := <-doneChan:
		gadgetCtx.Logger().Debugf("%-20s | done from server side (%v)", pod.node, doneErr)
		runErr = doneErr
	case <-gadgetCtx.Context().Done():
		// Send stop request
		gadgetCtx.Logger().Debugf("%-20s | sending stop request", pod.node)
		controlRequest := &pb.GadgetControlRequest{Event: &pb.GadgetControlRequest_StopRequest{StopRequest: &pb.GadgetStopRequest{}}}
		runClient.Send(controlRequest)

		// Wait for done or timeout
		select {
		case doneErr := <-doneChan:
			gadgetCtx.Logger().Debugf("%-20s | done after cancel request (%v)", pod.node, doneErr)
			runErr = doneErr
		case <-time.After(ResultTimeout * time.Second):
			return nil, fmt.Errorf("timed out while getting result")
		}
	}
	return result, runErr
}

func (r *Runtime) GetCatalog() (*runtime.Catalog, error) {
	if r.info == nil {
		return nil, nil
	}
	return r.info.Catalog, nil
}

func (r *Runtime) SetDefaultValue(key params.ValueHint, value string) {
	r.defaultValues[strings.ToLower(string(key))] = value
}

func (r *Runtime) GetDefaultValue(key params.ValueHint) (string, bool) {
	val, ok := r.defaultValues[strings.ToLower(string(key))]
	return val, ok
}
