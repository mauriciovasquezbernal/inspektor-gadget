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

package kubemanager

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	OperatorName       = "KubeManager"
	ParamContainerName = "containername"
	ParamSelector      = "selector"
	ParamAllNamespaces = "all-namespaces"
	ParamPodName       = "podname"
	ParamNamespace     = "namespace"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type KubeManager struct {
	gadgetTracerManager *gadgettracermanager.GadgetTracerManager
}

func (k *KubeManager) SetGadgetTracerMgr(g *gadgettracermanager.GadgetTracerManager) {
	log.Infof("gadget tracermgr set in kubemanager")
	k.gadgetTracerManager = g
}

func (k *KubeManager) Name() string {
	return OperatorName
}

func (k *KubeManager) Description() string {
	return "KubeManager handles container/pod/namespace information using Container-Collection and GadgetTracerMgr"
}

func (k *KubeManager) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *KubeManager) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ParamContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.K8SContainerName,
		},
		{
			Key:         ParamSelector,
			Alias:       "l",
			Description: "Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
			ValueHint:   gadgets.K8SLabels,
			Validator: func(value string) error {
				if value == "" {
					return nil
				}

				pairs := strings.Split(value, ",")
				for _, pair := range pairs {
					kv := strings.Split(pair, "=")
					if len(kv) != 2 {
						return fmt.Errorf("should be a comma-separated list of key-value pairs (key=value[,key=value,...])")
					}
				}

				return nil
			},
		},
		{
			Key:         ParamPodName,
			Alias:       "p",
			Description: "Show only data from pods with that name",
			ValueHint:   gadgets.K8SPodName,
		},
		{
			Key:          ParamAllNamespaces,
			Alias:        "A",
			Description:  "Show data from pods in all namespaces",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		},
		{
			Key:         ParamNamespace,
			Alias:       "n",
			Description: "Show only data from pods in a given namespace",
			ValueHint:   gadgets.K8SNamespace,
		},
	}
}

func (k *KubeManager) Dependencies() []string {
	return nil
}

func (k *KubeManager) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	// We need to be able to get MountNSID or NetNSID, and set ContainerInfo, so
	// check for that first
	_, canEnrichEventFromMountNs := gadget.EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadget.EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	// Secondly, we need to be able to inject the ebpf map onto the tracer
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}

	instance, err := gi.NewInstance()
	if err != nil {
		log.Warn("failed to create dummy instance")
		return false
	}
	_, isMountNsMapSetter := instance.(MountNsMapSetter)
	_, isAttacher := instance.(Attacher)

	log.Debugf("> canEnrichEvent: %v", canEnrichEvent)
	log.Debugf(" > canEnrichEventFromMountNs: %v", canEnrichEventFromMountNs)
	log.Debugf(" > canEnrichEventFromNetNs: %v", canEnrichEventFromNetNs)
	log.Debugf("> isMountNsMapSetter: %v", isMountNsMapSetter)
	log.Debugf("> isAttacher: %v", isAttacher)

	return isMountNsMapSetter || canEnrichEvent || isAttacher
}

func (k *KubeManager) CanOperateOnContainerizedGadget(info *runTypes.GadgetInfo) bool {
	features := info.Features
	log.Debugf("gadget features:\n%s", features.String())

	return features.HasMountNs || features.HasNetNs ||
		features.CanFilterByMountNs || features.IsAttacher
}

func (k *KubeManager) Init(params *params.Params) error {
	return nil
}

func (k *KubeManager) Close() error {
	return nil
}

func getGadgetFeatures(gadgetContext operators.GadgetContext, gadgetInstance any) runTypes.GadgetFeatures {
	// If the gadget is a run gadget, return the features from the context
	if gadgetContext.GadgetInfo() != nil {
		return gadgetContext.GadgetInfo().Features
	}

	// Otherwise use the gadget descriptor for built-in gadgets
	_, hasMountNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, hasNetNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromNetNSID)
	_, canFilterByMountNs := gadgetInstance.(MountNsMapSetter)
	_, isAttacher := gadgetInstance.(Attacher)

	return runTypes.GadgetFeatures{
		HasMountNs:         hasMountNs,
		HasNetNs:           hasNetNs,
		CanFilterByMountNs: canFilterByMountNs,
		IsAttacher:         isAttacher,
	}
}

func (k *KubeManager) Instantiate(gadgetContext operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	features := getGadgetFeatures(gadgetContext, gadgetInstance)
	canEnrichEvent := features.HasMountNs || features.HasNetNs

	traceInstance := &KubeManagerInstance{
		id:             uuid.New().String(),
		manager:        k,
		enrichEvents:   canEnrichEvent,
		params:         params,
		gadgetInstance: gadgetInstance,
		gadgetCtx:      gadgetContext,
		gadgetFeatures: features,
	}

	return traceInstance, nil
}

type KubeManagerInstance struct {
	id           string
	manager      *KubeManager
	enrichEvents bool
	mountnsmap   *ebpf.Map
	subscribed   bool

	attachedContainers map[string]*containercollection.Container
	attacher           Attacher
	params             *params.Params
	gadgetInstance     any
	gadgetCtx          operators.GadgetContext
	gadgetFeatures     runTypes.GadgetFeatures
}

func (m *KubeManagerInstance) Name() string {
	return "KubeManagerInstance"
}

func (m *KubeManagerInstance) PreGadgetRun() error {
	log := m.gadgetCtx.Logger()

	labels := make(map[string]string)
	selectorSlice := m.params.Get(ParamSelector).AsStringSlice()
	for _, pair := range selectorSlice {
		kv := strings.Split(pair, "=")
		labels[kv[0]] = kv[1]
	}

	containerSelector := containercollection.ContainerSelector{
		K8s: containercollection.K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     m.params.Get(ParamNamespace).AsString(),
				PodName:       m.params.Get(ParamPodName).AsString(),
				ContainerName: m.params.Get(ParamContainerName).AsString(),
			},
			PodLabels: labels,
		},
	}

	if m.params.Get(ParamAllNamespaces).AsBool() {
		containerSelector.K8s.Namespace = ""
	}

	if m.gadgetFeatures.CanFilterByMountNs {
		setter := m.gadgetInstance.(MountNsMapSetter)
		err := m.manager.gadgetTracerManager.AddTracer(m.id, containerSelector)
		if err != nil {
			return fmt.Errorf("adding tracer: %w", err)
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := m.manager.gadgetTracerManager.TracerMountNsMap(m.id)
		if err != nil {
			m.manager.gadgetTracerManager.RemoveTracer(m.id)
			return fmt.Errorf("creating mountns map: %w", err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)

		m.mountnsmap = mountnsmap
	}

	if m.gadgetFeatures.IsAttacher {
		m.attacher = m.gadgetInstance.(Attacher)
		m.attachedContainers = make(map[string]*containercollection.Container)

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachContainer()")
			err := m.attacher.AttachContainer(container)
			if err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					m.gadgetCtx.Logger().Debugf("start tracing container %q: verifier error: %+v\n", container.K8s.ContainerName, ve)
				}

				log.Warnf("start tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}

			m.attachedContainers[container.Runtime.ContainerID] = container

			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.Pid, container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			delete(m.attachedContainers, container.Runtime.ContainerID)

			err := m.attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.Pid, container.Mntns, container.Netns)
		}

		m.subscribed = true

		log.Debugf("add subscription")
		containers := m.manager.gadgetTracerManager.Subscribe(
			m.id,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				log.Debugf("%s: %s", event.Type.String(), event.Container.Runtime.ContainerID)
				switch event.Type {
				case containercollection.EventTypeAddContainer:
					attachContainerFunc(event.Container)
				case containercollection.EventTypeRemoveContainer:
					detachContainerFunc(event.Container)
				}
			},
		)

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}

	return nil
}

func (m *KubeManagerInstance) PostGadgetRun() error {
	if m.mountnsmap != nil {
		m.gadgetCtx.Logger().Debugf("calling RemoveTracer()")
		m.manager.gadgetTracerManager.RemoveTracer(m.id)
	}
	if m.subscribed {
		m.gadgetCtx.Logger().Debugf("calling Unsubscribe()")
		m.manager.gadgetTracerManager.Unsubscribe(m.id)

		// emit detach for all remaining containers
		for _, container := range m.attachedContainers {
			m.attacher.DetachContainer(container)
		}
	}
	return nil
}

func (m *KubeManagerInstance) enrich(ev any) {
	if event, canEnrichEventFromMountNs := ev.(operators.ContainerInfoFromMountNSID); canEnrichEventFromMountNs {
		m.manager.gadgetTracerManager.ContainerCollection.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		m.manager.gadgetTracerManager.ContainerCollection.EnrichEventByNetNs(event)
	}
}

func (m *KubeManagerInstance) EnrichEvent(ev any) error {
	if !m.enrichEvents {
		return nil
	}
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&KubeManager{})
}
