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

//go:build !withoutebpf

package tracer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/wapc/wapc-go"
	"github.com/wapc/wapc-go/engines/wazero"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
)

// keep aligned with pkg/gadgets/common/types.h
type l3EndpointT struct {
	addr    [16]byte
	version uint8
	pad     [3]uint8 // manual padding to avoid issues between C and Go
}

type l4EndpointT struct {
	l3    l3EndpointT
	port  uint16
	proto uint16
}

type Config struct {
	ProgContent []byte
	WasmContent []byte
	Metadata    *types.GadgetMetadata
	MountnsMap  *ebpf.Map

	// constants to replace in the ebpf program
	Consts map[string]interface{}
}

type linkSnapshotter struct {
	link *link.Iter
	typ  string
}

type Tracer struct {
	config             *Config
	eventCallback      func(*types.Event)
	eventArrayCallback func([]*types.Event)
	mu                 sync.Mutex
	gadgetCtx          gadgets.GadgetContext

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection
	// Type describing the format the gadget uses
	eventType *btf.Struct

	socketEnricher *socketenricher.SocketEnricher
	networkTracer  *networktracer.Tracer[types.Event]

	// Tracers related
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader

	// Snapshotters related
	linksSnapshotters []*linkSnapshotter

	containers   map[string]*containercollection.Container
	links        []link.Link
	wasmModule   wapc.Module
	wasmInstance wapc.Instance
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	// FIXME: Ideally, we should have one networktracer.NewTracer per socket
	//        filter program. But in NewInstance(), we don't have access to
	//        the ebpf program yet, so we don't know how many socket filters
	//        we have. For now, we don't support several socket filter.
	//        Currently, we unfortunately impact performance with the
	//        networkTracer even if there are no socket filters. This is
	//        difficult to fix because AttachContainer() is called for all
	//        initial containers before Run(), so we need to create the
	//        networkTracer in NewInstance().
	// https://github.com/inspektor-gadget/inspektor-gadget/pull/2003#discussion_r1320569238
	networkTracer, err := networktracer.NewTracer[types.Event]()
	if err != nil {
		return nil, fmt.Errorf("creating network tracer: %w", err)
	}

	tracer := &Tracer{
		config:        &Config{},
		networkTracer: networkTracer,
		containers:    make(map[string]*containercollection.Container),
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	t.gadgetCtx = gadgetCtx
	return nil
}

// Close is needed because of the StartStopGadget interface
func (t *Tracer) Close() {
}

func (t *Tracer) Stop() {
	if t.wasmModule != nil {
		t.wasmModule.Close(context.Background())
	}
	if t.wasmInstance != nil {
		t.wasmInstance.Close(context.Background())
	}

	if t.collection != nil {
		t.collection.Close()
		t.collection = nil
	}
	for _, l := range t.links {
		gadgets.CloseLink(l)
	}
	t.links = nil

	if t.ringbufReader != nil {
		t.ringbufReader.Close()
	}
	if t.perfReader != nil {
		t.perfReader.Close()
	}
	if t.socketEnricher != nil {
		t.socketEnricher.Close()
	}
}

func (t *Tracer) handleTracers() (string, error) {
	_, tracer := getAnyMapElem(t.config.Metadata.Tracers)

	traceMap := t.spec.Maps[tracer.MapName]
	if traceMap == nil {
		return "", fmt.Errorf("map %q not found", tracer.MapName)
	}

	return tracer.MapName, nil
}

func (t *Tracer) installTracer(params *params.Params) error {
	// Load wasm module
	ctx := context.Background()
	engine := wazero.Engine()

	var err error
	if t.config.WasmContent != nil {
		host := t.newWasmHost(t.gadgetCtx.Logger())
		t.wasmModule, err = engine.New(ctx, host, t.config.WasmContent, &wapc.ModuleConfig{
			Logger: func(msg string) {
				t.gadgetCtx.Logger().Info(msg)
			},
			Stdout: os.Stdout,
			Stderr: os.Stderr,
		})
		if err != nil {
			return fmt.Errorf("creating wasm module: %w", err)
		}
		t.wasmInstance, err = t.wasmModule.Instantiate(ctx)
		if err != nil {
			return fmt.Errorf("instantiating wasm module: %w", err)
		}

		_, err = t.wasmInstance.Invoke(t.newHostCallContext(),
			"Init", []byte{})
		if err != nil {
			return fmt.Errorf("invoking Init() in wasm module: %w", err)
		}
	}

	// Load the spec
	var tracerMapName string

	mapReplacements := map[string]*ebpf.Map{}

	t.eventType, err = getEventTypeBTF(t.config.ProgContent, t.config.Metadata)
	if err != nil {
		return err
	}

	switch {
	case len(t.config.Metadata.Tracers) > 0:
		tracerMapName, err = t.handleTracers()
		if err != nil {
			return fmt.Errorf("handling trace programs: %w", err)
		}
	}

	t.setEBPFParameters(t.config.Metadata.EBPFParams, params)
	consts := t.config.Consts

	// Handle special maps like mount ns filter, socket enricher, etc.
	for _, m := range t.spec.Maps {
		switch m.Name {
		// Only create socket enricher if this is used by the tracer
		case socketenricher.SocketsMapName:
			t.socketEnricher, err = socketenricher.NewSocketEnricher()
			if err != nil {
				// Containerized gadgets require a kernel with BTF
				return fmt.Errorf("creating socket enricher: %w", err)
			}
			mapReplacements[socketenricher.SocketsMapName] = t.socketEnricher.SocketsMap()
		// Replace filter mount ns map
		case gadgets.MntNsFilterMapName:
			if t.config.MountnsMap == nil {
				break
			}

			mapReplacements[gadgets.MntNsFilterMapName] = t.config.MountnsMap
			consts[gadgets.FilterByMntNsName] = true
		}
	}

	if err := t.spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("rewriting constants: %w", err)
	}

	// Load the ebpf objects
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	t.collection, err = ebpf.NewCollectionWithOptions(t.spec, opts)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	// Some logic before loading the programs
	if tracerMapName != "" {
		m := t.collection.Maps[tracerMapName]
		switch m.Type() {
		case ebpf.RingBuf:
			t.ringbufReader, err = ringbuf.NewReader(t.collection.Maps[tracerMapName])
		case ebpf.PerfEventArray:
			t.perfReader, err = perf.NewReader(t.collection.Maps[tracerMapName], gadgets.PerfBufferPages*os.Getpagesize())
		}
		if err != nil {
			return fmt.Errorf("create BPF map reader: %w", err)
		}
	}

	// Attach programs
	socketFilterFound := false
	for progName, p := range t.spec.Programs {
		if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kprobe/") {
			l, err := link.Kprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kretprobe/") {
			l, err := link.Kretprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.TracePoint && strings.HasPrefix(p.SectionName, "tracepoint/") {
			parts := strings.Split(p.AttachTo, "/")
			l, err := link.Tracepoint(parts[0], parts[1], t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.SocketFilter && strings.HasPrefix(p.SectionName, "socket") {
			if socketFilterFound {
				return fmt.Errorf("several socket filters found, only one is supported")
			}
			socketFilterFound = true
			err := t.networkTracer.AttachProg(t.collection.Programs[progName])
			if err != nil {
				return fmt.Errorf("attaching ebpf program to dispatcher: %w", err)
			}
		} else if p.Type == ebpf.Tracing && strings.HasPrefix(p.SectionName, "iter/") {
			switch p.AttachTo {
			case "task", "tcp", "udp":
				l, err := link.AttachIter(link.IterOptions{
					Program: t.collection.Programs[progName],
				})
				if err != nil {
					return fmt.Errorf("attach BPF program %q: %w", progName, err)
				}
				t.links = append(t.links, l)
				t.linksSnapshotters = append(t.linksSnapshotters, &linkSnapshotter{link: l, typ: p.AttachTo})
			default:
				return fmt.Errorf("unsupported iter type %q", p.AttachTo)
			}
		}
	}

	return nil
}

func verifyGadgetUint64Typedef(t btf.Type) error {
	typDef, ok := t.(*btf.Typedef)
	if !ok {
		return fmt.Errorf("not a typedef")
	}

	underlying, err := getUnderlyingType(typDef)
	if err != nil {
		return err
	}

	intM, ok := underlying.(*btf.Int)
	if !ok {
		return fmt.Errorf("not an integer")
	}

	if intM.Size != 8 {
		return fmt.Errorf("bad sized. Expected 8, got %d", intM.Size)
	}

	return nil
}

// processEventFunc returns a callback that parses a binary encoded event in data, enriches and
// returns it.
func (t *Tracer) processEventFunc(gadgetCtx gadgets.GadgetContext) func(data []byte) *types.Event {
	typ := t.eventType
	logger := gadgetCtx.Logger()

	var mntNsIdstart uint32
	mountNsIdFound := false

	type endpointType int

	const (
		U endpointType = iota
		L3
		L4
	)

	type endpointDef struct {
		name  string
		start uint32
		typ   endpointType
	}

	endpointDefs := []endpointDef{}
	timestampsOffsets := []uint32{}

	// The same same data structure is always sent, so we can precalculate the offsets for
	// different fields like mount ns id, endpoints, etc.
	for _, member := range typ.Members {
		switch member.Type.TypeName() {
		case types.MntNsIdTypeName:
			if err := verifyGadgetUint64Typedef(member.Type); err != nil {
				logger.Warn("%s is not a uint64: %s", member.Name, err)
				continue
			}
			mntNsIdstart = member.Offset.Bytes()
			mountNsIdFound = true
		case types.L3EndpointTypeName:
			typ, ok := member.Type.(*btf.Struct)
			if !ok {
				logger.Warn("%s is not a struct", member.Name)
				continue
			}
			expectedSize := uint32(unsafe.Sizeof(l3EndpointT{}))
			if typ.Size != expectedSize {
				logger.Warn("%s has a wrong size, expected %d, got %d", member.Name,
					expectedSize, typ.Size)
				continue
			}
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L3}
			endpointDefs = append(endpointDefs, e)
		case types.L4EndpointTypeName:
			typ, ok := member.Type.(*btf.Struct)
			if !ok {
				logger.Warn("%s is not a struct", member.Name)
				continue
			}
			expectedSize := uint32(unsafe.Sizeof(l4EndpointT{}))
			if typ.Size != expectedSize {
				logger.Warn("%s has a wrong size, expected %d, got %d", member.Name,
					expectedSize, typ.Size)
				continue
			}
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L4}
			endpointDefs = append(endpointDefs, e)
		case types.TimestampTypeName:
			if err := verifyGadgetUint64Typedef(member.Type); err != nil {
				logger.Warn("%s is not a uint64: %s", member.Name, err)
				continue
			}
			timestampsOffsets = append(timestampsOffsets, member.Offset.Bytes())
		}
	}

	return func(data []byte) *types.Event {
		// get mntNsId for enriching the event
		mntNsId := uint64(0)
		if mountNsIdFound {
			mntNsId = *(*uint64)(unsafe.Pointer(&data[mntNsIdstart]))
		}

		// enrich endpoints
		l3endpoints := []types.L3Endpoint{}
		l4endpoints := []types.L4Endpoint{}

		for _, endpoint := range endpointDefs {
			endpointC := (*l3EndpointT)(unsafe.Pointer(&data[endpoint.start]))
			var size int
			switch endpointC.version {
			case 4:
				size = 4
			case 6:
				size = 16
			default:
				logger.Warnf("bad IP version received: %d", endpointC.version)
				continue
			}

			ipBytes := make(net.IP, size)
			copy(ipBytes, endpointC.addr[:])

			l3endpoint := eventtypes.L3Endpoint{
				Addr:    ipBytes.String(),
				Version: endpointC.version,
			}

			switch endpoint.typ {
			case L3:
				endpoint := types.L3Endpoint{
					Name:       endpoint.name,
					L3Endpoint: l3endpoint,
				}
				l3endpoints = append(l3endpoints, endpoint)
			case L4:
				l4EndpointC := (*l4EndpointT)(unsafe.Pointer(&data[endpoint.start]))
				endpoint := types.L4Endpoint{
					Name: endpoint.name,
					L4Endpoint: eventtypes.L4Endpoint{
						L3Endpoint: l3endpoint,
						Port:       l4EndpointC.port,
						Proto:      l4EndpointC.proto,
					},
				}
				l4endpoints = append(l4endpoints, endpoint)
			}
		}

		// handle timestamps
		timestamps := []eventtypes.Time{}
		for _, offset := range timestampsOffsets {
			timestamp := *(*uint64)(unsafe.Pointer(&data[offset]))
			t := gadgets.WallTimeFromBootTime(timestamp)
			timestamps = append(timestamps, t)
		}

		return &types.Event{
			Type:        eventtypes.NORMAL,
			MountNsID:   mntNsId,
			RawData:     data,
			L3Endpoints: l3endpoints,
			L4Endpoints: l4endpoints,
			Timestamps:  timestamps,
		}
	}
}

func (t *Tracer) runTracers(gadgetCtx gadgets.GadgetContext) {
	cb := t.processEventFunc(gadgetCtx)

	for {
		var rawSample []byte

		if t.ringbufReader != nil {
			record, err := t.ringbufReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// nothing to do, we're done
					return
				}
				gadgetCtx.Logger().Errorf("read ring buffer: %w", err)
				return
			}
			rawSample = record.RawSample
		} else if t.perfReader != nil {
			record, err := t.perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				gadgetCtx.Logger().Errorf("read perf ring buffer: %w", err)
				return
			}

			if record.LostSamples != 0 {
				gadgetCtx.Logger().Warnf("lost %d samples", record.LostSamples)
				continue
			}
			rawSample = record.RawSample
		}

		ev := cb(rawSample)
		t.eventCallback(ev)
	}
}

func (t *Tracer) setEBPFParameters(ebpfParams map[string]types.EBPFParam, gadgetParams *params.Params) {
	t.config.Consts = make(map[string]interface{})
	for varName, paramDef := range ebpfParams {
		p := gadgetParams.Get(paramDef.Key)
		if !p.IsSet() {
			continue
		}
		t.config.Consts[varName] = p.AsAny()
	}
}

func (t *Tracer) runIterInAllNetNs(it *link.Iter, cb func([]byte) *types.Event) ([]*types.Event, error) {
	events := []*types.Event{}
	s := int(t.eventType.Size)

	namespacesToVisit := map[uint64]*containercollection.Container{}
	for _, c := range t.containers {
		namespacesToVisit[c.Netns] = c
	}

	for _, container := range namespacesToVisit {
		err := netnsenter.NetnsEnter(int(container.Pid), func() error {
			reader, err := it.Open()
			if err != nil {
				return err
			}
			defer reader.Close()

			buf, err := io.ReadAll(reader)
			if err != nil {
				return err
			}

			eventsLocal := splitAndConvert(buf, s, cb)
			for _, ev := range eventsLocal {
				// TODO: set all the values here to avoid depending on the enricher?
				ev.NetNsID = container.Netns
			}

			events = append(events, eventsLocal...)

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return events, nil
}

func splitAndConvert(data []byte, size int, cb func([]byte) *types.Event) []*types.Event {
	events := make([]*types.Event, len(data)/size)
	for i := 0; i < len(data)/size; i++ {
		ev := cb(data[i*size : (i+1)*size])
		events[i] = ev
	}
	return events
}

func (t *Tracer) runSnapshotter(gadgetCtx gadgets.GadgetContext) error {
	cb := t.processEventFunc(gadgetCtx)

	events := []*types.Event{}

	for _, l := range t.linksSnapshotters {
		switch l.typ {
		// Iterators that have to be run in the root pid namespace
		case "task":
			buf, err := bpfiterns.Read(l.link)
			if err != nil {
				return fmt.Errorf("reading iterator: %w", err)
			}
			eventsL := splitAndConvert(buf, int(t.eventType.Size), cb)
			events = append(events, eventsL...)
		// Iterators that have to be run on each network namespace
		case "tcp", "udp":
			var err error
			eventsL, err := t.runIterInAllNetNs(l.link, cb)
			if err != nil {
				return fmt.Errorf("reading iterator: %w", err)
			}
			events = append(events, eventsL...)
		}
	}

	t.eventArrayCallback(events)

	return nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	args := gadgetCtx.Args()

	info, err := getGadgetInfo(params, args, gadgetCtx.Logger())
	if err != nil {
		return fmt.Errorf("getting gadget info: %w", err)
	}

	t.config.ProgContent = info.ProgContent
	t.config.WasmContent = info.WasmContent
	t.spec, err = loadSpec(t.config.ProgContent)
	if err != nil {
		return err
	}

	t.config.Metadata = info.GadgetMetadata

	if err := t.installTracer(params); err != nil {
		t.Stop()
		return fmt.Errorf("install tracer: %w", err)
	}

	if t.perfReader != nil || t.ringbufReader != nil {
		go t.runTracers(gadgetCtx)
	}
	if len(t.linksSnapshotters) > 0 {
		return t.runSnapshotter(gadgetCtx)
	}
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) AttachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	t.containers[container.Runtime.ContainerID] = container
	t.mu.Unlock()
	return t.networkTracer.Attach(container.Pid)
}

func (t *Tracer) DetachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	delete(t.containers, container.Runtime.ContainerID)
	t.mu.Unlock()
	return t.networkTracer.Detach(container.Pid)
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventArrayCallback = nh
}
