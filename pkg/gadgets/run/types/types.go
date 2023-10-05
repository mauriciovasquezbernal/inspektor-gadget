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

package types

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type L3Endpoint struct {
	eventtypes.L3Endpoint
	Name string
}

type L4Endpoint struct {
	eventtypes.L4Endpoint
	Name string
}

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	L3Endpoints []L3Endpoint `json:"l3endpoints,omitempty"`
	L4Endpoints []L4Endpoint `json:"l4endpoints,omitempty"`

	// Raw event sent by the ebpf program
	RawData []byte `json:"raw_data,omitempty"`
	// How to flatten this?
	Data interface{} `json:"data"`
}

type GadgetInfo struct {
	GadgetMetadata *GadgetMetadata
	ProgContent    []byte
}

func (ev *Event) GetEndpoints() []*eventtypes.L3Endpoint {
	endpoints := make([]*eventtypes.L3Endpoint, 0, len(ev.L3Endpoints)+len(ev.L4Endpoints))

	for i := range ev.L3Endpoints {
		endpoints = append(endpoints, &ev.L3Endpoints[i].L3Endpoint)
	}
	for i := range ev.L4Endpoints {
		endpoints = append(endpoints, &ev.L4Endpoints[i].L3Endpoint)
	}

	return endpoints
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

type Alignment string

const (
	AlignmenNone   Alignment = ""
	AlignmentLeft  Alignment = "left"
	AlignmentRight Alignment = "right"
)

type EllipsisType string

const (
	EllipsisNone   EllipsisType = ""
	EllipsisStart  EllipsisType = "start"
	EllipsisMiddle EllipsisType = "middle"
	EllipsisEnd    EllipsisType = "end"
)

// FieldAttributes describes how to format a field.
// Almost 1:1 mapping with columns.Attributes.
// TODO: Better to use columns.Attributes directly?
type FieldAttributes struct {
	Width     uint         `yaml:"width,omitempty"`
	MinWidth  uint         `yaml:"min_width,omitempty"`
	MaxWidth  uint         `yaml:"max_width,omitempty"`
	Alignment Alignment    `yaml:"alignment,omitempty"`
	Visible   *bool        `yaml:"visible,omitempty"`
	Ellipsis  EllipsisType `yaml:"ellipsis,omitempty"`
	Template  string       `yaml:"template,omitempty"`
}

type Field struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Attributes  FieldAttributes   `yaml:"attributes"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}
type Struct struct {
	Fields []Field `yaml:"fields"`
}

type TraceMaps struct {
	StructName string `yaml:"structName"`
}
type GadgetMetadata struct {
	Name        string               `yaml:"name"`
	Description string               `yaml:"description,omitempty"`
	TraceMaps   map[string]TraceMaps `yaml:"traceMaps,omitempty"`
	Structs     map[string]Struct    `yaml:"structs,omitempty"`
}

func (g *GadgetMetadata) validateTraceMaps(spec *ebpf.CollectionSpec) error {
	var result error

	// Temporal limitation
	if len(g.TraceMaps) > 1 {
		result = multierror.Append(result, errors.New("only one trace map is allowed"))
	}

	for name, m := range g.TraceMaps {
		if m.StructName == "" {
			result = multierror.Append(result, fmt.Errorf("trace map %q is missing structName", name))
		}

		_, ok := g.Structs[m.StructName]
		if !ok {
			result = multierror.Append(result, fmt.Errorf("trace map %q references unknown struct %q", name, m.StructName))
		}

		ebpfm, ok := spec.Maps[name]
		if !ok {
			result = multierror.Append(result, fmt.Errorf("trace map %q not found in eBPF object", name))
		} else if ebpfm.Type != ebpf.RingBuf && ebpfm.Type != ebpf.PerfEventArray {
			result = multierror.Append(result, fmt.Errorf("trace map %q is not a ringbuf or perf event array", name))
		}
	}

	return result
}

func getBTFStruct(spec *ebpf.CollectionSpec, name string) *btf.Struct {
	it := spec.Types.Iterate()
	for it.Next() {
		s, ok := it.Type.(*btf.Struct)
		if !ok {
			continue
		}

		if s.Name == name {
			return s
		}
	}

	return nil
}

func (g *GadgetMetadata) validateStructs(spec *ebpf.CollectionSpec) error {
	var result error

	for name, mapStruct := range g.Structs {
		btfStruct := getBTFStruct(spec, name)
		if btfStruct == nil {
			result = multierror.Append(result, fmt.Errorf("struct %q not found in eBPF object", name))
			continue
		}

		mapStructFields := make(map[string]Field, len(mapStruct.Fields))
		for _, f := range mapStruct.Fields {
			mapStructFields[f.Name] = f
		}

		btfStructFields := make(map[string]btf.Member, len(btfStruct.Members))
		for _, m := range btfStruct.Members {
			btfStructFields[m.Name] = m
		}

		for fieldName := range mapStructFields {
			if _, ok := btfStructFields[fieldName]; !ok {
				result = multierror.Append(result, fmt.Errorf("field %q not found in eBPF struct %q", fieldName, name))
			}
		}
	}

	return result
}

func (g *GadgetMetadata) Validate(spec *ebpf.CollectionSpec) error {
	var result error

	if g.Name == "" {
		result = multierror.Append(result, errors.New("gadget name is required"))
	}

	if err := g.validateTraceMaps(spec); err != nil {
		result = multierror.Append(result, err)
	}

	if err := g.validateStructs(spec); err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

// Populate fills the metadata  from its ebpf spec
func (g *GadgetMetadata) Populate(spec *ebpf.CollectionSpec) error {
	if err := populateTraceMaps(spec, g); err != nil {
		return fmt.Errorf("handling trace maps: %w", err)
	}

	return nil
}

func getTraceMapFromeBPF(spec *ebpf.CollectionSpec) *ebpf.MapSpec {
	var mapName string

	it := spec.Types.Iterate()
	for it.Next() {
		v, ok := it.Type.(*btf.Var)
		if !ok {
			continue
		}

		// TODO: add more checks here.

		if strings.HasPrefix(v.Name, gadgets.TraceMapPrefix) {
			mapName = strings.TrimPrefix(v.Name, gadgets.TraceMapPrefix)
			break
		}
	}

	if mapName == "" {
		return nil
	}

	for _, m := range spec.Maps {
		if m.Name != mapName {
			continue
		}

		if m.Type != ebpf.RingBuf && m.Type != ebpf.PerfEventArray {
			continue
		}

		return m
	}

	return nil
}

func populateTraceMaps(spec *ebpf.CollectionSpec, metadata *GadgetMetadata) error {
	traceMap := getTraceMapFromeBPF(spec)
	if traceMap == nil {
		log.Debug("No trace map found")
		return nil
	}

	traceMapStruct, ok := traceMap.Value.(*btf.Struct)
	if !ok {
		return fmt.Errorf("BPF map %q does not have BTF info for values", traceMap.Name)
	}

	if metadata.TraceMaps == nil {
		metadata.TraceMaps = make(map[string]TraceMaps)
	}

	if metadata.Structs == nil {
		metadata.Structs = make(map[string]Struct)
	}

	metadata.TraceMaps[traceMap.Name] = TraceMaps{
		StructName: traceMapStruct.Name,
	}

	gadgetStruct := metadata.Structs[traceMapStruct.Name]
	existingFields := make(map[string]struct{})
	for _, field := range gadgetStruct.Fields {
		existingFields[field.Name] = struct{}{}
	}

	for _, member := range traceMapStruct.Members {
		// skip some specific members
		if member.Name == "timestamp" {
			log.Debug("Ignoring timestamp column: see https://github.com/inspektor-gadget/inspektor-gadget/issues/2000")
			continue
		}
		// TODO: temporary disable mount ns as it'll be duplicated otherwise
		if member.Type.TypeName() == gadgets.MntNsIdTypeName {
			continue
		}

		// check if column already exists
		if _, ok := existingFields[member.Name]; ok {
			log.Debugf("Column %s already exists, skipping", member.Name)
			continue
		}

		log.Debugf("Adding column %s", member.Name)
		field := Field{
			Name:        member.Name,
			Description: "TODO: Fill field description",
			Attributes: FieldAttributes{
				Width:     16,
				Alignment: AlignmentLeft,
				Ellipsis:  EllipsisEnd,
			},
		}

		gadgetStruct.Fields = append(gadgetStruct.Fields, field)
	}

	metadata.Structs[traceMapStruct.Name] = gadgetStruct

	return nil
}

// Printer is implemented by objects that can print information, like frontends.
type Printer interface {
	Output(payload string)
	Logf(severity logger.Level, fmt string, params ...any)
}

// RunGadgetDesc represents the different methods implemented by the run gadget descriptor.
type RunGadgetDesc interface {
	GetGadgetInfo(params *params.Params, args []string) (*GadgetInfo, error)
	CustomParser(info *GadgetInfo) (parser.Parser, error)
	JSONConverter(info *GadgetInfo, p Printer) func(ev any)
	JSONPrettyConverter(info *GadgetInfo, p Printer) func(ev any)
	YAMLConverter(info *GadgetInfo, p Printer) func(ev any)
}
