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

package tracer

import (
	"fmt"
	"reflect"
	"unsafe"

	log "github.com/sirupsen/logrus"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	columns_json "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/json"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

const (
	validateMetadataParam = "validate-metadata"
	authfileParam         = "authfile"
	insecureParam         = "insecure"
	pullParam             = "pull"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "run"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryNone
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	// Placeholder for gadget type. The actual type is determined at runtime by using
	// GetGadgetInfo()
	return gadgets.TypeRun
}

func (g *GadgetDesc) Description() string {
	return "Run a containerized gadget"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		// Hardcoded for now
		{
			Key:          authfileParam,
			Title:        "Auth file",
			DefaultValue: oci.DefaultAuthFile,
			TypeHint:     params.TypeString,
		},
		{
			Key:          validateMetadataParam,
			Title:        "Validate metadata",
			Description:  "Validate the gadget metadata before running the gadget",
			DefaultValue: "true",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          insecureParam,
			Title:        "Insecure connection",
			Description:  "Allow connections to HTTP only registries",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          pullParam,
			Title:        "Pull policy",
			Description:  "Specify when the gadget image should be pulled",
			DefaultValue: oci.PullImageMissing,
			PossibleValues: []string{
				oci.PullImageAlways,
				oci.PullImageMissing,
				oci.PullImageNever,
			},
			TypeHint: params.TypeString,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return nil
}

func (g *GadgetDesc) GetGadgetInfo(params *params.Params, args []string) (*types.GadgetInfo, error) {
	return getGadgetInfo(params, args, log.StandardLogger())
}

func reflectTypeFromType(typ types.Type) reflect.Type {
	if typ.Size != 0 {
		arrType := simpleReflectTypeFromType(typ)
		if arrType == nil {
			return nil
		}
		return reflect.ArrayOf(typ.Size, arrType)
	}

	return simpleReflectTypeFromType(typ)
}

func simpleReflectTypeFromType(typ types.Type) reflect.Type {
	switch typ.Name {
	case "int8":
		return reflect.TypeOf(int8(0))
	case "int16":
		return reflect.TypeOf(int16(0))
	case "int32":
		return reflect.TypeOf(int32(0))
	case "int64":
		return reflect.TypeOf(int64(0))
	case "uint8":
		return reflect.TypeOf(uint8(0))
	case "uint16":
		return reflect.TypeOf(uint16(0))
	case "uint32":
		return reflect.TypeOf(uint32(0))
	case "uint64":
		return reflect.TypeOf(uint64(0))
	case "float32":
		return reflect.TypeOf(float32(0))
	case "float64":
		return reflect.TypeOf(float64(0))
	case "bool":
		return reflect.TypeOf(false)
	case "string":
		return reflect.TypeOf("")
	}

	return nil
}

func addL3EndpointColumns(
	cols *columns.Columns[types.Event],
	name string,
	getEndpoint func(*types.Event) eventtypes.L3Endpoint,
) {
	cols.AddColumn(columns.Attributes{
		Name:     name + ".namespace",
		Template: "namespace",
	}, func(e *types.Event) any {
		return getEndpoint(e).Namespace
	})

	cols.AddColumn(columns.Attributes{
		Name: name + ".name",
	}, func(e *types.Event) any {
		return getEndpoint(e).Name
	})

	cols.AddColumn(columns.Attributes{
		Name: name + ".kind",
	}, func(e *types.Event) any {
		return string(getEndpoint(e).Kind)
	})

	cols.AddColumn(columns.Attributes{
		Name:     name + ".addr",
		Template: "ipaddr",
	}, func(e *types.Event) any {
		return getEndpoint(e).Addr
	})

	cols.AddColumn(columns.Attributes{
		Name:     name + ".v",
		Template: "ipversion",
	}, func(e *types.Event) any {
		return getEndpoint(e).Version
	})
}

func addL4EndpointColumns(
	cols *columns.Columns[types.Event],
	name string,
	getEndpoint func(*types.Event) eventtypes.L4Endpoint,
) {
	addL3EndpointColumns(cols, name, func(e *types.Event) eventtypes.L3Endpoint {
		return getEndpoint(e).L3Endpoint
	})

	cols.AddColumn(columns.Attributes{
		Name:     name + ".port",
		Template: "ipport",
	}, func(e *types.Event) any {
		return getEndpoint(e).Port
	})

	cols.AddColumn(columns.Attributes{
		Name:  name + ".proto",
		Width: 6,
	}, func(e *types.Event) any {
		return gadgets.ProtoString(int(getEndpoint(e).Proto))
	})
}

func field2ColumnAttrs(field *types.Field) columns.Attributes {
	fieldAttrs := field.Attributes

	defaultOpts := columns.GetDefault()

	attrs := columns.Attributes{
		Name:         field.Name,
		Alignment:    defaultOpts.DefaultAlignment,
		EllipsisType: defaultOpts.DefaultEllipsis,
		Width:        defaultOpts.DefaultWidth,
		Visible:      !fieldAttrs.Hidden,
	}

	if fieldAttrs.Width != 0 {
		attrs.Width = int(fieldAttrs.Width)
	}
	if fieldAttrs.MinWidth != 0 {
		attrs.MinWidth = int(fieldAttrs.MinWidth)
	}
	if fieldAttrs.MaxWidth != 0 {
		attrs.MaxWidth = int(fieldAttrs.MaxWidth)
	}
	if fieldAttrs.Template != "" {
		attrs.Template = fieldAttrs.Template
	}

	switch fieldAttrs.Alignment {
	case types.AlignmentLeft:
		attrs.Alignment = columns.AlignLeft
	case types.AlignmentRight:
		attrs.Alignment = columns.AlignRight
	}

	switch fieldAttrs.Ellipsis {
	case types.EllipsisStart:
		attrs.EllipsisType = ellipsis.Start
	case types.EllipsisMiddle:
		attrs.EllipsisType = ellipsis.Middle
	case types.EllipsisEnd:
		attrs.EllipsisType = ellipsis.End
	}

	return attrs
}

func (g *GadgetDesc) getColumns(info *types.GadgetInfo) (*columns.Columns[types.Event], error) {

	_, eventStruct := getAnyMapElem(info.GadgetMetadata.Structs)
	if eventStruct == nil {
		return nil, fmt.Errorf("struct not found in gadget metadata")
	}

	cols := types.GetColumns()

	// Remove columns according to the features that the gadget supports.
	// TODO: what about attacher interface?
	for name, col := range cols.ColumnMap {
		if !info.Features.HasMountNs && name == "mntns" {
			delete(cols.ColumnMap, name)
		}

		if !info.Features.HasNetNs && name == "netns" {
			delete(cols.ColumnMap, name)
		}

		if !info.Features.HasMountNs && !info.Features.HasNetNs {
			for _, tag := range col.Tags {
				switch tag {
				case "kubernetes", "runtime":
					delete(cols.ColumnMap, name)
				}
			}
		}
	}

	ebpfFields := []columns.DynamicField{}
	blobFields := []columns.DynamicField{}

	l3endpointCounter := 0
	l4endpointCounter := 0
	timestampsCounter := 0

	fields := map[string]types.Field{}
	for _, field := range eventStruct.Fields {
		fields[field.Name] = field
	}

	for i, col := range info.Columns {
		field, ok := fields[col.Name]
		if !ok {
			continue
		}

		attrs := field2ColumnAttrs(&field)
		attrs.Order = 1000 + i

		switch col.Index {
		case -1:
			typeName := col.Type.Name
			switch typeName {
			case "l3endpoint":
				// Take the value here, otherwise it'll use the wrong value after
				// it's increased
				index := l3endpointCounter
				// Add the column that is enriched
				eventtypes.MustAddVirtualL3EndpointColumn(cols, attrs, func(e *types.Event) eventtypes.L3Endpoint {
					if len(e.L3Endpoints) == 0 {
						return eventtypes.L3Endpoint{}
					}
					return e.L3Endpoints[index].L3Endpoint
				})
				// Add a single column for each field in the endpoint
				addL3EndpointColumns(cols, col.Name, func(e *types.Event) eventtypes.L3Endpoint {
					if len(e.L3Endpoints) == 0 {
						return eventtypes.L3Endpoint{}
					}
					return e.L3Endpoints[index].L3Endpoint
				})
				l3endpointCounter++
			case "l4endpoint":
				// Take the value here, otherwise it'll use the wrong value after
				// it's increased
				index := l4endpointCounter
				// Add the column that is enriched
				eventtypes.MustAddVirtualL4EndpointColumn(cols, attrs, func(e *types.Event) eventtypes.L4Endpoint {
					if len(e.L4Endpoints) == 0 {
						return eventtypes.L4Endpoint{}
					}
					return e.L4Endpoints[index].L4Endpoint
				})
				// Add a single column for each field in the endpoint
				addL4EndpointColumns(cols, col.Name, func(e *types.Event) eventtypes.L4Endpoint {
					if len(e.L4Endpoints) == 0 {
						return eventtypes.L4Endpoint{}
					}
					return e.L4Endpoints[index].L4Endpoint
				})
				l4endpointCounter++
			case "timestamp":
				// Take the value here, otherwise it'll use the wrong value after
				// it's increased
				index := timestampsCounter
				err := cols.AddColumn(attrs, func(e *types.Event) any {
					if len(e.Timestamps) == 0 {
						return ""
					}
					return e.Timestamps[index].String()
				})
				if err != nil {
					return nil, fmt.Errorf("adding timestamp column: %w", err)
				}
				timestampsCounter++
				continue

			}
		case 0:
			field := columns.DynamicField{
				Attributes: &attrs,
				Template:   attrs.Template,
				Type:       reflectTypeFromType(col.Type),
				Offset:     uintptr(col.Offset),
			}

			ebpfFields = append(ebpfFields, field)
		case 1:
			field := columns.DynamicField{
				Attributes: &attrs,
				Template:   attrs.Template,
				Type:       reflectTypeFromType(col.Type),
				Offset:     uintptr(col.Offset),
			}
			blobFields = append(blobFields, field)
		default:
			//fmt.Printf("handling string %q wth index %d\n", col.Name, col.Index)
			index := col.Index
			cols.AddColumn(attrs, func(e *types.Event) any {
				if e.Blob == nil {
					return ""
				}

				return string(e.Blob[index])
			})
		}
	}

	ebpfBase := func(ev *types.Event) unsafe.Pointer {
		return unsafe.Pointer(&ev.Blob[0][0])
	}
	if err := cols.AddFields(ebpfFields, ebpfBase); err != nil {
		return nil, fmt.Errorf("adding fields: %w", err)
	}

	blobBase := func(ev *types.Event) unsafe.Pointer {
		return unsafe.Pointer(&ev.Blob[1][0])
	}
	if err := cols.AddFields(blobFields, blobBase); err != nil {
		return nil, fmt.Errorf("adding blob fields: %w", err)
	}

	return cols, nil
}

func (g *GadgetDesc) CustomParser(info *types.GadgetInfo) (parser.Parser, error) {
	cols, err := g.getColumns(info)
	if err != nil {
		return nil, fmt.Errorf("getting columns: %w", err)
	}

	return parser.NewParser[types.Event](cols), nil
}

func (g *GadgetDesc) customJsonParser(info *types.GadgetInfo, options ...columns_json.Option) (*columns_json.Formatter[types.Event], error) {
	cols, err := g.getColumns(info)
	if err != nil {
		return nil, err
	}
	return columns_json.NewFormatter(cols.ColumnMap, options...), nil
}

func jsonConverterFn(formatter *columns_json.Formatter[types.Event], printer types.Printer) func(ev any) {
	return func(ev any) {
		switch typ := ev.(type) {
		case *types.Event:
			printer.Output(formatter.FormatEntry(typ))
		case []*types.Event:
			printer.Output(formatter.FormatEntries(typ))
		default:
			printer.Logf(logger.WarnLevel, "unknown type: %T", typ)
		}
	}
}

func (g *GadgetDesc) JSONConverter(info *types.GadgetInfo, printer types.Printer) func(ev any) {
	formatter, err := g.customJsonParser(info)
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return jsonConverterFn(formatter, printer)
}

func (g *GadgetDesc) JSONPrettyConverter(info *types.GadgetInfo, printer types.Printer) func(ev any) {
	formatter, err := g.customJsonParser(info, columns_json.WithPrettyPrint())
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return jsonConverterFn(formatter, printer)
}

func (g *GadgetDesc) YAMLConverter(info *types.GadgetInfo, printer types.Printer) func(ev any) {
	formatter, err := g.customJsonParser(info)
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return func(ev any) {
		var eventJson string
		switch typ := ev.(type) {
		case *types.Event:
			eventJson = formatter.FormatEntry(typ)
		case []*types.Event:
			eventJson = formatter.FormatEntries(typ)
		default:
			printer.Logf(logger.WarnLevel, "unknown type: %T", typ)
			return
		}

		eventYaml, err := k8syaml.JSONToYAML([]byte(eventJson))
		if err != nil {
			printer.Logf(logger.WarnLevel, "converting json to yaml: %s", err)
			return
		}
		printer.Output(string(eventYaml))
	}
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func init() {
	if experimental.Enabled() {
		gadgetregistry.Register(&GadgetDesc{})
	}
}
