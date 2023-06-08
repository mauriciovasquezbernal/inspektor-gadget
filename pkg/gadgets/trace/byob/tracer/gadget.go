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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/solo-io/bumblebee/pkg/decoder"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/byob/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamOCIImage        = "oci-image"
	ProgramContent       = "prog"
	GadgetDefinition     = "definition"
	ColumnsFormatSection = "columns_format"
	PrintMapPrefix       = "print_"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "byob"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryTrace
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "Trace with your own BPF program"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamOCIImage,
			Title:        "OCI Image",
			DefaultValue: "",
			Description:  "Name of the OCI image containing the BPF program",
			TypeHint:     params.TypeString,
		},
		{
			Key:          ProgramContent,
			Title:        "eBPF program",
			DefaultValue: "",
			Description:  "The compiled eBPF program. Prepend an @ in front of the path to input a file",
			TypeHint:     params.TypeBytes,
		},
		{
			Key:          GadgetDefinition,
			Title:        "Gadget definition",
			DefaultValue: "",
			Description:  "TODO",
			TypeHint:     params.TypeBytes,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func getValueStructBTF(progContent []byte) *btf.Struct {
	progReader := bytes.NewReader(progContent)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil
	}

	var valueStruct *btf.Struct

	for _, m := range spec.Maps {
		if m.Type != ebpf.RingBuf && m.Type != ebpf.PerfEventArray {
			continue
		}

		if !strings.HasPrefix(m.Name, PrintMapPrefix) {
			continue
		}

		var ok bool
		valueStruct, ok = m.Value.(*btf.Struct)
		if !ok {
			return nil
		}

		return valueStruct
	}

	return valueStruct
}

func (g *GadgetDesc) CustomParser(params *params.Params) parser.Parser {
	decoderFactory := decoder.NewDecoderFactory()()

	// TODO: add support for OCI programs
	progContent := params.Get(ProgramContent).AsBytes()
	definitionBytes := params.Get(GadgetDefinition).AsBytes()
	if len(definitionBytes) == 0 {
		return g.Parser()
	}

	valueStruct := getValueStructBTF(progContent)
	if valueStruct == nil {
		return g.Parser()
	}

	cols := types.GetColumns()
	ctx := context.TODO()

	var gadgetDefinition types.GadgetDefinition

	if err := yaml.Unmarshal(definitionBytes, &gadgetDefinition); err != nil {
		return g.Parser()
	}

	colAttrs := map[string]columns.Attributes{}
	for _, col := range gadgetDefinition.ColumnsAttrs {
		colAttrs[col.Name] = col
	}

	// TODO: This can be a generic helper that is used by other gadgets as well
	for _, member := range valueStruct.Members {
		member := member

		attrs, ok := colAttrs[member.Name]
		if !ok {
			continue
		}

		extractor := func(event *types.Event) string {
			bytes := event.RawData[member.Offset.Bytes():]

			// TODO: call processSingleType directly?
			result, err := decoderFactory.DecodeBtfBinary(ctx, member.Type, bytes)
			if err != nil {
				fmt.Printf("error decoding %q: %s\n", member.Name, err)
				return ""
			}

			return fmt.Sprintf("%v", result[""])
		}
		err := cols.AddColumn(attrs, extractor)
		if err != nil {
			//logger.Log.Errorf("error adding column: %v", err)
			return g.Parser()
		}
	}

	return parser.NewParser[types.Event](cols)
}

func (g *GadgetDesc) JsonConverter(params *params.Params, fe frontends.Frontend) func(ev any) {
	decoderFactory := decoder.NewDecoderFactory()()

	// TODO: add support for OCI programs
	progContent := params.Get(ProgramContent).AsBytes()

	valueStruct := getValueStructBTF(progContent)
	if valueStruct == nil {
		return nil
	}

	ctx := context.TODO()

	return func(ev any) {
		event := ev.(*types.Event)

		result, err := decoderFactory.DecodeBtfBinary(ctx, valueStruct, event.RawData)
		if err != nil {
			fe.Logf(logger.WarnLevel, "decoding %+v: %s", ev, err)
			return
		}

		// TODO: flatten the results?
		event.Data = result

		d, err := json.Marshal(event)
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshalling %+v: %s", ev, err)
			return
		}
		fe.Output(string(d))
	}
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
