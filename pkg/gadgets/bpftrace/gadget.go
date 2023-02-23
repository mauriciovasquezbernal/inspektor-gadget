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
	"encoding/json"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamProgram = "program"
)

type event struct {
	Output string `json:"output"`
}

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "bpftrace"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryNone
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "run a bpftrace program"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ParamProgram,
			Title:       "program",
			Alias:       "e",
			Description: "program to run",
			TypeHint:    params.TypeString,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return nil
}

func (g *GadgetDesc) EventPrototype() any {
	return &event{}
}

func (g *GadgetDesc) OutputFormats() (gadgets.OutputFormats, string) {
	return gadgets.OutputFormats{
		"text": gadgets.OutputFormat{
			Name:        "Text",
			Description: "The output of the gadget is returned as raw text",
			Transform: func(data []byte) ([]byte, error) {
				var ev event

				if err := json.Unmarshal(data, &ev); err != nil {
					return nil, err
				}

				return []byte(ev.Output), nil
			},
		},
	}, "text"
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
