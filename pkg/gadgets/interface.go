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

package gadgets

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

// GadgetType defines how a gadget is actually run
type GadgetType string

const (
	TypeTrace          GadgetType = "trace"          // Normal trace gadgets
	TypeTraceIntervals GadgetType = "traceIntervals" // top gadgets expecting arrays of events
	TypeOneShot        GadgetType = "oneShot"        // Gadgets that only fetch results
	TypeProfile        GadgetType = "profile"        // Gadgets that run until the user stops, or it times out and then shows results
)

func (t GadgetType) CanSort() bool {
	return t == TypeOneShot || t == TypeTraceIntervals
}

func (t GadgetType) IsPeriodic() bool {
	return t == TypeTraceIntervals
}

// GadgetDesc is the main interface for handling gadgets
type GadgetDesc interface {
	// Name provides the name of the gadget. This is used for the calling the gadget, auto-creating the cobra commands,
	// logging, etc.
	Name() string

	// Description provides a short description of the gadget. This is used for a quick help in cobra, help,
	// web-interface etc.
	Description() string

	// Category is used for cobra sub-commands and categories on the web interface.
	Category() string

	// Type is used to differentiate between how gadgets are run. The type essentially controls the workflow of the
	// gadget.
	Type() GadgetType

	// ParamDescs returns a map of configuration parameters. These hold also default values, descriptions, validators and
	// so on. Used whenever a gadget is called somehow. Auto-creates parameters for cobra as well.
	ParamDescs() params.ParamDescs

	// Parser returns a parser.Parser instance that can handle events and do certain operations on them
	// (sorting, filtering, etc.) without the caller needing to know about the underlying types.
	Parser() parser.Parser

	// EventPrototype returns a blank event. Useful for checking for interfaces on it (see operators).
	EventPrototype() any
}

type OutputFormats map[string]OutputFormat

// OutputFormat can hold alternative output formats for a gadget. Whenever
// such a format is used, the result of the gadget will be passed to the Transform()
// function and returned to the user.
type OutputFormat struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Transform   func([]byte) ([]byte, error)
}

// Append appends the OutputFormats given in other to of
func (of OutputFormats) Append(other OutputFormats) {
	for k, v := range other {
		of[k] = v
	}
}

// GadgetOutputFormats can be implemented together with the gadget interface
// to register alternative output formats that are used in combination with
// the GadgetResult interface. The defaultFormatKey MUST match the key of
// an entry in the supportedFormats map
type GadgetOutputFormats interface {
	OutputFormats() (supportedFormats OutputFormats, defaultFormatKey string)
}

type EventHandlerSetter interface {
	SetEventHandler(handler any)
}

type EventHandlerArraySetter interface {
	SetEventHandlerArray(handler any)
}

type EventEnricherSetter interface {
	SetEventEnricher(func(ev any) error)
}

// RunGadget runs a gadget and emits events using the EventHandler. The Run
// method is expected to be blocking and return only when the context is done,
// after which the gadget should clean up all resources.
type RunGadget interface {
	Run(GadgetContext) error
}

// RunWithResultGadget is an alternative to RunGadget that returns the result
// of the gadget instead of emitting events.
type RunWithResultGadget interface {
	RunWithResult(GadgetContext) ([]byte, error)
}

// InitRunClose is used when gadgets need to be initialized before the operators
// are installed. This could be useful when operators need to interact with the
// gadget during PreGadgetRun(). Notice Init is not blocking but it returns
// immediately after initializing the gadget. Run() must be called to wait for
// the gadget to run, and Close() to clean up things.
type InitRunClose interface {
	RunGadget
	Init(GadgetContext) error
	Close()
}

type Gadget interface{}

// GadgetInstantiate is the same interface as Gadget but adds one call to instantiate an actual
// tracer
type GadgetInstantiate interface {
	GadgetDesc

	// NewInstance creates a new gadget and returns it; the tracer should be allocated and configured but
	// should not run any code that depends on cleanup
	NewInstance() (Gadget, error)
}
