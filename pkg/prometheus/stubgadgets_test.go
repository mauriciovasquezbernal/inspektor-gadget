package prometheus

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type key string

const (
	valuekey key = "pkey"
)

type stubTracerEvent struct {
	Comm     string  `json:"comm,omitempty" column:"comm"`
	Uid      uint32  `json:"uid,omitempty" column:"uid"`
	IntVal   uint32  `json:"intval,omitempty" column:"intval"`
	FloatVal float32 `json:"floatval,omitempty" column:"floatval"`
}

/*** stub tracer ***/
type stubTracer struct {
	eventCallback func(ev *stubTracerEvent)
}

func (t *stubTracer) Name() string {
	return "stubtracer"
}

func (t *stubTracer) Description() string {
	return "fake tracer gadget"
}

func (t *stubTracer) Category() string {
	return gadgets.CategoryTrace
}

func (t *stubTracer) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (t *stubTracer) ParamDescs() params.ParamDescs {
	return nil
}

func (t *stubTracer) Parser() parser.Parser {
	cols := columns.MustCreateColumns[stubTracerEvent]()
	return parser.NewParser(cols)
}

func (t *stubTracer) EventPrototype() any {
	return &stubTracerEvent{}
}

func (t *stubTracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *stubTracerEvent))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *stubTracer) Run(gadgetCtx gadgets.GadgetContext) error {
	for _, ev := range testEvents {
		t.eventCallback(&ev)
	}

	ctx := gadgetCtx.Context()

	// Tell the caller test that events were generated
	if val := ctx.Value(valuekey); val != nil {
		p := val.(chan (struct{}))
		close(p)
	}

	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (g *stubTracer) NewInstance() (gadgets.Gadget, error) {
	// TODO: this can be highly confusing!
	return &stubTracer{}, nil
}

/*** stub snapshotter ***/
type stubSnapshotter struct {
	eventCallback func(ev *stubTracerEvent)
}

func (t *stubSnapshotter) Name() string {
	return "stubsnapshotter"
}

func (t *stubSnapshotter) Description() string {
	return "fake snapshotter gadget"
}

func (t *stubSnapshotter) Category() string {
	return gadgets.CategorySnapshot
}

func (t *stubSnapshotter) Type() gadgets.GadgetType {
	return gadgets.TypeOneShot
}

func (t *stubSnapshotter) ParamDescs() params.ParamDescs {
	return nil
}

func (t *stubSnapshotter) Parser() parser.Parser {
	cols := columns.MustCreateColumns[stubTracerEvent]()
	return parser.NewParser(cols)
}

func (t *stubSnapshotter) EventPrototype() any {
	return &stubTracerEvent{}
}

func (t *stubSnapshotter) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *stubTracerEvent))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *stubSnapshotter) Run(gadgetCtx gadgets.GadgetContext) error {
	ctx := gadgetCtx.Context()

	// Save pointer to this instance in context passed from above. This allows the test to have
	// a reference to the gadget to be able to generate events.
	if val := ctx.Value(valuekey); val != nil {
		p := val.(chan (*stubSnapshotter))
		p <- t
	}

	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (g *stubSnapshotter) NewInstance() (gadgets.Gadget, error) {
	// TODO: this can be highly confusing!
	return &stubTracer{}, nil
}

func init() {
	gadgetregistry.Register(&stubTracer{})
	gadgetregistry.Register(&stubSnapshotter{})
}
