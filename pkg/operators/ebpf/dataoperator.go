package ebpfoperator

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/bpfstats"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// data operator methods

func (i *ebpfOperator) GlobalParams() api.Params {
	return nil
}

func (i *ebpfOperator) Init(params *params.Params) error {
	return nil
}

func (i *ebpfOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	var err error

	fmt.Printf("ebpfOperator.InstantiateDataOperator\n")

	for _, ds := range gadgetCtx.GetDataSources() {
		fmt.Printf("ebpfOperator.InstantiateDataOperator: datasource %s\n", ds.Name())
		fmt.Printf("annotations is: %v\n", ds.Annotations())

		// TODO: it doesn't work, is there a race condition?
		//if ds.Annotations()["operator.ebpfstats.datsourceregistered"] != "true" {
		//	fmt.Printf("ebpfOperator.InstantiateDataOperator: datasource %s not registered by ebpfstats\n", ds.Name())
		//	continue
		//}

		progIDFields := ds.GetFieldsWithTag("type:ebpfprogid")
		if len(progIDFields) == 0 {
			continue
		}

		instance := &ebpfOperatorDataInstance{
			bpfOperator: i,
			ds:          ds,
		}
		instance.progIDField = progIDFields[0]
		instance.gadgetIDField, err = ds.AddField("gadgetID", api.Kind_String)
		if err != nil {
			return nil, err
		}
		instance.gadgetNameField, err = ds.AddField("gadgetName", api.Kind_String)
		if err != nil {
			return nil, err
		}
		instance.gadgetImageField, err = ds.AddField("gadgetImage", api.Kind_String)
		if err != nil {
			return nil, err
		}

		return instance, nil
	}

	fmt.Printf("ebpfOperator.InstantiateDataOperator: no ebpfstats datasource found\n")

	return nil, nil
}

func (i *ebpfOperator) InstanceParams() api.Params {
	return nil
}

func (i *ebpfOperator) Priority() int {
	return 0
}

type ebpfOperatorDataInstance struct {
	bpfOperator *ebpfOperator
	ds          datasource.DataSource

	// filled by the ebpfstats operator
	progIDField datasource.FieldAccessor

	// filled by this operator
	gadgetImageField datasource.FieldAccessor
	gadgetIDField    datasource.FieldAccessor
	gadgetNameField  datasource.FieldAccessor
}

func (i *ebpfOperatorDataInstance) Name() string {
	return "ebpfdataoperator"
}

func (i *ebpfOperatorDataInstance) Start(gadgetCtx operators.GadgetContext) error {
	err := i.ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		fmt.Print("subscribe called\n")

		progID, err := i.progIDField.Uint32(data)
		if err != nil {
			return err
		}

		ctx, ok := i.bpfOperator.gadgetContexts[ebpf.ProgramID(progID)]
		if !ok {
			fmt.Printf("ebpfOperatorDataInstance: no context found for progID %d\n", progID)
			return nil
		}

		i.gadgetIDField.PutString(data, ctx.ID())
		i.gadgetNameField.PutString(data, "TODO" /*ctx.Name()*/)
		i.gadgetImageField.PutString(data, ctx.ImageName())

		return nil
	}, 0)
	if err != nil {
		return err
	}

	runtimeField := i.ds.GetField("progRuntime")
	runcountField := i.ds.GetField("progRuncount")
	mapMemoryField := i.ds.GetField("mapMemory")
	mapCountField := i.ds.GetField("mapCount")

	err = i.ds.SubscribeArray(func(ds datasource.DataSource, arr datasource.DataArray) error {
		fmt.Print("subscribearray called\n")

		for ctx, ids := range i.bpfOperator.programIDs {
			d := arr.New()

			i.gadgetIDField.PutString(d, ctx.ID())
			i.gadgetImageField.PutString(d, ctx.ImageName())
			i.gadgetNameField.PutString(d, "TODO" /*ctx.Name()*/)

			totalRuntime := uint64(0)
			totalRuncount := uint64(0)

			for _, id := range ids {
				runtime, runcount, err := getProgStats(id)
				if err != nil {
					return err
				}

				totalRuntime += runtime
				totalRuncount += runcount
			}

			runtimeField.PutUint64(d, totalRuntime)
			runcountField.PutUint64(d, totalRuncount)

			mapIDs := i.bpfOperator.mapIDs[ctx]
			totalMemory := uint64(0)
			for _, mapID := range mapIDs {

				m, err := ebpf.NewMapFromID(mapID)
				if err != nil {
					return err
				}

				memoryUsage, err := bpfstats.GetMapMemUsage(m)
				if err != nil {
					m.Close()
					return err
				}

				totalMemory += memoryUsage
				m.Close()
			}

			mapMemoryField.PutUint64(d, totalMemory)
			mapCountField.PutUint64(d, uint64(len(mapIDs)))

			arr.Append(d)
		}

		return nil
	}, 0)
	if err != nil {
		return err
	}

	return nil
}

func getProgStats(id ebpf.ProgramID) (uint64, uint64, error) {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return 0, 0, err
	}

	pi, err := prog.Info()
	if err != nil {
		prog.Close()
		return 0, 0, err
	}

	runtime, _ := pi.Runtime()
	runcount, _ := pi.RunCount()
	return uint64(runtime), uint64(runcount), nil
}

func (i *ebpfOperatorDataInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}
