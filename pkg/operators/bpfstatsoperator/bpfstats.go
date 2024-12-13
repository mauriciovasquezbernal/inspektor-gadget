// Copyright 2024 The Inspektor Gadget authors
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

package bpfstatsoperator

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/bpfstats"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type bpfStatsOperator struct {
}

func (s *bpfStatsOperator) Name() string {
	return "bpfstats"
}

func (s *bpfStatsOperator) Init(params *params.Params) error {
	// when to disable it?
	if err := bpfstats.EnableBPFStats(); err != nil {
		return err
	}

	return nil
}

func (s *bpfStatsOperator) GlobalParams() api.Params {
	// TODO: enable stats params
	return nil
}

func (s *bpfStatsOperator) InstanceParams() api.Params {
	return nil
}

type bpfStatsOperatorInstance struct {
	ds datasource.DataSource

	progIDField       datasource.FieldAccessor
	progNameField     datasource.FieldAccessor
	progRuntimeField  datasource.FieldAccessor
	progRuncountField datasource.FieldAccessor
	mapMemoryField    datasource.FieldAccessor
	mapCountField     datasource.FieldAccessor
}

func (s *bpfStatsOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	// TODO: enable this conditionally in a smarter way
	if gadgetCtx.ImageName() != "bpfstats" {
		return nil, nil
	}

	var err error

	instance := &bpfStatsOperatorInstance{}

	instance.ds, err = gadgetCtx.RegisterDataSource(datasource.TypeArray, "bpfstats")
	if err != nil {
		return nil, err
	}

	instance.ds.AddAnnotation("fetch-interval", "5s")
	instance.ds.AddAnnotation("cli.clear-screen-before", "true")

	instance.progIDField, err = instance.ds.AddField("progID", api.Kind_Uint32, datasource.WithTags("type:ebpfprogid"))
	if err != nil {
		return nil, err
	}
	instance.progNameField, err = instance.ds.AddField("progName", api.Kind_String)
	if err != nil {
		return nil, err
	}
	instance.progRuntimeField, err = instance.ds.AddField("progRuntime", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}
	instance.progRuncountField, err = instance.ds.AddField("progRuncount", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}
	instance.mapMemoryField, err = instance.ds.AddField("mapMemory", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}
	instance.mapCountField, err = instance.ds.AddField("mapCount", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (s *bpfStatsOperator) Priority() int {
	// needs to be run before the ebpf operator
	return -1000
}

func (s *bpfStatsOperatorInstance) Name() string {
	return "bpfstats"
}

func (s *bpfStatsOperatorInstance) emitStats(gadgetCtx operators.GadgetContext) error {
	curID := ebpf.ProgramID(0)
	var nextID ebpf.ProgramID
	var err error

	arr, err := s.ds.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating new packet: %w", err)
	}

	mapSizes, err := bpfstats.GetMapsMemUsage()
	if err != nil {
		return fmt.Errorf("getting map memory usage: %w", err)
	}

	for {
		nextID, err = ebpf.ProgramGetNextID(curID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return fmt.Errorf("getting next program ID: %w", err)
		}
		if nextID <= curID {
			break
		}
		curID = nextID
		prog, err := ebpf.NewProgramFromID(curID)
		if err != nil {
			continue
		}
		pi, err := prog.Info()
		if err != nil {
			prog.Close()
			continue
		}

		d := arr.New()

		id, _ := pi.ID()
		runtime, _ := pi.Runtime()
		runcount, _ := pi.RunCount()
		mapIDs, _ := pi.MapIDs()
		totalMemory := uint64(0)
		for _, mapID := range mapIDs {
			totalMemory += mapSizes[mapID]
		}

		s.progIDField.PutUint32(d, uint32(id))
		s.progNameField.PutString(d, pi.Name)
		s.progRuntimeField.PutUint64(d, uint64(runtime))
		s.progRuncountField.PutUint64(d, uint64(runcount))
		s.mapMemoryField.PutUint64(d, totalMemory)
		s.mapCountField.PutUint64(d, uint64(len(mapIDs)))

		arr.Append(d)

		prog.Close()
	}

	s.ds.EmitAndRelease(arr)

	return nil
}

func (s *bpfStatsOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	go func() {
		for {
			time.Sleep(5 * time.Second)
			if err := s.emitStats(gadgetCtx); err != nil {
				gadgetCtx.Logger().Errorf("Failed to emit stats: %v",
					err)
			}
		}
	}()

	return nil
}

func (s *bpfStatsOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.RegisterDataOperator(&bpfStatsOperator{})
}
