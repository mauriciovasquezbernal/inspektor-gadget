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

package local

import (
	"errors"
	"fmt"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type Runtime struct {
	catalog *runtime.Catalog
}

func New() *Runtime {
	r := &Runtime{}
	r.prepareCatalog()
	return r
}

func (r *Runtime) prepareCatalog() {
	gadgetInfos := make([]*runtime.GadgetInfo, 0)
	for _, gadgetDesc := range gadgetregistry.GetAll() {
		gadgetInfos = append(gadgetInfos, runtime.GadgetInfoFromGadgetDesc(gadgetDesc))
	}
	operatorInfos := make([]*runtime.OperatorInfo, 0)
	for _, operator := range operators.GetAll() {
		operatorInfos = append(operatorInfos, runtime.OperatorToOperatorInfo(operator))
	}
	r.catalog = &runtime.Catalog{
		Gadgets:   gadgetInfos,
		Operators: operatorInfos,
	}
}

func (r *Runtime) Init(globalRuntimeParams *params.Params) error {
	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) RunGadget(gadgetCtx runtime.GadgetContext) (out map[string][]byte, err error) {
	log := gadgetCtx.Logger()

	log.Debugf("running with local runtime")

	gadget, ok := gadgetCtx.GadgetDesc().(gadgets.GadgetInstantiate)
	if !ok {
		return nil, errors.New("gadget not instantiable")
	}

	operatorsParamCollection := gadgetCtx.OperatorsParamCollection()

	// Create gadget instance
	gadgetInstance, err := gadget.NewInstance()
	if err != nil {
		return out, fmt.Errorf("instantiating gadget: %w", err)
	}

	err = gadgetInstance.Init(gadgetCtx)
	if err != nil {
		return out, fmt.Errorf("initializing gadget: %w", err)
	}

	// Deferring getting results and closing to make sure operators got their chance to clean up properly beforehand
	defer func() {
		if closer, ok := gadgetInstance.(gadgets.CloseGadget); ok {
			log.Debugf("calling gadget.Close()")
			closer.Close()
		}

		// No need to get results if gadget failed
		if err != nil {
			return
		}

		if results, ok := gadgetInstance.(gadgets.GadgetResult); ok {
			log.Debugf("getting result")
			res, tmpErr := results.Result()
			if tmpErr != nil {
				err = fmt.Errorf("getting result: %w", tmpErr)
			}
			out = map[string][]byte{"": res}
		}
	}()

	// Install operators
	operatorInstances, err := gadgetCtx.Operators().Instantiate(gadgetCtx, gadgetInstance, operatorsParamCollection)
	if err != nil {
		return out, fmt.Errorf("instantiating operators: %w", err)
	}
	log.Debugf("found %d operators", len(gadgetCtx.Operators()))

	// Set event handler
	if setter, ok := gadgetInstance.(gadgets.EventHandlerSetter); ok {
		log.Debugf("set event handler")
		if parser := gadgetCtx.Parser(); parser != nil {
			setter.SetEventHandler(parser.EventHandlerFunc(operatorInstances.Enrich))
		} else {
			setter.SetEventHandler(gadgetCtx.EventHandler())
		}
	}

	// Set event handler for array results
	if setter, ok := gadgetInstance.(gadgets.EventHandlerArraySetter); ok {
		log.Debugf("set event handler for arrays")
		setter.SetEventHandlerArray(gadgetCtx.Parser().EventHandlerFuncArray(operatorInstances.Enrich))
	}

	// Set event enricher (currently only used by profile/cpu)
	if setter, ok := gadgetInstance.(gadgets.EventEnricherSetter); ok {
		log.Debugf("set event enricher")
		setter.SetEventEnricher(operatorInstances.Enrich)
	}

	err = operatorInstances.PreGadgetRun()
	if err != nil {
		return nil, fmt.Errorf("gadget prerun: %w", err)
	}
	defer operatorInstances.PostGadgetRun()

	if startstop, ok := gadgetInstance.(gadgets.StartStopAltGadget); ok {
		log.Debugf("calling gadget.StartAlt()")
		err := startstop.StartAlt()
		if err != nil {
			return out, fmt.Errorf("starting gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.StopAlt()")
			startstop.StopAlt()
		}()
	} else if startstop, ok := gadgetInstance.(gadgets.StartStopGadget); ok {
		log.Debugf("calling gadget.Start()")
		err := startstop.Start()
		if err != nil {
			return out, fmt.Errorf("starting gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.Stop()")
			startstop.Stop()
		}()
	} else if run, ok := gadgetInstance.(gadgets.RunGadget); ok {
		log.Debugf("calling gadget.Run()")
		err := run.Run()
		if err != nil {
			return out, fmt.Errorf("running gadget: %w", err)
		}
	}

	log.Debugf("running")

	if gadget.Type() != gadgets.TypeOneShot {
		// Wait for context to close
		<-gadgetCtx.Context().Done()
	}

	log.Debugf("stopping gadget")
	return out, nil
}

func (r *Runtime) GetCatalog() (*runtime.Catalog, error) {
	return r.catalog, nil
}
