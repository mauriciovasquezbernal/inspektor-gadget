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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type Runtime struct{}

func (r *Runtime) Init(runtimeParams *params.Params) error {
	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) RunGadget(gadgetCtx runtime.GadgetContext) (out []byte, err error) {
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

	// Initialize gadgets, if needed
	if initRunClose, ok := gadgetInstance.(gadgets.InitRunClose); ok {
		log.Debugf("calling gadget.Init()")
		err = initRunClose.Init(gadgetCtx)
		if err != nil {
			return out, fmt.Errorf("running (early) gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.Close()")
			initRunClose.Close()
		}()
	}

	// Install operators
	operatorInstances, err := gadgetCtx.Operators().Instantiate(gadgetCtx, gadgetInstance, operatorsParamCollection)
	if err != nil {
		return out, fmt.Errorf("instantiating operators: %w", err)
	}
	log.Debugf("found %d operators", len(gadgetCtx.Operators()))

	// Set event handler
	if setter, ok := gadgetInstance.(gadgets.EventHandlerSetter); ok {
		log.Debugf("set event handler")
		setter.SetEventHandler(gadgetCtx.Parser().EventHandlerFunc(operatorInstances.Enrich))
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

	if run, ok := gadgetInstance.(gadgets.RunGadget); ok {
		log.Debugf("calling gadget.Run()")
		err := run.Run(gadgetCtx)
		if err != nil {
			return out, fmt.Errorf("running gadget: %w", err)
		}
	} else if runWithResult, ok := gadgetInstance.(gadgets.RunWithResultGadget); ok {
		log.Debugf("calling gadget.RunWithResult()")
		out, err = runWithResult.RunWithResult(gadgetCtx)
		if err != nil {
			return out, fmt.Errorf("running (with result) gadget: %w", err)
		}
	} else {
		return nil, errors.New("gadget not runnable")
	}

	return
}
