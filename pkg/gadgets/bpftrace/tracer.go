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

//go:build !withoutebpf

package tracer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type Config struct {
	Program string
}

type Tracer struct {
	eventCallback func([]byte)
	cmd           *exec.Cmd
	config        Config
	l             logger.Logger
}

func (t *Tracer) Start() error {
	t.cmd = exec.Command("bpftrace", "-e", t.config.Program)

	stdout, err := t.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("getting stdout pipe: %w", err)
	}

	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("running bpftrace: %w", err)
	}

	go func() {
		scanner := bufio.NewScanner(stdout)

		for scanner.Scan() {
			ev := event{
				Output: scanner.Text(),
			}

			bytes, err := json.Marshal(&ev)
			if err != nil {
				t.l.Warnf("Failed to marshal event %q: %s", ev, err)
				continue
			}
			t.eventCallback(bytes)
		}
	}()

	return nil
}

func (t *Tracer) Stop() {
	if err := t.cmd.Process.Signal(os.Interrupt); err != nil {
		t.l.Errorf("failed to stop process: %s", err)
		return
	}

	if err := t.cmd.Wait(); err != nil {
		t.l.Errorf("failed to wait process: %s", err)
		return
	}
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func([]byte))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.Program = params.Get(ParamProgram).AsString()
	t.l = gadgetCtx.Logger()
	return nil
}
