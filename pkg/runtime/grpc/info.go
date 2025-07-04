// Copyright 2023-2024 The Inspektor Gadget authors
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

package grpcruntime

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// InitDeployInfo loads the locally stored deploy info. If no deploy info is stored locally,
// it will try to fetch it from one of the remotes and store it locally. It will issue warnings on
// failures.
func (r *Runtime) InitDeployInfo() (*deployinfo.DeployInfo, error) {
	// Initialize info
	info, err := deployinfo.Load()
	if err == nil {
		r.info = info
		return info, nil
	}

	info, err = r.loadRemoteDeployInfo()
	if err != nil {
		return nil, fmt.Errorf("loading gadget info from remote: %w", err)
	}

	r.info = info

	err = deployinfo.Store(info)
	if err != nil {
		return nil, fmt.Errorf("storing gadget info: %w", err)
	}

	return info, nil
}

func (r *Runtime) UpdateDeployInfo() error {
	info, err := r.loadRemoteDeployInfo()
	if err != nil {
		return fmt.Errorf("loading remote gadget info: %w", err)
	}

	return deployinfo.Store(info)
}

func (r *Runtime) loadRemoteDeployInfo() (*deployinfo.DeployInfo, error) {
	duration := r.globalParams.Get(ParamConnectionTimeout).AsUint()
	if duration > math.MaxInt64 {
		return nil, fmt.Errorf("duration (%d) exceeds math.MaxInt64 (%d)", duration, math.MaxInt64)
	}
	timeout := time.Second * time.Duration(duration)
	ctx, cancelDial := context.WithTimeout(context.Background(), timeout)
	defer cancelDial()

	// use default params for now
	params := r.ParamDescs().ToParams()
	conn, err := r.getConnToRandomTarget(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("dialing random target: %w", err)
	}
	defer conn.Close()
	client := api.NewBuiltInGadgetManagerClient(conn)

	info, err := client.GetInfo(ctx, &api.InfoRequest{Version: "1.0"})
	if err != nil {
		return nil, fmt.Errorf("get info from gadget pod: %w", err)
	}

	retInfo := &deployinfo.DeployInfo{
		Experimental:  info.Experimental,
		ServerVersion: info.ServerVersion,
	}
	return retInfo, nil
}
