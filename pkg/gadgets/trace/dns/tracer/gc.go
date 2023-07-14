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
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// Delay between each garbage collection run.
const garbageCollectorInterval = 1 * time.Second

// startGarbageCollector runs a background goroutine to delete old query timestamps
// from the DNS query_map. This ensures that queries that never receive a response
// are deleted from the map.
//
// The garbage collector goroutine terminates when the context is done.
func startGarbageCollector(ctx context.Context, logger logger.Logger, gadgetParams *params.Params, queryMap *ebpf.Map) error {
	dnsTimeout := gadgetParams.Get(ParamDNSTimeout).AsDuration()
	if dnsTimeout <= 0 {
		return fmt.Errorf("DNS timeout must be > 0")
	}

	logger.Debugf("starting garbage collection for DNS tracer with dnsTimeout %s", dnsTimeout)
	go func() {
		ticker := time.NewTicker(garbageCollectorInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Debugf("stopping garbage collection for DNS tracer")
				return

			case <-ticker.C:
				logger.Debugf("executing DNS query map garbage collection")
				collectGarbage(logger, dnsTimeout, queryMap)
			}
		}
	}()

	return nil
}

func collectGarbage(logger logger.Logger, dnsTimeout time.Duration, queryMap *ebpf.Map) {
	var (
		key          dnsQueryKeyT
		val          dnsQueryTsT
		keysToDelete []dnsQueryKeyT
	)
	cutoffTs := types.Time(time.Now().Add(-1 * dnsTimeout).UnixNano())
	iter := queryMap.Iterate()

	// If the BPF program is deleting keys from the map during iteration,
	// we may see duplicate keys or stop without processing some keys (ErrIterationAborted).
	// Duplicate keys are okay since we handle ErrKeyNotExists on delete,
	// and ErrIterationAborted is okay because we'll retry on the next garbage collection.
	for iter.Next(&key, &val) {
		ts := gadgets.WallTimeFromBootTime(val.Timestamp)
		if ts < cutoffTs {
			keysToDelete = append(keysToDelete, key)
		}
	}

	if err := iter.Err(); err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			logger.Warnf("received ErrIterationAborted when iterating through DNS query map, possibly due to concurrent deletes. Some entries may be skipped this garbage collection cycle.")
		} else {
			logger.Errorf("received err %s when iterating through DNS query map", err)
		}
	}

	for _, key := range keysToDelete {
		logger.Debugf("deleting key with mntNs=%d and DNS ID=%x from query map for DNS tracer", key.MountNsId, key.Id)
		err := queryMap.Delete(key)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				// Could happen if the BPF program deleted the key, or if the map iter returned a duplicate key
				// due to concurrent write operations.
				logger.Debugf("ErrKeyNotExist when trying to delete DNS query timestamp with key mntNs=%d and DNS ID=%x", key.MountNsId, key.Id)
			} else {
				logger.Errorf("could not delete DNS query timestamp with key mntNs=%d and DNS ID=%x, err: %s", key.MountNsId, key.Id, err)
			}
		}
	}
}
