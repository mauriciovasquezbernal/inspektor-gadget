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
	"errors"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// Delay between each garbage collection run.
const garbageCollectorInterval = 1 * time.Second

// garbageCollector runs a background goroutine to delete old query timestamps
// from the DNS query_map. This ensures that queries that never receive a response
// are deleted from the map.
type garbageCollector struct {
	started     bool
	doneChan    chan struct{}
	logger      logger.Logger
	queryMap    *ebpf.Map
	queryMaxAge time.Duration
}

func newGarbageCollector(gadgetCtx gadgets.GadgetContext, queryMap *ebpf.Map, queryMaxAge time.Duration) *garbageCollector {
	return &garbageCollector{
		logger:      gadgetCtx.Logger(),
		queryMap:    queryMap,
		queryMaxAge: queryMaxAge,
	}
}

func (gc *garbageCollector) start() {
	if gc.started {
		gc.logger.Warn("Cannot start DNS queries map garbage collector because it is already running")
		return
	}

	gc.logger.Debugf("Starting garbage collection for DNS tracer with queryMaxAge %s", gc.queryMaxAge)
	gc.doneChan = make(chan struct{}, 0)
	go gc.runLoop()
	gc.started = true
}

func (gc *garbageCollector) stop() {
	if !gc.started {
		gc.logger.Warn("Cannot stop log queries map garbage collector because it isn't running")
		return
	}

	gc.logger.Debugf("Stopping garbage collection for DNS tracer")
	close(gc.doneChan)
	gc.started = false
}

func (gc *garbageCollector) runLoop() {
	ticker := time.NewTicker(garbageCollectorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-gc.doneChan:
			return

		case <-ticker.C:
			gc.logger.Debugf("Executing DNS query map garbage collection")
			gc.collect()
		}
	}
}

func (gc *garbageCollector) collect() {
	var (
		key          dnsQueryKeyT
		val          dnsQueryTsT
		keysToDelete []dnsQueryKeyT
	)
	cutoffTs := types.Time(time.Now().Add(-1 * gc.queryMaxAge).UnixNano())
	iter := gc.queryMap.Iterate()

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
			gc.logger.Warnf("Received ErrIterationAborted when iterating through DNS query map, possibly due to concurrent deletes. Some entries may be skipped this garbage collection cycle.")
		} else {
			gc.logger.Errorf("Received err %s when iterating through DNS query map", err)
		}
	}

	for _, key := range keysToDelete {
		gc.logger.Debugf("Deleting key with mntNs=%d and DNS ID=%x from query map for DNS tracer", key.MountNsId, key.Id)
		err := gc.queryMap.Delete(key)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				// Could happen if the BPF program deleted the key, or if the map iter returned a duplicate key
				// due to concurrent write operations.
				gc.logger.Debugf("ErrKeyNotExist when trying to delete DNS query timestamp with key mntNs=%d and DNS ID=%x", key.MountNsId, key.Id)
			} else {
				gc.logger.Errorf("Could not delete DNS query timestamp with key mntNs=%d and DNS ID=%x, err: %s", key.MountNsId, key.Id, err)
			}
		}
	}
}
