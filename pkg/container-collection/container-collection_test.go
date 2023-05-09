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

package containercollection

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type fakeTracerMapsUpdater struct {
	containers map[string]*Container
}

func (f *fakeTracerMapsUpdater) TracerMapsUpdater() FuncNotify {
	return func(event PubSubEvent) {
		switch event.Type {
		case EventTypeAddContainer:
			f.containers[event.Container.ID] = event.Container
		case EventTypeRemoveContainer:
			delete(f.containers, event.Container.ID)
		}
	}
}

func TestWithTracerCollection(t *testing.T) {
	t.Parallel()

	// We need root to create the runners that will act as containers on this test
	utilstest.RequireRoot(t)

	cc := ContainerCollection{}
	f := &fakeTracerMapsUpdater{containers: make(map[string]*Container)}

	if err := cc.Initialize(WithTracerCollection(f)); err != nil {
		t.Fatalf("Failed to initialize container collection: %s", err)
	}

	nContainers := 5

	// We have to use real runners here as the WithTracerCollection() will drop the enricher if
	// this doesn't have a valid PID
	runners := make([]*utilstest.Runner, nContainers)
	containers := make([]*Container, nContainers)

	for i := 0; i < nContainers; i++ {
		runner, err := utilstest.NewRunner(nil)
		if err != nil {
			t.Fatalf("Creating runner: %s", err)
		}
		t.Cleanup(runner.Close)

		runners[i] = runner

		containers[i] = &Container{
			ID:        fmt.Sprintf("id%d", i),
			Name:      fmt.Sprintf("name%d", i),
			Namespace: fmt.Sprintf("namespace%d", i),
			Podname:   fmt.Sprintf("pod%d", i),
			Mntns:     runner.Info.MountNsID,
			Pid:       uint32(runner.Info.Pid),
		}
		cc.AddContainer(containers[i])
	}

	require.Equal(t, nContainers, len(f.containers), "number of containers should be equal")

	verifyEnrich := func() {
		for i := 0; i < nContainers; i++ {
			ev := types.CommonData{}
			expected := types.CommonData{
				Namespace: containers[i].Namespace,
				Pod:       containers[i].Podname,
				Container: containers[i].Name,
			}

			cc.EnrichByMntNs(&ev, containers[i].Mntns)

			require.Equal(t, expected, ev, "events should be equal")
		}
	}

	// Enrich by MountNs should work
	verifyEnrich()

	cc.RemoveContainer(containers[0].ID)

	// Pubsub events should be triggered immediately after container removal
	require.Equal(t, nContainers-1, len(f.containers), "number of containers should be equal")

	time.Sleep(1 * time.Second)

	// Enrich by MountNs should work 1 second after removing container
	verifyEnrich()

	time.Sleep(2 * time.Second)

	// Enrich by MountNs should **not** work after removing container more than 2 seconds ago
	ev := types.CommonData{}
	expected := types.CommonData{}
	cc.EnrichByMntNs(&ev, containers[0].Mntns)

	require.Equal(t, expected, ev, "events should be equal")
}

func fillMaps() (int, *sync.Map, map[uint64]*Container, map[uint64][]*Container) {
	syncMap := new(sync.Map)
	mntNsMap := make(map[uint64]*Container)
	netNsMap := make(map[uint64][]*Container)
	entries := 100
	for n := 0; n < entries; n++ {
		containerID := fmt.Sprintf("container-%d", n)
		container := &Container{
			ID:    containerID,
			Mntns: uint64(n),
			Netns: uint64(n / 2),
		}
		syncMap.Store(uint32(n), container)
		mntNsMap[container.Mntns] = container
		if _, ok := netNsMap[container.Netns]; !ok {
			netNsMap[container.Netns] = []*Container{container}
		} else {
			netNsMap[container.Netns] = append(netNsMap[container.Netns], container)
		}
	}
	return entries, syncMap, mntNsMap, netNsMap
}

func BenchmarkSyncMapIter(b *testing.B) {
	b.StopTimer()
	entries, m, _, _ := fillMaps()
	rnd := rand.New(rand.NewSource(0))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		lookupContainerByMntns(m, uint64(rnd.Intn(entries)))
	}
}

func BenchmarkSyncMapLookup(b *testing.B) {
	b.StopTimer()
	entries, m, _, _ := fillMaps()
	rnd := rand.New(rand.NewSource(0))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		m.Load(uint64(rnd.Intn(entries)))
	}
}

func BenchmarkMutexedMapLookup(b *testing.B) {
	b.StopTimer()
	var mu sync.RWMutex
	entries, _, m, _ := fillMaps()
	rnd := rand.New(rand.NewSource(0))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		mu.RLock()
		_ = m[uint64(rnd.Intn(entries))]
		mu.RUnlock()
	}
}

func BenchmarkRangeMapArray(b *testing.B) {
	b.StopTimer()
	entries, m, _, _ := fillMaps()
	rnd := rand.New(rand.NewSource(0))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		lookupID := uint64(rnd.Intn(entries/2 - 1))
		var containers []*Container
		m.Range(func(key, value interface{}) bool {
			c := value.(*Container)
			if c.Netns == lookupID {
				containers = append(containers, c)
			}
			return true
		})
	}
}

func BenchmarkMutexedMapArrayLookup(b *testing.B) {
	b.StopTimer()
	var mu sync.RWMutex
	entries, _, _, m := fillMaps()
	rnd := rand.New(rand.NewSource(0))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		lookupID := uint64(rnd.Intn(entries/2 - 1))
		mu.RLock()
		_ = m[lookupID]
		mu.RUnlock()
	}
}
