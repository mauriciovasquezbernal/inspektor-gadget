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

//go:build linux
// +build linux

package tracer

import (
	"fmt"
	"net"
	"testing"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSocketTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer, err := NewTracer(types.ALL)
	require.ErrorIsf(t, nil, err, "creating tracer: %v", err)

	tracer.CloseIters()
}

func testSocket(t *testing.T, proto types.Proto, addr string, port uint16, expectedEvent types.Event) {
	tracer, err := NewTracer(proto)
	require.ErrorIsf(t, nil, err, "creating tracer: %v", err)
	defer tracer.CloseIters()

	evs, err := tracer.RunCollector(1, "", "", "")
	require.ErrorIsf(t, nil, err, "running collector: %v", err)

	type extra struct {
		addr string
		port uint16
	}

	events := make([]types.Event, len(evs))
	for i, ev := range evs {
		events[i] = *ev

		// Normalize few fields before comparing:
		// 1. This is hard to guess the inode number, let's normalize it for the
		// moment.
		// 2. We do not want to get the net namespace ID associated to PID 1, so
		// let's normalize it too.
		events[i].NetNsID = 0
		events[i].InodeNumber = 0
	}

	utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, e extra) *types.Event {
		// Deal with common fields here.
		expectedEvent.Event = eventtypes.Event{Type: eventtypes.NORMAL}
		expectedEvent.SrcEndpoint = eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				Addr: e.addr,
			},
			Port: e.port,
		}
		expectedEvent.DstEndpoint = eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				// There is no connection in this test, so there remote address is null.
				Addr: "0.0.0.0",
			},
		}

		return &expectedEvent
	})(t, nil, extra{addr, port}, events)
}

func TestSocketTCPv4(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	addr := "127.0.0.1"
	port := uint16(8082)

	conn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	require.ErrorIsf(t, nil, err, "listening to %s: %v", addr, err)
	defer conn.Close()

	testSocket(t, types.TCP, addr, port, types.Event{
		Protocol: "TCP",
		Status:   "LISTEN",
	})
}

func TestSocketUDPv4(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	addr := "127.0.0.1"
	port := 8082

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(addr),
	})
	require.ErrorIsf(t, nil, err, "listening to %s: %v", addr, err)
	defer conn.Close()

	testSocket(t, types.UDP, addr, uint16(port), types.Event{
		Protocol: "UDP",
		Status:   "INACTIVE",
	})
}
