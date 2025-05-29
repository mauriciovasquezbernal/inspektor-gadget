// Copyright 2022 The Inspektor Gadget authors
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

package socketenricher

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketenricher ./bpf/socket-enricher.bpf.c -- -I./bpf/

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketsiter ./bpf/sockets-iter.bpf.c -- -I./bpf/

const (
	SocketsMapName = "gadget_sockets"
)

// SocketEnricher creates a map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and
// display it directly from the BPF code. Example of such code in the dns and
// sni gadgets.
type SocketEnricher struct {
	objs     socketenricherObjects
	objsIter socketsiterObjects
	links    []link.Link

	closeOnce sync.Once
	done      chan bool
	config    Config
}

func (se *SocketEnricher) SocketsMap() *ebpf.Map {
	return se.objs.GadgetSockets
}

type Config struct {
	CwdEnabled     bool
	ExepathEnabled bool
}

func NewSocketEnricher(config Config) (*SocketEnricher, error) {
	se := &SocketEnricher{
		config: config,
	}

	if err := se.start(); err != nil {
		se.Close()
		return nil, err
	}

	return se, nil
}

func BtfInt(size uint32, encoding btf.IntEncoding) *btf.Int {
	return &btf.Int{
		Size:     size,
		Encoding: encoding,
	}
}

func CString(nelems uint32) *btf.Array {
	// TODO: do I need to register these types?
	charT := BtfInt(8, btf.Char)
	indexT := BtfInt(32, btf.Unsigned)

	return &btf.Array{
		Index:  indexT,
		Type:   charT,
		Nelems: nelems,
	}
}

func (se *SocketEnricher) Btf() (*btf.Spec, uint32, error) {
	uint8T := BtfInt(8, btf.Unsigned)
	uint16T := BtfInt(16, btf.Unsigned)
	uint32T := BtfInt(32, btf.Unsigned)
	uint64T := BtfInt(64, btf.Unsigned)
	int8T := BtfInt(8, btf.Signed)
	int16T := BtfInt(16, btf.Signed)
	int32T := BtfInt(32, btf.Signed)
	int64T := BtfInt(64, btf.Signed)
	cString16 := CString(16)
	cString512 := CString(512)

	types := []btf.Type{
		uint8T,
		uint16T,
		uint32T,
		uint64T,
		int8T,
		int16T,
		int32T,
		int64T,
		cString16,
		cString512,
	}

	currentOffset := uint32(0)

	// fixed fields
	// BE AWARE OF PADDING!
	members := []btf.Member{
		{
			Name:   "mntns",
			Type:   uint64T,
			Offset: btf.Bits(0 * 8),
		},
		{
			Name:   "pid_tgid",
			Type:   uint64T,
			Offset: btf.Bits(8 * 8),
		},
		{
			Name:   "uid_gid",
			Type:   uint64T,
			Offset: btf.Bits(16 * 8),
		},
		{
			Name:   "ptask",
			Type:   cString16,
			Offset: btf.Bits(24 * 8),
		},
		{
			Name:   "task",
			Type:   cString16,
			Offset: btf.Bits(40 * 8),
		},
		{
			Name:   "sock",
			Type:   uint64T,
			Offset: btf.Bits(56 * 8),
		},
		{
			Name:   "deletion_timestamp",
			Type:   uint64T,
			Offset: btf.Bits(64 * 8),
		},
		{
			Name:   "ppid",
			Type:   uint32T,
			Offset: btf.Bits(72 * 8),
		},
		{
			Name:   "ipv6only",
			Type:   uint32T,
			Offset: btf.Bits(76 * 8),
		},
	}
	currentOffset = 80

	// optional fields
	if se.config.CwdEnabled {
		members = append(members, btf.Member{
			Name:   "cwd",
			Type:   cString512,
			Offset: btf.Bits(currentOffset * 8),
		})
		currentOffset += 512

	}
	if se.config.ExepathEnabled {
		members = append(members, btf.Member{
			Name:   "exepath",
			Type:   cString512,
			Offset: btf.Bits(currentOffset * 8),
		})
		currentOffset += 512
	}

	btfStruct := &btf.Struct{
		Name:    "sockets_value",
		Size:    currentOffset,
		Members: members,
	}
	types = append(types, btfStruct)

	builder, err := btf.NewBuilder(types)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create BTF builder: %w", err)
	}

	buf := make([]byte, 0, 10*1024*1024) // 1MB buffer
	mergedBtfRaw, err := builder.Marshal(buf, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal BTF: %w", err)
	}

	btfStrutBtf, err := btf.LoadSpecFromReader(bytes.NewReader(mergedBtfRaw))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load merged BTF spec: %w", err)
	}

	return btfStrutBtf, btfStruct.Size, nil
}

func (se *SocketEnricher) start() error {
	//	specIter, err := loadSocketsiter()
	//	if err != nil {
	//		return fmt.Errorf("loading socketsiter asset: %w", err)
	//	}
	//
	//	err = kallsyms.SpecUpdateAddresses(specIter, []string{"socket_file_ops"})
	//	if err != nil {
	//		// Being unable to access to /proc/kallsyms can be caused by not having
	//		// CAP_SYSLOG.
	//		log.Warnf("updating socket_file_ops address with ksyms: %v\nEither you cannot access /proc/kallsyms or this file does not contain socket_file_ops", err)
	//	}

	// TODO: btfgen support
	seBtf, structSize, err := se.Btf()
	if err != nil {
		return fmt.Errorf("getting BTF spec: %w", err)
	}
	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}

	mergedBtf, err := btfhelpers.MergeBtfs(kernelSpec, seBtf)
	if err != nil {
		return fmt.Errorf("merging BTF specs: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: mergedBtf,
		},
	}

	// TODO: enable later on!
	disableBPFIterators := true
	//if err := specIter.LoadAndAssign(&se.objsIter, nil); err != nil {
	//	disableBPFIterators = true
	//	log.Warnf("Socket enricher: skip loading iterators: %v", err)
	//}

	spec, err := loadSocketenricher()
	if err != nil {
		return fmt.Errorf("loading socket enricher asset: %w", err)
	}

	spec.Maps[SocketsMapName].ValueSize = structSize

	if disableBPFIterators {
		socketSpec := &socketenricherSpecs{}
		if err := spec.Assign(socketSpec); err != nil {
			return err
		}
		if err := socketSpec.DisableBpfIterators.Set(true); err != nil {
			return err
		}
	} else {
		opts.MapReplacements = map[string]*ebpf.Map{
			SocketsMapName: se.objsIter.GadgetSockets,
		}
	}

	if err := spec.LoadAndAssign(&se.objs, &opts); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	var l link.Link

	// bind
	l, err = link.Kprobe("inet_bind", se.objs.IgBindIpv4E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet_bind", se.objs.IgBindIpv4X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_bind", se.objs.IgBindIpv6E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet6_bind", se.objs.IgBindIpv6X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// connect
	l, err = link.Kprobe("tcp_connect", se.objs.IgTcpCoE, nil)
	if err != nil {
		return fmt.Errorf("attaching connect kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("tcp_connect", se.objs.IgTcpCoX, nil)
	if err != nil {
		return fmt.Errorf("attaching connect kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// udp_sendmsg
	l, err = link.Kprobe("udp_sendmsg", se.objs.IgUdpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching udp_sendmsg ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("udpv6_sendmsg", se.objs.IgUdp6Sendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching udpv6_sendmsg ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	// release
	l, err = link.Kprobe("inet_release", se.objs.IgFreeIpv4E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_release", se.objs.IgFreeIpv6E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	if !disableBPFIterators {
		// get initial sockets
		socketsIter, err := link.AttachIter(link.IterOptions{
			Program: se.objsIter.IgSocketsIt,
		})
		if err != nil {
			return fmt.Errorf("attach BPF iterator: %w", err)
		}
		defer socketsIter.Close()

		_, err = bpfiterns.Read(socketsIter)
		if err != nil {
			return fmt.Errorf("read BPF iterator: %w", err)
		}

		// Schedule socket cleanup
		cleanupIter, err := link.AttachIter(link.IterOptions{
			Program: se.objsIter.IgSkCleanup,
			Map:     se.objsIter.GadgetSockets,
		})
		if err != nil {
			return fmt.Errorf("attach BPF iterator for cleanups: %w", err)
		}
		se.links = append(se.links, cleanupIter)

		se.done = make(chan bool)
		go se.cleanupDeletedSockets(cleanupIter)
	}

	return nil
}

func (se *SocketEnricher) cleanupDeletedSockets(cleanupIter *link.Iter) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-se.done:
			return
		case <-ticker.C:
			err := se.cleanupDeletedSocketsNow(cleanupIter)
			if err != nil {
				fmt.Printf("socket enricher: %v\n", err)
			}
		}
	}
}

func (se *SocketEnricher) cleanupDeletedSocketsNow(cleanupIter *link.Iter) error {
	// No need to change pidns for this iterator because cleanupIter is an
	// iterator on a map, not on tasks.
	_, err := bpfiterns.ReadOnCurrentPidNs(cleanupIter)
	return err
}

func (se *SocketEnricher) Close() {
	se.closeOnce.Do(func() {
		if se.done != nil {
			close(se.done)
		}
	})

	for _, l := range se.links {
		gadgets.CloseLink(l)
	}
	se.links = nil
	se.objs.Close()
	se.objsIter.Close()
}
