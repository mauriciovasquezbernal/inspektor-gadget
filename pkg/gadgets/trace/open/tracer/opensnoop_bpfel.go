// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type opensnoopEvent struct {
	Timestamp uint64
	Pid       uint32
	Uid       uint32
	MntnsId   uint64
	Ret       int32
	Flags     int32
	Comm      [16]uint8
	Fname     [255]uint8
	_         [1]byte
}

// loadOpensnoop returns the embedded CollectionSpec for opensnoop.
func loadOpensnoop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_OpensnoopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load opensnoop: %w", err)
	}

	return spec, err
}

// loadOpensnoopObjects loads opensnoop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*opensnoopObjects
//	*opensnoopPrograms
//	*opensnoopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadOpensnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadOpensnoop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// opensnoopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopSpecs struct {
	opensnoopProgramSpecs
	opensnoopMapSpecs
}

// opensnoopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopProgramSpecs struct {
	IgOpenE   *ebpf.ProgramSpec `ebpf:"ig_open_e"`
	IgOpenX   *ebpf.ProgramSpec `ebpf:"ig_open_x"`
	IgOpenatE *ebpf.ProgramSpec `ebpf:"ig_openat_e"`
	IgOpenatX *ebpf.ProgramSpec `ebpf:"ig_openat_x"`
}

// opensnoopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
	Start         *ebpf.MapSpec `ebpf:"start"`
}

// opensnoopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopObjects struct {
	opensnoopPrograms
	opensnoopMaps
}

func (o *opensnoopObjects) Close() error {
	return _OpensnoopClose(
		&o.opensnoopPrograms,
		&o.opensnoopMaps,
	)
}

// opensnoopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
	Start         *ebpf.Map `ebpf:"start"`
}

func (m *opensnoopMaps) Close() error {
	return _OpensnoopClose(
		m.Events,
		m.MountNsFilter,
		m.Start,
	)
}

// opensnoopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopPrograms struct {
	IgOpenE   *ebpf.Program `ebpf:"ig_open_e"`
	IgOpenX   *ebpf.Program `ebpf:"ig_open_x"`
	IgOpenatE *ebpf.Program `ebpf:"ig_openat_e"`
	IgOpenatX *ebpf.Program `ebpf:"ig_openat_x"`
}

func (p *opensnoopPrograms) Close() error {
	return _OpensnoopClose(
		p.IgOpenE,
		p.IgOpenX,
		p.IgOpenatE,
		p.IgOpenatX,
	)
}

func _OpensnoopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed opensnoop_bpfel.o
var _OpensnoopBytes []byte
