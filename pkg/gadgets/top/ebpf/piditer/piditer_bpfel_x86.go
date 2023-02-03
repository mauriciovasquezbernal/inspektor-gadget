// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package piditer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type piditerPidIterEntry struct {
	Id   uint32
	Pid  uint32
	Comm [16]uint8
}

// loadPiditer returns the embedded CollectionSpec for piditer.
func loadPiditer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_PiditerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load piditer: %w", err)
	}

	return spec, err
}

// loadPiditerObjects loads piditer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*piditerObjects
//	*piditerPrograms
//	*piditerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadPiditerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadPiditer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// piditerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type piditerSpecs struct {
	piditerProgramSpecs
	piditerMapSpecs
}

// piditerSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type piditerProgramSpecs struct {
	IgTopEbpfIt *ebpf.ProgramSpec `ebpf:"ig_top_ebpf_it"`
}

// piditerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type piditerMapSpecs struct {
}

// piditerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadPiditerObjects or ebpf.CollectionSpec.LoadAndAssign.
type piditerObjects struct {
	piditerPrograms
	piditerMaps
}

func (o *piditerObjects) Close() error {
	return _PiditerClose(
		&o.piditerPrograms,
		&o.piditerMaps,
	)
}

// piditerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadPiditerObjects or ebpf.CollectionSpec.LoadAndAssign.
type piditerMaps struct {
}

func (m *piditerMaps) Close() error {
	return _PiditerClose()
}

// piditerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadPiditerObjects or ebpf.CollectionSpec.LoadAndAssign.
type piditerPrograms struct {
	IgTopEbpfIt *ebpf.Program `ebpf:"ig_top_ebpf_it"`
}

func (p *piditerPrograms) Close() error {
	return _PiditerClose(
		p.IgTopEbpfIt,
	)
}

func _PiditerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed piditer_bpfel_x86.o
var _PiditerBytes []byte
