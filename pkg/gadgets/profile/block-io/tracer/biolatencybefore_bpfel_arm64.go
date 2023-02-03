// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type biolatencyBeforeHist struct{ Slots [27]uint32 }

type biolatencyBeforeHistKey struct {
	CmdFlags uint32
	Dev      uint32
}

// loadBiolatencyBefore returns the embedded CollectionSpec for biolatencyBefore.
func loadBiolatencyBefore() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BiolatencyBeforeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load biolatencyBefore: %w", err)
	}

	return spec, err
}

// loadBiolatencyBeforeObjects loads biolatencyBefore and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*biolatencyBeforeObjects
//	*biolatencyBeforePrograms
//	*biolatencyBeforeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBiolatencyBeforeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBiolatencyBefore()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// biolatencyBeforeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type biolatencyBeforeSpecs struct {
	biolatencyBeforeProgramSpecs
	biolatencyBeforeMapSpecs
}

// biolatencyBeforeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type biolatencyBeforeProgramSpecs struct {
	IgProfioDone *ebpf.ProgramSpec `ebpf:"ig_profio_done"`
	IgProfioIns  *ebpf.ProgramSpec `ebpf:"ig_profio_ins"`
	IgProfioIss  *ebpf.ProgramSpec `ebpf:"ig_profio_iss"`
}

// biolatencyBeforeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type biolatencyBeforeMapSpecs struct {
	CgroupMap *ebpf.MapSpec `ebpf:"cgroup_map"`
	Hists     *ebpf.MapSpec `ebpf:"hists"`
	Start     *ebpf.MapSpec `ebpf:"start"`
}

// biolatencyBeforeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBiolatencyBeforeObjects or ebpf.CollectionSpec.LoadAndAssign.
type biolatencyBeforeObjects struct {
	biolatencyBeforePrograms
	biolatencyBeforeMaps
}

func (o *biolatencyBeforeObjects) Close() error {
	return _BiolatencyBeforeClose(
		&o.biolatencyBeforePrograms,
		&o.biolatencyBeforeMaps,
	)
}

// biolatencyBeforeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBiolatencyBeforeObjects or ebpf.CollectionSpec.LoadAndAssign.
type biolatencyBeforeMaps struct {
	CgroupMap *ebpf.Map `ebpf:"cgroup_map"`
	Hists     *ebpf.Map `ebpf:"hists"`
	Start     *ebpf.Map `ebpf:"start"`
}

func (m *biolatencyBeforeMaps) Close() error {
	return _BiolatencyBeforeClose(
		m.CgroupMap,
		m.Hists,
		m.Start,
	)
}

// biolatencyBeforePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBiolatencyBeforeObjects or ebpf.CollectionSpec.LoadAndAssign.
type biolatencyBeforePrograms struct {
	IgProfioDone *ebpf.Program `ebpf:"ig_profio_done"`
	IgProfioIns  *ebpf.Program `ebpf:"ig_profio_ins"`
	IgProfioIss  *ebpf.Program `ebpf:"ig_profio_iss"`
}

func (p *biolatencyBeforePrograms) Close() error {
	return _BiolatencyBeforeClose(
		p.IgProfioDone,
		p.IgProfioIns,
		p.IgProfioIss,
	)
}

func _BiolatencyBeforeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed biolatencybefore_bpfel_arm64.o
var _BiolatencyBeforeBytes []byte
