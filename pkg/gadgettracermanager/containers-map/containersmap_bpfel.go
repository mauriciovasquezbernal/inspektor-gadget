// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package containersmap

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type containersmapContainer struct {
	ContainerId [256]int8
	Namespace   [256]int8
	Pod         [256]int8
	Container   [256]int8
}

// loadContainersmap returns the embedded CollectionSpec for containersmap.
func loadContainersmap() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ContainersmapBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load containersmap: %w", err)
	}

	return spec, err
}

// loadContainersmapObjects loads containersmap and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*containersmapObjects
//	*containersmapPrograms
//	*containersmapMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadContainersmapObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadContainersmap()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// containersmapSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type containersmapSpecs struct {
	containersmapProgramSpecs
	containersmapMapSpecs
}

// containersmapSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type containersmapProgramSpecs struct {
}

// containersmapMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type containersmapMapSpecs struct {
	Containers *ebpf.MapSpec `ebpf:"containers"`
}

// containersmapObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadContainersmapObjects or ebpf.CollectionSpec.LoadAndAssign.
type containersmapObjects struct {
	containersmapPrograms
	containersmapMaps
}

func (o *containersmapObjects) Close() error {
	return _ContainersmapClose(
		&o.containersmapPrograms,
		&o.containersmapMaps,
	)
}

// containersmapMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadContainersmapObjects or ebpf.CollectionSpec.LoadAndAssign.
type containersmapMaps struct {
	Containers *ebpf.Map `ebpf:"containers"`
}

func (m *containersmapMaps) Close() error {
	return _ContainersmapClose(
		m.Containers,
	)
}

// containersmapPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadContainersmapObjects or ebpf.CollectionSpec.LoadAndAssign.
type containersmapPrograms struct {
}

func (p *containersmapPrograms) Close() error {
	return _ContainersmapClose()
}

func _ContainersmapClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed containersmap_bpfel.o
var _ContainersmapBytes []byte
