package image

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

const (
	ProgramContent  = "prog"
	ParamDefinition = "definition"
	printMapPrefix  = "print_"
)

func loadSpec(progContent []byte) (*ebpf.CollectionSpec, error) {
	progReader := bytes.NewReader(progContent)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}
	return spec, err
}

// getPrintMap returns the first map with a "print_" prefix. If not found returns nil.
func getPrintMap(spec *ebpf.CollectionSpec) *ebpf.MapSpec {
	for _, m := range spec.Maps {
		if m.Type != ebpf.RingBuf && m.Type != ebpf.PerfEventArray {
			continue
		}

		if !strings.HasPrefix(m.Name, printMapPrefix) {
			continue
		}

		return m
	}

	return nil
}

func getEventTypeBTF(progContent []byte) (*btf.Struct, error) {
	spec, err := loadSpec(progContent)
	if err != nil {
		return nil, err
	}

	// Look for gadgets with a "print_" map
	printMap := getPrintMap(spec)
	if printMap != nil {
		valueStruct, ok := printMap.Value.(*btf.Struct)
		if !ok {
			return nil, fmt.Errorf("BPF map %q does not have BTF info for values", printMap.Name)
		}

		return valueStruct, nil
	}

	return nil, fmt.Errorf("the gadget doesn't provide any compatible way to show information")
}
