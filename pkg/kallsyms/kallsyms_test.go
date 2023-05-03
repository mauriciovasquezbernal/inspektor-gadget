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

package kallsyms

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
)

func TestCustomKAllSyms(t *testing.T) {
	kAllSymsStr := strings.Join([]string{
		"0000000000000000 A fixed_percpu_data",
		"ffffffffb4231f40 D bpf_prog_fops",
		"ffffffffb43723e0 d socket_file_ops",
	}, "\n")

	kAllSymsReader := strings.NewReader(kAllSymsStr)
	kAllSyms, err := NewKAllSymsFromReader(kAllSymsReader)
	if err != nil {
		t.Errorf("NewKAllSymsFromReader failed: %v", err)
	}
	if !kAllSyms.SymbolExists("bpf_prog_fops") {
		t.Errorf("SymbolExists should have found bpf_prog_fops")
	}
	if kAllSyms.SymbolExists("abcde_bad_name") {
		t.Errorf("SymbolExists should not have found abcde_bad_name")
	}

	lookupByInstructionPointerTests := []struct {
		instructionPointer uint64
		expectedSymbol     string
	}{
		{0, "fixed_percpu_data"},
		{0xffffffffb4231f39, "fixed_percpu_data"},
		{0xffffffffb4231f40, "bpf_prog_fops"},
		// TODO: is it correct? should it be bpf_prog_fops?
		{0xffffffffb4231f41, "bpf_prog_fops"},
		{0xffffffffb43723df, "bpf_prog_fops"},
		{0xffffffffb43723e0, "socket_file_ops"},
		{0xffffffffb43723e1, "socket_file_ops"},
	}
	for _, tt := range lookupByInstructionPointerTests {
		symbol := kAllSyms.LookupByInstructionPointer(tt.instructionPointer)
		if symbol != tt.expectedSymbol {
			t.Errorf("LookupByInstructionPointer(0x%x) returned %v, expected %v", tt.instructionPointer, symbol, tt.expectedSymbol)
		}
	}
}

func TestRealKAllSyms(t *testing.T) {
	utilstest.RequireRoot(t)

	kAllSyms, err := NewKAllSyms()
	if err != nil {
		t.Errorf("NewKAllSyms failed: %v", err)
	}
	if !kAllSyms.SymbolExists("bpf_prog_fops") {
		t.Errorf("SymbolExists should have found bpf_prog_fops")
	}
	if kAllSyms.SymbolExists("abcde_bad_name") {
		t.Errorf("SymbolExists should not have found abcde_bad_name")
	}

	addr, ok := kAllSyms.symbolsMap["bpf_prog_fops"]
	if !ok {
		t.Errorf("bpf_prog_fops not found in symbolsMap")
	}
	if addr == 0 {
		// /proc/kallsyms contains the address 0 without CAP_SYSLOG.
		// Since we use RequireRoot, it should not happen.
		t.Errorf("bpf_prog_fops has a zero address: %x", addr)
	}
}

func TestSpecRewriteConstants(t *testing.T) {
	kAllSymsFactory := func() (*KAllSyms, error) {
		kAllSymsStr := strings.Join([]string{
			"0000000000000000 A fixed_percpu_data",
			"ffffffffb4231f40 D bpf_prog_fops",
			"ffffffffb43723e0 d socket_file_ops",
		}, "\n")

		kAllSymsReader := strings.NewReader(kAllSymsStr)
		kAllSyms, err := NewKAllSymsFromReader(kAllSymsReader)
		if err != nil {
			t.Errorf("NewKAllSymsFromReader failed: %v", err)
		}
		return kAllSyms, nil
	}

	// Little endian representation of the addresses above:
	bpfProgFopsAddr := []byte{0x40, 0x1f, 0x23, 0xb4, 0xff, 0xff, 0xff, 0xff}
	socketFileOpsAddr := []byte{0xe0, 0x23, 0x37, 0xb4, 0xff, 0xff, 0xff, 0xff}

	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			".rodata": {
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
				Value: &btf.Datasec{
					Vars: []btf.VarSecinfo{
						{
							Type: &btf.Var{
								Name: "bpf_prog_fops_addr",
								Type: &btf.Int{Size: 8},
							},
							Offset: 0,
							Size:   8,
						},
						{
							Type: &btf.Var{
								Name: "socket_file_ops_addr",
								Type: &btf.Int{Size: 8},
							},
							Offset: 8,
							Size:   8,
						},
					},
				},
				Contents: []ebpf.MapKV{
					{Key: uint32(0), Value: []byte{
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
					}},
				},
			},
		},
	}

	err := specUpdateAddresses(
		kAllSymsFactory,
		spec,
		[]string{"abcde_bad_name"},
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("specRewriteConstantsWithSymbolAddresses should have failed")
	}

	err = specUpdateAddresses(
		kAllSymsFactory,
		spec,
		[]string{"bpf_prog_fops", "socket_file_ops"},
	)
	if err != nil {
		t.Errorf("specRewriteConstantsWithSymbolAddresses failed: %v", err)
	}

	expectedContents := []byte{}
	expectedContents = append(expectedContents, bpfProgFopsAddr...)
	expectedContents = append(expectedContents, socketFileOpsAddr...)
	contents := spec.Maps[".rodata"].Contents[0].Value
	if !reflect.DeepEqual(contents, expectedContents) {
		t.Errorf("contents should be %v, got %v", expectedContents, contents)
	}
}
