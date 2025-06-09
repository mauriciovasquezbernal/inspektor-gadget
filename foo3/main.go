package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func dumpBtfStruct(s *btf.Struct) {
	fmt.Printf("BTF Struct: %s\n", s.Name)
	for _, field := range s.Members {
		fmt.Printf("  Field: %s, Type:%+v\n", field.Name, field.Type)
		switch field.Name {
		case "max_entries":
			if uint32Val, err := uintFromBTF(field.Type); err == nil {
				fmt.Printf("    max_entries: %d\n", uint32Val)
			}
		case "value":
			vk, ok := field.Type.(*btf.Pointer)
			if !ok {
				fmt.Printf("    value is not a pointer: %v\n", field.Type)
				continue
			}
			value := btf.UnderlyingType(vk.Target)
			//valueStruct := value.(*btf.Struct)
			fmt.Printf("    value type: %s\n", value)
		}
	}
}

// uintFromBTF resolves the __uint macro, which is a pointer to a sized
// array, e.g. for int (*foo)[10], this function will return 10.
func uintFromBTF(typ btf.Type) (uint32, error) {
	ptr, ok := typ.(*btf.Pointer)
	if !ok {
		return 0, fmt.Errorf("not a pointer: %v", typ)
	}

	arr, ok := ptr.Target.(*btf.Array)
	if !ok {
		return 0, fmt.Errorf("not a pointer to array: %v", typ)
	}

	return arr.Nelems, nil
}

func do3(file *elf.File, btfSpec *btf.Spec) (map[uintptr]string, error) {
	fmt.Printf("BTF spec: %+v\n", btfSpec)

	//fmt.Printf("ELF file: %s\n", file)

	ret := make(map[uintptr]string)

	var mapsSec *elf.Section

	for i, sec := range file.Sections {
		if strings.HasPrefix(sec.Name, ".maps") {
			//fmt.Printf("Section %d: %s, Type: %s, Flags: %s\n", i, sec.Name, sec.Type, sec.Flags)
			fmt.Printf("found %s section at %d\n", sec.Name, i)
			mapsSec = sec
			break
		}
	}

	if mapsSec == nil {
		return nil, fmt.Errorf("no .maps section found in ELF file")
	}

	var ds *btf.Datasec
	if err := btfSpec.TypeByName(".maps", &ds); err != nil {
		return nil, fmt.Errorf("cannot find section '%s' in BTF: %w", ".maps", err)
	}

	for _, vs := range ds.Vars {
		v, ok := vs.Type.(*btf.Var)
		if !ok {
			return nil, fmt.Errorf("section %v: unexpected type %s", ".maps", vs.Type)
		}
		name := string(v.Name)
		fmt.Printf("found map %s\n", name)

		fmt.Printf("vas offset is %d\n", vs.Offset)

		// Each Var representing a BTF map definition contains a Struct.
		mapStruct, ok := btf.UnderlyingType(v.Type).(*btf.Struct)
		if !ok {
			return nil, fmt.Errorf("expected struct, got %s", v.Type)
		}

		fmt.Printf("map struct: %p\n", mapStruct)

		ret[uintptr(unsafe.Pointer(mapStruct))] = name

		dumpBtfStruct(mapStruct)

	}

	return ret, nil
}

//func decodeType(typ btf.Type) (btf,) {

func dumpTracer(tracers *elf.Section, s *btf.Struct, ret map[uintptr]string) {
	data, err := tracers.Data()
	if err != nil {
		fmt.Printf("failed to read section data: %v\n", err)
		return
	}

	fmt.Printf("tracer: %s\n", s.Name)
	for _, member := range s.Members {
		fmt.Printf("  Field: %s, Type:%+v\n", member.Name, member.Type)
		switch member.Name {
		//case "type":
		case "name":
			target := btf.UnderlyingType(member.Type)
			//btfPointer := target.(*btf.Pointer)
			btfArray := target.(*btf.Array)
			//fmt.Printf("    name: %s elems\n", btfChar.Name)

			offset := member.Offset.Bytes()
			val := data[offset : offset+btfArray.Nelems]
			fmt.Printf("	name value: %s\n", string(val))

		//case "foo":
		//	fmt.Printf("    foo: %s\n", member.Type)
		//	btfInt := member.Type.(*btf.Int)
		//	offset := member.Offset.Bytes()
		//	val := data[offset : offset+btfInt.Size]
		//	fmt.Printf("	foo value: %x\n", val)
		//	// val:

		case "map":
			//if uint32Val, err := uintFromBTF(field.Type); err == nil {
			//	fmt.Printf("    max_entries: %d\n", uint32Val)
			//}
			btfPointer := member.Type.(*btf.Pointer)
			target := btf.UnderlyingType(btfPointer.Target)
			btfStruct := target.(*btf.Struct)

			mapName := ret[uintptr(unsafe.Pointer(btfStruct))]
			fmt.Printf("    map: %s\n", mapName)

		case "type":
			vk, ok := member.Type.(*btf.Pointer)
			if !ok {
				fmt.Printf("    value is not a pointer: %v\n", member.Type)
				continue
			}
			value := btf.UnderlyingType(vk.Target)
			//valueStruct := value.(*btf.Struct)
			fmt.Printf("    value type: %s\n", value)
		}
	}
}

func do4() error {
	reader := bytes.NewReader(_HostBytes)

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return fmt.Errorf("failed to load BPF collection spec: %w", err)
	}

	fmt.Printf("BPF Collection Spec: %+v\n", spec)

	p, ok := spec.Programs["ig_execveat_e"]
	if !ok {
		return fmt.Errorf("program 'ig_execveat_e' not found in BPF collection spec")
	}

	//fmt.Printf("ins %s\n", p.Instructions.String())
	for i, ins := range p.Instructions {
		fmt.Printf("Instruction %d: %+v\n", i, ins)
		fmt.Printf("reference  %s\n", ins.Reference())

	}

	return nil

}

func do(file *elf.File, btfSpec *btf.Spec, ret map[uintptr]string) error {
	fmt.Printf("BTF spec: %+v\n", btfSpec)

	//fmt.Printf("ELF file: %s\n", file)

	var tracers *elf.Section

	const secName = ".tracers"

	for i, sec := range file.Sections {
		if strings.HasPrefix(sec.Name, secName) {
			//fmt.Printf("Section %d: %s, Type: %s, Flags: %s\n", i, sec.Name, sec.Type, sec.Flags)
			fmt.Printf("found %s section at %d\n", sec.Name, i)
			tracers = sec
			break
		}
	}

	if tracers == nil {
		return fmt.Errorf("no .tracers section found in ELF file")
	}

	//fmt.Printf("symbols: ")
	//symbols, err := file.Symbols()
	//if err != nil {
	//	return fmt.Errorf("failed to get symbols from ELF file: %w", err)
	//}
	//for _, sym := range symbols {
	//	fmt.Printf("-> %s\n", sym.Name)
	//}

	var ds *btf.Datasec
	if err := btfSpec.TypeByName(secName, &ds); err != nil {
		return fmt.Errorf("cannot find section '%s' in BTF: %w", ".maps", err)
	}

	for _, vs := range ds.Vars {
		v, ok := vs.Type.(*btf.Var)
		if !ok {
			return fmt.Errorf("section %v: unexpected type %s", ".maps", vs.Type)
		}
		name := string(v.Name)
		fmt.Printf("found tracer %s\n", name)

		// Each Var representing a BTF map definition contains a Struct.
		mapStruct, ok := btf.UnderlyingType(v.Type).(*btf.Struct)
		if !ok {
			return fmt.Errorf("expected struct, got %s", v.Type)
		}

		dumpTracer(tracers, mapStruct, ret)

	}

	return nil
}

type tracerDef struct {
	Name string
	Type btf.Type
	// should it really be a string? or (ebpf.Map?)
	Map string
}

const snapshottersSecName = ".snapshotters"
const mapsSecName = ".maps"

func extractTracers(file *elf.File, btfSpec *btf.Spec) ([]tracerDef, error) {
	ret := make([]tracerDef, 0)

	mapsNames := make(map[uintptr]string)

	// TODO: Do I actually need to care about elf sections?
	//var tracersSec *elf.Section
	//var mapsSec *elf.Section
	var ds *btf.Datasec

	//	// do a first pass over the maps to find them
	//	if err := btfSpec.TypeByName(mapsSecName, &ds); err != nil {
	//		return nil, fmt.Errorf("cannot find section '%s' in BTF: %w", ".maps", err)
	//	}
	//
	//	for _, vs := range ds.Vars {
	//		v, ok := vs.Type.(*btf.Var)
	//		if !ok {
	//			return nil, fmt.Errorf("section %v: unexpected type %s", ".maps", vs.Type)
	//		}
	//		name := string(v.Name)
	//
	//		// Each Var representing a BTF map definition contains a Struct.
	//		mapStruct, ok := btf.UnderlyingType(v.Type).(*btf.Struct)
	//		if !ok {
	//			return nil, fmt.Errorf("expected struct, got %s", v.Type)
	//		}
	//
	//		mapsNames[uintptr(unsafe.Pointer(mapStruct))] = name
	//	}

	// do a second pass over the tracers
	if err := btfSpec.TypeByName(snapshottersSecName, &ds); err != nil {
		return nil, fmt.Errorf("cannot find section '%s' in BTF: %w", snapshottersSecName, err)
	}
	for _, vs := range ds.Vars {
		v, ok := vs.Type.(*btf.Var)
		if !ok {
			return nil, fmt.Errorf("section %v: unexpected type %s", ".maps", vs.Type)
		}
		tracerStruct, ok := btf.UnderlyingType(v.Type).(*btf.Struct)
		if !ok {
			return nil, fmt.Errorf("expected struct, got %s", v.Type)
		}

		tracer := tracerDef{
			Name: string(v.Name),
		}

		for _, member := range tracerStruct.Members {
			switch member.Name {
			case "map":
				btfPointer := member.Type.(*btf.Pointer)
				target := btf.UnderlyingType(btfPointer.Target)
				btfStruct := target.(*btf.Struct)
				tracer.Map = mapsNames[uintptr(unsafe.Pointer(btfStruct))]
			case "type":
				vk := member.Type.(*btf.Pointer)
				tracer.Type = btf.UnderlyingType(vk.Target)
			case "program0":
				fmt.Printf("program0: %+v\n", member.Type)
				//vk := member.Type.(*btf.Pointer)
				typ := btf.UnderlyingType(member.Type)
				btfPointer := typ.(*btf.Pointer)
				btfFuncProto := btfPointer.Target.(*btf.FuncProto)
				fmt.Printf("program0 type: %+v\n", btfFuncProto)

			}
		}

		// TODO: validate mandatory fields are set

		ret = append(ret, tracer)
	}

	return ret, nil
}

func main() {
	//reader := bytes.NewReader(_HostBytes)
	reader, err := os.Open("/tmp/trace_open/amd64.bpf.o")
	if err != nil {
		panic(fmt.Errorf("failed to open file: %w", err))
	}

	//file, err := elf.NewFile(reader)
	//if err != nil {
	//	panic(fmt.Errorf("elf failed err %w", err))
	//}

	btfSpec, err := btf.LoadSpecFromReader(reader)
	if err != nil {
		//return fmt.Errorf("failed to load BTF from reader: %w", err)
		panic(fmt.Errorf("failed to load BTF from reader: %w", err))
	}

	tracers, err := extractTracers(nil, btfSpec)
	if err != nil {
		panic(fmt.Errorf("failed to extract tracers: %w", err))
	}

	fmt.Printf("Tracers: \n")
	for _, tracer := range tracers {
		fmt.Printf("  Name: %s, Map: %s, Type: %s\n", tracer.Name, tracer.Map, tracer.Type)
	}

	//ret, err := do3(file, btfSpec)
	//if err != nil {
	//	fmt.Printf("Error in do1: %v\n", err)
	//}
	//if err := do(file, btfSpec, ret); err != nil {
	//	fmt.Printf("Error: %v\n", err)
	//}

	//if err := do4(); err != nil {
	//	fmt.Printf("Error in do4: %v\n", err)
	//}
}
