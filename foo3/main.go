package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

func printVerifierError(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Printf("BPF program verification failed: %+v\n", ve)
	}
}

func mergeBtfs(hostBtf, kernelBtf *btf.Spec) (*btf.Spec, error) {
	kernelTypes := []btf.Type{}
	iterator := kernelBtf.Iterate()
	for iterator.Next() {
		kernelTypes = append(kernelTypes, iterator.Type)
	}

	builder, err := btf.NewBuilder(kernelTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to create BTF builder: %w", err)
	}

	iterator = hostBtf.Iterate()
	for iterator.Next() {
		if _, err := builder.Add(iterator.Type); err != nil {
			return nil, fmt.Errorf("failed to add host BTF type: %w", err)
		}
	}

	buf := make([]byte, 0, 10*1024*1024) // 1MB buffer
	mergedBtfRaw, err := builder.Marshal(buf, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal BTF: %w", err)
	}

	mergedBtf, err := btf.LoadSpecFromReader(bytes.NewReader(mergedBtfRaw))
	if err != nil {
		return nil, fmt.Errorf("failed to load merged BTF spec: %w", err)
	}

	return mergedBtf, nil
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

func buildHostBtf() (*btf.Spec, uint32, error) {
	//memberNames := strings.Split(fields, ",")
	field1 := true
	field2 := true
	field3 := true
	field4 := false

	uint8T := BtfInt(8, btf.Unsigned)
	uint16T := BtfInt(16, btf.Unsigned)
	uint32T := BtfInt(32, btf.Unsigned)
	uint64T := BtfInt(64, btf.Unsigned)
	int8T := BtfInt(8, btf.Signed)
	int16T := BtfInt(16, btf.Signed)
	int32T := BtfInt(32, btf.Signed)
	int64T := BtfInt(64, btf.Signed)

	types := []btf.Type{
		uint8T,
		uint16T,
		uint32T,
		uint64T,
		int8T,
		int16T,
		int32T,
		int64T,
	}

	currentOffset := uint32(0)
	totalSize := uint32(0)

	members := []btf.Member{}
	if field1 {
		members = append(members, btf.Member{
			Name:   "field1",
			Type:   uint64T,
			Offset: btf.Bits(currentOffset * 8),
		})
		currentOffset += 8
		totalSize += 8
	}
	if field2 {
		members = append(members, btf.Member{
			Name:   "field2",
			Type:   uint64T,
			Offset: btf.Bits(currentOffset * 8),
		})
		currentOffset += 8
		totalSize += 8
	}
	if field3 {
		members = append(members, btf.Member{
			Name:   "field3",
			Type:   uint64T,
			Offset: btf.Bits(currentOffset * 8),
		})
		currentOffset += 8
		totalSize += 8
	}
	if field4 {
		str := CString(16) // 64 bytes for string
		members = append(members, btf.Member{
			Name:   "field4",
			Type:   str,
			Offset: btf.Bits(currentOffset * 8),
		})
		currentOffset += 16 // 64 bytes for string
		totalSize += 16
	}

	// To simplify poc we only use int64 fields

	btfStruct := &btf.Struct{
		Name:    "value",
		Size:    totalSize,
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

	mergedBtf, err := btf.LoadSpecFromReader(bytes.NewReader(mergedBtfRaw))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load merged BTF spec: %w", err)
	}

	return mergedBtf, totalSize, nil
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} host ./host.bpf.c -- -I /usr/include/x86_64-linux-gnu
func do() error {
	// load btf spec from host
	//hostBtf, err := btf.LoadSpec("host_bpfel.o")
	hostBtf, totalSize, err := buildHostBtf()
	if err != nil {
		return fmt.Errorf("failed to load BTF spec from host: %w", err)
	}
	//fmt.Printf("BTF spec loaded from host: %+v\n", hostBtf)

	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("failed to load kernel BTF spec: %w", err)
	}

	mergedBtf, err := mergeBtfs(hostBtf, kernelSpec)
	if err != nil {
		return fmt.Errorf("failed to merge BTF specs: %w", err)
	}

	/** host **/
	hostSpec, err := loadHost()
	if err != nil {
		return fmt.Errorf("failed to load host BPF collection spec: %w", err)
	}

	gadgetMapHostSpec, ok := hostSpec.Maps["gadget_map"]
	if !ok {
		return fmt.Errorf("gadget_map not found in host BPF objects")
	}
	fmt.Printf("gadget_map host spec: %+v\n", gadgetMapHostSpec)
	gadgetMapHostSpec.ValueSize = totalSize

	hostObjects := &hostObjects{}

	hostOpts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: mergedBtf,
		},
	}

	if err := hostSpec.LoadAndAssign(hostObjects, hostOpts); err != nil {
		printVerifierError(err)
		return err
	}

	hostL, err := link.Tracepoint("syscalls", "sys_enter_execve", hostObjects.IgExecveatE, nil)
	if err != nil {
		return err
	}
	defer hostL.Close()

	/**** host done ***/

	/** user **/
	spec, err := ebpf.LoadCollectionSpec("user_bpfel.o")
	if err != nil {
		return fmt.Errorf("failed to load user BPF collection spec: %w", err)
	}

	gadgetMapUserSpec, ok := spec.Maps["gadget_map"]
	if !ok {
		return fmt.Errorf("gadget_map not found in user BPF collection spec")
	}
	fmt.Printf("gadget_map user spec: %+v\n", gadgetMapUserSpec)

	//if gadgetMapHostSpec.ValueSize > gadgetMapUserSpec.ValueSize {
	fmt.Printf("updating user map spec to match value size\n")
	//gadgetMapUserSpec.ValueSize = gadgetMapHostSpec.ValueSize

	gadgetMapUserSpec.ValueSize = totalSize

	//}

	iterator := hostBtf.Iterate()
	for iterator.Next() {
		t := iterator.Type
		fmt.Printf("consdering type %+v\n", t.TypeName())
	}

	btfStruct := &btf.Struct{}
	hostBtf.TypeByName("value", &btfStruct)
	fmt.Printf("BTF struct 'val': %+v\n", btfStruct)
	for _, field := range btfStruct.Members {
		fmt.Printf("Field: %+v, Type: %s, size: %d, offset: %d\n",
			field.Name, field.Type.TypeName(), field.BitfieldSize, field.Offset)
	}

	userOpts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"gadget_map": hostObjects.GadgetMap,
		},
		Programs: ebpf.ProgramOptions{
			KernelTypes: mergedBtf,
		},
	}
	col, err := ebpf.NewCollectionWithOptions(spec, userOpts)
	if err != nil {
		printVerifierError(err)
		return err
	}

	userL, err := link.Tracepoint("syscalls", "sys_enter_execve", col.Programs["ig_user"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach user BPF program: %w", err)
	}
	defer userL.Close()

	// wait for ctrl + c
	fmt.Println("BPF program is running. Press Ctrl+C to exit.")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	return nil

}

func main() {
	if err := do(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
