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

func buildHostBtf() (*btf.Spec, error) {
	types := []btf.Type{}

	int64T := &btf.Int{
		Name:     "__u64",
		Size:     8,
		Encoding: btf.Unsigned,
	}
	types = append(types, int64T)

	btfStruct := &btf.Struct{
		Name: "value",
		Size: 8 * 3,
		Members: []btf.Member{
			{
				Name:   "bar1",
				Type:   int64T,
				Offset: 0,
			},
			{
				Name:   "field1",
				Type:   int64T,
				Offset: 64,
			},
			{
				Name:   "field2",
				Type:   int64T,
				Offset: 128,
			},
			{
				Name:   "bar2",
				Type:   int64T,
				Offset: 192,
			},
		},
	}
	types = append(types, btfStruct)

	builder, err := btf.NewBuilder(types)
	if err != nil {
		return nil, fmt.Errorf("failed to create BTF builder: %w", err)
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} host ./host.bpf.c -- -I /usr/include/x86_64-linux-gnu
func do() error {
	/** host **/
	hostSpec, err := loadHost()
	if err != nil {
		return fmt.Errorf("failed to load host BPF collection spec: %w", err)
	}

	hostObjects := &hostObjects{}
	if err := loadHostObjects(hostObjects, nil); err != nil {
		printVerifierError(err)
		return err
	}

	hostL, err := link.Tracepoint("syscalls", "sys_enter_execve", hostObjects.IgExecveatE, nil)
	if err != nil {
		return err
	}
	defer hostL.Close()

	gadgetMapHostSpec, ok := hostSpec.Maps["gadget_map"]
	if !ok {
		return fmt.Errorf("gadget_map not found in host BPF objects")
	}
	fmt.Printf("gadget_map host spec: %+v\n", gadgetMapHostSpec)
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
	gadgetMapUserSpec.ValueSize = gadgetMapHostSpec.ValueSize
	//}

	// load btf spec from host
	//hostBtf, err := btf.LoadSpec("host_bpfel.o")
	hostBtf, err := buildHostBtf()
	if err != nil {
		return fmt.Errorf("failed to load BTF spec from host: %w", err)
	}
	//fmt.Printf("BTF spec loaded from host: %+v\n", hostBtf)

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

	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("failed to load kernel BTF spec: %w", err)
	}

	mergedBtf, err := mergeBtfs(hostBtf, kernelSpec)
	if err != nil {
		return fmt.Errorf("failed to merge BTF specs: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"gadget_map": hostObjects.GadgetMap,
		},
		Programs: ebpf.ProgramOptions{
			KernelTypes: mergedBtf,
		},
	}
	col, err := ebpf.NewCollectionWithOptions(spec, opts)
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
