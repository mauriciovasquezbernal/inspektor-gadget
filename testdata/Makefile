CLANG ?= clang
LLVM_STRIP ?= llvm-strip
GADGET_BUILDER ?= ghcr.io/inspektor-gadget/gadget-builder

.PHOHY: all
all: testdata_docker

TESTDATA = \
	populate_metadata_1_param_from_scratch.o \
	populate_metadata_1_tracer_1_struct_from_scratch.o \
	populate_metadata_no_tracers_from_scratch.o \
	populate_metadata_tracer_wrong_map_type.o \
	populate_metadata_tracer_non_existing_structure.o \
	populate_metadata_tracer_map_without_btf.o \
	populate_metadata_tracer_add_missing_field.o \
	populate_metadata_tracer_non_existing_map.o \
	populate_metadata_tracer_bad_tracer_info.o \
	populate_metadata_snapshotter_struct.o \
	validate_metadata1.o \
	validate_metadata_topper.o \
	populate_metadata_1_topper_1_struct_from_scratch.o \
	populate_metadata_topper_non_existing_map.o \
	populate_metadata_topper_bad_topper_info.o \
	populate_metadata_topper_wrong_map_type.o \
	populate_metadata_topper_map_without_btf.o \
	populate_metadata_topper_wrong_map_value_type.o \
	populate_metadata_topper_add_missing_field.o \
	populate_metadata_topper_multi_definition.o \
	#

.PHONY: testdata_host
testdata_host: $(TESTDATA)

# build only amd64 variants for testing
%.o: %.bpf.c
	$(CLANG) -target bpf -Wall -g -O2 -D __TARGET_ARCH_x86 -o good.o \
		-I /usr/include/gadget/amd64 -c $< -o $@
	$(LLVM_STRIP) -g $@

.PHONY: testdata_docker
testdata_docker:
	docker run --rm --name testdata-builder --user $(shell id -u):$(shell id -g) \
		-v $(shell pwd):/work $(GADGET_BUILDER) \
		bash -c "cd /work && make testdata_host"

.PHONY: clean
clean:
	rm -f $(TESTDATA)
