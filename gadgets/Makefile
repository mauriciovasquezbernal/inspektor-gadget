GADGETS = \
	trace_exec_x86.bpf.o trace_exec_arm64.bpf.o \
	trace_open_x86.bpf.o trace_open_arm64.bpf.o \
	trace_tcpconnect_x86.bpf.o trace_tcpconnect_arm64.bpf.o \
	trace_tcpretrans_x86.bpf.o trace_tcpretrans_arm64.bpf.o \
	trace_dns_bpfel.bpf.o \
	#

EBPF_BUILDER ?= ghcr.io/inspektor-gadget/inspektor-gadget-ebpf-builder

.PHONY: all
all: $(GADGETS)

%_x86.bpf.o : %.bpf.c
	clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_x86 -c $(filter %.c,$^) \
		-I ../pkg/amd64/ \
		-I ../pkg/gadgets/common/ \
		-I ../pkg/gadgets/internal/socketenricher/bpf/ \
		-o $@
%_arm64.bpf.o : %.bpf.c
	clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_arm64 -c $(filter %.c,$^) \
		-I ../pkg/arm64/ \
		-I ../pkg/gadgets/common/ \
		-I ../pkg/gadgets/internal/socketenricher/bpf/ \
		-o $@

# Networking gadgets
#
# We need <asm/types.h> and depending on Linux distributions, it is installed
# at different paths:
#
# * Ubuntu, package linux-libc-dev:
#   /usr/include/x86_64-linux-gnu/asm/types.h
#
# * Fedora, package kernel-headers
#   /usr/include/asm/types.h
#
# Since Ubuntu does not install it in a standard path, add a compiler flag for
# it.
%_bpfel.bpf.o : %.bpf.c
	CLANG_OS_FLAGS= ; \
	if [ "$(shell grep -oP '^NAME="\K\w+(?=")' /etc/os-release)" == "Ubuntu" ]; then \
		CLANG_OS_FLAGS="-I/usr/include/$(shell uname -m)-linux-gnu" ; \
	fi ; \
	docker run --rm \
		--name ebpf-object-builder \
		--user $(shell id -u):$(shell id -g) \
		-v $(shell pwd)/..:/work \
		--entrypoint "/bin/bash" \
		$(EBPF_BUILDER) -c \
		"clang -target bpf -Wall -g -O2 -c gadgets/$(filter %.c,$^) \
		$$CLANG_OS_FLAGS \
		-I pkg/gadgets/common/ \
		-I pkg/gadgets/internal/socketenricher/bpf \
		-o gadgets/$@"

clean:
	rm *.o
