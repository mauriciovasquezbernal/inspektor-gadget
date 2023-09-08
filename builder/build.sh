# This script is designed to be called by ig. Don't run it directly.
set -ux

clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_x86 -c $1 \
	-I /usr/include/gadget/amd64/ \
	-o $2/x86.bpf.o

clang -target bpf -Wall -g -O2 -D __TARGET_ARCH_arm64 -c $1 \
	-I  /usr/include/gadget/arm64/ \
	-o $2/arm64.bpf.o
