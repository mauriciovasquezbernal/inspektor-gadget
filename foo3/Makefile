all: foo3

foo3: main.go user_bpfel.o host.bpf.c header_host.h
	go generate . && go build

user_bpfel.o: user.bpf.c header_user.h
	clang -target bpf -Wall -g -O2 -I /usr/include/x86_64-linux-gnu -c user.bpf.c -o user_bpfel.o
