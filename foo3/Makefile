all: foo3 host_bpfel.o

foo3: main.go host_bpfel.o
	go build .

host_bpfel.o: host.bpf.c
	clang -target bpf -g -c host.bpf.c -o host_bpfel.o -I /usr/include/x86_64-linux-gnu
