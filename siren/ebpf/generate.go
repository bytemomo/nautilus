package ebpf

//go:generate bash -c "cd program && clang -O2 -g -Wall -target bpf -c xdp_proxy.c -o xdp_proxy.bpf.o"
