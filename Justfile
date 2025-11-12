
set shell := ["bash", "-c"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

kraken_build_all: kraken_build kraken_build_modules

kraken_build:
    cd kraken/pkg/modulepb && go generate
    go build -o dist/kraken ./kraken/main.go

kraken_build_modules:
    cd modules/kraken/abi && just clean-all
    cd modules/kraken/abi && just build-all

siren_build:
    rm -f ./siren/ebpf/program/xdp_proxy.bpf.o
    go generate ./siren/ebpf
    go build -o dist/siren ./siren/cmd/siren
