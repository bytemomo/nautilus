package modulepb

//go:generate echo "Generating protobuf files"
//go:generate protoc -I . --go_out=. --go-grpc_out=. ./module.proto
