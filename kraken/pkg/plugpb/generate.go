//go:build tools
// +build tools

package plugpb

//go:generate echo "Generating protobuf files"
//go:generate protoc -I . --go_out=. --go-grpc_out=. ./plugin.proto
