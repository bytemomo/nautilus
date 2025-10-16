//go:build tools
// +build tools

package plugpb

//go:generate sh -c "protoc -I . --go_out=. --go-grpc_out=. ./plugin.proto"
