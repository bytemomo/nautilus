//go:build tools
// +build tools

package plugpb

//go:generate sh -c "cd ../.. && protoc -I proto --go_out=pkg/plugpb --go-grpc_out=pkg/plugpb proto/plugin.proto"
