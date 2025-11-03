//go:build !windows

package abi

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include "../../../pkg/plugabi/orca_plugin_abi.h"
#include "../../../pkg/plugabi/orca_plugin_abi_v2.h"

static void* my_dlopen(const char* p)              { return dlopen(p, RTLD_NOW); }
static void* my_dlsym(void* h, const char* s)      { return dlsym(h, s); }
static int   my_dlclose(void* h)                   { return dlclose(h); }
static const char* my_dlerror()                    { return dlerror(); }

// Thin bridge wrappers so Go can call function pointers.
static inline int call_ORCA_Run(ORCA_RunFn f, const char* host, uint32_t port, uint32_t timeout_ms,
                                const char* params_json, ORCA_RunResult** out_result) {
    return f(host, port, timeout_ms, params_json, out_result);
}

static inline void call_ORCA_Free(ORCA_FreeFn f, void* p) { f(p); }

// V2 API wrappers
static inline int call_ORCA_Run_V2(ORCA_RunV2Fn f, ORCA_ConnectionHandle conn, const ORCA_ConnectionOps* ops,
                                   const ORCA_HostPort* target, uint32_t timeout_ms,
                                   const char* params_json, ORCA_RunResult** out_result) {
    return f(conn, ops, target, timeout_ms, params_json, out_result);
}

static inline void call_ORCA_Free_V2(ORCA_FreeV2Fn f, void* p) { f(p); }

// V2 I/O operation callbacks (implemented in Go)
int64_t go_conduit_send(ORCA_ConnectionHandle conn, uint8_t* data, size_t len, uint32_t timeout_ms);
int64_t go_conduit_recv(ORCA_ConnectionHandle conn, uint8_t* buffer, size_t buffer_size, uint32_t timeout_ms);
ORCA_ConnectionInfo* go_conduit_get_info(ORCA_ConnectionHandle conn);

*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"bytemomo/kraken/internal/domain"
	cnd "bytemomo/trident/conduit"
)

type LIBModule struct{}

func New() *LIBModule { return &LIBModule{} }

func (c *LIBModule) Supports(transport string) bool {
	return strings.EqualFold(transport, "abi")
}

type v2ConnectionHandle struct {
	conduit interface{}
	info    *C.ORCA_ConnectionInfo
}

var (
	v2HandleMap             = make(map[uintptr]*v2ConnectionHandle)
	v2HandleCounter uintptr = 1
	v2HandleMutex   sync.RWMutex
)

//export go_conduit_send
func go_conduit_send(conn C.ORCA_ConnectionHandle, data *C.uint8_t, length C.size_t, timeout_ms C.uint32_t) C.int64_t {
	v2HandleMutex.RLock()
	handle, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()

	if !ok {
		return -1
	}

	goData := C.GoBytes(unsafe.Pointer(data), C.int(length))

	switch c := handle.conduit.(type) {
	case cnd.Stream:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		n, _, err := c.Send(ctx, goData, nil, &cnd.SendOptions{})
		if err != nil {
			return -1
		}
		return C.int64_t(n)

	case cnd.Datagram:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		buf := cnd.GetBuf(len(goData))
		copy(buf.Bytes(), goData)
		msg := &cnd.DatagramMsg{
			Data: buf,
		}
		n, _, err := c.Send(ctx, msg, &cnd.SendOptions{})
		if err != nil {
			return -1
		}
		return C.int64_t(n)

	default:
		return -1
	}
}

//export go_conduit_recv
func go_conduit_recv(conn C.ORCA_ConnectionHandle, buffer *C.uint8_t, buffer_size C.size_t, timeout_ms C.uint32_t) C.int64_t {
	v2HandleMutex.RLock()
	handle, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()

	if !ok {
		return -1
	}

	switch c := handle.conduit.(type) {
	case cnd.Stream:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		maxBytes := int(buffer_size)
		if maxBytes == 0 {
			maxBytes = 4096
		}

		chunk, err := c.Recv(ctx, &cnd.RecvOptions{MaxBytes: maxBytes})
		if err == io.EOF {
			return 0
		} else if err != nil {
			return -1
		}

		if chunk != nil && chunk.Data != nil {
			data := chunk.Data.Bytes()
			n := len(data)
			if n > int(buffer_size) {
				n = int(buffer_size)
			}
			C.memcpy(unsafe.Pointer(buffer), unsafe.Pointer(&data[0]), C.size_t(n))
			chunk.Data.Release()
			return C.int64_t(n)
		}
		return 0

	case cnd.Datagram:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		maxBytes := int(buffer_size)
		if maxBytes == 0 {
			maxBytes = 4096
		}

		chunk, err := c.Recv(ctx, &cnd.RecvOptions{MaxBytes: maxBytes})
		if err == io.EOF {
			return 0
		} else if err != nil {
			return -1
		}

		if chunk != nil && chunk.Data != nil {
			data := chunk.Data.Bytes()
			n := len(data)
			if n > int(buffer_size) {
				n = int(buffer_size)
			}
			C.memcpy(unsafe.Pointer(buffer), unsafe.Pointer(&data[0]), C.size_t(n))
			chunk.Data.Release()
			return C.int64_t(n)
		}
		return 0

	default:
		return -1
	}
}

//export go_conduit_get_info
func go_conduit_get_info(conn C.ORCA_ConnectionHandle) *C.ORCA_ConnectionInfo {
	v2HandleMutex.RLock()
	handle, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()

	if !ok {
		return nil
	}
	return handle.info
}

// func (c *LIBModule) Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
// 	if timeout > 0 {
// 		var cancel context.CancelFunc
// 		ctx, cancel = context.WithTimeout(ctx, timeout)
// 		defer cancel()
// 	}

// 	return c.RunWithConduit(ctx, params, t, timeout, nil)
// }

func (c *LIBModule) RunWithConduit(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration, conduit interface{}) (domain.RunResult, error) {
	abiConfig := ctx.Value("abi").(*domain.ABIConfig)

	var extension string
	switch runtime.GOOS {
	case "darwin":
		extension = ".dylib"
	case "linux":
		extension = ".so"
	default:
		return domain.RunResult{}, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	libPath := abiConfig.LibraryPath + extension
	if libPath == "" {
		return domain.RunResult{}, fmt.Errorf("abi library path missing in exec.params")
	}
	symbol := abiConfig.Symbol
	if symbol == "" {
		symbol = "ORCA_Run"
	}

	clib := C.CString(libPath)
	defer C.free(unsafe.Pointer(clib))

	handle := C.my_dlopen(clib)
	if handle == nil {
		return domain.RunResult{}, fmt.Errorf("dlopen(%s) failed: %s", libPath, C.GoString(C.my_dlerror()))
	}
	defer C.my_dlclose(handle)

	if strings.HasSuffix(symbol, "_V2") || symbol == "ORCA_Run_V2" {
		return c.runV2(handle, symbol, params, t, timeout, conduit)
	}

	return c.runV1(handle, symbol, params, t, timeout)
}

func (c *LIBModule) runV1(handle unsafe.Pointer, symbol string, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	runPtr := C.my_dlsym(handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(%s) failed: %s", symbol, C.GoString(C.my_dlerror()))
	}
	run := (C.ORCA_RunFn)(runPtr)

	freeSym := C.CString("ORCA_Free")
	defer C.free(unsafe.Pointer(freeSym))

	freePtr := C.my_dlsym(handle, freeSym)
	if freePtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(ORCA_Free) failed: %s", C.GoString(C.my_dlerror()))
	}
	freeFn := (C.ORCA_FreeFn)(freePtr)

	hostC := C.CString(t.Host)
	defer C.free(unsafe.Pointer(hostC))

	portC := C.uint32_t(t.Port)
	timeoutMs := C.uint32_t(timeout.Milliseconds())

	paramsBytes, _ := json.Marshal(params)
	cParams := C.CString(string(paramsBytes))
	defer C.free(unsafe.Pointer(cParams))

	var outResult *C.ORCA_RunResult

	ret := C.call_ORCA_Run(run, hostC, portC, timeoutMs, cParams, &outResult)
	if int(ret) != 0 {
		return domain.RunResult{}, fmt.Errorf("plugin returned error code %d", int(ret))
	}

	if outResult == nil {
		return domain.RunResult{}, errors.New("plugin returned empty result")
	}
	defer C.call_ORCA_Free(freeFn, unsafe.Pointer(outResult))

	return decodeRunResult(outResult)
}

func (c *LIBModule) runV2(handle unsafe.Pointer, symbol string, params map[string]any, t domain.HostPort, timeout time.Duration, conduit interface{}) (domain.RunResult, error) {
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	runPtr := C.my_dlsym(handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(%s) failed: %s", symbol, C.GoString(C.my_dlerror()))
	}
	run := (C.ORCA_RunV2Fn)(runPtr)

	freeSym := C.CString("ORCA_Free_V2")
	defer C.free(unsafe.Pointer(freeSym))

	freePtr := C.my_dlsym(handle, freeSym)
	if freePtr == nil {
		freeSym = C.CString("ORCA_Free")
		defer C.free(unsafe.Pointer(freeSym))
		freePtr = C.my_dlsym(handle, freeSym)
		if freePtr == nil {
			return domain.RunResult{}, fmt.Errorf("dlsym(ORCA_Free_V2/ORCA_Free) failed: %s", C.GoString(C.my_dlerror()))
		}
	}
	freeFn := (C.ORCA_FreeV2Fn)(freePtr)

	v2HandleMutex.Lock()
	handleID := v2HandleCounter
	v2HandleCounter++
	connHandle := C.ORCA_ConnectionHandle(unsafe.Pointer(handleID))

	info := (*C.ORCA_ConnectionInfo)(C.malloc(C.sizeof_ORCA_ConnectionInfo))
	remoteAddr := fmt.Sprintf("%s:%d", t.Host, t.Port)
	info.remote_addr = C.CString(remoteAddr)
	info.local_addr = C.CString("0.0.0.0:0")

	var stackLayers []string
	if conduit != nil {
		switch c := conduit.(type) {
		case cnd.Stream:
			*(*C.ORCA_ConnectionType)(unsafe.Pointer(info)) = C.ORCA_CONN_TYPE_STREAM
			if c.LocalAddr() != nil {
				C.free(unsafe.Pointer(info.local_addr))
				info.local_addr = C.CString(c.LocalAddr().String())
			}
			if c.RemoteAddr() != nil {
				C.free(unsafe.Pointer(info.remote_addr))
				info.remote_addr = C.CString(c.RemoteAddr().String())
			}
			stackLayers = []string{"tcp"}

		case cnd.Datagram:
			*(*C.ORCA_ConnectionType)(unsafe.Pointer(info)) = C.ORCA_CONN_TYPE_DATAGRAM
			if c.LocalAddr().IsValid() {
				C.free(unsafe.Pointer(info.local_addr))
				info.local_addr = C.CString(c.LocalAddr().String())
			}
			if c.RemoteAddr().IsValid() {
				C.free(unsafe.Pointer(info.remote_addr))
				info.remote_addr = C.CString(c.RemoteAddr().String())
			}
			stackLayers = []string{"udp"}

		default:
			*(*C.ORCA_ConnectionType)(unsafe.Pointer(info)) = C.ORCA_CONN_TYPE_STREAM
			stackLayers = []string{"tcp"}
		}
	} else {
		*(*C.ORCA_ConnectionType)(unsafe.Pointer(info)) = C.ORCA_CONN_TYPE_STREAM
		stackLayers = []string{"tcp"}
	}

	info.stack_layers_count = C.size_t(len(stackLayers))
	info.stack_layers = (**C.char)(C.malloc(C.size_t(len(stackLayers)) * C.sizeof_uintptr_t))
	for i, layer := range stackLayers {
		layerPtr := (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(info.stack_layers)) + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		*layerPtr = C.CString(layer)
	}

	v2HandleMap[handleID] = &v2ConnectionHandle{
		conduit: conduit,
		info:    info,
	}
	v2HandleMutex.Unlock()

	defer func() {
		v2HandleMutex.Lock()
		delete(v2HandleMap, handleID)
		v2HandleMutex.Unlock()

		C.free(unsafe.Pointer(info.remote_addr))
		C.free(unsafe.Pointer(info.local_addr))
		for i := 0; i < len(stackLayers); i++ {
			layerPtr := (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(info.stack_layers)) + uintptr(i)*unsafe.Sizeof(uintptr(0))))
			C.free(unsafe.Pointer(*layerPtr))
		}
		C.free(unsafe.Pointer(info.stack_layers))
		C.free(unsafe.Pointer(info))
	}()

	var ops C.ORCA_ConnectionOps
	ops.send = C.ORCA_SendFn(C.go_conduit_send)
	ops.recv = C.ORCA_RecvFn(C.go_conduit_recv)
	ops.get_info = C.ORCA_GetConnectionInfoFn(C.go_conduit_get_info)

	hostC := C.CString(t.Host)
	defer C.free(unsafe.Pointer(hostC))

	var target C.ORCA_HostPort
	target.host = hostC
	target.port = C.uint16_t(t.Port)

	timeoutMs := C.uint32_t(timeout.Milliseconds())

	paramsBytes, _ := json.Marshal(params)
	cParams := C.CString(string(paramsBytes))
	defer C.free(unsafe.Pointer(cParams))

	var outResult *C.ORCA_RunResult

	ret := C.call_ORCA_Run_V2(run, connHandle, &ops, &target, timeoutMs, cParams, &outResult)
	if int(ret) != 0 {
		return domain.RunResult{}, fmt.Errorf("plugin returned error code %d", int(ret))
	}

	if outResult == nil {
		return domain.RunResult{}, errors.New("plugin returned empty result")
	}
	defer C.call_ORCA_Free_V2(freeFn, unsafe.Pointer(outResult))

	return decodeRunResult(outResult)
}

func decodeRunResult(cResult *C.ORCA_RunResult) (domain.RunResult, error) {
	var res domain.RunResult
	res.Target.Host = C.GoString(cResult.target.host)
	res.Target.Port = uint16(cResult.target.port)

	if cResult.logs.count > 0 {
		logSlice := unsafe.Slice(cResult.logs.strings, cResult.logs.count)
		for _, s := range logSlice {
			res.Logs = append(res.Logs, C.GoString(s))
		}
	}

	if cResult.findings_count > 0 {
		findingSlice := unsafe.Slice(cResult.findings, cResult.findings_count)
		for _, cFinding := range findingSlice {
			ev := make(map[string]any)
			if cFinding.evidence.count > 0 {
				evidenceSlice := unsafe.Slice(cFinding.evidence.items, cFinding.evidence.count)
				for _, kv := range evidenceSlice {
					ev[C.GoString(kv.key)] = C.GoString(kv.value)
				}
			}

			var tags []domain.Tag
			if cFinding.tags.count > 0 {
				tagSlice := unsafe.Slice(cFinding.tags.strings, cFinding.tags.count)
				for _, s := range tagSlice {
					tags = append(tags, domain.Tag(C.GoString(s)))
				}
			}

			findingTarget := domain.HostPort{
				Host: C.GoString(cFinding.target.host),
				Port: uint16(cFinding.target.port),
			}

			var timestamp time.Time
			if cFinding.timestamp != 0 {
				timestamp = time.Unix(int64(cFinding.timestamp), 0).UTC()
			} else {
				timestamp = time.Now()
			}

			res.Findings = append(res.Findings, domain.Finding{
				ID:          C.GoString(cFinding.id),
				PluginID:    C.GoString(cFinding.plugin_id),
				Success:     bool(cFinding.success),
				Title:       C.GoString(cFinding.title),
				Severity:    C.GoString(cFinding.severity),
				Description: C.GoString(cFinding.description),
				Evidence:    ev,
				Tags:        tags,
				Timestamp:   timestamp,
				Target:      findingTarget,
			})
		}
	}

	return res, nil
}
