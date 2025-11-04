//go:build windows

package loader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"bytemomo/kraken/internal/domain"
	cnd "bytemomo/trident/conduit"
)

/*
#include <windows.h>
#include <stdlib.h>
#include "../../../pkg/moduleabi/kraken_module_abi.h"
#include "../../../pkg/moduleabi/kraken_module_abi_v2.h"

static HMODULE my_LoadLibrary(const char* p) { return LoadLibraryA(p); }
static FARPROC my_GetProcAddress(HMODULE h, const char* s) { return GetProcAddress(h, s); }
static BOOL my_FreeLibrary(HMODULE h) { return FreeLibrary(h); }

// Thin bridge wrappers so Go can call function pointers.
static inline int call_kraken_run(KrakenRunFn f, const char* host, uint32_t port, uint32_t timeout_ms,
                                const char* params_json, KrakenRunResult** out_result) {
    return f(host, port, timeout_ms, params_json, out_result);
}

static inline void call_kraken_free(KrakenFreeFn f, void* p) { f(p); }

// V2 API wrappers
static inline int call_kraken_run_v2(KrakenRunV2Fn f, KrakenConnectionHandle conn, const KrakenConnectionOps* ops,
                                   const KrakenHostPort* target, uint32_t timeout_ms,
                                   const char* params_json, KrakenRunResult** out_result) {
    return f(conn, ops, target, timeout_ms, params_json, out_result);
}

static inline void call_kraken_free_v2(KrakenFreeV2Fn f, void* p) { f(p); }

// V2 I/O operation callbacks (implemented in Go)
int64_t go_conduit_send(KrakenConnectionHandle conn, uint8_t* data, size_t len, uint32_t timeout_ms);
int64_t go_conduit_recv(KrakenConnectionHandle conn, uint8_t* buffer, size_t buffer_size, uint32_t timeout_ms);
KrakenConnectionInfo* go_conduit_get_info(KrakenConnectionHandle conn);

*/
import "C"

type nativeModule struct {
	handle C.HMODULE
}

func (m *nativeModule) Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration, conduit interface{}) (domain.RunResult, error) {
	abiConfig := ctx.Value("abi").(*domain.ABIConfig)

	symbol := abiConfig.Symbol
	if symbol == "" {
		symbol = "kraken_run"
	}

	if strings.HasSuffix(symbol, "_v2") || symbol == "kraken_run_v2" {
		return m.runV2(symbol, params, t, timeout, conduit)
	}

	return m.runV1(symbol, params, t, timeout)
}

func (m *nativeModule) Close() error {
	if m.handle != nil {
		ret := C.my_FreeLibrary(m.handle)
		if ret == 0 {
			return fmt.Errorf("FreeLibrary failed")
		}
	}
	return nil
}

func (m *nativeModule) runV1(symbol string, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	runPtr := C.my_GetProcAddress(m.handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("GetProcAddress(%s) failed", symbol)
	}
	run := (C.KrakenRunFn)(runPtr)

	freeSym := C.CString("kraken_free")
	defer C.free(unsafe.Pointer(freeSym))

	freePtr := C.my_GetProcAddress(m.handle, freeSym)
	if freePtr == nil {
		return domain.RunResult{}, fmt.Errorf("GetProcAddress(kraken_free) failed")
	}
	freeFn := (C.KrakenFreeFn)(freePtr)

	hostC := C.CString(t.Host)
	defer C.free(unsafe.Pointer(hostC))

	portC := C.uint32_t(t.Port)
	timeoutMs := C.uint32_t(timeout.Milliseconds())

	paramsBytes, _ := json.Marshal(params)
	cParams := C.CString(string(paramsBytes))
	defer C.free(unsafe.Pointer(cParams))

	var outResult *C.KrakenRunResult

	ret := C.call_kraken_run(run, hostC, portC, timeoutMs, cParams, &outResult)
	if int(ret) != 0 {
		return domain.RunResult{}, fmt.Errorf("module returned error code %d", int(ret))
	}

	if outResult == nil {
		return domain.RunResult{}, errors.New("module returned empty result")
	}
	defer C.call_kraken_free(freeFn, unsafe.Pointer(outResult))

	return decodeRunResult(outResult)
}

func (m *nativeModule) runV2(symbol string, params map[string]any, t domain.HostPort, timeout time.Duration, conduit interface{}) (domain.RunResult, error) {
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	runPtr := C.my_GetProcAddress(m.handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("GetProcAddress(%s) failed", symbol)
	}
	run := (C.KrakenRunV2Fn)(runPtr)

	freeSym := C.CString("kraken_free_v2")
	defer C.free(unsafe.Pointer(freeSym))

	freePtr := C.my_GetProcAddress(m.handle, freeSym)
	if freePtr == nil {
		freeSym = C.CString("kraken_free")
		defer C.free(unsafe.Pointer(freeSym))
		freePtr = C.my_GetProcAddress(m.handle, freeSym)
		if freePtr == nil {
			return domain.RunResult{}, fmt.Errorf("GetProcAddress(kraken_free_v2/kraken_free) failed")
		}
	}
	freeFn := (C.KrakenFreeV2Fn)(freePtr)

	v2HandleMutex.Lock()
	handleID := v2HandleCounter
	v2HandleCounter++
	connHandle := C.KrakenConnectionHandle(unsafe.Pointer(handleID))

	info := (*C.KrakenConnectionInfo)(C.malloc(C.sizeof_KrakenConnectionInfo))
	remoteAddr := fmt.Sprintf("%s:%d", t.Host, t.Port)
	info.remote_addr = C.CString(remoteAddr)
	info.local_addr = C.CString("0.0.0.0:0")

	var stackLayers []string
	if conduit != nil {
		switch c := conduit.(type) {
		case cnd.Stream:
			*(*C.KrakenConnectionType)(unsafe.Pointer(info)) = C.KRAKEN_CONN_TYPE_STREAM
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
			*(*C.KrakenConnectionType)(unsafe.Pointer(info)) = C.KRAKEN_CONN_TYPE_DATAGRAM
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
			*(*C.KrakenConnectionType)(unsafe.Pointer(info)) = C.KRAKEN_CONN_TYPE_STREAM
			stackLayers = []string{"tcp"}
		}
	} else {
		*(*C.KrakenConnectionType)(unsafe.Pointer(info)) = C.KRAKEN_CONN_TYPE_STREAM
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

	var ops C.KrakenConnectionOps
	ops.send = C.KrakenSendFn(C.go_conduit_send)
	ops.recv = C.KrakenRecvFn(C.go_conduit_recv)
	ops.get_info = C.KrakenGetConnectionInfoFn(C.go_conduit_get_info)

	hostC := C.CString(t.Host)
	defer C.free(unsafe.Pointer(hostC))

	var target C.KrakenHostPort
	target.host = hostC
	target.port = C.uint16_t(t.Port)

	timeoutMs := C.uint32_t(timeout.Milliseconds())

	paramsBytes, _ := json.Marshal(params)
	cParams := C.CString(string(paramsBytes))
	defer C.free(unsafe.Pointer(cParams))

	var outResult *C.KrakenRunResult

	ret := C.call_kraken_run_v2(run, connHandle, &ops, &target, timeoutMs, cParams, &outResult)
	if int(ret) != 0 {
		return domain.RunResult{}, fmt.Errorf("module returned error code %d", int(ret))
	}

	if outResult == nil {
		return domain.RunResult{}, errors.New("module returned empty result")
	}
	defer C.call_kraken_free_v2(freeFn, unsafe.Pointer(outResult))

	return decodeRunResult(outResult)
}

func Load(path string) (LoadableModule, error) {
	libPath := path + ".dll"
	clib := C.CString(libPath)
	defer C.free(unsafe.Pointer(clib))

	handle := C.my_LoadLibrary(clib)
	if handle == nil {
		return nil, fmt.Errorf("LoadLibrary(%s) failed", libPath)
	}

	return &nativeModule{handle: handle}, nil
}
