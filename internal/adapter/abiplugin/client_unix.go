//go:build !windows

package abiplugin

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include "../../../pkg/plugabi/orca_plugin_abi.h"

static void* my_dlopen(const char* p)              { return dlopen(p, RTLD_NOW); }
static void* my_dlsym(void* h, const char* s)      { return dlsym(h, s); }
static int   my_dlclose(void* h)                   { return dlclose(h); }
static const char* my_dlerror()                    { return dlerror(); }

// Thin bridge wrappers so Go can call function pointers.
static inline int call_ORCA_Run(ORCA_RunFn f,
                                const char* host,
                                uint32_t port,
                                uint32_t timeout_ms,
                                const char* params_json,
                                char** out_json,
                                size_t* out_len) {
    return f(host, port, timeout_ms, params_json, out_json, out_len);
}

static inline void call_ORCA_Free(ORCA_FreeFn f, void* p) { f(p); }

*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"bytemomo/orca/internal/domain"
)

type Client struct{}

func New() *Client { return &Client{} }

func (c *Client) Supports(transport string) bool {
	return strings.EqualFold(transport, "abi")
}

func (c *Client) Run(ctx context.Context, params map[string]string, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	abiConfig := ctx.Value("abi").(*domain.ABIConfig)

	libPath := abiConfig.LibraryPath + ".so"
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

	// resolve run symbol
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))
	runPtr := C.my_dlsym(handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(%s) failed: %s", symbol, C.GoString(C.my_dlerror()))
	}
	run := (C.ORCA_RunFn)(runPtr)

	// resolve free symbol
	freeSym := C.CString("ORCA_Free")
	defer C.free(unsafe.Pointer(freeSym))
	freePtr := C.my_dlsym(handle, freeSym)
	if freePtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(ORCA_Free) failed: %s", C.GoString(C.my_dlerror()))
	}
	freeFn := (C.ORCA_FreeFn)(freePtr)

	// prepare args
	hostC := C.CString(t.Host)
	defer C.free(unsafe.Pointer(hostC))
	portC := C.uint32_t(t.Port)
	timeoutMs := C.uint32_t(timeout.Milliseconds())

	paramsBytes, _ := json.Marshal(params)
	cParams := C.CString(string(paramsBytes))
	defer C.free(unsafe.Pointer(cParams))

	var outBuf *C.char
	var outLen C.size_t

	// call into plugin
	ret := C.call_ORCA_Run(run, hostC, portC, timeoutMs, cParams, &outBuf, &outLen)
	if int(ret) != 0 {
		return domain.RunResult{}, fmt.Errorf("plugin returned error code %d", int(ret))
	}
	if outBuf == nil || outLen == 0 {
		return domain.RunResult{}, errors.New("plugin returned empty buffer")
	}
	defer C.call_ORCA_Free(freeFn, unsafe.Pointer(outBuf))

	// copy buffer then decode
	buf := C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen))
	return decodeJSONResult(buf, t)
}

// decodeJSONResult is shared logic (duplicated to avoid build tag import hassles)
func decodeJSONResult(data []byte, t domain.HostPort) (domain.RunResult, error) {
	var wire struct {
		Findings []struct {
			ID, PluginID, Title, Severity, Description string
			Evidence                                   map[string]string
			Tags                                       []string
			Timestamp                                  int64
		} `json:"findings"`
		Logs []struct {
			TS   int64
			Line string
		} `json:"logs"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return domain.RunResult{}, fmt.Errorf("decode plugin JSON: %w", err)
	}
	var res domain.RunResult
	res.Target = t
	for _, f := range wire.Findings {
		ev := map[string]any{}
		for k, v := range f.Evidence {
			ev[k] = v
		}
		var tags []domain.Tag
		for _, s := range f.Tags {
			tags = append(tags, domain.Tag(s))
		}
		res.Findings = append(res.Findings, domain.Finding{
			ID: f.ID, PluginID: f.PluginID, Title: f.Title, Severity: f.Severity,
			Description: f.Description, Evidence: ev, Tags: tags, Timestamp: f.Timestamp,
			Target: t,
		})
	}
	for _, l := range wire.Logs {
		res.Logs = append(res.Logs, l.Line)
	}
	return res, nil
}
