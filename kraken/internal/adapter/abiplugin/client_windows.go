//go:build windows

package abiplugin

/*
#include <windows.h>
#include <stdlib.h>
#include "../../../pkg/plugabi/orca_plugin_abi.h"

static HMODULE my_LoadLibrary(const char* p) { return LoadLibraryA(p); }
static FARPROC my_GetProcAddress(HMODULE h, const char* s) { return GetProcAddress(h, s); }
static BOOL my_FreeLibrary(HMODULE h) { return FreeLibrary(h); }

// Thin bridge wrappers so Go can call function pointers.
static inline int call_ORCA_Run(ORCA_RunFn f, const char* host, uint32_t port, uint32_t timeout_ms,
                                const char* params_json, ORCA_RunResult** out_result) {
    return f(host, port, timeout_ms, params_json, out_result);
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

	"bytemomo/kraken/internal/domain"
)

type Client struct{}

func New() *Client { return &Client{} }

func (c *Client) Supports(transport string) bool {
	return strings.EqualFold(transport, "abi")
}

func (c *Client) Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	abiConfig := ctx.Value("abi").(*domain.ABIConfig)

	libPath := abiConfig.LibraryPath + ".dll"
	if libPath == "" {
		return domain.RunResult{}, fmt.Errorf("abi library path missing in exec.params")
	}
	symbol := abiConfig.Symbol
	if symbol == "" {
		symbol = "ORCA_Run"
	}

	clib := C.CString(libPath)
	defer C.free(unsafe.Pointer(clib))

	handle := C.my_LoadLibrary(clib)
	if handle == nil {
		return domain.RunResult{}, fmt.Errorf("LoadLibrary(%s) failed", libPath)
	}
	defer C.my_FreeLibrary(handle)

	// resolve run symbol
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	runPtr := C.my_GetProcAddress(handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("GetProcAddress(%s) failed", symbol)
	}
	run := (C.ORCA_RunFn)(runPtr)

	// resolve free symbol
	freeSym := C.CString("ORCA_Free")
	defer C.free(unsafe.Pointer(freeSym))

	freePtr := C.my_GetProcAddress(handle, freeSym)
	if freePtr == nil {
		return domain.RunResult{}, fmt.Errorf("GetProcAddress(ORCA_Free) failed")
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

	var outResult *C.ORCA_RunResult

	// call into plugin
	ret := C.call_ORCA_Run(run, hostC, portC, timeoutMs, cParams, &outResult)
	if int(ret) != 0 {
		return domain.RunResult{}, fmt.Errorf("plugin returned error code %d", int(ret))
	}

	if outResult == nil {
		return domain.RunResult{}, errors.New("plugin returned empty result")
	}
	defer C.call_ORCA_Free(freeFn, unsafe.Pointer(outResult))

	// copy and decode
	return decodeRunResult(outResult)
}

// decodeRunResult is shared logic (duplicated to avoid build tag import hassles)
func decodeRunResult(cResult *C.ORCA_RunResult) (domain.RunResult, error) {
	var res domain.RunResult
	res.Target.Host = C.GoString(cResult.target.host)
	res.Target.Port = uint16(cResult.target.port)

	// logs
	if cResult.logs.count > 0 {
		logSlice := unsafe.Slice(cResult.logs.strings, cResult.logs.count)
		for _, s := range logSlice {
			res.Logs = append(res.Logs, C.GoString(s))
		}
	}

	// findings
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

			res.Findings = append(res.Findings, domain.Finding{
				ID:          C.GoString(cFinding.id),
				PluginID:    C.GoString(cFinding.plugin_id),
				Success:     bool(cFinding.success),
				Title:       C.GoString(cFinding.title),
				Severity:    C.GoString(cFinding.severity),
				Description: C.GoString(cFinding.description),
				Evidence:    ev,
				Tags:        tags,
				Timestamp:   int64(cFinding.timestamp),
				Target:      findingTarget,
			})
		}
	}

	return res, nil
}
