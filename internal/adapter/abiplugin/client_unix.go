//go:build !windows

package abiplugin

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
typedef int (*ORCA_RunFn)(const char*, unsigned int, unsigned int, char**, size_t*);
typedef void (*ORCA_FreeFn)(void*);
static void* my_dlopen(const char* p) { return dlopen(p, RTLD_NOW); }
static void* my_dlsym(void* h, const char* s) { return dlsym(h, s); }
static const char* my_dlerror() { return dlerror(); }
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
	libPath := params["library"]
	if libPath == "" {
		return domain.RunResult{}, fmt.Errorf("abi library path missing in exec.params")
	}
	symbol := params["symbol"]
	if symbol == "" {
		symbol = "ORCA_Run"
	}

	clib := C.CString(libPath)
	defer C.free(unsafe.Pointer(clib))
	h := C.my_dlopen(clib)
	if h == nil {
		return domain.RunResult{}, fmt.Errorf("dlopen(%s): %s", libPath, C.GoString(C.my_dlerror()))
	}

	runSym := C.CString(symbol)
	defer C.free(unsafe.Pointer(runSym))
	freeSym := C.CString("ORCA_Free")
	defer C.free(unsafe.Pointer(freeSym))

	runPtr := C.my_dlsym(h, runSym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(%s): %s", symbol, C.GoString(C.my_dlerror()))
	}
	freePtr := C.my_dlsym(h, freeSym)
	if freePtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(ORCA_Free): %s", C.GoString(C.my_dlerror()))
	}

	run := (C.ORCA_RunFn)(runPtr)
	fre := (C.ORCA_FreeFn)(freePtr)

	hostC := C.CString(t.Host)
	defer C.free(unsafe.Pointer(hostC))
	portC := C.uint(t.Port)
	timeoutMs := C.uint(timeout.Milliseconds())
	var outBuf *C.char
	var outLen C.size_t

	// Blocking call; plugin expected to respect timeoutMs
	ret := run(hostC, portC, timeoutMs, &outBuf, &outLen)
	if ret != 0 {
		return domain.RunResult{}, fmt.Errorf("plugin returned error code %d", int(ret))
	}
	if outBuf == nil || outLen == 0 {
		return domain.RunResult{}, errors.New("plugin returned empty buffer")
	}
	defer fre(unsafe.Pointer(outBuf))

	// Parse JSON to RunResult
	data := C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen))
	return decodeJSONResult(data, t)
}

func decodeJSONResult(data []byte, t domain.HostPort) (domain.RunResult, error) {
	var wire struct {
		Findings []struct {
			ID, PluginID, Title, Severity, Description string
			Evidence                                   map[string]string
			Tags                                       []string
			Timestamp                                  int64
		} `json:"findings"`
		Logs []struct {
			TS   int64  `json:"ts"`
			Line string `json:"line"`
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
