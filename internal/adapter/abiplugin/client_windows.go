//go:build windows

package abiplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"bytemomo/orca/internal/domain"
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

	dll, err := syscall.LoadDLL(libPath)
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("LoadLibrary(%s): %w", libPath, err)
	}

	runProc, err := dll.FindProc(symbol)
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("GetProcAddress(%s): %w", symbol, err)
	}

	freeProc, err := dll.FindProc("ORCA_Free")
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("GetProcAddress(ORCA_Free): %w", err)
	}

	hostPtr, err := syscall.BytePtrFromString(t.Host)
	if err != nil {
		return domain.RunResult{}, err
	}

	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("encode params json: %w", err)
	}

	paramsPtr, err := syscall.BytePtrFromString(string(paramsBytes))
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("encode params json: %w", err)
	}

	var outPtr uintptr
	var outLen uintptr
	timeoutMs := uintptr(timeout.Milliseconds())
	r1, _, callErr := runProc.Call(
		uintptr(unsafe.Pointer(hostPtr)),
		uintptr(uint32(t.Port)),
		timeoutMs,
		uintptr(unsafe.Pointer(paramsPtr)),
		uintptr(unsafe.Pointer(&outPtr)),
		uintptr(unsafe.Pointer(&outLen)),
	)

	if callErr != syscall.Errno(0) {
		return domain.RunResult{}, fmt.Errorf("ORCA_Run call error: %v", callErr)
	}

	if int(r1) != 0 {
		return domain.RunResult{}, fmt.Errorf("plugin returned error code %d", int(r1))
	}

	if outPtr == 0 || outLen == 0 {
		return domain.RunResult{}, errors.New("plugin returned empty buffer")
	}

	// Copy then free
	data := unsafe.Slice((*byte)(unsafe.Pointer(outPtr)), int(outLen))
	buf := make([]byte, len(data))
	copy(buf, data)
	_, _, _ = freeProc.Call(outPtr)

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
