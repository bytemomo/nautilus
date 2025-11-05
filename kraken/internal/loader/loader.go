package loader

import (
	"context"
	"io"
	"sync"
	"time"
	"unsafe"

	"bytemomo/kraken/internal/domain"

	cnd "bytemomo/trident/conduit"
	utils "bytemomo/trident/conduit/utils"
)

/*
#include <stdlib.h>
#include <string.h>
#include "../../pkg/moduleabi/kraken_module_abi.h"
#include "../../pkg/moduleabi/kraken_module_abi_v2.h"
*/
import "C"

// LoadableModule is an interface for a loadable native module.
type LoadableModule interface {
	// Run runs the module.
	Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration, conduit interface{}) (domain.RunResult, error)
	// Close closes the module.
	Close() error
}

type v2ConnectionHandle struct {
	conduit interface{}
	info    *C.KrakenConnectionInfo
}

var (
	v2HandleMap             = make(map[uintptr]*v2ConnectionHandle)
	v2HandleCounter uintptr = 1
	v2HandleMutex   sync.RWMutex
)

//export go_conduit_send
func go_conduit_send(conn C.KrakenConnectionHandle, data *C.uint8_t, length C.size_t, timeout_ms C.uint32_t) C.int64_t {
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

		buf := utils.GetBuf(len(goData))
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
func go_conduit_recv(conn C.KrakenConnectionHandle, buffer *C.uint8_t, buffer_size C.size_t, timeout_ms C.uint32_t) C.int64_t {
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
func go_conduit_get_info(conn C.KrakenConnectionHandle) *C.KrakenConnectionInfo {
	v2HandleMutex.RLock()
	handle, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()

	if !ok {
		return nil
	}
	return handle.info
}

func decodeRunResult(cResult *C.KrakenRunResult) (domain.RunResult, error) {
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
				ModuleID:    C.GoString(cFinding.module_id),
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
