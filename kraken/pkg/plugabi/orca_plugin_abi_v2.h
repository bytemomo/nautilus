#ifndef ORCA_PLUGIN_ABI_V2_H
#define ORCA_PLUGIN_ABI_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "orca_plugin_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#if defined(ORCA_PLUGIN_BUILD)
#define ORCA_API __declspec(dllexport)
#else
#define ORCA_API __declspec(dllimport)
#endif
#else
#define ORCA_API __attribute__((visibility("default")))
#endif

#define ORCA_ABI_VERSION_V2 2u
ORCA_API extern const uint32_t ORCA_PLUGIN_ABI_VERSION_V2;

typedef void *ORCA_ConnectionHandle;

typedef enum {
    ORCA_CONN_TYPE_STREAM = 1,
    ORCA_CONN_TYPE_DATAGRAM = 2,
} ORCA_ConnectionType;

typedef struct {
    ORCA_ConnectionType type;
    const char *local_addr;
    const char *remote_addr;
    const char **stack_layers;
    size_t stack_layers_count;
} ORCA_ConnectionInfo;

/* Send data over a connection (stream or datagram)
   - conn: connection handle
   - data: pointer to data buffer to send
   - len: length of data in bytes
   - timeout_ms: operation timeout in milliseconds (0 = no timeout)
   Returns: number of bytes sent, or -1 on error */
typedef int64_t (*ORCA_SendFn)(ORCA_ConnectionHandle conn, const uint8_t *data, size_t len, uint32_t timeout_ms);

/* Receive data from a connection (stream or datagram)
   - conn: connection handle
   - buffer: pointer to buffer to store received data
   - buffer_size: size of the buffer
   - timeout_ms: operation timeout in milliseconds (0 = no timeout)
   Returns: number of bytes received, 0 on EOF, or -1 on error */
typedef int64_t (*ORCA_RecvFn)(ORCA_ConnectionHandle conn, uint8_t *buffer, size_t buffer_size, uint32_t timeout_ms);

/* Get information about the connection
   - conn: connection handle
   Returns: pointer to connection info struct (valid until conn is closed) */
typedef const ORCA_ConnectionInfo *(*ORCA_GetConnectionInfoFn)(ORCA_ConnectionHandle conn);

typedef struct {
    ORCA_SendFn send;
    ORCA_RecvFn recv;
    ORCA_GetConnectionInfoFn get_info;
} ORCA_ConnectionOps;

/* Main entrypoint: run the plugin with a connected conduit handle

   Parameters:
   - conn: Opaque handle to the connected conduit
   - ops: Function pointers for I/O operations on the connection
   - target: The target host:port info (for reporting purposes)
   - timeout_ms: Execution timeout in milliseconds
   - params_json: UTF-8 JSON string with module-specific parameters (may be NULL)
   - out_result: Pointer to a pointer to ORCA_RunResult. Plugin allocates memory.

   Returns: 0 on success, nonzero on error.
*/
typedef int (*ORCA_RunV2Fn)(ORCA_ConnectionHandle conn, const ORCA_ConnectionOps *ops, const ORCA_HostPort *target, uint32_t timeout_ms,
                            const char *params_json, ORCA_RunResult **out_result);

/* Deallocator for buffers returned by ORCA_Run_V2 (same as V1) */
typedef void (*ORCA_FreeV2Fn)(void *p);

/* Optional: Plugin initialization/cleanup functions */
typedef int (*ORCA_InitFn)(void);
typedef void (*ORCA_CleanupFn)(void);

ORCA_API int ORCA_Run_V2(ORCA_ConnectionHandle conn, const ORCA_ConnectionOps *ops, const ORCA_HostPort *target, uint32_t timeout_ms, const char *params_json,
                         ORCA_RunResult **out_result);
ORCA_API void ORCA_Free_V2(void *p);

ORCA_API int ORCA_Init(void);
ORCA_API void ORCA_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_PLUGIN_ABI_V2_H */
