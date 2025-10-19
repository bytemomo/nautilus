#ifndef ORCA_PLUGIN_ABI_V2_H
#define ORCA_PLUGIN_ABI_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Include V1 header for shared type definitions
#include "orca_plugin_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Platform export macro                                              */
/* ------------------------------------------------------------------ */
#if defined(_WIN32)
#if defined(ORCA_PLUGIN_BUILD)
#define ORCA_API __declspec(dllexport)
#else
#define ORCA_API __declspec(dllimport)
#endif
#else
#define ORCA_API __attribute__((visibility("default")))
#endif

/* ------------------------------------------------------------------ */
/* ABI version                                                        */
/* ------------------------------------------------------------------ */
#define ORCA_ABI_VERSION_V2 2u

/* Optional: exported constant for ABI version compatibility check */
ORCA_API extern const uint32_t ORCA_PLUGIN_ABI_VERSION_V2;

/* ------------------------------------------------------------------ */
/* Connection Handle - Opaque pointer to a conduit stream/datagram   */
/* ------------------------------------------------------------------ */

/* Opaque handle to a connected conduit (managed by the runner) */
typedef void *ORCA_ConnectionHandle;

/* Connection types that the handle can represent */
typedef enum {
    ORCA_CONN_TYPE_STREAM = 1,   /* Stream-based (TCP, TLS, etc.) */
    ORCA_CONN_TYPE_DATAGRAM = 2, /* Datagram-based (UDP, DTLS, etc.) */
} ORCA_ConnectionType;

/* Connection metadata */
typedef struct {
    ORCA_ConnectionType type;
    const char *local_addr;    /* Local address string (e.g., "192.168.1.10:12345") */
    const char *remote_addr;   /* Remote address string (e.g., "10.0.0.1:80") */
    const char **stack_layers; /* Array of layer names (e.g., ["tcp", "tls"]) */
    size_t stack_layers_count;
} ORCA_ConnectionInfo;

/* ------------------------------------------------------------------ */
/* I/O operations on connection handle                                */
/* ------------------------------------------------------------------ */

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

/* Connection I/O operations table passed to the plugin */
typedef struct {
    ORCA_SendFn send;
    ORCA_RecvFn recv;
    ORCA_GetConnectionInfoFn get_info;
} ORCA_ConnectionOps;

/* ------------------------------------------------------------------ */
/* Data structures - shared with V1 via orca_plugin_abi.h            */
/* ------------------------------------------------------------------ */

// ORCA_HostPort, ORCA_StringList, ORCA_KeyValue, ORCA_Evidence,
// ORCA_Finding, and ORCA_RunResult are defined in orca_plugin_abi.h

/* ------------------------------------------------------------------ */
/* Function pointer typedefs                                          */
/* ------------------------------------------------------------------ */

/* V2 Main entrypoint: run the plugin with a connected conduit handle

   Key difference from V1: Instead of receiving host:port and making its own
   connection, the plugin receives an already-connected handle. The conduit
   (TCP, TLS, UDP, DTLS, etc.) is established by the runner based on the
   module's conduit configuration.

   Parameters:
   - conn: Opaque handle to the connected conduit
   - ops: Function pointers for I/O operations on the connection
   - target: The target host:port info (for reporting purposes)
   - timeout_ms: Execution timeout in milliseconds
   - params_json: UTF-8 JSON string with module-specific parameters (may be NULL)
   - out_result: Pointer to a pointer to ORCA_RunResult. Plugin allocates memory.

   Returns: 0 on success, nonzero on error.

   Note: The plugin MUST NOT close the connection. The runner manages the
   connection lifecycle. The plugin should only use it for I/O operations.
*/
typedef int (*ORCA_RunV2Fn)(ORCA_ConnectionHandle conn, const ORCA_ConnectionOps *ops, const ORCA_HostPort *target, uint32_t timeout_ms,
                            const char *params_json, ORCA_RunResult **out_result);

/* Deallocator for buffers returned by ORCA_Run_V2 (same as V1) */
typedef void (*ORCA_FreeV2Fn)(void *p);

/* Optional: Plugin initialization/cleanup functions */
typedef int (*ORCA_InitFn)(void);
typedef void (*ORCA_CleanupFn)(void);

/* ------------------------------------------------------------------ */
/* Required exports for V2 plugins                                    */
/* ------------------------------------------------------------------ */

/* Main V2 entrypoint - receives connected conduit handle */
ORCA_API int ORCA_Run_V2(ORCA_ConnectionHandle conn, const ORCA_ConnectionOps *ops, const ORCA_HostPort *target, uint32_t timeout_ms, const char *params_json,
                         ORCA_RunResult **out_result);

/* Memory deallocator */
ORCA_API void ORCA_Free_V2(void *p);

/* Optional: initialization and cleanup hooks */
ORCA_API int ORCA_Init(void);     /* Called once when plugin is loaded (optional) */
ORCA_API void ORCA_Cleanup(void); /* Called once before plugin is unloaded (optional) */

/* ------------------------------------------------------------------ */
/* Helper macros for plugin implementation                            */
/* ------------------------------------------------------------------ */

/* Example usage in plugin implementation:
 *
 * ORCA_API int ORCA_Run_V2(
 *     ORCA_ConnectionHandle conn,
 *     const ORCA_ConnectionOps *ops,
 *     const ORCA_HostPort *target,
 *     uint32_t timeout_ms,
 *     const char *params_json,
 *     ORCA_RunResult **out_result)
 * {
 *     // Get connection info
 *     const ORCA_ConnectionInfo *info = ops->get_info(conn);
 *
 *     // Send request
 *     const char *request = "GET / HTTP/1.0\r\n\r\n";
 *     int64_t sent = ops->send(conn, (uint8_t*)request, strlen(request), timeout_ms);
 *     if (sent < 0) return -1;
 *
 *     // Receive response
 *     uint8_t buffer[4096];
 *     int64_t received = ops->recv(conn, buffer, sizeof(buffer), timeout_ms);
 *     if (received < 0) return -1;
 *
 *     // Process and create findings...
 *     *out_result = create_result(...);
 *     return 0;
 * }
 */

/* ------------------------------------------------------------------ */
/* Backward compatibility notes                                       */
/* ------------------------------------------------------------------ */

/*
 * V1 vs V2 Comparison:
 *
 * V1 (ORCA_Run):
 *   - Plugin receives host:port
 *   - Plugin creates its own connection
 *   - Plugin handles all transport logic
 *   - Less flexible (hard to change transport)
 *
 * V2 (ORCA_Run_V2):
 *   - Plugin receives connected handle
 *   - Runner creates connection based on module config
 *   - Plugin focuses on protocol logic only
 *   - Highly flexible (same code works over TCP, TLS, UDP, etc.)
 *
 * Migration path:
 *   - V1 plugins continue to work (legacy support)
 *   - New plugins should use V2 API
 *   - V1 plugins can be wrapped to work with conduits
 */

#ifdef __cplusplus
}
#endif

#endif /* ORCA_PLUGIN_ABI_V2_H */
