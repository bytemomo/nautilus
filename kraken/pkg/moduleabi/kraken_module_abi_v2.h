#ifndef KRAKEN_MODULE_ABI_V2_H
#define KRAKEN_MODULE_ABI_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kraken_module_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#if defined(KRAKEN_MODULE_BUILD)
#define KRAKEN_API __declspec(dllexport)
#else
#define KRAKEN_API __declspec(dllimport)
#endif
#else
#define KRAKEN_API __attribute__((visibility("default")))
#endif

#define KRAKEN_ABI_VERSION_V2 2u

typedef void *KrakenConnectionHandle;

typedef enum {
    KRAKEN_CONN_TYPE_STREAM = 1,
    KRAKEN_CONN_TYPE_DATAGRAM = 2,
} KrakenConnectionType;

typedef struct {
    KrakenConnectionType type;
    const char *local_addr;
    const char *remote_addr;
    const char **stack_layers;
    size_t stack_layers_count;
} KrakenConnectionInfo;

/* Send data over a connection (stream or datagram)
   - conn: connection handle
   - data: pointer to data buffer to send
   - len: length of data in bytes
   - timeout_ms: operation timeout in milliseconds (0 = no timeout)
   Returns: number of bytes sent, or -1 on error */
typedef int64_t (*KrakenSendFn)(KrakenConnectionHandle conn, const uint8_t *data, size_t len, uint32_t timeout_ms);

/* Receive data from a connection (stream or datagram)
   - conn: connection handle
   - buffer: pointer to buffer to store received data
   - buffer_size: size of the buffer
   - timeout_ms: operation timeout in milliseconds (0 = no timeout)
   Returns: number of bytes received, 0 on EOF, or -1 on error */
typedef int64_t (*KrakenRecvFn)(KrakenConnectionHandle conn, uint8_t *buffer, size_t buffer_size, uint32_t timeout_ms);

/* Get information about the connection
   - conn: connection handle
   Returns: pointer to connection info struct (valid until conn is closed) */
typedef const KrakenConnectionInfo *(*KrakenGetConnectionInfoFn)(KrakenConnectionHandle conn);

/* Open a new connection using the same conduit configuration as the provided handle.
   - conn: existing connection handle (used to pick configuration)
   - timeout_ms: dial timeout in milliseconds (0 = default)
   Returns: new connection handle or NULL on error */
typedef KrakenConnectionHandle (*KrakenOpenFn)(KrakenConnectionHandle conn, uint32_t timeout_ms);

/* Close a connection previously obtained via KrakenOpenFn.
   - conn: connection handle to close
*/
typedef void (*KrakenCloseFn)(KrakenConnectionHandle conn);

typedef struct {
    KrakenSendFn send;
    KrakenRecvFn recv;
    KrakenGetConnectionInfoFn get_info;
    KrakenOpenFn open;   /* optional, may be NULL */
    KrakenCloseFn close; /* optional, may be NULL */
} KrakenConnectionOps;

/* Main entrypoint: run the kraken with a connected conduit handle

   Parameters:
   - conn: Opaque handle to the connected conduit
   - ops: Function pointers for I/O operations on the connection
   - target: The target host:port info (for reporting purposes)
   - timeout_ms: Execution timeout in milliseconds
   - params_json: UTF-8 JSON string with module-specific parameters (may be NULL)
   - out_result: Pointer to a pointer to KrakenRunResult. Kraken allocates memory.

   Returns: 0 on success, nonzero on error.
*/
typedef int (*KrakenRunV2Fn)(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenHostPort *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResult **out_result);

/* Deallocator for buffers returned by kraken_run_v2 (same as V1) */
typedef void (*KrakenFreeV2Fn)(void *p);

/* Optional: Module initialization/cleanup functions */
typedef int (*KrakenInitFn)(void);
typedef void (*KrakenCleanupFn)(void);

KRAKEN_API int kraken_run_v2(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenHostPort *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResult **out_result);
KRAKEN_API void kraken_free_v2(void *p);

KRAKEN_API int kraken_init(void);
KRAKEN_API void kraken_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* KRAKEN_MODULE_ABI_V2_H */
