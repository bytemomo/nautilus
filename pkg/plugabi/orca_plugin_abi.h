#ifndef ORCA_PLUGIN_ABI_H
#define ORCA_PLUGIN_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#ifdef ORCA_PLUGIN_EXPORTS
#define ORCA_API __declspec(dllexport)
#else
#define ORCA_API __declspec(dllimport)
#endif
#else
#define ORCA_API __attribute__((visibility("default")))
#endif

// Increment if you break ABI. ORCA checks this at load time.
#define ORCA_ABI_VERSION 1

// Optional: plugin can export this exact symbol with the same value.
// ORCA validates if present (not required).
ORCA_API extern const uint32_t ORCA_PLUGIN_ABI_VERSION;

// Metadata is optional. Return 0 on success, non-zero on error.
// If buf is NULL or buf_len == 0, return required size in *needed_out.
typedef int (*ORCA_MetadataFn)(char *buf, size_t buf_len, size_t *needed_out);

// Main entrypoint. ORCA passes only host:port and a timeout (ms).
// On success, return 0 and set *out_json to a malloc'ed UTF-8 JSON blob
// with the following schema (RunResponse):
//   { "findings":[{ ... }], "logs":[{ "ts": <int64>, "line": "<str>" }] }
// ORCA will call ORCA_Free on *out_json. Implementations must allocate with the
// same CRT.
typedef int (*ORCA_RunFn)(const char *host, uint32_t port, uint32_t timeout_ms,
                          char **out_json, size_t *out_len);

// ORCA calls this to free any buffers returned by ORCA_Run.
typedef void (*ORCA_FreeFn)(void *p);

// Exported symbols the loader will resolve:
//   ORCA_Run   : ORCA_RunFn (required)
//   ORCA_Free  : ORCA_FreeFn (required)
//   ORCA_Metadata : ORCA_MetadataFn (optional)
//   ORCA_PLUGIN_ABI_VERSION : uint32_t (optional)
ORCA_API int ORCA_Run(const char *host, uint32_t port, uint32_t timeout_ms,
                      char **out_json, size_t *out_len);
ORCA_API void ORCA_Free(void *p);
ORCA_API int ORCA_Metadata(char *buf, size_t buf_len, size_t *needed_out);
ORCA_API const uint32_t ORCA_PLUGIN_ABI_VERSION;

#endif // ORCA_PLUGIN_ABI_H
