#ifndef ORCA_PLUGIN_ABI_H
#define ORCA_PLUGIN_ABI_H

#include <stddef.h>
#include <stdint.h>

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
#define ORCA_ABI_VERSION 1u

/* Optional: exported constant for ABI version compatibility check */
ORCA_API extern const uint32_t ORCA_PLUGIN_ABI_VERSION;

/* ------------------------------------------------------------------ */
/* Function pointer typedefs                                          */
/* ------------------------------------------------------------------ */

/* Main entrypoint: run the plugin test.
   - host, port: target to assess
   - timeout_ms: execution timeout in milliseconds
   - params_json: UTF-8 JSON string with plugin-specific parameters (may be NULL)
   - out_json: pointer to malloc'ed UTF-8 JSON blob describing results
   - out_len: length of *out_json in bytes
   Return 0 on success, nonzero on error. */
typedef int (*ORCA_RunFn)(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, char **out_json, size_t *out_len);

/* Deallocator for buffers returned by ORCA_Run. */
typedef void (*ORCA_FreeFn)(void *p);

/* ------------------------------------------------------------------ */
/* Required exports                                                   */
/* ------------------------------------------------------------------ */

ORCA_API int ORCA_Run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, char **out_json, size_t *out_len);
ORCA_API void ORCA_Free(void *p);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_PLUGIN_ABI_H */
