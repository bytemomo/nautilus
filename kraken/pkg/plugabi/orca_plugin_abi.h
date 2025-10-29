#ifndef ORCA_PLUGIN_ABI_H
#define ORCA_PLUGIN_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#define ORCA_ABI_VERSION 2u
ORCA_API extern const uint32_t ORCA_PLUGIN_ABI_VERSION;

typedef struct {
    const char *host;
    uint16_t port;
} ORCA_HostPort;

typedef struct {
    const char **strings;
    size_t count;
} ORCA_StringList;

typedef struct {
    const char *key;
    const char *value;
} ORCA_KeyValue;

typedef struct {
    ORCA_KeyValue *items;
    size_t count;
} ORCA_Evidence;

typedef struct {
    const char *id;
    const char *plugin_id;
    bool success;
    const char *title;
    const char *severity;
    const char *description;
    ORCA_Evidence evidence;
    ORCA_StringList tags;
    int64_t timestamp;
    ORCA_HostPort target;
} ORCA_Finding;

typedef struct {
    ORCA_HostPort target;
    ORCA_Finding *findings;
    size_t findings_count;
    ORCA_StringList logs;
} ORCA_RunResult;

/* Main entrypoint: run the plugin test.
   - host, port: target to assess
   - timeout_ms: execution timeout in milliseconds
   - params_json: UTF-8 JSON string with plugin-specific parameters (may be NULL)
   - out_result: pointer to a pointer to a ORCA_RunResult struct. The plugin allocates memory for the struct.
   Return 0 on success, nonzero on error. */
typedef int (*ORCA_RunFn)(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, ORCA_RunResult **out_result);

/* Deallocator for buffers returned by ORCA_Run. */
typedef void (*ORCA_FreeFn)(void *p);

ORCA_API int ORCA_Run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, ORCA_RunResult **out_result);
ORCA_API void ORCA_Free(void *p);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_PLUGIN_ABI_H */
