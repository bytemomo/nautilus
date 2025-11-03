#ifndef KRAKEN_MODULE_ABI_H
#define KRAKEN_MODULE_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#define KRAKEN_ABI_VERSION 1u
KRAKEN_API extern const uint32_t KRAKEN_MODULE_ABI_VERSION;

typedef struct {
    const char *host;
    uint16_t port;
} KrakenHostPort;

typedef struct {
    const char **strings;
    size_t count;
} KrakenStringList;

typedef struct {
    const char *key;
    const char *value;
} KrakenKeyValue;

typedef struct {
    KrakenKeyValue *items;
    size_t count;
} KrakenEvidence;

typedef struct {
    const char *id;
    const char *module_id;
    bool success;
    const char *title;
    const char *severity;
    const char *description;
    KrakenEvidence evidence;
    KrakenStringList tags;
    int64_t timestamp;
    KrakenHostPort target;
} KrakenFinding;

typedef struct {
    KrakenHostPort target;
    KrakenFinding *findings;
    size_t findings_count;
    KrakenStringList logs;
} KrakenRunResult;

/* Main entrypoint: run the module test.
   - host, port: target to assess
   - timeout_ms: execution timeout in milliseconds
   - params_json: UTF-8 JSON string with module-specific parameters (may be NULL)
   - out_result: pointer to a pointer to a KrakenRunResult struct. The module allocates memory for the struct.
   Return 0 on success, nonzero on error. */
typedef int (*KrakenRunFn)(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result);

/* Deallocator for buffers returned by kraken_run. */
typedef void (*KrakenFreeFn)(void *p);

KRAKEN_API int kraken_run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result);
KRAKEN_API void kraken_free(void *p);

#ifdef __cplusplus
}
#endif

#endif /* KRAKEN_MODULE_ABI_H */
