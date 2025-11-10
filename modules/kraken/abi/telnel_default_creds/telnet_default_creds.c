#define KRAKEN_MODULE_BUILD
#define BUILDING_TELNET_DEFAULT_CREDS_V2
#include <kraken_module_abi_v2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* ABI Version Export                                                 */
/* ------------------------------------------------------------------ */
KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION_V2 = KRAKEN_ABI_VERSION_V2;

/* ------------------------------------------------------------------ */
/* V2 Telnet Default Credentials Check                                */
/* ------------------------------------------------------------------ */

/*
 * V2 API Design Note:
 *
 * In V1, this module would create its own TCP connection and try different credentials.
 * In V2, the runner provides a connected TCP stream.
 *
 * For a proper implementation, credential testing requires multiple connections.
 * This V2 example demonstrates the API but notes the limitation.
 */

KRAKEN_API int kraken_run_v2(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenHostPort *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResult **out_result) {
    // 1. Allocate and initialize
    KrakenRunResult *result = (KrakenRunResult *)calloc(1, sizeof(KrakenRunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(target->host);
    result->target.port = target->port;

    add_log(result, "Telnet default credentials check started (V2)");

    // 2. Get connection info
    const KrakenConnectionInfo *info = ops->get_info(conn);

    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "Connection type: %s", info->type == KRAKEN_CONN_TYPE_STREAM ? "stream" : "datagram");
    add_log(result, log_buf);

    // 3. Send a probe to see if telnet responds
    const char *probe = "\r\n";
    int64_t sent = ops->send(conn, (const uint8_t *)probe, strlen(probe), timeout_ms);

    if (sent > 0) {
        snprintf(log_buf, sizeof(log_buf), "Sent %lld bytes", (long long)sent);
        add_log(result, log_buf);

        // Try to receive banner
        uint8_t recv_buffer[1024];
        int64_t received = ops->recv(conn, recv_buffer, sizeof(recv_buffer), timeout_ms);

        if (received > 0) {
            snprintf(log_buf, sizeof(log_buf), "Received %lld bytes (likely telnet banner)", (long long)received);
            add_log(result, log_buf);

            // Create a finding
            result->findings_count = 1;
            result->findings = (KrakenFinding *)calloc(1, sizeof(KrakenFinding));
            KrakenFinding *f = &result->findings[0];

            f->id = mystrdup("TELNET-SERVICE-V2");
            f->module_id = mystrdup("telnet-default-creds-v2");
            f->success = true;
            f->title = mystrdup("Telnet service detected");
            f->severity = mystrdup("medium");
            f->description = mystrdup("Telnet service is active. Note: Credential testing requires multiple connections (use V1 for full testing)");
            f->timestamp = time(NULL);
            f->target.host = mystrdup(target->host);
            f->target.port = target->port;

            f->tags.count = 2;
            f->tags.strings = (const char **)malloc(2 * sizeof(char *));
            f->tags.strings[0] = mystrdup("telnet");
            f->tags.strings[1] = mystrdup("v2-api");
        } else {
            add_log(result, "No response from telnet service");
        }
    } else {
        add_log(result, "Failed to send probe");
    }

    add_log(result, "Note: V2 single-connection model limits credential brute-forcing");
    add_log(result, "Consider using V1 for comprehensive credential testing");

    *out_result = result;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Memory Deallocator                                                 */
/* ------------------------------------------------------------------ */

KRAKEN_API void kraken_free_v2(void *p) {
    if (!p)
        return;

    KrakenRunResult *result = (KrakenRunResult *)p;

    free((void *)result->target.host);

    for (size_t i = 0; i < result->findings_count; i++) {
        KrakenFinding *f = &result->findings[i];
        free((void *)f->id);
        free((void *)f->module_id);
        free((void *)f->title);
        free((void *)f->severity);
        free((void *)f->description);
        free((void *)f->target.host);

        for (size_t j = 0; j < f->evidence.count; j++) {
            free((void *)f->evidence.items[j].key);
            free((void *)f->evidence.items[j].value);
        }
        free(f->evidence.items);

        for (size_t j = 0; j < f->tags.count; j++) {
            free((void *)f->tags.strings[j]);
        }
        free(f->tags.strings);
    }
    free(result->findings);

    for (size_t i = 0; i < result->logs.count; i++) {
        free((void *)result->logs.strings[i]);
    }
    free(result->logs.strings);

    free(result);
}

// KRAKEN_API int KrakenInit(void) {
//     return 0;
// }

// KRAKEN_API void KrakenCleanup(void) {}
