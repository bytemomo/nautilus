#define KRAKEN_MODULE_BUILD
#define BUILDING_TLS_VERSION_CHECK
#include <kraken_module_abi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

/* ------------------------------------------------------------------ */
/* ABI Version Export                                                 */
/* ------------------------------------------------------------------ */
KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION = KRAKEN_ABI_VERSION;

/* ------------------------------------------------------------------ */
/* OpenSSL Version Compatibility                                      */
/* ------------------------------------------------------------------ */
#ifndef TLS1_VERSION
#define TLS1_VERSION 0
#endif
#ifndef TLS1_1_VERSION
#define TLS1_1_VERSION 0
#endif
#ifndef TLS1_2_VERSION
#define TLS1_2_VERSION 0
#endif
#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION 0
#endif

/* ------------------------------------------------------------------ */
/* Utility Functions for ABI Structs                                  */
/* ------------------------------------------------------------------ */

static char *mystrdup(const char *s) {
    if (!s)
        return NULL;
    size_t len = strlen(s) + 1;
    char *p = (char *)malloc(len);
    if (p) {
        memcpy(p, s, len);
    }
    return p;
}

static void add_log(KrakenRunResult *result, const char *log_line) {
    result->logs.count++;
    result->logs.strings = (const char **)realloc((void *)result->logs.strings, result->logs.count * sizeof(char *));
    result->logs.strings[result->logs.count - 1] = mystrdup(log_line);
}

/* ------------------------------------------------------------------ */
/* TLS Check Logic                                                    */
/* ------------------------------------------------------------------ */

static int try_tls_version(const char *host, uint16_t port, int version) {
    if (version == 0) {
        return -1; // Indicates the version is not available in this OpenSSL build
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return 0;

    // Set the specific TLS protocol version to test
    SSL_CTX_set_min_proto_version(ctx, version);
    SSL_CTX_set_max_proto_version(ctx, version);

    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        SSL_CTX_free(ctx);
        return 0;
    }

    char target[256];
    snprintf(target, sizeof(target), "%s:%u", host, port);
    BIO_set_conn_hostname(bio, target);

    SSL *ssl = NULL;
    BIO_get_ssl(bio, &ssl);
    if (ssl) {
        // Set SNI, which is crucial for many modern servers
        SSL_set_tlsext_host_name(ssl, host);
    }

    // Attempt to connect and perform handshake
    int ok = (BIO_do_connect(bio) > 0);

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return ok ? 1 : 0;
}

static const char *status_str(int v) {
    return v < 0 ? "not_available" : (v ? "supported" : "not_supported");
}

/* ------------------------------------------------------------------ */
/* Module Entry Point                                                 */
/* ------------------------------------------------------------------ */

KRAKEN_API int kraken_run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    // OpenSSL initialization (for versions < 1.1.0)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

    // 1. Allocate and initialize the main result structure
    KrakenRunResult *result = (KrakenRunResult *)calloc(1, sizeof(KrakenRunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(host);
    result->target.port = (uint16_t)port;

    // 2. Perform TLS version checks
    const int versions_to_check[] = {TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION};
    const char *version_names[] = {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"};
    const char *version_keys[] = {"tls1.0", "tls1.1", "tls1.2", "tls1.3"};
    int results[4];

    for (int i = 0; i < 4; ++i) {
        results[i] = try_tls_version(host, (uint16_t)port, versions_to_check[i]);
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "Check %s: %s", version_names[i], status_str(results[i]));
        add_log(result, log_buf);
    }

    // 3. Create a single finding to report all results
    result->findings_count = 1;
    result->findings = (KrakenFinding *)calloc(1, sizeof(KrakenFinding));
    KrakenFinding *f = &result->findings[0];

    f->id = mystrdup("TLS-SUPPORT-OVERVIEW");
    f->module_id = mystrdup("tls_version_check");
    f->success = true;
    f->title = mystrdup("TLS Protocol Support Summary");
    f->severity = mystrdup("info");
    f->description = mystrdup("A summary of the TLS protocol versions supported by the target server.");
    f->timestamp = time(NULL);
    f->target.host = mystrdup(host);
    f->target.port = (uint16_t)port;

    // 4. Populate evidence with the results of each check
    f->evidence.count = 4;
    f->evidence.items = (KrakenKeyValue *)malloc(4 * sizeof(KrakenKeyValue));
    for (int i = 0; i < 4; ++i) {
        f->evidence.items[i].key = mystrdup(version_keys[i]);
        f->evidence.items[i].value = mystrdup(status_str(results[i]));
    }

    // 5. Add relevant tags
    f->tags.count = 2;
    f->tags.strings = (const char **)malloc(2 * sizeof(char *));
    f->tags.strings[0] = mystrdup("tls");
    f->tags.strings[1] = mystrdup("ssl");

    // 6. Finalize and return
    *out_result = result;

#ifdef _WIN32
    WSACleanup();
#endif
    return 0; // Success
}

/* ------------------------------------------------------------------ */
/* Memory Deallocator                                                 */
/* ------------------------------------------------------------------ */

KRAKEN_API void kraken_free(void *p) {
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
        free((void *)f->tags.strings);
    }
    free(result->findings);

    for (size_t i = 0; i < result->logs.count; i++) {
        free((void *)result->logs.strings[i]);
    }
    free((void *)result->logs.strings);

    free(result);
}
