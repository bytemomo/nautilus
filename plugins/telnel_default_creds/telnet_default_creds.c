#define ORCA_PLUGIN_BUILD
#include "../../pkg/plugabi/orca_plugin_abi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#define closesocket close
#endif

/* ------------------------------------------------------------------ */
/* ABI Version Export                                                 */
/* ------------------------------------------------------------------ */
ORCA_API const uint32_t ORCA_PLUGIN_ABI_VERSION = ORCA_ABI_VERSION;

/* ------------------------------------------------------------------ */
/* Plugin Configuration                                               */
/* ------------------------------------------------------------------ */
static const char *default_users[] = {"admin", "root", "user", "guest"};
static const char *default_passwords[] = {"admin", "root", "1234", "password", "guest"};

/* ------------------------------------------------------------------ */
/* Utility Functions for ABI Structs                                  */
/* ------------------------------------------------------------------ */

// strdup is not standard in C, so we provide our own.
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

// Helper to add a new log message to the results
static void add_log(ORCA_RunResult *result, const char *log_line) {
    result->logs.count++;
    result->logs.strings = (const char **)realloc((void *)result->logs.strings, result->logs.count * sizeof(char *));
    result->logs.strings[result->logs.count - 1] = mystrdup(log_line);
}

// Helper to add a new finding to the results
static void add_finding(ORCA_RunResult *result, ORCA_Finding *finding) {
    result->findings_count++;
    result->findings = (ORCA_Finding *)realloc(result->findings, result->findings_count * sizeof(ORCA_Finding));
    result->findings[result->findings_count - 1] = *finding;
}

/* ------------------------------------------------------------------ */
/* Network and Telnet Logic (largely unchanged)                       */
/* ------------------------------------------------------------------ */

static int connect_socket(const char *host, uint16_t port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;

    int sock = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0)
            break;
        closesocket(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

// Minimal Telnet login attempt
static int try_telnet_login(const char *host, uint16_t port, const char *user, const char *pass) {
    int s = connect_socket(host, port);
    if (s < 0)
        return 0;

    char buf[2048];
    // Simple state machine: 0=initial, 1=sent user, 2=sent pass
    int state = 0;

    // Naive sleep intervals to wait for prompts
    const int wait_ms = 500;

#ifdef _WIN32
    Sleep(wait_ms);
#else
    usleep(wait_ms * 1000);
#endif

    // Read initial banner
    recv(s, buf, sizeof(buf) - 1, 0);

    // Send username
    send(s, user, (int)strlen(user), 0);
    send(s, "\r\n", 2, 0);
#ifdef _WIN32
    Sleep(wait_ms);
#else
    usleep(wait_ms * 1000);
#endif

    // Read response (should be password prompt)
    recv(s, buf, sizeof(buf) - 1, 0);

    // Send password
    send(s, pass, (int)strlen(pass), 0);
    send(s, "\r\n", 2, 0);
#ifdef _WIN32
    Sleep(wait_ms);
#else
    usleep(wait_ms * 1000);
#endif

    // Read final response to check for shell prompt
    int n = recv(s, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        closesocket(s);
        return 0;
    }
    buf[n] = 0;

    // Heuristic: if response contains "$" or "#" -> success
    int success = (strchr(buf, '$') || strchr(buf, '#')) ? 1 : 0;
    closesocket(s);
    return success;
}

/* ------------------------------------------------------------------ */
/* Plugin Entry Point                                                 */
/* ------------------------------------------------------------------ */

ORCA_API int ORCA_Run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, ORCA_RunResult **out_result) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    // 1. Allocate and initialize the main result structure
    ORCA_RunResult *result = (ORCA_RunResult *)calloc(1, sizeof(ORCA_RunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(host);
    result->target.port = (uint16_t)port;
    add_log(result, "Default Password Audit started");

    // 2. Main plugin logic: only run for the Telnet port
    if (port == 23) {
        for (size_t i = 0; i < sizeof(default_users) / sizeof(default_users[0]); i++) {
            for (size_t j = 0; j < sizeof(default_passwords) / sizeof(default_passwords[0]); j++) {

                if (try_telnet_login(host, (uint16_t)port, default_users[i], default_passwords[j])) {
                    // 3. If successful, create a finding struct
                    time_t ts = time(NULL);

                    char log_buf[256];
                    snprintf(log_buf, sizeof(log_buf), "SUCCESS: Telnet login with %s:%s", default_users[i], default_passwords[j]);
                    add_log(result, log_buf);

                    ORCA_Finding f = {0};
                    f.id = mystrdup("TELNET-DEFAULT-CREDS");
                    f.plugin_id = mystrdup("default_password_audit");
                    f.success = true;
                    f.title = mystrdup("Default Telnet credentials accepted");
                    f.severity = mystrdup("high");
                    f.description = mystrdup("The Telnet service allowed login with a common default username and password.");
                    f.timestamp = ts;
                    f.target.host = mystrdup(host);
                    f.target.port = (uint16_t)port;

                    // Add evidence
                    f.evidence.count = 2;
                    f.evidence.items = (ORCA_KeyValue *)malloc(2 * sizeof(ORCA_KeyValue));
                    f.evidence.items[0].key = mystrdup("user");
                    f.evidence.items[0].value = mystrdup(default_users[i]);
                    f.evidence.items[1].key = mystrdup("pass");
                    f.evidence.items[1].value = mystrdup(default_passwords[j]);

                    // Add tags
                    f.tags.count = 2;
                    f.tags.strings = (const char **)malloc(2 * sizeof(char *));
                    f.tags.strings[0] = mystrdup("telnet");
                    f.tags.strings[1] = mystrdup("default-creds");

                    add_finding(result, &f);
                    goto done; // Exit after first success
                }
            }
        }
    } else {
        add_log(result, "Skipping: Port is not 23 (Telnet).");
    }

done:
    // 4. Finalize and return the result
    *out_result = result;
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

/* ------------------------------------------------------------------ */
/* Memory Deallocator                                                 */
/* ------------------------------------------------------------------ */

ORCA_API void ORCA_Free(void *p) {
    if (!p)
        return;

    ORCA_RunResult *result = (ORCA_RunResult *)p;

    // Free target host string
    free((void *)result->target.host);

    // Free findings and their nested content
    for (size_t i = 0; i < result->findings_count; i++) {
        ORCA_Finding *f = &result->findings[i];
        free((void *)f->id);
        free((void *)f->plugin_id);
        free((void *)f->title);
        free((void *)f->severity);
        free((void *)f->description);
        free((void *)f->target.host);

        // Free evidence key-value pairs
        for (size_t j = 0; j < f->evidence.count; j++) {
            free((void *)f->evidence.items[j].key);
            free((void *)f->evidence.items[j].value);
        }
        free(f->evidence.items);

        // Free tag strings
        for (size_t j = 0; j < f->tags.count; j++) {
            free((void *)f->tags.strings[j]);
        }
        free(f->tags.strings);
    }
    free(result->findings);

    // Free log strings
    for (size_t i = 0; i < result->logs.count; i++) {
        free((void *)result->logs.strings[i]);
    }
    free((void *)result->logs.strings);

    // Finally, free the main struct itself
    free(result);
}
