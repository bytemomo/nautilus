#define ORCA_PLUGIN_BUILD
#define BUILDING_MQTT_AUTH_CHECK_V2
#include <orca_plugin_abi_v2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* ABI Version Export                                                 */
/* ------------------------------------------------------------------ */
ORCA_API const uint32_t ORCA_PLUGIN_ABI_VERSION_V2 = ORCA_ABI_VERSION_V2;

/* -------------------------------------------------------- */
/* Minimal MQTT Helper                                      */
/* -------------------------------------------------------- */
typedef struct {
    uint8_t buf[512];
    size_t len;
} mqtt_packet_t;

static int mqtt_encode_string(uint8_t *buf, const char *s) {
    size_t len = strlen(s);
    if (len > 65535)
        return -1;
    buf[0] = (uint8_t)(len >> 8);
    buf[1] = (uint8_t)(len & 0xFF);
    memcpy(buf + 2, s, len);
    return (int)(len + 2);
}

static int mqtt_build_connect(mqtt_packet_t *pkt, const char *client_id, const char *user, const char *pass) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    const char *proto = "MQTT";
    p += mqtt_encode_string(p, proto);
    *p++ = 4; // Protocol level 3.1.1
    uint8_t flags = 0;
    if (user && *user)
        flags |= 0x80;
    if (pass && *pass)
        flags |= 0x40;
    *p++ = flags;
    *p++ = 0;
    *p++ = 60; // Keepalive 60s
    p += mqtt_encode_string(p, client_id);
    if (user && *user)
        p += mqtt_encode_string(p, user);
    if (pass && *pass)
        p += mqtt_encode_string(p, pass);

    size_t rem_len = p - pkt->buf;
    uint8_t head[5];
    size_t hl = 1;
    head[0] = 0x10; // CONNECT
    size_t x = rem_len;
    do {
        uint8_t b = x % 128;
        x /= 128;
        if (x > 0)
            b |= 128;
        head[hl++] = b;
    } while (x > 0);

    memmove(pkt->buf + hl, pkt->buf, rem_len);
    memcpy(pkt->buf, head, hl);
    pkt->len = rem_len + hl;
    return (int)pkt->len;
}

static int mqtt_parse_connack(uint8_t *buf, size_t n) {
    return n >= 4 && buf[0] == 0x20 && buf[3] == 0x00;
}

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

static void add_log(ORCA_RunResult *result, const char *log_line) {
    result->logs.count++;
    result->logs.strings = (const char **)realloc((void *)result->logs.strings, result->logs.count * sizeof(char *));
    result->logs.strings[result->logs.count - 1] = mystrdup(log_line);
}

static void add_finding(ORCA_RunResult *result, ORCA_Finding *finding) {
    result->findings_count++;
    result->findings = (ORCA_Finding *)realloc(result->findings, result->findings_count * sizeof(ORCA_Finding));
    result->findings[result->findings_count - 1] = *finding;
}

/* ------------------------------------------------------------------ */
/* JSON Helper                                                        */
/* ------------------------------------------------------------------ */
static char *json_extract_path(const char *json, const char *key) {
    if (!json)
        return NULL;
    static char path[512];
    path[0] = 0;
    const char *p = strstr(json, key);
    if (!p)
        return NULL;
    p = strchr(p, ':');
    if (!p)
        return NULL;
    p++;
    while (*p && (*p == ' ' || *p == '\"'))
        p++;
    char *q = path;
    while (*p && *p != '\"' && *p != ' ' && *p != '}')
        *q++ = *p++;
    *q = 0;
    return path;
}

static int mqtt_check_conduit(ORCA_ConnectionHandle conn, const ORCA_ConnectionOps *ops, const char *user, const char *pass, uint32_t timeout_ms) {
    mqtt_packet_t pkt;
    char cid[32];
    snprintf(cid, sizeof(cid), "ORCA_%u", (unsigned)rand());

    // Build MQTT CONNECT packet
    int len = mqtt_build_connect(&pkt, cid, user, pass);

    // Send CONNECT packet over conduit
    int64_t sent = ops->send(conn, pkt.buf, len, timeout_ms);
    if (sent <= 0) {
        return 0; // Failed to send
    }

    // Receive CONNACK response
    uint8_t resp[8];
    int64_t received = ops->recv(conn, resp, sizeof(resp), timeout_ms);
    if (received <= 0) {
        return 0; // No response
    }

    // Check if CONNACK indicates success
    return mqtt_parse_connack(resp, (size_t)received);
}

/* ------------------------------------------------------------------ */
/* Plugin Entry Point                                                 */
/* ------------------------------------------------------------------ */

ORCA_API int ORCA_Run_V2(ORCA_ConnectionHandle conn, const ORCA_ConnectionOps *ops, const ORCA_HostPort *target, uint32_t timeout_ms, const char *params_json,
                         ORCA_RunResult **out_result) {
    srand((unsigned)time(NULL));

    // 1. Allocate and initialize the main result structure
    ORCA_RunResult *result = (ORCA_RunResult *)calloc(1, sizeof(ORCA_RunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(target->host);
    result->target.port = target->port;

    add_log(result, "MQTT authentication assessment started (V2)");

    // 2. Get connection info
    const ORCA_ConnectionInfo *info = ops->get_info(conn);

    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "Connection type: %s", info->type == ORCA_CONN_TYPE_STREAM ? "stream" : "datagram");
    add_log(result, log_buf);

    time_t ts = time(NULL);

    // 3. Test anonymous authentication
    add_log(result, "Testing anonymous MQTT authentication...");

    if (mqtt_check_conduit(conn, ops, NULL, NULL, timeout_ms)) {
        ORCA_Finding f = {0};
        f.id = mystrdup("MQTT-ANON");
        f.plugin_id = mystrdup("mqtt-auth-check-v2");
        f.success = true;
        f.title = mystrdup("Anonymous authentication accepted");
        f.severity = mystrdup("high");
        f.description = mystrdup("The MQTT broker allows unauthenticated clients to connect.");
        f.timestamp = ts;
        f.target.host = mystrdup(target->host);
        f.target.port = target->port;

        f.tags.count = 3;
        f.tags.strings = (const char **)malloc(3 * sizeof(char *));
        f.tags.strings[0] = mystrdup("mqtt");
        f.tags.strings[1] = mystrdup("auth");
        f.tags.strings[2] = mystrdup("anonymous");

        add_finding(result, &f);
        add_log(result, "FINDING: Anonymous authentication is allowed!");
    } else {
        add_log(result, "Anonymous authentication rejected (good)");
    }

    char *creds_path = json_extract_path(params_json, "creds_file");
    if (creds_path && *creds_path) {
        snprintf(log_buf, sizeof(log_buf), "Credential testing requested (file: %s) but not implemented in V2 single-connection model", creds_path);
        add_log(result, log_buf);
        add_log(result, "Note: V2 receives a single connected conduit; credential brute-forcing requires multiple connections");
        add_log(result, "Consider using V1 for credential testing, or implement connection pooling in the runner");
    }

    // 5. Finalize and return
    *out_result = result;
    return 0; // Success
}

/* ------------------------------------------------------------------ */
/* Memory Deallocator                                                 */
/* ------------------------------------------------------------------ */

ORCA_API void ORCA_Free_V2(void *p) {
    if (!p)
        return;

    ORCA_RunResult *result = (ORCA_RunResult *)p;

    free((void *)result->target.host);

    for (size_t i = 0; i < result->findings_count; i++) {
        ORCA_Finding *f = &result->findings[i];
        free((void *)f->id);
        free((void *)f->plugin_id);
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

/* ------------------------------------------------------------------ */
/* Optional: Initialization and Cleanup hooks                         */
/* ------------------------------------------------------------------ */

ORCA_API int ORCA_Init(void) {
    return 0; // Success
}

ORCA_API void ORCA_Cleanup(void) {
    // Cleanup if needed
}
