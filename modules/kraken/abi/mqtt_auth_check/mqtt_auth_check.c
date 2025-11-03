#define KRAKEN_MODULE_BUILD
#define BUILDING_MQTT_AUTH_CHECK_V2
#include <kraken_module_abi_v2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* ABI Version Export                                                 */
/* ------------------------------------------------------------------ */
KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION_V2 = KRAKEN_ABI_VERSION_V2;

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

static int mqtt_build_subscribe(mqtt_packet_t *pkt, const char *topic) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    size_t topic_len = strlen(topic);
    size_t rem_len = 2 + 2 + topic_len + 1;
    *p++ = 0x82; // SUBSCRIBE
    *p++ = (uint8_t)rem_len;
    *p++ = 0;
    *p++ = 1; // Packet ID
    p += mqtt_encode_string(p, topic);
    *p++ = 0; // QoS 0
    pkt->len = p - pkt->buf;
    return (int)pkt->len;
}

static int mqtt_build_publish(mqtt_packet_t *pkt, const char *topic, const char *msg) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    *p++ = 0x30; // PUBLISH, QoS 0
    size_t topic_len = strlen(topic);
    size_t msg_len = strlen(msg);
    size_t rem_len = 2 + topic_len + msg_len;
    size_t rem_temp = rem_len;
    do {
        uint8_t b = rem_temp % 128;
        rem_temp /= 128;
        if (rem_temp > 0)
            b |= 128;
        *p++ = b;
    } while (rem_temp > 0);
    p += mqtt_encode_string(p, topic);
    memcpy(p, msg, msg_len);
    pkt->len = (p + msg_len) - pkt->buf;
    return (int)pkt->len;
}

static int mqtt_parse_connack(uint8_t *buf, size_t n) {
    return n >= 4 && buf[0] == 0x20 && buf[3] == 0x00;
}

static int mqtt_parse_suback(uint8_t *buf, size_t n) {
    return n >= 3 && buf[0] == 0x90;
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

static void add_log(KrakenRunResult *result, const char *log_line) {
    result->logs.count++;
    result->logs.strings = (const char **)realloc((void *)result->logs.strings, result->logs.count * sizeof(char *));
    result->logs.strings[result->logs.count - 1] = mystrdup(log_line);
}

static void add_finding(KrakenRunResult *result, KrakenFinding *finding) {
    result->findings_count++;
    result->findings = (KrakenFinding *)realloc(result->findings, result->findings_count * sizeof(KrakenFinding));
    result->findings[result->findings_count - 1] = *finding;
}

/* ------------------------------------------------------------------ */
/* JSON Helper                                                        */
/* ------------------------------------------------------------------ */
static char *json_extract_string(const char *json, const char *key) {
    if (!json)
        return NULL;

    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p)
        return NULL;

    p = strchr(p, ':');
    if (!p)
        return NULL;
    p++;

    // Skip whitespace and opening quote
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n'))
        p++;
    if (*p != '\"')
        return NULL;
    p++;

    // Find closing quote
    const char *end = p;
    while (*end && *end != '\"')
        end++;

    size_t len = end - p;
    char *result = (char *)malloc(len + 1);
    if (result) {
        memcpy(result, p, len);
        result[len] = '\0';
    }
    return result;
}

/* ------------------------------------------------------------------ */
/* MQTT Check Functions using V2 API                                  */
/* ------------------------------------------------------------------ */

static int mqtt_check_auth(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const char *user, const char *pass, uint32_t timeout_ms) {
    mqtt_packet_t pkt;
    char cid[32];
    snprintf(cid, sizeof(cid), "kraken_%u", (unsigned)rand());

    // Build MQTT CONNECT packet
    int len = mqtt_build_connect(&pkt, cid, user, pass);

    // Send CONNECT packet over conduit
    int64_t sent = ops->send(conn, pkt.buf, len, timeout_ms);
    if (sent <= 0) {
        return -1; // Failed to send
    }

    // Receive CONNACK response
    uint8_t resp[16];
    int64_t received = ops->recv(conn, resp, sizeof(resp), timeout_ms);
    if (received <= 0) {
        return -1; // No response
    }

    // Check if CONNACK indicates success
    return mqtt_parse_connack(resp, (size_t)received) ? 1 : 0;
}

static int mqtt_check_pubsub(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, uint32_t timeout_ms) {
    mqtt_packet_t pkt;
    const char *topic = "kraken/test/topic";

    // Try SUBSCRIBE
    int len = mqtt_build_subscribe(&pkt, topic);
    int64_t sent = ops->send(conn, pkt.buf, len, timeout_ms);
    if (sent <= 0) {
        return 0;
    }

    // Check for SUBACK
    uint8_t resp[16];
    int64_t received = ops->recv(conn, resp, sizeof(resp), timeout_ms);
    int sub_ok = (received > 0 && mqtt_parse_suback(resp, (size_t)received));

    // Try PUBLISH
    const char *msg = "hello from Kraken";
    len = mqtt_build_publish(&pkt, topic, msg);
    sent = ops->send(conn, pkt.buf, len, timeout_ms);

    return sub_ok; // Return 1 if subscribe worked
}

/* ------------------------------------------------------------------ */
/* Credential File Parser                                             */
/* ------------------------------------------------------------------ */
typedef struct {
    char **entries;
    size_t count;
} creds_list_t;

static void free_creds_list(creds_list_t *list) {
    if (!list)
        return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->entries[i]);
    }
    free(list->entries);
    list->entries = NULL;
    list->count = 0;
}

static creds_list_t load_creds_file(const char *path) {
    creds_list_t list = {0};

    FILE *f = fopen(path, "r");
    if (!f) {
        return list;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0 || line[0] == '#') {
            continue; // Skip empty lines and comments
        }

        list.count++;
        list.entries = (char **)realloc(list.entries, list.count * sizeof(char *));
        list.entries[list.count - 1] = mystrdup(line);
    }

    fclose(f);
    return list;
}

/* ------------------------------------------------------------------ */
/* Module Entry Point (V2 API)                                        */
/* ------------------------------------------------------------------ */

KRAKEN_API int kraken_run_v2(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenHostPort *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResult **out_result) {
    srand((unsigned)time(NULL));

    // 1. Allocate and initialize the main result structure
    KrakenRunResult *result = (KrakenRunResult *)calloc(1, sizeof(KrakenRunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(target->host);
    result->target.port = target->port;

    add_log(result, "MQTT authentication assessment started (V2 with conduit)");

    // 2. Get connection info
    const KrakenConnectionInfo *info = ops->get_info(conn);

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf), "Connection type: %s", info->type == KRAKEN_CONN_TYPE_STREAM ? "stream" : "datagram");
    add_log(result, log_buf);

    time_t ts = time(NULL);

    // 3. Test anonymous authentication
    add_log(result, "Testing anonymous MQTT authentication...");

    int anon_result = mqtt_check_auth(conn, ops, NULL, NULL, timeout_ms);

    if (anon_result == 1) {
        KrakenFinding f = {0};
        f.id = mystrdup("MQTT-ANON");
        f.module_id = mystrdup("mqtt-auth-check-v2");
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

        // 3b. Test publish/subscribe capabilities for anonymous
        add_log(result, "Testing anonymous publish/subscribe...");
        int pubsub_ok = mqtt_check_pubsub(conn, ops, timeout_ms);

        if (pubsub_ok) {
            KrakenFinding f_pubsub = {0};
            f_pubsub.id = mystrdup("MQTT-PUBSUB-ANON");
            f_pubsub.module_id = mystrdup("mqtt-auth-check-v2");
            f_pubsub.success = true;
            f_pubsub.title = mystrdup("Unauthenticated publish/subscribe allowed");
            f_pubsub.severity = mystrdup("critical");
            f_pubsub.description = mystrdup("The MQTT broker allows unauthenticated clients to publish and/or subscribe to topics.");
            f_pubsub.timestamp = ts;
            f_pubsub.target.host = mystrdup(target->host);
            f_pubsub.target.port = target->port;

            f_pubsub.tags.count = 3;
            f_pubsub.tags.strings = (const char **)malloc(3 * sizeof(char *));
            f_pubsub.tags.strings[0] = mystrdup("mqtt");
            f_pubsub.tags.strings[1] = mystrdup("pubsub");
            f_pubsub.tags.strings[2] = mystrdup("unauthenticated");

            add_finding(result, &f_pubsub);
            add_log(result, "FINDING: Anonymous publish/subscribe is allowed!");
        } else {
            add_log(result, "Anonymous publish/subscribe is restricted (good)");
        }

    } else if (anon_result == 0) {
        add_log(result, "Anonymous authentication rejected (good)");
    } else {
        add_log(result, "Failed to test anonymous authentication (connection issue)");
    }

    // 4. Test credentials if file provided
    char *creds_path = json_extract_string(params_json, "creds_file");
    if (creds_path && *creds_path) {
        snprintf(log_buf, sizeof(log_buf), "Credential testing from file: %s", creds_path);
        add_log(result, log_buf);

        add_log(result, "WARNING: V2 API with single conduit - cannot test multiple credentials");
        add_log(result, "Each credential test requires a fresh connection");
        add_log(result, "Consider using a connection pool or runner-side credential iteration");

        // Load credentials for reference
        creds_list_t creds = load_creds_file(creds_path);
        if (creds.count > 0) {
            snprintf(log_buf, sizeof(log_buf), "Loaded %zu credential pairs (testing requires reconnection)", creds.count);
            add_log(result, log_buf);

            // Note: In a real implementation, you would need the runner to:
            // 1. Dial a new conduit for each credential
            // 2. Pass that new conduit to this function
            // 3. Or implement a connection pool pattern
            //
            // For now, just log that credentials were found
            add_log(result, "Credentials available for testing in future multi-connection implementation");
        } else {
            snprintf(log_buf, sizeof(log_buf), "No credentials loaded from %s", creds_path);
            add_log(result, log_buf);
        }

        free_creds_list(&creds);
        free(creds_path);
    }

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
