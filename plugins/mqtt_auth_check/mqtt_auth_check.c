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
    do {
        uint8_t b = rem_len % 128;
        rem_len /= 128;
        if (rem_len > 0)
            b |= 128;
        *p++ = b;
    } while (rem_len > 0);
    p += mqtt_encode_string(p, topic);
    memcpy(p, msg, msg_len);
    pkt->len = (p + msg_len) - pkt->buf;
    return (int)pkt->len;
}

static int mqtt_parse_connack(uint8_t *buf, size_t n) {
    return n >= 4 && buf[0] == 0x20 && buf[3] == 0x00;
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

/* -------------------------------------------------------- */
/* Network Helper                                           */
/* -------------------------------------------------------- */
static int tcp_connect(const char *host, uint16_t port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;

    int s = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0)
            break;
        closesocket(s);
        s = -1;
    }
    freeaddrinfo(res);
    return s;
}

static int mqtt_check_full(const char *host, uint16_t port, const char *user, const char *pass, int *pubsub_ok) {
    *pubsub_ok = 0;
    int s = tcp_connect(host, port);
    if (s < 0)
        return 0;

    mqtt_packet_t pkt;
    char cid[32];
    snprintf(cid, sizeof(cid), "ORCA_%u", (unsigned)rand());

    // CONNECT
    int len = mqtt_build_connect(&pkt, cid, user, pass);
    if (send(s, (const char *)pkt.buf, len, 0) < 0) {
        closesocket(s);
        return 0;
    }

    uint8_t resp[8];
    int n = recv(s, (char *)resp, sizeof(resp), 0);
    if (n <= 0 || !mqtt_parse_connack(resp, n)) {
        closesocket(s);
        return 0; // Connection failed or rejected
    }

    // SUBSCRIBE
    const char *topic = "orca/test/topic";
    len = mqtt_build_subscribe(&pkt, topic);
    send(s, (const char *)pkt.buf, len, 0);
    n = recv(s, (char *)resp, sizeof(resp), 0); // Check for SUBACK
    int sub_ack = n > 0;

    // PUBLISH
    const char *msg = "hello from ORCA";
    len = mqtt_build_publish(&pkt, topic, msg);
    send(s, (const char *)pkt.buf, len, 0);

    if (sub_ack) {
        *pubsub_ok = 1;
    }

    closesocket(s);
    return 1; // Connection successful
}

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

// Helper to add a new finding to the results
static void add_finding(ORCA_RunResult *result, ORCA_Finding *finding) {
    result->findings_count++;
    result->findings = (ORCA_Finding *)realloc(result->findings, result->findings_count * sizeof(ORCA_Finding));
    result->findings[result->findings_count - 1] = *finding;
}

/* -------------------------------------------------------- */
/* Plugin Entry Point                                       */
/* -------------------------------------------------------- */

ORCA_API int ORCA_Run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, ORCA_RunResult **out_result) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    srand((unsigned)time(NULL));

    // 1. Allocate and initialize the main result structure
    ORCA_RunResult *result = (ORCA_RunResult *)calloc(1, sizeof(ORCA_RunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(host);
    result->target.port = (uint16_t)port;

    // 2. Add initial log message
    result->logs.count = 1;
    result->logs.strings = (const char **)malloc(sizeof(char *));
    result->logs.strings[0] = mystrdup("MQTT assessment started");

    int pubsub_flag = 0;
    time_t ts = time(NULL);

    // 3. Anonymous login test
    if (mqtt_check_full(host, (uint16_t)port, NULL, NULL, &pubsub_flag)) {
        ORCA_Finding f = {0};
        f.id = mystrdup("MQTT-ANON");
        f.plugin_id = mystrdup("mqtt_auth_check");
        f.success = true;
        f.title = mystrdup("Anonymous authentication accepted");
        f.severity = mystrdup("high");
        f.description = mystrdup("The MQTT broker allows unauthenticated clients to connect.");
        f.timestamp = ts;
        f.target.host = mystrdup(host);
        f.target.port = (uint16_t)port;
        f.tags.count = 3;
        f.tags.strings = (const char **)malloc(3 * sizeof(char *));
        f.tags.strings[0] = mystrdup("mqtt");
        f.tags.strings[1] = mystrdup("auth");
        f.tags.strings[2] = mystrdup("anonymous");
        add_finding(result, &f);

        if (pubsub_flag) {
            ORCA_Finding f_pubsub = {0};
            f_pubsub.id = mystrdup("MQTT-PUBSUB-ANON");
            f_pubsub.plugin_id = mystrdup("mqtt_auth_check");
            f_pubsub.success = true;
            f_pubsub.title = mystrdup("Unauthenticated publish/subscribe allowed");
            f_pubsub.severity = mystrdup("high");
            f_pubsub.description = mystrdup("The MQTT broker allows unauthenticated clients to publish and/or subscribe to topics.");
            f_pubsub.timestamp = ts;
            f_pubsub.target.host = mystrdup(host);
            f_pubsub.target.port = (uint16_t)port;
            f_pubsub.tags.count = 3;
            f_pubsub.tags.strings = (const char **)malloc(3 * sizeof(char *));
            f_pubsub.tags.strings[0] = mystrdup("mqtt");
            f_pubsub.tags.strings[1] = mystrdup("pubsub");
            f_pubsub.tags.strings[2] = mystrdup("unauthenticated");
            add_finding(result, &f_pubsub);
        }
    }

    // 4. Credential-based tests
    char *path = json_extract_path(params_json, "creds_file");
    if (path && *path) {
        FILE *f = fopen(path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                char user[128] = {0}, pass[128] = {0};
                // Simple parsing for user:pass format
                char *p = strchr(line, ':');
                if (p) {
                    *p = '\0';
                    strncpy(user, line, sizeof(user) - 1);
                    strncpy(pass, p + 1, sizeof(pass) - 1);
                    // Trim newline characters
                    user[strcspn(user, "\r\n")] = 0;
                    pass[strcspn(pass, "\r\n")] = 0;
                } else {
                    continue; // Skip malformed lines
                }

                int pubsub = 0;
                if (mqtt_check_full(host, (uint16_t)port, user, pass, &pubsub)) {
                    ORCA_Finding f = {0};
                    f.id = mystrdup("MQTT-WEAK-CREDS");
                    f.plugin_id = mystrdup("mqtt_auth_check");
                    f.success = true;
                    f.title = mystrdup("Weak/default credentials accepted");
                    f.severity = mystrdup("high");
                    f.description = mystrdup("The MQTT broker accepted a weak or default username/password combination.");
                    f.timestamp = ts;
                    f.target.host = mystrdup(host);
                    f.target.port = (uint16_t)port;

                    // Add evidence
                    f.evidence.count = 2;
                    f.evidence.items = (ORCA_KeyValue *)malloc(2 * sizeof(ORCA_KeyValue));
                    f.evidence.items[0].key = mystrdup("user");
                    f.evidence.items[0].value = mystrdup(user);
                    f.evidence.items[1].key = mystrdup("pass");
                    f.evidence.items[1].value = mystrdup(pass);

                    f.tags.count = 3;
                    f.tags.strings = (const char **)malloc(3 * sizeof(char *));
                    f.tags.strings[0] = mystrdup("mqtt");
                    f.tags.strings[1] = mystrdup("auth");
                    f.tags.strings[2] = mystrdup("default-creds");
                    add_finding(result, &f);
                }
            }
            fclose(f);
        }
    }

    // 5. Finalize and return the result
    *out_result = result;

#ifdef _WIN32
    WSACleanup();
#endif
    return 0; // Success
}

/* -------------------------------------------------------- */
/* Memory Deallocator                                       */
/* -------------------------------------------------------- */

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
    free(result->logs.strings);

    // Finally, free the main struct itself
    free(result);
}
