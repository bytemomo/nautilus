#define ORCA_PLUGIN_BUILD
#include "../../pkg/plugabi/orca_plugin_abi.h"

#include <stdint.h>
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

// ================================================================
// Minimal, header-only MQTT v3.1.1 helper (safe)
// ================================================================

typedef struct {
    uint8_t buf[512];
    size_t len;
} mqtt_packet_t;

static int mqtt_encode_string(uint8_t *buf, const char *s) {
    size_t len = strlen(s);
    buf[0] = (uint8_t)(len >> 8);
    buf[1] = (uint8_t)(len & 0xFF);
    memcpy(buf + 2, s, len);
    return (int)(len + 2);
}

static int mqtt_build_connect(mqtt_packet_t *pkt, const char *client_id, const char *user, const char *pass) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    const char *proto = "MQTT";
    size_t proto_len = strlen(proto);
    uint8_t flags = 0;
    if (user && *user)
        flags |= 0x80;
    if (pass && *pass)
        flags |= 0x40;

    p += mqtt_encode_string(p, proto);
    *p++ = 4;     // Protocol level
    *p++ = flags; // Flags
    *p++ = 0;
    *p++ = 60; // Keepalive

    p += mqtt_encode_string(p, client_id);
    if (user && *user)
        p += mqtt_encode_string(p, user);
    if (pass && *pass)
        p += mqtt_encode_string(p, pass);

    size_t rem_len = p - pkt->buf;
    uint8_t head[5];
    size_t hl = 1;
    head[0] = 0x10;
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
    *p++ = 0x82;                      // SUBSCRIBE, QoS 1
    *p++ = 2 + 2 + strlen(topic) + 1; // Remaining length (simple)
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
    size_t topic_len = strlen(topic);
    size_t msg_len = strlen(msg);
    *p++ = 0x30; // PUBLISH QoS0
    size_t rem = 2 + topic_len + msg_len;
    do {
        uint8_t b = rem % 128;
        rem /= 128;
        if (rem > 0)
            b |= 128;
        *p++ = b;
    } while (rem > 0);
    p += mqtt_encode_string(p, topic);
    memcpy(p, msg, msg_len);
    p += msg_len;
    pkt->len = p - pkt->buf;
    return (int)pkt->len;
}

static int mqtt_parse_connack(uint8_t *buf, size_t n) {
    return n >= 4 && buf[0] == 0x20 && buf[3] == 0x00;
}

// ================================================================
// Simple JSON helper (parse "creds_file" : "path")
// ================================================================

static char *json_extract_path(const char *json, const char *key) {
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

// ================================================================
// Core connection check
// ================================================================

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
    int s = tcp_connect(host, port);
    if (s < 0)
        return 0;
    mqtt_packet_t pkt;
    char cid[32];
    snprintf(cid, sizeof(cid), "ORCA_%u", (unsigned)rand());
    int len = mqtt_build_connect(&pkt, cid, user, pass);
    send(s, (const char *)pkt.buf, len, 0);

    uint8_t resp[8];
    int n = recv(s, (char *)resp, sizeof(resp), 0);
    if (!mqtt_parse_connack(resp, n)) {
        closesocket(s);
        return 0;
    }

    // Connection accepted
    *pubsub_ok = 0;
    const char *topic = "orca/test/topic";
    const char *msg = "hello from ORCA";

    // SUBSCRIBE
    len = mqtt_build_subscribe(&pkt, topic);
    send(s, (const char *)pkt.buf, len, 0);
    n = recv(s, (char *)resp, sizeof(resp), 0);
    int sub_ack = n > 0;

    // PUBLISH
    len = mqtt_build_publish(&pkt, topic, msg);
    send(s, (const char *)pkt.buf, len, 0);
    *pubsub_ok = sub_ack ? 1 : 0;

    closesocket(s);
    return 1;
}

// ================================================================
// Plugin Entry
// ================================================================

ORCA_API int ORCA_Run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, char **out_json, size_t *out_len) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    srand((unsigned)time(NULL));
    time_t ts = time(NULL);
    char *path = json_extract_path(params_json, "creds_file");

    char *json = malloc(8192);
    char findings[4096] = "";
    char logs[1024];
    snprintf(logs, sizeof(logs), "[{\"ts\":%lld,\"line\":\"MQTT assessment started\"}]", (long long)ts);

    int pubsub_flag = 0;

    // --- Anonymous test ---
    if (mqtt_check_full(host, (uint16_t)port, NULL, NULL, &pubsub_flag)) {
        strcat(findings, "{\"id\":\"MQTT-ANON\",\"plugin_id\":\"mqtt_auth_check\",\"title\":\"Anonymous authentication accepted\","
                         "\"severity\":\"high\",\"description\":\"Broker allows unauthenticated connections.\","
                         "\"tags\":[\"mqtt\",\"auth\",\"anonymous\"],\"timestamp\":");
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%lld},", (long long)ts);
        strcat(findings, tmp);
        if (pubsub_flag) {
            strcat(findings, "{\"id\":\"MQTT-PUBSUB\",\"plugin_id\":\"mqtt_auth_check\",\"title\":\"Unauthenticated pub/sub allowed\","
                             "\"severity\":\"high\",\"description\":\"Broker allows publish/subscribe without auth.\","
                             "\"tags\":[\"mqtt\",\"pubsub\",\"unauthenticated\"],\"timestamp\":");
            snprintf(tmp, sizeof(tmp), "%lld},", (long long)ts);
            strcat(findings, tmp);
        }
    }

    // --- Credential tests ---
    if (path && *path) {
        FILE *f = fopen(path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                char user[128], pass[128];
                if (sscanf(line, "%127[^:]:%127s", user, pass) == 2) {
                    int pubsub = 0;
                    if (mqtt_check_full(host, (uint16_t)port, user, pass, &pubsub)) {
                        strcat(findings, "{\"id\":\"MQTT-WEAK-CREDS\",\"plugin_id\":\"mqtt_auth_check\","
                                         "\"title\":\"Weak/default credentials accepted\","
                                         "\"severity\":\"high\",\"description\":\"Broker accepted weak credentials.\","
                                         "\"evidence\":{\"user\":\"");
                        strcat(findings, user);
                        strcat(findings, "\",\"pass\":\"");
                        strcat(findings, pass);
                        strcat(findings, "\"},\"tags\":[\"mqtt\",\"auth\",\"default-creds\"],\"timestamp\":");
                        char tmp[64];
                        snprintf(tmp, sizeof(tmp), "%lld},", (long long)ts);
                        strcat(findings, tmp);
                        if (pubsub) {
                            strcat(findings, "{\"id\":\"MQTT-PUBSUB\",\"plugin_id\":\"mqtt_auth_check\","
                                             "\"title\":\"Unauthenticated pub/sub allowed (weak creds)\","
                                             "\"severity\":\"high\",\"description\":\"Broker allows pub/sub with weak creds.\","
                                             "\"tags\":[\"mqtt\",\"pubsub\",\"weak-creds\"],\"timestamp\":");
                            snprintf(tmp, sizeof(tmp), "%lld},", (long long)ts);
                            strcat(findings, tmp);
                        }
                    }
                }
            }
            fclose(f);
        }
    }

    if (findings[strlen(findings) - 1] == ',')
        findings[strlen(findings) - 1] = '\0';

    snprintf(json, 8192, "{ \"findings\":[%s], \"logs\":%s }", findings, logs);
    *out_json = json;
    *out_len = strlen(json);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

ORCA_API void ORCA_Free(void *p) {
    if (p)
        free(p);
}
