#include <stdint.h>
#define KRAKEN_MODULE_BUILD
#define BUILDING_MQTT_AUTH_CHECK_V2
#include <kraken_module_abi_v2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
/* MQTT Check Functions                                               */
/* ------------------------------------------------------------------ */

static int mqtt_check_sys_leakage(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const char *user, const char *pass, uint32_t timeout_ms) {
    mqtt_packet_t pkt;
    char cid[32];
    snprintf(cid, sizeof(cid), "kraken_%u", (unsigned)rand());

    int len = mqtt_build_connect(&pkt, cid, user, pass);

    int64_t sent = ops->send(conn, pkt.buf, len, timeout_ms);
    if (sent <= 0) {
        return -1; // Failed to send
    }

    uint8_t resp[16];
    int64_t received = ops->recv(conn, resp, sizeof(resp), timeout_ms);
    if (received <= 0) {
        return -1; // No response
    }

    if (mqtt_parse_connack(resp, (size_t)received)) {
        return -1; // No CONNACK
    }

    mqtt_packet_t sub_pkt;
    len = mqtt_build_subscribe(&sub_pkt, "#");
    if (ops->send(conn, sub_pkt.buf, len, timeout_ms)) {
        return -1; // Failed to send
    }

    received = ops->recv(conn, resp, sizeof(resp), timeout_ms);
    if (received <= 0) {
        return -1; // No response
    }

    if (mqtt_parse_suback(resp, (size_t)received)) {
        return -1; // No Suback
    }

    // TODO: Wait to read some information
    // under $SYS, here the timeout is foundamental to
    // avoid blocking behaviour from this plugin.

    return 0;
}

KRAKEN_API int kraken_run_v2(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenHostPort *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResult **out_result) {
    srand((unsigned)time(NULL));

    KrakenRunResult *result = (KrakenRunResult *)calloc(1, sizeof(KrakenRunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(target->host);
    result->target.port = target->port;
    add_log(result, "MQTT sys leakage assessment started");

    const KrakenConnectionInfo *info = ops->get_info(conn);

    // % TODO

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
