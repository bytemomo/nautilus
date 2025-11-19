#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wolfmqtt/mqtt_packet.h"

__AFL_FUZZ_INIT();

#if defined(WOLFMQTT_V5)
static void free_props(MqttProp *props) {
    if (props != NULL) {
        (void)MqttProps_Free(props);
    }
}
#else
static void free_props(void *props) {
    (void)props;
}
#endif

static void decode_connect_ack(byte *buf, int len) {
    MqttConnectAck ack;
    memset(&ack, 0, sizeof(ack));
#if defined(WOLFMQTT_V5)
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
#endif
    if (MqttDecode_ConnectAck(buf, len, &ack) >= 0) {
#if defined(WOLFMQTT_V5)
        free_props(ack.props);
#endif
    }
}

static void decode_publish(byte *buf, int len) {
    MqttPublish publish;
    memset(&publish, 0, sizeof(publish));
#if defined(WOLFMQTT_V5)
    publish.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
#endif
    if (MqttDecode_Publish(buf, len, &publish) >= 0) {
#if defined(WOLFMQTT_V5)
        free_props(publish.props);
#endif
    }
}

static void decode_publish_resp(byte *buf, int len, MqttPacketType type) {
    MqttPublishResp resp;
    memset(&resp, 0, sizeof(resp));
#if defined(WOLFMQTT_V5)
    resp.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
#endif
    if (MqttDecode_PublishResp(buf, len, (byte)type, &resp) >= 0) {
#if defined(WOLFMQTT_V5)
        free_props(resp.props);
#endif
    }
}

static void decode_subscribe_ack(byte *buf, int len) {
    MqttSubscribeAck ack;
    memset(&ack, 0, sizeof(ack));
#if defined(WOLFMQTT_V5)
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
#endif
    if (MqttDecode_SubscribeAck(buf, len, &ack) >= 0) {
#if defined(WOLFMQTT_V5)
        free_props(ack.props);
#endif
    }
}

static void decode_unsubscribe_ack(byte *buf, int len) {
    MqttUnsubscribeAck ack;
    memset(&ack, 0, sizeof(ack));
#if defined(WOLFMQTT_V5)
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
#endif
    if (MqttDecode_UnsubscribeAck(buf, len, &ack) >= 0) {
#if defined(WOLFMQTT_V5)
        free_props(ack.props);
#endif
    }
}

static void decode_ping(byte *buf, int len) {
    MqttPing ping;
    memset(&ping, 0, sizeof(ping));
    (void)MqttDecode_Ping(buf, len, &ping);
}

#if defined(WOLFMQTT_V5)
static void decode_disconnect(byte *buf, int len) {
    MqttDisconnect disc;
    memset(&disc, 0, sizeof(disc));
    disc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    if (MqttDecode_Disconnect(buf, len, &disc) >= 0) {
        free_props(disc.props);
    }
}

static void decode_auth(byte *buf, int len) {
    MqttAuth auth;
    memset(&auth, 0, sizeof(auth));
    if (MqttDecode_Auth(buf, len, &auth) >= 0) {
        free_props(auth.props);
    }
}
#endif

static void fuzz_one(const uint8_t *data, size_t size) {
    if (size < MQTT_PACKET_HEADER_MIN_SIZE || size > (size_t)INT_MAX) {
        return;
    }

    byte *mutable_buf = malloc(size);
    if (mutable_buf == NULL) {
        return;
    }
    memcpy(mutable_buf, data, size);

    decode_connect_ack(mutable_buf, (int)size);
    decode_publish(mutable_buf, (int)size);
    decode_publish_resp(mutable_buf, (int)size,
                        MQTT_PACKET_TYPE_PUBLISH_ACK);
    decode_publish_resp(mutable_buf, (int)size,
                        MQTT_PACKET_TYPE_PUBLISH_REC);
    decode_publish_resp(mutable_buf, (int)size,
                        MQTT_PACKET_TYPE_PUBLISH_REL);
    decode_publish_resp(mutable_buf, (int)size,
                        MQTT_PACKET_TYPE_PUBLISH_COMP);
    decode_subscribe_ack(mutable_buf, (int)size);
    decode_unsubscribe_ack(mutable_buf, (int)size);
    decode_ping(mutable_buf, (int)size);
#if defined(WOLFMQTT_V5)
    decode_disconnect(mutable_buf, (int)size);
    decode_auth(mutable_buf, (int)size);
#endif

    free(mutable_buf);
}

int main(void) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000)) {
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
        fuzz_one(buf, len);
    }

    return 0;
}
