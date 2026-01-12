#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wolfmqtt/mqtt_client.h"

__AFL_FUZZ_INIT();

#ifdef WOLFMQTT_V5
static int Handle_Props(MqttClient *client, MqttProp *props, byte use_cb,
                        byte free_props) {
    int rc = MQTT_CODE_SUCCESS;

    if (props != NULL) {
#ifdef WOLFMQTT_PROPERTY_CB
        if ((use_cb == 1) && (client->property_cb != NULL)) {
            int rc_err = client->property_cb(client, props,
                                             client->property_ctx);
            if (rc_err < 0) {
                rc = rc_err;
            }
        }
#else
        (void)client;
        (void)use_cb;
#endif
        if (free_props) {
            MqttProps_Free(props);
        }
    }
    return rc;
}
#endif

static int MqttClient_DecodePacket(MqttClient *client, byte *rx_buf,
                                   word32 rx_len, void *packet_obj,
                                   MqttPacketType *ppacket_type,
                                   MqttQoS *ppacket_qos, word16 *ppacket_id,
                                   int doProps) {
    int rc = MQTT_CODE_SUCCESS;
    MqttPacket *header;
    MqttPacketType packet_type;
    MqttQoS packet_qos;
    word16 packet_id = 0;

    if (rx_buf == NULL || rx_len < MQTT_PACKET_HEADER_MIN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    header = (MqttPacket *)rx_buf;
    packet_type = (MqttPacketType)MQTT_PACKET_TYPE_GET(header->type_flags);
    if (ppacket_type) {
        *ppacket_type = packet_type;
    }
    packet_qos = (MqttQoS)MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);
    if (ppacket_qos) {
        *ppacket_qos = packet_qos;
    }

    if (ppacket_id || packet_obj) {
        switch (packet_type) {
        case MQTT_PACKET_TYPE_CONNECT_ACK: {
            MqttConnectAck connect_ack, *p_connect_ack = &connect_ack;
            if (packet_obj) {
                p_connect_ack = (MqttConnectAck *)packet_obj;
            } else {
                XMEMSET(p_connect_ack, 0, sizeof(MqttConnectAck));
            }
#ifdef WOLFMQTT_V5
            p_connect_ack->protocol_level = client->protocol_level;
#endif
            rc = MqttDecode_ConnectAck(rx_buf, rx_len, p_connect_ack);
#ifdef WOLFMQTT_V5
            if (rc >= 0 && doProps) {
                int tmp = Handle_Props(client, p_connect_ack->props,
                                       (packet_obj != NULL), 1);
                p_connect_ack->props = NULL;
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
#endif
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH: {
            MqttPublish publish, *p_publish;
            if (packet_obj) {
                p_publish = (MqttPublish *)packet_obj;
#ifdef WOLFMQTT_V5
                p_publish->protocol_level = client->protocol_level;
#endif
            } else {
                p_publish = &publish;
                XMEMSET(p_publish, 0, sizeof(MqttPublish));
            }
            rc = MqttDecode_Publish(rx_buf, rx_len, p_publish);
            if (rc >= 0) {
                packet_id = p_publish->packet_id;
#ifdef WOLFMQTT_V5
                if (doProps) {
                    int tmp = Handle_Props(client, p_publish->props,
                                           (packet_obj != NULL), 0);
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
#endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_PUBLISH_COMP: {
            MqttPublishResp publish_resp, *p_publish_resp = &publish_resp;
            if (packet_obj) {
                p_publish_resp = (MqttPublishResp *)packet_obj;
            } else {
                XMEMSET(p_publish_resp, 0, sizeof(MqttPublishResp));
            }

#ifdef WOLFMQTT_V5
            p_publish_resp->protocol_level = client->protocol_level;
#endif
            rc = MqttDecode_PublishResp(rx_buf, rx_len, packet_type,
                                        p_publish_resp);
            if (rc >= 0) {
                packet_id = p_publish_resp->packet_id;
#ifdef WOLFMQTT_V5
                if (doProps) {
                    int tmp = Handle_Props(client, p_publish_resp->props,
                                           (packet_obj != NULL), 1);
                    p_publish_resp->props = NULL;
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
#endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK: {
            MqttSubscribeAck subscribe_ack, *p_subscribe_ack = &subscribe_ack;
            if (packet_obj) {
                p_subscribe_ack = (MqttSubscribeAck *)packet_obj;
            } else {
                XMEMSET(p_subscribe_ack, 0, sizeof(MqttSubscribeAck));
            }
#ifdef WOLFMQTT_V5
            p_subscribe_ack->protocol_level = client->protocol_level;
#endif
            rc = MqttDecode_SubscribeAck(rx_buf, rx_len, p_subscribe_ack);
            if (rc >= 0) {
                packet_id = p_subscribe_ack->packet_id;
#ifdef WOLFMQTT_V5
                if (doProps) {
                    int tmp = Handle_Props(client, p_subscribe_ack->props,
                                           (packet_obj != NULL), 1);
                    p_subscribe_ack->props = NULL;
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
#endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK: {
            MqttUnsubscribeAck unsubscribe_ack,
                *p_unsubscribe_ack = &unsubscribe_ack;
            if (packet_obj) {
                p_unsubscribe_ack = (MqttUnsubscribeAck *)packet_obj;
            } else {
                XMEMSET(p_unsubscribe_ack, 0, sizeof(MqttUnsubscribeAck));
            }
#ifdef WOLFMQTT_V5
            p_unsubscribe_ack->protocol_level = client->protocol_level;
#endif
            rc = MqttDecode_UnsubscribeAck(rx_buf, rx_len, p_unsubscribe_ack);
            if (rc >= 0) {
                packet_id = p_unsubscribe_ack->packet_id;
#ifdef WOLFMQTT_V5
                if (doProps) {
                    int tmp = Handle_Props(client, p_unsubscribe_ack->props,
                                           (packet_obj != NULL), 1);
                    p_unsubscribe_ack->props = NULL;
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
#endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_PING_RESP: {
            MqttPing ping, *p_ping = &ping;
            if (packet_obj) {
                p_ping = (MqttPing *)packet_obj;
            } else {
                XMEMSET(p_ping, 0, sizeof(MqttPing));
            }
            rc = MqttDecode_Ping(rx_buf, rx_len, p_ping);
            break;
        }
        case MQTT_PACKET_TYPE_AUTH: {
#ifdef WOLFMQTT_V5
            MqttAuth auth, *p_auth = &auth;
            if (packet_obj) {
                p_auth = (MqttAuth *)packet_obj;
            } else {
                XMEMSET(p_auth, 0, sizeof(MqttAuth));
            }
            rc = MqttDecode_Auth(rx_buf, rx_len, p_auth);
            if (rc >= 0 && doProps) {
                int tmp = Handle_Props(client, p_auth->props,
                                       (packet_obj != NULL), 1);
                p_auth->props = NULL;
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
#else
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
#endif
            break;
        }
        case MQTT_PACKET_TYPE_DISCONNECT: {
#ifdef WOLFMQTT_V5
            MqttDisconnect disc, *p_disc = &disc;
            if (packet_obj) {
                p_disc = (MqttDisconnect *)packet_obj;
            } else {
                XMEMSET(p_disc, 0, sizeof(MqttDisconnect));
            }
            rc = MqttDecode_Disconnect(rx_buf, rx_len, p_disc);
            if (rc >= 0 && doProps) {
                int tmp = Handle_Props(client, p_disc->props,
                                       (packet_obj != NULL), 1);
                p_disc->props = NULL;
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
#else
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
#endif
            break;
        }
        default:
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
            break;
        }
    }

    if (ppacket_id) {
        *ppacket_id = packet_id;
    }

    return rc;
}

static void fuzz_one(const uint8_t *data, size_t size) {
    if (size < MQTT_PACKET_HEADER_MIN_SIZE || size > (size_t)INT_MAX) {
        return;
    }

    byte *mutable_buf = malloc(size);
    if (mutable_buf == NULL) {
        return;
    }
    memcpy(mutable_buf, data, size);

    MqttClient client;
    memset(&client, 0, sizeof(client));
#if defined(WOLFMQTT_V5)
    client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
#endif
    MqttObject obj;
    memset(&obj, 0, sizeof(obj));
    MqttPacketType type = MQTT_PACKET_TYPE_RESERVED;
    MqttQoS qos = MQTT_QOS_0;
    word16 packet_id = 0;

    (void)MqttClient_DecodePacket(&client, mutable_buf, (word32)size, &obj,
                                  &type, &qos, &packet_id, 1);

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
