#!./.venv/bin/python3

import sys
import json
from boofuzz import *
import io
import os


OUTDIR = "./boofuzz-results"
LOG_FILEPATH = f"{OUTDIR}/fuzz.log"

# (mqtt_varlen_encoder and its unit tests remain the same as before)
def mqtt_varlen_encoder(value):
    n = int.from_bytes(value, byteorder="big", signed=False) if value else 0
    if n < 0 or n > 268_435_455: raise ValueError(f"Remaining Length out of range for MQTT varint: {n}")
    out = bytearray()
    while True:
        encoded = n % 128
        n //= 128
        if n > 0: encoded |= 0x80
        out.append(encoded)
        if n == 0: break
    if len(out) > 4: raise ValueError("MQTT varint produced >4 bytes, which is invalid.")
    return bytes(out)

# --- Packet Building Functions ---
def build_mqtt_packet(name: str, control_header: int, variable_header_fields=None, payload_fields=None):
    variable_header_fields = variable_header_fields or []
    payload_fields = payload_fields or []

    def build_fields(field_defs):
        elements = []
        for f in field_defs:
            ftype, fname, fval, fuzzable, endian = f.get("type"), f.get("name"), f.get("value", 0), f.get("fuzzable", True), f.get("endian", "big")
            if ftype == "byte": elements.append(Byte(name=fname, default_value=fval, fuzzable=fuzzable))
            elif ftype == "word": elements.append(Word(name=fname, default_value=fval, endian=endian, fuzzable=fuzzable))
            elif ftype == "string":
                elements.append(Word(name=f"{fname}_len", default_value=len(fval), endian=endian, fuzzable=False))
                elements.append(String(name=fname, default_value=fval, fuzzable=fuzzable))
            elif ftype == "raw": elements.append(Bytes(name=fname, default_value=fval, fuzzable=fuzzable))
        return elements

    return Request(name, children=(
        Block(name="FixedHeader", children=(
            Byte(name="ControlHeader", default_value=control_header, fuzzable=False),
            Block(name="RemainingLength", children=Size(name="RemainingLengthRaw", block_name="Body", fuzzable=True, length=4, endian=">"), encoder=mqtt_varlen_encoder, fuzzable=False)
        )),
        Block(name="Body", children=(
            Block(name="VariableHeader", children=build_fields(variable_header_fields)),
            Block(name="Payload", children=build_fields(payload_fields))
        ))
    ))

# --- Connection Packet Definitions ---
def build_connect_request():
    variable_header = [{"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False}, {"type": "byte", "name": "ProtocolLevel", "value": 5}, {"type": "byte", "name": "ConnectFlags", "value": 0x02}, {"type": "word", "name": "KeepAlive", "value": 60}]
    payload = [{"type": "string", "name": "ClientID", "value": "fuzz_client_simple"}]
    return build_mqtt_packet("MQTT_CONNECT", 0x10, variable_header, payload)

def build_connect_with_auth_request():
    variable_header = [{"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False}, {"type": "byte", "name": "ProtocolLevel", "value": 5}, {"type": "byte", "name": "ConnectFlags", "value": 0xC2}, {"type": "word", "name": "KeepAlive", "value": 60}]
    payload = [{"type": "string", "name": "ClientID", "value": "fuzz_auth_client"}, {"type": "string", "name": "Username", "value": "fuzzer"}, {"type": "string", "name": "Password", "value": "password123"}]
    return build_mqtt_packet("MQTT_CONNECT_AUTH", 0x10, variable_header, payload)

def build_connect_with_lwt_request():
    variable_header = [{"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False}, {"type": "byte", "name": "ProtocolLevel", "value": 5}, {"type": "byte", "name": "ConnectFlags", "value": 0x2E}, {"type": "word", "name": "KeepAlive", "value": 60}]
    payload = [{"type": "string", "name": "ClientID", "value": "fuzz_lwt_client"}, {"type": "string", "name": "WillTopic", "value": "fuzz/lwt"}, {"type": "string", "name": "WillMessage", "value": "client disconnected"}]
    return build_mqtt_packet("MQTT_CONNECT_LWT", 0x10, variable_header, payload)

# --- Publish Packet Definitions for Each QoS Level ---
def build_publish_qos0_request():
    variable_header = [{"type": "string", "name": "TopicName", "value": "fuzz/qos0"}]
    payload = [{"type": "raw", "name": "Message", "value": b"QoS 0 Test"}]
    return build_mqtt_packet("MQTT_PUBLISH_QOS0", 0x30, variable_header, payload)

def build_publish_qos1_request():
    variable_header = [{"type": "string", "name": "TopicName", "value": "fuzz/qos1"}, {"type": "word", "name": "PacketIdentifier", "value": 11}]
    payload = [{"type": "raw", "name": "Message", "value": b"QoS 1 Test"}]
    return build_mqtt_packet("MQTT_PUBLISH_QOS1", 0x32, variable_header, payload)

def build_publish_qos2_request():
    variable_header = [{"type": "string", "name": "TopicName", "value": "fuzz/qos2"}, {"type": "word", "name": "PacketIdentifier", "value": 12}]
    payload = [{"type": "raw", "name": "Message", "value": b"QoS 2 Test"}]
    return build_mqtt_packet("MQTT_PUBLISH_QOS2", 0x34, variable_header, payload)

def build_pubrel_request():
    variable_header = [{"type": "word", "name": "PacketIdentifier", "value": 12}]
    return build_mqtt_packet("MQTT_PUBREL", 0x62, variable_header)

# --- Subscription and Other Packets ---
def build_subscribe_request():
    variable_header = [{"type": "word", "name": "PacketIdentifier", "value": 1}]
    payload = [{"type": "string", "name": "TopicFilter", "value": "fuzz/#"}, {"type": "byte", "name": "SubscriptionOptions", "value": 0x00}]
    return build_mqtt_packet("MQTT_SUBSCRIBE", 0x82, variable_header, payload)

def build_unsubscribe_request():
    variable_header = [{"type": "word", "name": "PacketIdentifier", "value": 2}]
    payload = [{"type": "string", "name": "TopicFilter", "value": "fuzz/#"}]
    return build_mqtt_packet("MQTT_UNSUBSCRIBE", 0xA2, variable_header, payload)

def build_pingreq_request():
    return build_mqtt_packet("MQTT_PINGREQ", 0xC0)

def build_disconnect_request():
    return build_mqtt_packet("MQTT_DISCONNECT", 0xE0)

def main():
    if len(sys.argv) < 3 and not len(sys.argv) > 1:
        print(json.dumps({"error": "Usage: python3 mqtt_fuzzer.py <HOST> <PORT>"}))
        rev[1], int(sys.argv[2])

    host, port = sys.argv[1], int(sys.argv[2])

    session = Session(
        target=Target(connection=TCPSocketConnection(host, port)),
        fuzz_loggers=[FuzzLoggerText(), FuzzLoggerText(file_handle=io.TextIOWrapper(open(LOG_FILEPATH, "wb+"), encoding="utf-8"))],
    )

    # 1. Instantiate all possible Request objects and store them in variables.
    connect_req = build_connect_request()
    connect_auth_req = build_connect_with_auth_request()
    connect_lwt_req = build_connect_with_lwt_request()
    subscribe_req = build_subscribe_request()
    unsubscribe_req = build_unsubscribe_request()
    publish_qos0_req = build_publish_qos0_request()
    publish_qos1_req = build_publish_qos1_request()
    publish_qos2_req = build_publish_qos2_request()
    pubrel_req = build_pubrel_request()
    ping_req = build_pingreq_request()
    disconnect_req = build_disconnect_request()

    # 2. Build the protocol graph by passing the Request objects directly.
    # The fuzzer can start with any of the connection types.
    session.connect(connect_req)
    session.connect(connect_auth_req)
    session.connect(connect_lwt_req)

    # Define valid transitions from a simple connected state.
    session.connect(connect_req, subscribe_req)
    session.connect(connect_req, publish_qos0_req)
    session.connect(connect_req, publish_qos1_req)
    session.connect(connect_req, publish_qos2_req)
    session.connect(connect_req, ping_req)

    # After subscribing, you can publish or unsubscribe.
    session.connect(subscribe_req, publish_qos0_req)
    session.connect(subscribe_req, publish_qos1_req)
    session.connect(subscribe_req, publish_qos2_req)
    session.connect(subscribe_req, unsubscribe_req)

    # The stateful QoS 2 handshake.
    session.connect(publish_qos2_req, pubrel_req)

    # Pinging is a valid action after many other actions.
    session.connect(publish_qos1_req, ping_req)
    session.connect(unsubscribe_req, ping_req)

    # Most states can lead to a disconnect.
    session.connect(ping_req, disconnect_req)
    session.connect(publish_qos0_req, disconnect_req)
    session.connect(pubrel_req, disconnect_req)
    session.connect(unsubscribe_req, disconnect_req)


    print(f"Logs will be saved to {LOG_FILEPATH}")

    session.fuzz()
    print("Fuzzing session finished.")

if __name__ == "__main__":
    main()
