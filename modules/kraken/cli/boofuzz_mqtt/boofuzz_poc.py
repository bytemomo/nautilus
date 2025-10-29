#!/Users/cosimo.giraldi/repos/nautilus/.venv/bin/python3

import sys
import json
from boofuzz import *
import io
import os
import argparse
from typing import Union


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
def build_mqtt_packet(name: str, control_header: Union[int, dict], variable_header_fields=None, payload_fields=None):
    variable_header_fields = variable_header_fields or []
    payload_fields = payload_fields or []

    def build_fields(field_defs):
        elements = []
        for f in field_defs:
            ftype, fname, fval, fuzzable, endian, max_len = f.get("type"), f.get("name"), f.get("value", 0), f.get("fuzzable", True), f.get("endian", "big"), f.get("max_len", None)

            if ftype == "group":
                values, default_value = f.get("values", []), f.get("default_value", None)
                elements.append(Group(name=fname, values=values, default_value=default_value, fuzzable=fuzzable))
            elif ftype == "byte": elements.append(Byte(name=fname, default_value=fval, fuzzable=fuzzable))
            elif ftype == "word": elements.append(Word(name=fname, default_value=fval, endian=endian, fuzzable=fuzzable))
            elif ftype == "string":
                elements.append(Word(name=f"{fname}_len", default_value=len(fval), endian=endian, fuzzable=False))
                elements.append(String(name=fname, default_value=fval, fuzzable=fuzzable, max_len=max_len))
            elif ftype == "raw": elements.append(Bytes(name=fname, default_value=fval, fuzzable=fuzzable))

        return elements

    if type(control_header) == dict:
        fvalues, fdef, ffuzz = control_header.get("values", None), control_header.get("default_value", None), control_header.get("fuzzable", False)
        if fvalues == None and fdef == None:
            print("[FATAL] At least values or default value has to be specified for the control header")
            exit()
        ch = Group(name="ControlHeader", values=fvalues, default_value=fdef, fuzzable=ffuzz)
    else:
        ch = Byte(name="ControlHeader", default_value=control_header, fuzzable=False)

    return Request(name, children=(
        Block(name="FixedHeader", children=(
            ch, # Control Header
            Block(name="RemainingLength", children=Size(name="RemainingLengthRaw", block_name="Body", fuzzable=True, length=4, endian=">"), encoder=mqtt_varlen_encoder, fuzzable=False)
        )),
        Block(name="Body", children=(
            Block(name="VariableHeader", children=build_fields(variable_header_fields)),
            Block(name="Payload", children=build_fields(payload_fields))
        ))
    ))

# --- Connection Packet Definitions ---
def build_connect_request():
    variable_header = [
        {"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False},
        {"type": "byte", "name": "ProtocolLevel", "value": 5, "fuzzable": False},
        {"type": "byte", "name": "ConnectFlags", "value": 0x02, "fuzzable": False},
        {"type": "word", "name": "KeepAlive", "value": 60},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]

    payload = [
        {"type": "string", "name": "ClientID", "value": "boofuzz", "max_len": 30}
    ]
    return build_mqtt_packet("MQTT_CONNECT", 0x10, variable_header, payload)

def build_connect_with_auth_request():
    variable_header = [
        {"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False},
        {"type": "byte", "name": "ProtocolLevel", "value": 5, "fuzzable": False},
        {"type": "byte", "name": "ConnectFlags", "value": 0xC2},
        {"type": "word", "name": "KeepAlive", "value": 60},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]

    payload = [
        {"type": "string", "name": "ClientID", "value": "fuzz_auth_client"},
        {"type": "string", "name": "Username", "value": "fuzzer"},
        {"type": "string", "name": "Password", "value": "password123"}
    ]
    return build_mqtt_packet("MQTT_CONNECT_AUTH", 0x10, variable_header, payload)

def build_connect_with_lwt_request():
    variable_header = [
        {"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False},
        {"type": "byte", "name": "ProtocolLevel", "value": 5, "fuzzable": False},
        {"type": "byte", "name": "ConnectFlags", "value": 0x2E},
        {"type": "word", "name": "KeepAlive", "value": 60},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "string", "name": "ClientID", "value": "fuzz_lwt_client"},
        {"type": "string", "name": "WillTopic", "value": "fuzz/lwt"},
        {"type": "string", "name": "WillMessage", "value": "client disconnected"}
    ]
    return build_mqtt_packet("MQTT_CONNECT_LWT", 0x10, variable_header, payload)

# --- Publish Packet Definitions for Each QoS Level ---
def build_publish_request():
    variable_header = [
        {"type": "string", "name": "TopicName", "value": "fuzz/publish"},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]

    payload = [
        {"type": "raw", "name": "Message", "value": b"Publish Test"}
    ]
    return build_mqtt_packet("MQTT_PUBLISH",  0x30, variable_header, payload)

def build_publish_qos1_request():
    variable_header = [
        {"type": "string", "name": "TopicName", "value": "fuzz/qos1"},
        {"type": "word", "name": "PacketIdentifier", "value": 11},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "raw", "name": "Message", "value": b"QoS 1 Test"}
    ]
    return build_mqtt_packet("MQTT_PUBLISH_QOS1", 0x32, variable_header, payload)

def build_publish_qos2_request():
    variable_header = [
        {"type": "string", "name": "TopicName", "value": "fuzz/qos2"},
        {"type": "word", "name": "PacketIdentifier", "value": 12},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "raw", "name": "Message", "value": b"QoS 2 Test"}
    ]
    return build_mqtt_packet("MQTT_PUBLISH_QOS2", 0x34, variable_header, payload)

def build_pubrel_request():
    variable_header = [
        {"type": "word", "name": "PacketIdentifier", "value": 12}
    ]
    return build_mqtt_packet("MQTT_PUBREL", 0x62, variable_header)

# --- Subscription and Other Packets ---
def build_subscribe_request():
    variable_header = [
        {"type": "word", "name": "PacketIdentifier", "value": 0},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "string", "name": "TopicFilter", "value": "fuzz/#"},
        {"type": "byte", "name": "SubscriptionOptions", "value": 0x00}
    ]
    return build_mqtt_packet("MQTT_SUBSCRIBE", 0x82, variable_header, payload)

def build_unsubscribe_request():
    variable_header = [
        {"type": "word", "name": "PacketIdentifier", "value": 0},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "string", "name": "TopicFilter", "value": "fuzz/#"}
    ]
    return build_mqtt_packet("MQTT_UNSUBSCRIBE", 0xA2, variable_header, payload)

def build_pingreq_request():
    return build_mqtt_packet("MQTT_PINGREQ", 0xC0)

def build_disconnect_request():
    variable_header = [
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    return build_mqtt_packet("MQTT_DISCONNECT", 0xE0, variable_header)


# UTILS ------------------------------

def parse_dynamic_args(dynamic_args):
    """
    Parses arbitrary flags like --key value from a list of arguments.
    Returns a dictionary.
    """
    parsed = {}
    i = 0
    while i < len(dynamic_args):
        if dynamic_args[i].startswith('--'):
            key = dynamic_args[i][2:]
            # Make sure there is a value after the key
            if i + 1 < len(dynamic_args) and not dynamic_args[i+1].startswith('--'):
                value = dynamic_args[i+1]
                i += 2
            else:
                value = True  # flag without a value (boolean style)
                i += 1
            parsed[key] = value
        else:
            print(f"Warning: Unexpected argument {dynamic_args[i]}")
            i += 1
    return parsed

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True)
    args, remainder = parser.parse_known_args()

    if '--' in remainder:
        sep_index = remainder.index('--')
        extra_args = remainder[sep_index + 1:]
    else:
        extra_args = []

    dynamic_params = parse_dynamic_args(extra_args)

    print("Host:", args.host)
    print("Port:", args.port)
    print("Dynamic Params:", dynamic_params)
    return args.host, int(args.port), dynamic_params


# Callbacks ------------------------------


def conn_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT CONNACK after CONNECT using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No response to CONNECT packet.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x20:
            fuzz_data_logger.log_info(f"Received CONNACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected CONNACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in conn_callback: {e}")


def qos1_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT PUBACK for QoS1 publish using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No PUBACK received for QoS1 Publish.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x40:
            fuzz_data_logger.log_info(f"Received PUBACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected PUBACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in qos1_callback: {e}")


def qos2_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT PUBREC -> PUBREL -> PUBCOMP for QoS2 publish using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No PUBREC received for QoS2 Publish.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x50:
            fuzz_data_logger.log_info(f"Received PUBREC: {resp.hex()}")

            # Send PUBREL
            pubrel = b'\x62\x02\x00\x0C'
            target.send(pubrel)
            fuzz_data_logger.log_info(f"Sent PUBREL: {pubrel.hex()}")

            # Wait for PUBCOMP via session.last_recv again
            resp2 = session.last_recv
            if resp2 and (resp2[0] & 0xF0) == 0x70:
                fuzz_data_logger.log_info(f"Received PUBCOMP: {resp2.hex()}")
            else:
                fuzz_data_logger.log_error(f"Expected PUBCOMP, got: {resp2.hex() if resp2 else 'None'}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected PUBREC): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in qos2_callback: {e}")


def sub_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT SUBACK using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No SUBACK received.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x90:
            fuzz_data_logger.log_info(f"Received SUBACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected SUBACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in sub_callback: {e}")


def unsub_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT UNSUBACK using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No UNSUBACK received.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0xB0:
            fuzz_data_logger.log_info(f"Received UNSUBACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected UNSUBACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in unsub_callback: {e}")


def ping_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT PINGRESP using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No PINGRESP received.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0xD0:
            fuzz_data_logger.log_info("Received PINGRESP")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected PINGRESP): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in ping_callback: {e}")

# General TODOS:
# - Look at AUTH

def main():
    host, port, dynamic_args = parse_args()

    session = Session(
        receive_data_after_fuzz=True, # Session will attempt to receive a reply after transmitting fuzzed message
        target=Target(connection=TCPSocketConnection(host, port)),
        fuzz_loggers=[FuzzLoggerText(), FuzzLoggerText(file_handle=io.TextIOWrapper(open(LOG_FILEPATH, "wb+"), encoding="utf-8"))],
    )

    connect_req = build_connect_request()
    connect_auth_req = build_connect_with_auth_request()
    connect_lwt_req = build_connect_with_lwt_request()

    publish_req = build_publish_request()
    publish_qos1_req = build_publish_qos1_request()
    publish_qos2_req = build_publish_qos2_request()

    subscribe_req = build_subscribe_request()
    unsubscribe_req = build_unsubscribe_request()

    pubrel_req = build_pubrel_request()

    ping_req = build_pingreq_request()
    disconnect_req = build_disconnect_request()

    session.connect(connect_req)
    session.connect(connect_auth_req)
    session.connect(connect_lwt_req)

    session.connect(connect_req, subscribe_req, callback=conn_callback)
    session.connect(connect_req, unsubscribe_req, callback=conn_callback)
    session.connect(connect_req, publish_req, callback=conn_callback)

    session.connect(connect_req, publish_qos1_req, callback=conn_callback)
    session.connect(connect_req, publish_qos2_req, callback=conn_callback)

    session.connect(connect_req, ping_req, callback=conn_callback)

    session.connect(subscribe_req, unsubscribe_req, callback=sub_callback)
    session.connect(subscribe_req, disconnect_req, callback=sub_callback)

    session.connect(unsubscribe_req, disconnect_req, callback=unsub_callback)
    session.connect(ping_req, disconnect_req, callback=ping_callback)

    session.connect(publish_req, disconnect_req)

    session.connect(publish_qos1_req, disconnect_req, callback=qos1_callback)
    session.connect(publish_qos2_req, disconnect_req, callback=qos2_callback)
    session.connect(connect_auth_req, disconnect_req, callback=conn_callback)
    session.connect(connect_lwt_req, disconnect_req, callback=conn_callback)

    with open('somefile.png', 'wb') as file:
        file.write(session.render_graph_graphviz().create_png())

    print(f"Logs will be saved to {LOG_FILEPATH}")

    session.fuzz()
    print("Fuzzing session finished.")

if __name__ == "__main__":
    main()
