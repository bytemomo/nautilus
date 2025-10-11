#!./.venv/bin/python3

import sys
import json
from boofuzz import *
import io

OUTDIR = "./boofuzz-results"
PCAP_DIR = f"{OUTDIR}/captures"
LOG_FILEPATH = f"{OUTDIR}/fuzz.log"

def mqtt_varlen_encoder(value):
    """
    Encode Remaining Length using MQTT variable-length encoding.
    If MSB = 1:
        the following byte it is used to represent the length of the VariableHeader + Payload.
    """
    n = int.from_bytes(value, byteorder="big", signed=False) if value else 0

    #    Max encodable value with 4 bytes: 268_435_455 (0x0FFFFFFF)
    if n < 0 or n > 268_435_455:
        raise ValueError(f"Remaining Length out of range for MQTT varint: {n}")

    # 3) Encode (7 data bits per byte; MSB=1 means more bytes follow)
    out = bytearray()
    while True:
        encoded = n % 128
        n //= 128
        if n > 0:
            encoded |= 0x80
        out.append(encoded)
        if n == 0:
            break

    # at most 4 bytes
    if len(out) > 4:
        raise ValueError("MQTT varint produced >4 bytes, which is invalid.")
    return bytes(out)


# Unit tests for the len method
assert mqtt_varlen_encoder(int.to_bytes(0, length=4, byteorder="big"))               == b"\x00"
assert mqtt_varlen_encoder(int.to_bytes(127, length=4, byteorder="big"))             == b"\x7f"
assert mqtt_varlen_encoder(int.to_bytes(128, length=4, byteorder="big"))             == b"\x80\x01"
assert mqtt_varlen_encoder(int.to_bytes(16383, length=4, byteorder="big"))           == b"\xff\x7f"
assert mqtt_varlen_encoder(int.to_bytes(16384, length=4, byteorder="big"))           == b"\x80\x80\x01"
assert mqtt_varlen_encoder(int.to_bytes(2097151, length=4, byteorder="big"))         == b"\xff\xff\x7f"
assert mqtt_varlen_encoder(int.to_bytes(2097152, length=4, byteorder="big"))         == b"\x80\x80\x80\x01"
assert mqtt_varlen_encoder(int.to_bytes(268435455, length=4, byteorder="big"))       == b"\xff\xff\xff\x7f"


def build_mqtt_packet(name: str, control_header: int, variable_header_fields=None, payload_fields=None):
    variable_header_fields = variable_header_fields or []
    payload_fields = payload_fields or []

    # Helper for dynamic field construction
    def build_fields(field_defs):
        elements = []
        for f in field_defs:
            ftype = f.get("type")
            fname = f.get("name")
            fval = f.get("value", 0)
            fuzzable = f.get("fuzzable", True)
            endian = f.get("endian", "big")

            if ftype == "byte":
                elements.append(Byte(name=fname, default_value=fval, fuzzable=fuzzable))
            elif ftype == "word":
                elements.append(Word(name=fname, default_value=fval, endian=endian, fuzzable=fuzzable))
            elif ftype == "string":
                # NOTE: String in MQTT are represented as len + string
                elements.append(Word(name=f"{fname}_len", default_value=len(fval), endian=endian, fuzzable=False)) # Word = 16 bit => 2 bytes
                elements.append(String(name=fname, default_value=fval, fuzzable=fuzzable))
            elif ftype == "raw":
                elements.append(Bytes(name=fname, default_value=fval, fuzzable=fuzzable))
        return elements

    # Fixed Header
    req  = Request(name,
        children=(Block(name="FixedHeader",
            children=(
                Byte(name="ControlHeader", default_value=control_header, fuzzable=False), # TODO: Could be defined in depth, ctr_header -> packet type | flags
                Block(name="RemainingLength", children=Size(name="RemainingLengthRaw",    # TODO: For now the length is fuzzable, but the formatted one is not.
                    block_name="Body", fuzzable=True, length=4, endian=">"
                ), encoder=mqtt_varlen_encoder, fuzzable=False)
            )
        ),
        Block(name="Body", children=(
            Block(name="VariableHeader", children=build_fields(variable_header_fields)),
            Block(name="Payload",children= build_fields(payload_fields))
        ))
    ))

    return req


def build_connect_request():
    variable_header = [
        {"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False},
        {"type": "byte", "name": "ProtocolLevel", "value": 5, "fuzzable": False}, # For now testing only v5, its a superset of the 3.1.1
        {"type": "byte", "name": "ConnectFlags", "value": 0x02},
        {"type": "word", "name": "KeepAlive", "value": 60},
    ]

    payload = [
        {"type": "string", "name": "ClientID", "value": "fuzzclient", "fuzzable": True},
    ]

    return build_mqtt_packet("MQTT_CONNECT", control_header=0x10, variable_header_fields=variable_header, payload_fields=payload)


def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            "error": "Usage: python3 mqtt_fuzzer.py <HOST> <PORT>"
        }))
        return

    host = sys.argv[1]
    port = int(sys.argv[2])


    # netmon = NetworkMonitor(
    #     host=host, port=port,
    # )


    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port),
            sleep_time=0.05,
            monitors=[
                # TODO: add Process monitor -> sees crashes
            ],
            fuzz_loggers=[
                FuzzLoggerText(file_handle=io.TextIOWrapper(open(LOG_FILEPATH, "wb+"), encoding="utf-8")),
                # FuzzLoggerText(),
            ],

        ),
    )

    # Requests
    CONNECT = build_connect_request()
    print(f"CONNECT SAMPLE: {CONNECT.render()}")

    try:
        session.connect(CONNECT)

        # NOTE: Equal to 1 == simple fuzzing
        session.fuzz(max_depth=1)
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "target": {"host": host, "port": port},
            "message": str(e),
        }))

if __name__ == "__main__":
    main()
