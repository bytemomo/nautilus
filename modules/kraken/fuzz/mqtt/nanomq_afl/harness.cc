#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "nng/nng.h"
#include "nng/mqtt/packet.h"

extern "C" {
        #include "nanomq/include/mqtt_api.h"
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    size_t header_len = 1;
    size_t pos = 1;

    while (pos < size) {
        header_len++;
        if ((data[pos] & 0x80) == 0) {
            break;
        }

        pos++;
        if (header_len >= 5) {
            break;
        }
    }

    nng_msg *msg;
    if (nng_mqtt_msg_alloc(&msg, 0) != 0) {
        return 0;
    }

    if (nng_msg_header_append(msg, data, header_len) != 0) {
        nng_msg_free(msg);
        return 0;
    }

    if (header_len < size) {
        size_t body_len = size - header_len;
        if (nng_msg_append(msg, data + header_len, body_len) != 0) {
            nng_msg_free(msg);
            return 0;
        }
    }

    nng_mqtt_msg_set_packet_type(msg, (nng_mqtt_packet_type)(data[0] & 0xF0));
    int rc = nng_mqtt_msg_decode(msg);

    // TODO: If successful, you could access fields to trigger more logic,
    // but simply decoding is a good first step.
    (void)rc;

    nng_msg_free(msg);
    return 0;
}
