#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "nng/nng.h"
#include "nng/mqtt/packet.h"
#include "nanomq/include/mqtt_api.h"

int fuzz_mqtt_parser(const uint8_t *data, size_t size);

static int read_file(const char *path, uint8_t **out_buf, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    size_t n;
    long len;

    if (f == NULL) {
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    len = ftell(f);
    if (len < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);

    buf = (uint8_t *) malloc((size_t)len);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }

    n = fread(buf, 1, (size_t)len, f);
    fclose(f);

    if (n != (size_t)len) {
        free(buf);
        return -1;
    }

    *out_buf  = buf;
    *out_size = (size_t)len;
    return 0;
}

#ifdef __AFL_LOOP
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    while (__AFL_LOOP(1000)) {
        uint8_t *buf = NULL;
        size_t size  = 0;

        if (read_file(argv[1], &buf, &size) != 0) {
            continue;
        }

        if (buf != NULL && size > 0) {
            fuzz_mqtt_parser(buf, size);
        }

        free(buf);
    }

    return 0;
}
#else
int main(int argc, char **argv) {
    fprintf(stderr, "Can't run the binary without AFLPP");
    return 1;
}
#endif

int fuzz_mqtt_parser(const uint8_t *data, size_t size) {
    nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);

	// Append the raw fuzzed data as the message body
	if (nng_msg_append(msg, data, size) != 0) {
		nng_msg_free(msg);
		return 0;
	}

	// Target the main message decoder.
	// This function will attempt to parse the raw data as an MQTT message.
	nng_mqtt_msg_decode(msg);

	// The decoder may or may not have allocated internal data,
	// so always free the message.
	nng_msg_free(msg);

	return 0;
}
