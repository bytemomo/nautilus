#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "memory_mosq.h"

static int read_file(const char *path, uint8_t **out_buf, size_t *out_size)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf = NULL;
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

	if (len == 0) {
		fclose(f);
		return -1;
	}

	buf = (uint8_t *) malloc((size_t) len);
	if (buf == NULL) {
		fclose(f);
		return -1;
	}

	n = fread(buf, 1, (size_t) len, f);
	fclose(f);

	if (n != (size_t) len) {
		free(buf);
		return -1;
	}

	*out_buf  = buf;
	*out_size = (size_t) len;
	return 0;
}

static void fuzz_packet(const uint8_t *data, size_t size)
{
	struct mosquitto *mosq = NULL;
	uint8_t *payload       = NULL;

	if (size < 2 || size > (1024 * 8)) {
		return;
	}

	mosq = mosquitto_new(NULL, true, NULL);
	if (mosq == NULL) {
		return;
	}
	mosq->protocol = mosq_p_mqtt5;

	payload = mosquitto__malloc(size - 1);
	if (payload == NULL) {
		mosquitto_destroy(mosq);
		return;
	}
	memcpy(payload, data + 1, size - 1);

	mosq->in_packet.command          = data[0];
	mosq->in_packet.payload          = payload;
	mosq->in_packet.remaining_length = (uint32_t)(size - 1);
	mosq->in_packet.pos              = 0;
	mosq->in_packet.to_process       = (uint32_t)(size - 1);

	(void) handle__packet(mosq);

	packet__cleanup(&mosq->in_packet);
	mosquitto_destroy(mosq);
}

static void fuzz_file(const char *path)
{
	uint8_t *buf = NULL;
	size_t size  = 0;

	if (read_file(path, &buf, &size) != 0) {
		return;
	}

	fuzz_packet(buf, size);
	free(buf);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
		return 1;
	}

	if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "mosquitto_lib_init failed\n");
		return 1;
	}

#ifdef __AFL_LOOP
	while (__AFL_LOOP(1000)) {
		fuzz_file(argv[1]);
	}
#else
	fuzz_file(argv[1]);
#endif

	mosquitto_lib_cleanup();
	return 0;
}
