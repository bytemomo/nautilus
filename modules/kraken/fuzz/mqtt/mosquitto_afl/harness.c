#include <unistd.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "memory_mosq.h"

__AFL_FUZZ_INIT();

void fuzz_packet(const uint8_t *data, size_t size);

int main() {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
      __AFL_INIT();
    #endif

      unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

      while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        {
            if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS) {
                return 1;
            }

            fuzz_packet(buf, len);

            mosquitto_lib_cleanup();
        }
      }

      return 0;
}

void fuzz_packet(const uint8_t *data, size_t size) {
	struct mosquitto *mosq = NULL;
	uint8_t *payload       = NULL;

	if (size < 2) {
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
