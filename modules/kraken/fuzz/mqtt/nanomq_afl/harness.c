#include <unistd.h>

#include "nng/nng.h"
#include "nng/mqtt/packet.h"
#include "nanomq/include/mqtt_api.h"

__AFL_FUZZ_INIT();

void fuzz_mqtt_parser(const uint8_t *data, size_t size);

int main() {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
      __AFL_INIT();
    #endif

      unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

      while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_mqtt_parser(buf, len);
      }

      return 0;
}

void fuzz_mqtt_parser(const uint8_t *data, size_t size) {
    nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);

	if (nng_msg_header_append(msg, data, size) != 0) {
		nng_msg_free(msg);
		return;
	}

	nng_mqtt_msg_decode(msg);
	nng_msg_free(msg);

	nng_closeall();
	return;
}
