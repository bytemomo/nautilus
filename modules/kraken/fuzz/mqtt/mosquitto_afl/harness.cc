#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>

extern "C" {
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "memory_mosq.h"
}

static int g_initialized = 0;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS) {
        return 0;
    }
    g_initialized = 1;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_initialized) return 0;

    if (size < 2 || (size > 1 << 16) ) return 0;

    struct mosquitto *mosq = mosquitto_new(NULL, true, NULL);
    if (!mosq) return 0;

    // 2. Setup the Mock Network Layer (socketpair)
    // sv[0] -> for Mosquitto (it reads from here)
    // sv[1] -> for the Fuzzer (we write data here)
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        mosquitto_destroy(mosq);
        return 0;
    }

    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);

    ssize_t written = write(sv[1], data, size);
    if (written < (ssize_t)size) {
        close(sv[0]); close(sv[1]);
        mosquitto_destroy(mosq);
        return 0;
    }

    mosq->sock = sv[0];
    mosq->protocol = mosq_p_mqtt5;
    mosq->state = mosq_cs_connected;

    int rc = packet__read(mosq);

    close(sv[1]);
    mosquitto_destroy(mosq);

    return 0;
}
