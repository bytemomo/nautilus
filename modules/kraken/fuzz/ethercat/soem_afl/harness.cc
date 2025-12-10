#include <cstddef>
#include <cstdint>
#include <cstring>

#include "soem/soem.h"
#include "oshw/linux/nicdrv.h"

extern "C" int ecx_inframe(ecx_portt *port, uint8 idx, int stacknumber);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    const uint16_t len = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1] & 0x0F) << 8);
    if (len + 2 > EC_BUFSIZE) {
        return 0;
    }

    ecx_portt port{};

    port.stack.sock = &port.sockhandle;
    port.stack.txbuf = &port.txbuf;
    port.stack.txbuflength = &port.txbuflength;
    port.stack.tempbuf = &port.tempinbuf;
    port.stack.rxbuf = &port.rxbuf;
    port.stack.rxbufstat = &port.rxbufstat;
    port.stack.rxsa = &port.rxsa;
    port.stack.rxcnt = 0;

    port.redstate = 0;

    const uint8_t idx = 0;
    std::memset(&port.rxbufstat, 0, sizeof(port.rxbufstat));
    port.rxbufstat[idx] = EC_BUF_RCVD;

    std::memset(&port.rxbuf[idx], 0, sizeof(port.rxbuf[idx]));
    const size_t copy_len = size < EC_BUFSIZE ? size : EC_BUFSIZE;
    std::memcpy(&port.rxbuf[idx], data, copy_len);

    (void)ecx_inframe(&port, idx, 0);
    return 0;
}
