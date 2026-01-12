#include <cstddef>
#include <cstdint>
#include <vector>

#include "shim.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least frame header + one datagram header + footer.
    if (size < EC_FRAME_HEADER_SIZE + EC_DATAGRAM_HEADER_SIZE +
                       EC_DATAGRAM_FOOTER_SIZE) {
        return 0;
    }

    // Extract the first datagram metadata to seed the queue entry the parser
    // will try to match.
    const uint8_t dgram_type = data[2];
    const uint8_t dgram_index = data[3];
    const size_t declared_data_size =
            (static_cast<uint16_t>(data[8]) |
             static_cast<uint16_t>(data[9]) << 8) &
            EC_DATAGRAM_SIZE_MASK;

    ec_master master{};
    INIT_LIST_HEAD(&master.datagram_queue);
    master.devices[EC_DEVICE_MAIN].name = "fuzz0";
    master.devices[EC_DEVICE_MAIN].cycles_poll = 0;
    master.devices[EC_DEVICE_MAIN].jiffies_poll = 0;

    // Prepare a datagram that matches the header so the parser exercises the
    // received-path instead of early dropping everything as unmatched.
    ec_datagram dgram{};
    INIT_LIST_HEAD(&dgram.queue);
    dgram.state = EC_DATAGRAM_SENT;
    dgram.type = static_cast<ec_datagram_type_t>(dgram_type);
    dgram.index = dgram_index;
    dgram.data_size = declared_data_size;

    std::vector<uint8_t> dgram_buf(declared_data_size ? declared_data_size : 1);
    dgram.data = dgram_buf.data();

    list_add_tail(&dgram.queue, &master.datagram_queue);

    ec_master_receive_datagrams(&master, &master.devices[EC_DEVICE_MAIN],
                                data, size);
    return 0;
}
