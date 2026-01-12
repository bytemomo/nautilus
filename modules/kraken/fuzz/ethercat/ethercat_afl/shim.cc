#include "shim.h"

// Adapted from master/master.c: validates the frame and dequeues matching
// datagrams. Debug printing is stripped to avoid kernel dependencies.
void ec_master_receive_datagrams(ec_master *master,
                                 ec_device *device,
                                 const uint8_t *frame_data,
                                 size_t size) {
    size_t frame_size, data_size;
    uint8_t datagram_type, datagram_index;
    unsigned int cmd_follows, matched;
    const uint8_t *cur_data;
    ec_datagram *datagram = nullptr;

    if (size < EC_FRAME_HEADER_SIZE) {
        master->stats.corrupted++;
        return;
    }

    cur_data = frame_data;
    frame_size = EC_READ_U16(cur_data) & EC_DATAGRAM_SIZE_MASK;
    cur_data += EC_FRAME_HEADER_SIZE;

    if (frame_size > size) {
        master->stats.corrupted++;
        return;
    }

    cmd_follows = 1;
    while (cmd_follows) {
        if (static_cast<size_t>(cur_data - frame_data) + EC_DATAGRAM_HEADER_SIZE >
            size) {
            master->stats.corrupted++;
            return;
        }

        datagram_type = EC_READ_U8(cur_data);
        datagram_index = EC_READ_U8(cur_data + 1);
        data_size = EC_READ_U16(cur_data + 6) & EC_DATAGRAM_SIZE_MASK;
        cmd_follows = EC_READ_U16(cur_data + 6) & EC_DATAGRAM_FOLLOWS_MASK;
        cur_data += EC_DATAGRAM_HEADER_SIZE;

        if (static_cast<size_t>(cur_data - frame_data) + data_size +
                EC_DATAGRAM_FOOTER_SIZE >
            size) {
            master->stats.corrupted++;
            return;
        }

        // search for matching datagram in the queue
        matched = 0;
        for (list_head *pos = master->datagram_queue.next;
             pos != &master->datagram_queue; pos = pos->next) {
            ec_datagram *candidate =
                    container_of(pos, ec_datagram, queue);
            if (candidate->index == datagram_index &&
                candidate->state == EC_DATAGRAM_SENT &&
                candidate->type == datagram_type &&
                candidate->data_size == data_size) {
                matched = 1;
                datagram = candidate;
                break;
            }
        }

        // no matching datagram was found
        if (!matched) {
            master->stats.unmatched++;
            cur_data += data_size + EC_DATAGRAM_FOOTER_SIZE;
            continue;
        }

        if (datagram->type != EC_DATAGRAM_APWR &&
            datagram->type != EC_DATAGRAM_FPWR &&
            datagram->type != EC_DATAGRAM_BWR &&
            datagram->type != EC_DATAGRAM_LWR) {
            // copy received data into the datagram memory,
            // if something has been read
            memcpy(datagram->data, cur_data, data_size);
        }
        cur_data += data_size;

        // set the datagram's working counter
        datagram->working_counter = EC_READ_U16(cur_data);
        cur_data += EC_DATAGRAM_FOOTER_SIZE;

        // dequeue the received datagram
        datagram->state = EC_DATAGRAM_RECEIVED;
        datagram->jiffies_received = device->jiffies_poll;
        list_del_init(&datagram->queue);
    }
}
