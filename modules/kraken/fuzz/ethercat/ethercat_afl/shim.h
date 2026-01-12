#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// Minimal double linked list helpers (subset of linux/list.h)
struct list_head {
    list_head *next;
    list_head *prev;
};

inline void INIT_LIST_HEAD(list_head *list) {
    list->next = list;
    list->prev = list;
}

inline void __list_add(list_head *entry, list_head *prev, list_head *next) {
    next->prev = entry;
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
}

inline void list_add_tail(list_head *entry, list_head *head) {
    __list_add(entry, head->prev, head);
}

inline void __list_del(list_head *prev, list_head *next) {
    next->prev = prev;
    prev->next = next;
}

inline void list_del_init(list_head *entry) {
    __list_del(entry->prev, entry->next);
    INIT_LIST_HEAD(entry);
}

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr)-offsetof(type, member)))

// EtherCAT protocol constants
constexpr size_t EC_FRAME_HEADER_SIZE = 2;
constexpr size_t EC_DATAGRAM_HEADER_SIZE = 10;
constexpr size_t EC_DATAGRAM_FOOTER_SIZE = 2;
constexpr uint16_t EC_DATAGRAM_SIZE_MASK = 0x07FF;
constexpr uint16_t EC_DATAGRAM_FOLLOWS_MASK = 0x8000;
constexpr uint8_t EC_DEVICE_MAIN = 0;

// Helpers to read little-endian values from the fuzzer input.
inline uint8_t EC_READ_U8(const uint8_t *ptr) { return *ptr; }
inline uint16_t EC_READ_U16(const uint8_t *ptr) {
    return static_cast<uint16_t>(ptr[0]) |
           static_cast<uint16_t>(ptr[1]) << 8;
}

enum ec_datagram_type_t : uint8_t {
    EC_DATAGRAM_NONE = 0x00,
    EC_DATAGRAM_APRD = 0x01,
    EC_DATAGRAM_APWR = 0x02,
    EC_DATAGRAM_APRW = 0x03,
    EC_DATAGRAM_FPRD = 0x04,
    EC_DATAGRAM_FPWR = 0x05,
    EC_DATAGRAM_FPRW = 0x06,
    EC_DATAGRAM_BRD = 0x07,
    EC_DATAGRAM_BWR = 0x08,
    EC_DATAGRAM_BRW = 0x09,
    EC_DATAGRAM_LRD = 0x0A,
    EC_DATAGRAM_LWR = 0x0B,
    EC_DATAGRAM_LRW = 0x0C,
    EC_DATAGRAM_ARMW = 0x0D,
    EC_DATAGRAM_FRMW = 0x0E,
};

enum ec_datagram_state_t {
    EC_DATAGRAM_INIT,
    EC_DATAGRAM_QUEUED,
    EC_DATAGRAM_SENT,
    EC_DATAGRAM_RECEIVED,
    EC_DATAGRAM_TIMED_OUT,
    EC_DATAGRAM_ERROR,
};

struct ec_stats_t {
    unsigned int timeouts;
    unsigned int corrupted;
    unsigned int unmatched;
    unsigned long output_jiffies;
};

struct ec_device {
    const char *name;
    uint64_t cycles_poll;
    unsigned long jiffies_poll;
};

struct ec_datagram {
    list_head queue;
    ec_datagram_type_t type;
    uint8_t index;
    size_t data_size;
    uint8_t *data;
    ec_datagram_state_t state;
    uint16_t working_counter;
    unsigned long jiffies_received;
};

struct ec_master {
    unsigned int debug_level;
    ec_stats_t stats;
    ec_device devices[1];
    list_head datagram_queue;
};

// Exposed parser copied from master/master.c with logging stripped.
void ec_master_receive_datagrams(ec_master *master,
                                 ec_device *device,
                                 const uint8_t *frame_data,
                                 size_t size);
