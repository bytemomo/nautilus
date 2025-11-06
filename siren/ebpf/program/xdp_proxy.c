#include <linux/types.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

char LICENSE[] SEC("license") = "GPL";

#define SIREN_SNAPLEN 256
#define SIREN_ACT_NONE 0
#define SIREN_ACT_DROP 1
#define TARGET_KIND_ANY 0
#define TARGET_KIND_IP 1
#define TARGET_KIND_IP_PORT 2
#define TARGET_KIND_MAC 3
#define TARGET_KIND_ETHERCAT 4

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 reserved;
    __u16 ethercat_slave;
} __attribute__((packed));

struct flow_action {
    __u32 action;
    __u64 expires_ns;
};

struct target_key {
    __u8 kind;
    __u8 reserved;
    __u16 port;
    __u32 ip;
    __u16 ethercat;
    __u16 pad;
    __u8 mac[6];
} __attribute__((packed));

struct packet_event {
    __u64 ts;
    __u32 len;
    __u32 ifindex;
    __u16 ether_type;
    __u16 capture_len;
    __u16 payload_off;
    __u8 proto;
    __u8 direction;
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
    __u16 ethercat_slave;
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    __u8 payload[SIREN_SNAPLEN];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, struct flow_action);
} flow_actions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct target_key);
    __type(value, __u8);
} targets SEC(".maps");

static __always_inline bool has_allow_all_target() {
    struct target_key key = {};
    return bpf_map_lookup_elem(&targets, &key);
}

static __always_inline bool match_mac_target(const __u8 *mac) {
    struct target_key key = {};
    key.kind = TARGET_KIND_MAC;
    __builtin_memcpy(key.mac, mac, ETH_ALEN);
    return bpf_map_lookup_elem(&targets, &key);
}

static __always_inline bool match_ip_target(__u32 ip) {
    if (!ip)
        return false;
    struct target_key key = {};
    key.kind = TARGET_KIND_IP;
    key.ip = ip;
    return bpf_map_lookup_elem(&targets, &key);
}

static __always_inline bool match_ip_port_target(__u32 ip, __u16 port) {
    if (!ip || !port)
        return false;
    struct target_key key = {};
    key.kind = TARGET_KIND_IP_PORT;
    key.ip = ip;
    key.port = port;
    return bpf_map_lookup_elem(&targets, &key);
}

static __always_inline bool match_ethercat_target(__u16 slave) {
    if (!slave)
        return false;
    struct target_key key = {};
    key.kind = TARGET_KIND_ETHERCAT;
    key.ethercat = slave;
    return bpf_map_lookup_elem(&targets, &key);
}

static __always_inline bool is_target_allowed(struct ethhdr *eth, const struct flow_key *key, __u16 ether_type) {
    if (has_allow_all_target())
        return true;

    if (match_mac_target(eth->h_source) || match_mac_target(eth->h_dest))
        return true;

    if (match_ip_target(key->src_ip) || match_ip_target(key->dst_ip))
        return true;

    if (match_ip_port_target(key->src_ip, key->src_port) || match_ip_port_target(key->dst_ip, key->dst_port))
        return true;

    if (ether_type == ETH_P_ETHERCAT && match_ethercat_target(key->ethercat_slave))
        return true;

    return false;
}

static __always_inline int apply_flow_action(struct flow_key *key) {
    struct flow_action *act = bpf_map_lookup_elem(&flow_actions, key);
    if (!act)
        return XDP_PASS;

    if (act->expires_ns) {
        __u64 now = bpf_ktime_get_ns();
        if (now > act->expires_ns) {
            bpf_map_delete_elem(&flow_actions, key);
            return XDP_PASS;
        }
    }

    if (act->action == SIREN_ACT_DROP)
        return XDP_DROP;

    return XDP_PASS;
}

static __always_inline void emit_event(struct xdp_md *ctx, const struct flow_key *key, struct ethhdr *eth, __u16 ether_type, __u16 payload_off, __u32 total_len,
                                       __u8 direction) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct packet_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->ts = bpf_ktime_get_ns();
    evt->len = total_len;
    evt->ifindex = ctx->ingress_ifindex;
    evt->ether_type = ether_type;
    evt->proto = key->proto;
    evt->direction = direction;
    evt->sport = key->src_port;
    evt->dport = key->dst_port;
    evt->saddr = key->src_ip;
    evt->daddr = key->dst_ip;
    evt->ethercat_slave = key->ethercat_slave;
    __builtin_memcpy(evt->src_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(evt->dst_mac, eth->h_dest, ETH_ALEN);

    __u64 avail = data_end - data;
    __u32 snaplen = total_len;
    if (snaplen > avail)
        snaplen = avail;
    if (snaplen > SIREN_SNAPLEN)
        snaplen = SIREN_SNAPLEN;

    evt->capture_len = snaplen;
    evt->payload_off = payload_off;

    if (snaplen > 0)
        bpf_probe_read_kernel(evt->payload, snaplen, data);

    bpf_ringbuf_submit(evt, 0);
}

struct ethercat_datagram {
    __u8 cmd;
    __u8 idx;
    __u16 adp;
    __u16 ado;
    __u16 len;
    __u8 irq;
} __attribute__((packed));

SEC("xdp")
int siren_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 ether_type = bpf_ntohs(eth->h_proto);
    struct flow_key key = {};
    __u16 payload_off = sizeof(*eth);

    if (ether_type == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u8 proto = ip->protocol;
        __u32 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(*ip))
            return XDP_PASS;

        void *l4 = (void *)ip + ip_hdr_len;
        if (l4 > data_end)
            return XDP_PASS;

        key.src_ip = bpf_ntohl(ip->saddr);
        key.dst_ip = bpf_ntohl(ip->daddr);
        key.proto = proto;
        payload_off = (__u16)((void *)ip - data) + ip_hdr_len;

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;

            key.src_port = bpf_ntohs(tcp->source);
            key.dst_port = bpf_ntohs(tcp->dest);
            payload_off = (__u16)((void *)tcp - data) + tcp->doff * 4;
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;

            key.src_port = bpf_ntohs(udp->source);
            key.dst_port = bpf_ntohs(udp->dest);
            payload_off = (__u16)((void *)udp - data) + sizeof(*udp);
        }
    } else if (ether_type == ETH_P_ETHERCAT) {
        struct ethercat_datagram *ec = data + sizeof(*eth);
        if ((void *)(ec + 1) > data_end)
            return XDP_PASS;
        key.ethercat_slave = bpf_ntohs(ec->adp);
        key.proto = 0;
        payload_off = (__u16)((void *)(ec + 1) - data);
    } else {
        return XDP_PASS;
    }

    if (!is_target_allowed(eth, &key, ether_type))
        return XDP_PASS;

    int action = apply_flow_action(&key);
    if (action == XDP_DROP)
        return XDP_DROP;

    emit_event(ctx, &key, eth, ether_type, payload_off, data_end - data, 0);
    return XDP_PASS;
}
