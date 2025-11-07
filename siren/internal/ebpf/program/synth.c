#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define SYNTH_SNAPLEN 196
#define SYNTH_MODE_CLONE 0
#define SYNTH_MODE_REDIRECT 1

struct synth_key {
    __u8 proto;
    __u8 _pad;
    __u16 port;
} __attribute__((packed));

struct synth_action {
    __u32 ifindex;
    __u8 mode;
    __u8 reserved[3];
    __u8 dst_mac[ETH_ALEN];
    __u8 src_mac[ETH_ALEN];
};

struct synth_event {
    __u64 ts;
    __u32 ifindex;
    __u8 proto;
    __u8 mode;
    __u16 port;
    __u16 length;
    __u16 truncated;
    __u8 payload[SYNTH_SNAPLEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct synth_key);
    __type(value, struct synth_action);
} synth_jobs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} synth_events SEC(".maps");

static __always_inline void log_event(const struct xdp_md *ctx, const struct synth_key *key, const void *data, const void *data_end, __u8 mode) {
    struct synth_event *ev = bpf_ringbuf_reserve(&synth_events, sizeof(*ev), 0);
    if (!ev)
        return;

    __u64 len = data_end - data;
    if (len > SYNTH_SNAPLEN) {
        ev->truncated = len - SYNTH_SNAPLEN;
        len = SYNTH_SNAPLEN;
    } else {
        ev->truncated = 0;
    }
    ev->length = len;
    ev->ts = bpf_ktime_get_ns();
    ev->ifindex = ctx->ingress_ifindex;
    ev->proto = key->proto;
    ev->mode = mode;
    ev->port = key->port;
    __builtin_memcpy(ev->payload, data, len);

    bpf_ringbuf_submit(ev, 0);
}

static __always_inline int apply_action(struct xdp_md *ctx, struct ethhdr *eth, struct synth_action *action) {
    __u32 ifindex = action->ifindex;
    if (!ifindex)
        ifindex = ctx->ingress_ifindex;

    __u8 original_dst[ETH_ALEN];
    __u8 original_src[ETH_ALEN];
    __builtin_memcpy(original_dst, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(original_src, eth->h_source, ETH_ALEN);

    if (action->dst_mac[0] | action->dst_mac[1] | action->dst_mac[2] | action->dst_mac[3] | action->dst_mac[4] | action->dst_mac[5]) {
        __builtin_memcpy(eth->h_dest, action->dst_mac, ETH_ALEN);
    }
    if (action->src_mac[0] | action->src_mac[1] | action->src_mac[2] | action->src_mac[3] | action->src_mac[4] | action->src_mac[5]) {
        __builtin_memcpy(eth->h_source, action->src_mac, ETH_ALEN);
    }

    int ret = XDP_PASS;
    if (action->mode == SYNTH_MODE_REDIRECT) {
        ret = bpf_redirect(ifindex, 0);
        return ret;
    }

    bpf_clone_redirect(ctx, ifindex, 0);

    __builtin_memcpy(eth->h_dest, original_dst, ETH_ALEN);
    __builtin_memcpy(eth->h_source, original_src, ETH_ALEN);
    return XDP_PASS;
}

SEC("xdp")
int siren_synth(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ihl_len = ip->ihl * 4;
    if ((__u8 *)ip + ihl_len > (__u8 *)data_end)
        return XDP_PASS;

    __u16 dest_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((__u8 *)ip + ihl_len);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dest_port = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = (void *)((__u8 *)ip + ihl_len);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dest_port = bpf_ntohs(udp->dest);
    }

    struct synth_key key = {
        .proto = ip->protocol,
        .port = dest_port,
    };

    struct synth_action *action = bpf_map_lookup_elem(&synth_jobs, &key);
    if (!action)
        return XDP_PASS;

    log_event(ctx, &key, data, data_end, action->mode);
    return apply_action(ctx, eth, action);
}

char LICENSE[] SEC("license") = "GPL";
