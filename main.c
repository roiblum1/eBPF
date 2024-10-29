#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}

// Helper function to check if the packet is TCP
static bool is_tcp(struct ethhdr *eth, void *data_end, char* protocol)
{
    // Ensure Ethernet header is within bounds
    if ((void *)(eth + 1) > data_end)
        return false;

    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Ensure IP header is within bounds
    if ((void *)(ip + 1) > data_end)
        return false;

    // Check if the protocol is TCP
    if (ip->protocol != IPPROTO_TCP)
        return false;
   
    if (strcmp(protocol, "TCP") == 0) 
    {
        if (ip->protocol != IPPROTO_TCP)
            return false;
    } 
    else 
    { 
        if (ip->protocol != IPPROTO_UDP)
            return false;
    } 
    return true;
}

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    if (!is_tcp(l2, data_end, "TCP")) {
        return TC_ACT_OK;
    }

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d \npacket data: %p \n", bpf_ntohs(l3->tot_len), l3->ttl, (void*)data);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";