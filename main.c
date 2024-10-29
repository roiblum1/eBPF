#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>


#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define PROTOCOL "TCP"
/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}

// Helper function to check if the packet is TCP
static bool is_tcp(struct ethhdr *eth, void *data_end, char* protocol)
{
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    // Check if the protocol is TCP
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
    //check if the ehternet frame is in bounds.  
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    //check if the IP header is in bounds. 
    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    if (!is_tcp(l2, data_end, PROTOCOL)) {
        return TC_ACT_OK;
    }
    
    bpf_printk("Got IP packet: tot_len: %d, ttl: %d, protocol: %s\npacket data: %p\n", bpf_ntohs(l3->tot_len), l3->ttl, PROTOCOL,(void*)data);
    bpf_printk("Packet src_ip: %pI4, dest_ip: %pI4", l3->saddr, l3->daddr);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";