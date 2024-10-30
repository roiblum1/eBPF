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

struct packet_data {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 tot_len;
    __u8 ttl;
    char protocol[4]; //In ASCII its 3 letters and each one is byte, + null terminator
    char data[1024]; //1024 bytes of data. 
};

// Helper function to check if the packet is TCP
static bool is_tcp(struct ethhdr *eth, void *data_end, char* protocol)
{
    struct iphdr *ip = (struct iphdr *)(eth + 1);
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
    
    struct packet_data packet_data;
    packet_data.src_ip = l3->saddr;
    packet_data.dest_ip = l3->daddr;
    packet_data.tot_len = bpf_ntohs(l3->tot_len);
    packet_data.ttl = l3->ttl;
    strcpy(packet_data.protocol, PROTOCOL);
    memcpy(packet_data.data, data, 1024);

    bpf_printk("src_ip:%pI4,dest_ip:%pI4,tot_len:%d,ttl:%d,protocol:%s,data:%s\n", l3->saddr, l3->daddr, bpf_ntohs(l3->tot_len), l3->ttl, PROTOCOL,(void*)data); 
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";