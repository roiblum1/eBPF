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

struct packet_information {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 tot_len;
    __u8 ttl;
    char protocol[4];
    char data[256];
};

struct packet_map_key {
    __u32 src_ip;
    __u32 dst_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct packet_map_key);
    __type(value, struct packet_information);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_map SEC(".maps");

// Helper function to check if the packet is TCP
static bool is_protocol(struct ethhdr *eth, void *data_end, char* protocol)
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
    bpf_printk("tc_ingress function called\n");
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


    if (!is_protocol(l2, data_end, PROTOCOL)) {
        return TC_ACT_OK;
    }
    
    struct packet_information packet_data;
    packet_data.src_ip = l3->saddr;
    packet_data.dst_ip = l3->daddr;
    packet_data.tot_len = bpf_ntohs(l3->tot_len);
    packet_data.ttl = l3->ttl;
    strcpy(packet_data.protocol, PROTOCOL);
    
    //to ensure theat the data size is 256 bytes
    int data_size = data_end - data;
    if (data_size > 256)
        data_size = 256;

    for (int i = 0; i < data_size; i++) {
        //insure that i am still in the packet size, because if its less than 256 
        //I have got an error without it. 
        if ((void *)(data + i + 1) > data_end)
            break;
        packet_data.data[i] = ((char *)data)[i];
    }

    struct packet_map_key key_map; 
    key_map.src_ip = l3->saddr;
    key_map.dst_ip = l3->daddr;
    
    //I figure out that     
    unsigned char *src_ip_bytes = (unsigned char *)&key_map.src_ip;
    unsigned char *dst_ip_bytes = (unsigned char *)&key_map.dst_ip;
    bpf_map_update_elem(&packet_map, &key_map, &packet_data, BPF_ANY);
    bpf_printk("src_ip:%d.%d.%d.%d,dest_ip:%d.%d.%d.%d,tot_len:%d,ttl:%d,protocol:%s,data:%p\n",
    src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3],
    dst_ip_bytes[0], dst_ip_bytes[1], dst_ip_bytes[2], dst_ip_bytes[3], 
    packet_data.tot_len, packet_data.ttl, packet_data.protocol, packet_data.data); 
   
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";