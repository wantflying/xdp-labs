/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};
	//vlan头
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};
/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	// if (nh->pos + 1 > data_end)
	// 	return -1;
	// char *str1 = "goto";
	int ethhdrsize =sizeof(**ethhdr);

	if(nh->pos + ethhdrsize > data_end){
          return -1;
    }
	// struct ethhdr *eth = nh->pos;
	*ethhdr = nh->pos;
	bpf_printk("Received packet with ipv6 protocol: %u,ethhdrsize:%u \n", (*ethhdr)->h_proto,ethhdrsize);
    // bpf_trace_printk("execve called with parse ethhdr: %u\n", ethhdrsize);
	nh->pos += ethhdrsize;
	// *ethhdr = eth;
	__u16 h_proto = (*ethhdr)->h_proto;


	struct vlan_hdr *vlh;
	vlh = nh->pos;
	int i;
	//处理vlan标记
	#pragma unroll
	for (i = 0; i < 2; i++) {
		if (!proto_is_vlan(h_proto))
			break;
		//判断是否越界
		if (vlh + 1 > data_end)
			break;
		h_proto = vlh->h_vlan_encapsulated_proto;
		//指针移动动下一个头起点
		vlh++;
	}

	nh->pos = vlh;

	return h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	int ipv6hdrsize = sizeof(**ip6hdr);
	if(nh->pos + ipv6hdrsize > data_end)
		return -1;
	struct ipv6hdr *ip6 = nh->pos;
	*ip6hdr = nh->pos;
	nh->pos += ipv6hdrsize;
	bpf_printk("Received packet with icmp protocol: %u,ipv6size:%u %u\n", ip6->nexthdr,ipv6hdrsize,bpf_htons(IPPROTO_ICMPV6));
	return ip6->nexthdr;

}

/* 处理ipv4报文 */
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iphdr)
{
	*iphdr = nh->pos;
	if((*iphdr)+1 > data_end){
		return -1;
	}
	int iphdrsize = (*iphdr)->ihl * 4;
	//ipv4 header ihl*4 表明了header的大小，这个大小要不能大于iphdrsize
	if(iphdrsize > sizeof(**iphdr)){
		return -1;
	}

	nh->pos += iphdrsize;

	return (*iphdr)->protocol;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	bpf_printk("start prase icmp packet ");
	int icmp6length = sizeof(**icmp6hdr);
	if(nh->pos + icmp6length > data_end)
		return 0;
	struct icmp6hdr *icmp6 = nh->pos;
	*icmp6hdr = nh->pos;
	nh->pos += icmp6length;
	bpf_printk("Received packet with icmp seq: %u\n", icmp6->icmp6_sequence);
	return bpf_ntohs(icmp6->icmp6_sequence);
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{	
	// const char *str1 = "ts";
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
		/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
		/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	//检查是否是ip报文
	if(nh_type == bpf_htons(ETH_P_IP)){
		struct  iphdr *ip;
		//检查是否是icmp报文,如果是则丢弃
		if(parse_iphdr(&nh, data_end, &ip) == IPPROTO_ICMP){
					action = XDP_DROP;
		}
		goto out;
	}
	
	if (nh_type != bpf_htons(ETH_P_IPV6))
		goto out;
	/* Assignment additions go below here  IPPROTO_ICMPV6*/ 
	struct  ipv6hdr *ipv6;
    nh_type =parse_ip6hdr(&nh,data_end,&ipv6);
	if (nh_type != IPPROTO_ICMPV6)
		goto out;
	
	struct icmp6hdr *icmpv6;
	if(parse_icmp6hdr(&nh, data_end, &icmpv6)%2 == 0){
		goto out;
	}
	action = XDP_DROP;
out:
	// bpf_trace_printk("execve called with filename: %s\n", *str1);
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
