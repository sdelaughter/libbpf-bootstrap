/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __PARSE_H
#define __PARSE_H

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct event {
	unsigned long long ts;
	unsigned char packet_size;
	unsigned char ip_version;
	unsigned char ip_protocol;
	unsigned long ip_saddr;
	unsigned long ip_daddr;
	unsigned char ip_ttl;
	unsigned short sport;
	unsigned short dport;
	unsigned short payload_size;
};

// struct event {
// 	__u64 ts;
// 	__u8 packet_size;
// 	// __u8 eth_src;
// 	// __u8 eth_dst;
// 	// __u16 eth_protocol;
// 	__u8 ip_version;
// 	__u8 ip_protocol;
// 	__u32 ip_saddr;
// 	__u32 ip_daddr;
// 	__u8 ip_ttl;
// 	__u16 sport;
// 	__u16 dport;
// 	__u16 payload_size;
// };

#endif /* __PARSE_H */
