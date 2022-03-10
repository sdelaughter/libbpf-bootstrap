/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */


#ifndef __PARSE_H
#define __PARSE_H

struct event {
	uint64_t ts;
	uint8_t packet_size;
	// uint8_t eth_src;
	// uint8_t eth_dst;
	// uint16_t eth_protocol;
	uint8_t ip_version;
	uint8_t ip_protocol;
	uint32_t ip_saddr;
	uint32_t ip_daddr;
	uint8_t ip_ttl;
	uint16_t sport;
	uint16_t dport;
	uint16_t payload_size;
};

#endif /* __PARSE_H */
