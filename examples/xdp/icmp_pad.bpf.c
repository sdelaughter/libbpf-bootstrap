// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "icmp_pad.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// const volatile unsigned long long min_duration_ns = 0;
//

static unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

SEC("xdp")
int icmp_pad(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	int packet_size = data_end - data;

	// Parse Ethernet Header
  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) <= data_end) {
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
      // Parse IPv4 Header
      struct iphdr *ip = data + sizeof(*eth);
      if ((void *)ip + sizeof(*ip) <= data_end) {
        if (ip->protocol == IPPROTO_ICMP) {
          // Parse ICMP Header
          struct icmphdr *icmp = (void *)ip + sizeof(*ip);
          if ((void *)icmp + sizeof(*icmp) <= data_end) {
						char *payload = (void *)icmp + sizeof(*icmp);
						struct event *e;
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
					  if (!e) {
							return XDP_PASS;
						}
						// memset((void *)e, 0, sizeof(struct event));

						ip->ttl = 42;
						ip->check = 0;
						int ip_size = packet_size - sizeof(eth)
						ip->check = csum((unsigned short*)ip, ip_size);

						e->ts = bpf_ktime_get_ns();
						e->packet_size = packet_size;
						bpf_ringbuf_submit(e, 0);
          }
        }
      }
    }
	}
  return XDP_PASS;
}
