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

static void update_ip_csum(struct iphdr* iph, __u8 old_ttl) {
  if (old_ttl == iph->ttl){
    return;
  }
  __sum16 sum = old_ttl + (~bpf_ntohs(*(unsigned short *)&iph->ttl) & 0xffff);
  sum += bpf_ntohs(iph->check);
  sum = (sum & 0xffff) + (sum>>16);
  iph->check = bpf_htons(sum + (sum>>16) + 1);
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
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
						struct event *e;
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
					  if (!e) {
							return XDP_PASS;
						}
						// memset((void *)e, 0, sizeof(struct event));

						__u8 old_ttl = ip->ttl;
						ip->ttl = 42;
						update_ip_csum(ip, old_ttl);

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
