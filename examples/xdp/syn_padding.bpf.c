// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syn_prover.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 8192);
// 	__type(key, pid_t);
// 	__type(value, u64);
// } exec_start SEC(".maps");

struct message_digest {
	unsigned long saddr;
	unsigned long daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned long seq;
	unsigned long ack_seq;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

static void update_tcp_csum(struct tcphdr* tcph, __u32 old_ack_seq) {
  if (old_ack_seq == tcph->ack_seq){
    return;
  }
  __sum16 sum = old_ack_seq + (~bpf_ntohs(*(unsigned short *)&tcph->ack_seq) & 0xffff);
  sum += bpf_ntohs(tcph->check);
  sum = (sum & 0xffff) + (sum>>16);
  tcph->check = bpf_htons(sum + (sum>>16) + 1);
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	unsigned long long start_time = bpf_ktime_get_ns();

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int packet_size = data_end - data;

	// Parse Ethernet Header
	struct ethhdr *ethh = data;
	if ((void *)ethh + sizeof(*ethh) <= data_end) {
		if (bpf_htons(ethh->h_proto) == ETH_P_IP) {
			// Parse IPv4 Header
			struct iphdr *iph = data + sizeof(*ethh);
			if ((void *)iph + sizeof(*iph) <= data_end) {
				if (iph->protocol == IPPROTO_TCP) {
					// Parse TCP Header
					struct tcphdr *tcph = (void *)iph + sizeof(*iph);
					if ((void *)tcph + sizeof(*tcph) <= data_end) {
						if(is_syn(tcph)){
							// It's a SYN! Compute the proof of work
							struct event *e;
							e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
							if (!e) {
								bpf_printk("WARNING: Failed to reserve space in ring buffer\n");
								return XDP_PASS;
							}
							e->start = start_time;

							do_syn_pow(iph, tcph, e);
							update_tcp_csum(tcph, 0);

							e->end = bpf_ktime_get_ns();
							bpf_ringbuf_submit(e, 0);
						} else {
							// bpf_ringbuf_discard(e, 0);
							return XDP_PASS;
						}
					} else {
						// bpf_ringbuf_discard(e, 0);
						return XDP_PASS;
					}
				} else {
					// bpf_ringbuf_discard(e, 0);
					return XDP_PASS;
				}
			} else {
				// bpf_ringbuf_discard(e, 0);
				return XDP_PASS;
			}
		} else {
			// bpf_ringbuf_discard(e, 0);
			return XDP_PASS;
		}
	} else {
		// bpf_ringbuf_discard(e, 0);
		return XDP_PASS;
	}
	return XDP_PASS;
}
