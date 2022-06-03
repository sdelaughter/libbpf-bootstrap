// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syn_pad.h"

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
  if (old_ack_seq == tcph->ack_seq) return;
  __sum16 sum = old_ack_seq + (~bpf_ntohs(*(unsigned short *)&tcph->ack_seq) & 0xffff);
  sum += bpf_ntohs(tcph->check);
  sum = (sum & 0xffff) + (sum>>16);
  tcph->check = bpf_htons(sum + (sum>>16) + 1);
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	bool found_syn = false;
	unsigned short padding_added = 0;

	unsigned long long start_time;
	unsigned long long end_time;
	#if MEASURE_TIME
		start_time = bpf_ktime_get_ns();
	#endif

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
						if (is_syn(tcph)) {
							found_syn = true;
							int n_tcp_op_bytes = (tcp->doff - 5) * 4;
							int padding_needed = SYN_PAD_MIN_BYTES - n_tcp_op_bytes;
							if (padding_needed > 0) {
								if (bpf_xdp_adjust_tail(xdp, padding_needed)) {
										return XDP_PASS;
								}
								if ((void *)tcp + sizeof(*tcp) + n_tcp_op_bytes < data_end) {
		              char *payload = (void *)tcp + sizeof(*tcp) + n_tcp_op_bytes;
									size_t payload_size = ip->tot_len - (sizeof(struct iphdr) + sizeof(struct tcphdr));
									memmove((void *)payload + padding_needed, (void * payload), payload_size);
									if padding_needed > 1 {
										memset((void * )payload, NO_OP_VAL, padding_needed - 1);
									}
									memset((void * )payload + (padding_needed - 1), END_OP_VAL, 1);
		            }
								tcp->doff = (SYN_PAD_MIN_BYTES/4) + 5;
								padding_added = padding_needed;
							}
						}
					}
				}
			}
		}
	}

	#if GENERATE_EVENTS
		if (found_syn) {
			#if MEASURE_TIME
				end_time = bpf_ktime_get_ns();
			#endif
			struct event *e;
			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
			if (!e) {
				bpf_printk("WARNING: Failed to reserve space in ring buffer\n");
				return XDP_PASS;
			}
			e->status = 0;
			e->start = start_time;
			e->end = end_time;
			e->padding = padding_added;
			bpf_ringbuf_submit(e, 0);
		}
	#endif

	return XDP_PASS;
}
