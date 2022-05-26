// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 8192);
// 	__type(key, pid_t);
// 	__type(value, u64);
// } exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// const volatile unsigned long long min_duration_ns = 0;

SEC("tp/net/netif_receive_skb")
int bootstrap(struct sk_buff *skb) {
	void *data = (void *)(unsigned long long)skb->data;
	void *data_end = (void *)(unsigned long long)skb->end;


	struct ethhdr *ethh = data;
	if ((void *)ethh + sizeof(*ethh) <= data_end) {
		if (bpf_htons(ethh->h_proto) == ETH_P_IP) {
			// Parse IPv4 Header
			struct iphdr *iph = data + sizeof(*ethh);
			if ((void *)iph + sizeof(*iph) <= data_end) {
				struct event *e;
				e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
				if (!e) return 0;
				unsigned long long start_ts;
				unsigned long long end_ts;
				start_ts = bpf_ktime_get_ns();
				e->protocol = iph->protocol;
				e->start = start_ts;
				end_ts = bpf_ktime_get_ns();
				e->end = end_ts;
				bpf_ringbuf_submit(e, 0);
				return 0;

				// if (iph->protocol == IPPROTO_TCP) {
				// 	// Parse TCP Header
				// 	struct tcphdr *tcph = (void *)iph + sizeof(*iph);
				// 	if ((void *)tcph + sizeof(*tcph) <= data_end) {
				// 		if(is_syn(tcph)){
				// 			/* reserve sample from BPF ringbuf */
				//
				// 		}
				// 	}
				// }
			}
		}
	}

	// void *data = (void *)(long)skb->data;
	// void *data_end = (void *)(long)skb->end;
	// pkt_size = data_end - data;

	// bpf_trace_printk(skb);

	return 0;
}
