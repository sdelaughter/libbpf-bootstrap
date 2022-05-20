// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

SEC("tp/net/net_dev_queue")
int hello(struct sk_buff *skb) {
	unsigned long long start_time = bpf_ktime_get_ns();

	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_printk("WARNING: Failed to reserve space in ring buffer\n");
		return XDP_PASS;
	}
	e->start = start_time;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->end;
	int packet_size = data_end - data;

	e->size = packet_size;
	e->end = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);

	return XDP_PASS;
}
