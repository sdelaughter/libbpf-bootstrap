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

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	int packet_size = data_end - data;

	bpf_trace_printk(packet_size);

	return XDP_PASS;
}
