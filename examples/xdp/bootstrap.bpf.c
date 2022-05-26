// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
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

SEC("tp/net/net_dev_start_xmit")
int bootstrap(struct sk_buff *skb, struct net_device *dev) {
	struct event *e;
	unsigned long long start_ts;
	unsigned long long end_ts;
	unsigned int pkt_size;

	start_ts = bpf_ktime_get_ns();

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->end;
	pkt_size = data_end - data;

	end_ts = bpf_ktime_get_ns();

	e->size = pkt_size;
	e->start = start_ts;
	e->end = end_ts;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
