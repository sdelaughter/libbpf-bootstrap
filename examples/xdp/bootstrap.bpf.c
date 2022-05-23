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

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/net/net_dev_start_xmit")
int hello(const struct sk_buff *skb, const struct net_device *dev) {
	struct event *e;
	u64 ts = bpf_ktime_get_ns();
	// bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
