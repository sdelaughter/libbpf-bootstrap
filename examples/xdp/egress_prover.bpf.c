// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/crypto.h>
#include "egress_prover.h"

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

static const unsigned char T[256] = {
	29,  186, 180, 162, 184, 218, 3,   141, 55,  0,   72,  98,  226, 108, 220,
	158, 231, 248, 247, 251, 130, 46,  174, 135, 170, 127, 163, 109, 229, 36,
	45,  145, 79,  137, 122, 12,  182, 117, 17,  198, 204, 212, 39,  189, 52,
	200, 102, 149, 15,  124, 233, 64,  88,  225, 105, 183, 131, 114, 187, 197,
	165, 48,  56,  214, 227, 41,  95,  4,   93,  243, 239, 38,  61,  116, 51,
	90,  236, 89,  18,  196, 213, 42,  96,  104, 27,  11,  21,  203, 250, 194,
	57,  85,  54,  211, 32,  25,  140, 121, 147, 171, 6,   115, 234, 206, 101,
	8,   7,   33,  112, 159, 28,  240, 238, 92,  249, 22,  129, 208, 118, 125,
	179, 24,  178, 143, 156, 63,  207, 164, 103, 172, 71,  157, 185, 199, 128,
	181, 175, 193, 154, 152, 176, 26,  9,   132, 62,  151, 2,   97,  205, 120,
	77,  190, 150, 146, 50,  23,  155, 47,  126, 119, 254, 40,  241, 192, 144,
	83,  138, 49,  113, 160, 74,  70,  253, 217, 110, 58,  5,   228, 136, 87,
	215, 169, 14,  168, 73,  219, 167, 10,  148, 173, 100, 35,  222, 76,  221,
	139, 235, 16,  69,  166, 133, 210, 67,  30,  84,  43,  202, 161, 195, 223,
	53,  34,  232, 245, 237, 230, 59,  80,  191, 91,  66,  209, 75,  78,  44,
	65,  1,   188, 252, 107, 86,  177, 242, 134, 13,  246, 99,  20,  81,  111,
	68,  153, 37,  123, 216, 224, 19,  31,  82,  106, 201, 244, 60,  142, 94,
	25
};


// static unsigned long long Pearson64(const unsigned char *message, size_t len) {
// 	size_t i;
// 	size_t j;
// 	unsigned char h;
// 	unsigned long long retval;
//
// 	for (j = 0; j < sizeof(retval); ++j) {
// 		// Change the first byte
// 		h = T[(message[0] + j) % 256];
// 		for (i = 1; i < len; ++i) {
// 			h = T[h ^ message[i]];
// 		}
// 		retval = ((retval << 8) | h);
// 	}
// 	return retval;
// }

static bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

static unsigned long syn_hash(struct message_digest* digest) {
	unsigned long sum = 0;
	sum = ((digest->saddr * digest->ack_seq) +
				(digest->daddr * digest->ack_seq) +
				(digest->sport * digest->ack_seq) +
				(digest->dport * digest->ack_seq) +
				(digest->seq * digest->ack_seq)) /
				(digest->ack_seq * digest->ack_seq);
	return sum;
	bpf_printk("HASH: %ull\n", sum);
	// return Pearson64((unsigned char *)digest, sizeof(struct message_digest));
}

static void do_syn_pow(struct iphdr* iph, struct tcphdr* tcph, struct event* e){
	unsigned long nonce = bpf_get_prandom_u32();
	unsigned long best_nonce = nonce;
	unsigned long hash = 0;
	unsigned long best_hash = 0;

	struct message_digest digest;
	digest.saddr = iph->saddr;
	digest.daddr = iph->daddr;
	digest.sport = tcph->source;
	digest.dport = tcph->dest;
	digest.seq = tcph->seq;

	#pragma unroll
	for (int i=0; i<POW_ITERS; i++) {
		// e->hash_iters = i+1;
		// digest.ack_seq = nonce + i;
		// hash = syn_hash(&digest);
		nonce = bpf_get_prandom_u32();
		hash = nonce;
		if (hash > best_hash) {
			best_nonce = nonce + i;
			best_hash = hash;
			if (best_hash >= POW_THRESHOLD) {
				break;
			}
		}
	}
	tcph->ack_seq = best_nonce;
	e->best_hash = best_hash;
	e->best_nonce = best_nonce;
	if (best_hash < POW_THRESHOLD){
		e->hash_iters = -1;
	}
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return XDP_PASS;
	}

	e->start_ts = bpf_ktime_get_ns();

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
							do_syn_pow(iph, tcph, e);
						} else {
							bpf_ringbuf_discard(e, 0);
							return XDP_PASS;
						}
					} else {
						bpf_ringbuf_discard(e, 0);
						return XDP_PASS;
					}
				} else {
					bpf_ringbuf_discard(e, 0);
					return XDP_PASS;
				}
			} else {
				bpf_ringbuf_discard(e, 0);
				return XDP_PASS;
			}
		} else {
			bpf_ringbuf_discard(e, 0);
			return XDP_PASS;
		}
	} else {
		bpf_ringbuf_discard(e, 0);
		return XDP_PASS;
	}
	e->end_ts = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);
	return XDP_PASS;
}
