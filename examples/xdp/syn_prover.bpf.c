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

#if !defined (get16bits)
#define get16bits(d) ((((unsigned long)(((const unsigned char *)(d))[1])) << 8)\
                       +(unsigned long)(((const unsigned char *)(d))[0]) )
#endif

static unsigned long SuperFastHash (const char* data, int len) {
	uint32_t hash = len, tmp;
	int rem;

  if (len <= 0 || data == NULL) return 0;

  rem = len & 3;
  len >>= 2;

  /* Main loop */
  for (;len > 0; len--) {
	  hash  += get16bits (data);
	  tmp    = (get16bits (data+2) << 11) ^ hash;
	  hash   = (hash << 16) ^ tmp;
	  data  += 2*sizeof (uint16_t);
	  hash  += hash >> 11;
  }

  /* Handle end cases */
  switch (rem) {
    case 3: hash += get16bits (data);
            hash ^= hash << 16;
            hash ^= ((signed char)data[sizeof (uint16_t)]) << 18;
            hash += hash >> 11;
            break;
    case 2: hash += get16bits (data);
            hash ^= hash << 11;
            hash += hash >> 17;
            break;
    case 1: hash += (signed char)*data;
            hash ^= hash << 10;
            hash += hash >> 1;
  }

  /* Force "avalanching" of final 127 bits */
  hash ^= hash << 3;
  hash += hash >> 5;
  hash ^= hash << 4;
  hash += hash >> 17;
  hash ^= hash << 25;
  hash += hash >> 6;

  return hash;
}

static bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

static unsigned long syn_hash(struct message_digest* digest) {
	return SuperFastHash((const char *)digest, sizeof(struct message_digest));
}

static unsigned short do_syn_pow(struct iphdr* iph, struct tcphdr* tcph, struct event* e) {
	unsigned short hash_iters = 0;

	// unsigned long nonce = bp, __u32 old_ack_seqf_get_prandom_u32();
	unsigned long nonce = 0;
	// unsigned long nonce = (unsigned long)(e->start_ts & 0xffffffff);
	unsigned long best_nonce = nonce;
	unsigned long hash = 0;
	unsigned long best_hash = 0;

	struct message_digest digest;
	digest.saddr = iph->saddr;
	digest.daddr = iph->daddr;
	digest.sport = tcph->source;
	digest.dport = tcph->dest;
	digest.seq = tcph->seq;

	if (POW_THRESHOLD > 0) {
		#pragma unroll
		for (unsigned short i=0; i<POW_ITERS; i++) {
			digest.ack_seq = nonce + i;
			hash = syn_hash(&digest);
			hash_iters += 1;
			if (hash > best_hash) {
				best_nonce = nonce + i;
				best_hash = hash;
				if (best_hash >= POW_THRESHOLD) {
					break;
				}
			}
		}
		tcph->ack_seq = bpf_htons(best_nonce);
	}
	return hash_iters;
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

							unsigned short hash_iters = do_syn_pow(iph, tcph);
							update_tcp_csum(tcph, 0);

							struct event *e;
							e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
							if (!e) {
								bpf_printk("WARNING: Failed to reserve space in ring buffer\n");
								return XDP_PASS;
							}
							e->start_ts = start_time;
							e->end_ts = bpf_ktime_get_ns();
							e->hash_iters = hash_iters;
							e->best_nonce = bpf_ntohs(tcph->ack_seq);
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
