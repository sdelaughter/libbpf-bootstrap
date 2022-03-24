// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syn_verify.h"

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

static unsigned long do_syn_verify(struct iphdr* iph, struct tcphdr* tcph) {
	struct message_digest digest;
	digest.saddr = iph->saddr;
	digest.daddr = iph->daddr;
	digest.sport = tcph->source;
	digest.dport = tcph->dest;
	digest.seq = tcph->seq;
	digest.ack_seq = tcph->ack_seq;

	return syn_hash(&digest);
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
							unsigned long hash = do_syn_verify(iph, tcph);
							unsigned char valid = hash >= POW_THRESHOLD;
							e->hash = hash;
							e->valid = valid;
							e->end_ts = bpf_ktime_get_ns();
							bpf_ringbuf_submit(e, 0);
							if(valid) {
								return XDP_PASS;
							} else{
								return XDP_DROP;
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
	} else {
		bpf_ringbuf_discard(e, 0);
		return XDP_PASS;
	}
	bpf_ringbuf_discard(e, 0);
	return XDP_PASS;
}
