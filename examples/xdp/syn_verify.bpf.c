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

// static const unsigned char T[256] = {
// 	29,  186, 180, 162, 184, 218, 3,   141, 55,  0,   72,  98,  226, 108, 220,
// 	158, 231, 248, 247, 251, 130, 46,  174, 135, 170, 127, 163, 109, 229, 36,
// 	45,  145, 79,  137, 122, 12,  182, 117, 17,  198, 204, 212, 39,  189, 52,
// 	200, 102, 149, 15,  124, 233, 64,  88,  225, 105, 183, 131, 114, 187, 197,
// 	165, 48,  56,  214, 227, 41,  95,  4,   93,  243, 239, 38,  61,  116, 51,
// 	90,  236, 89,  18,  196, 213, 42,  96,  104, 27,  11,  21,  203, 250, 194,
// 	57,  85,  54,  211, 32,  25,  140, 121, 147, 171, 6,   115, 234, 206, 101,
// 	8,   7,   33,  112, 159, 28,  240, 238, 92,  249, 22,  129, 208, 118, 125,
// 	179, 24,  178, 143, 156, 63,  207, 164, 103, 172, 71,  157, 185, 199, 128,
// 	181, 175, 193, 154, 152, 176, 26,  9,   132, 62,  151, 2,   97,  205, 120,
// 	77,  190, 150, 146, 50,  23,  155, 47,  126, 119, 254, 40,  241, 192, 144,
// 	83,  138, 49,  113, 160, 74,  70,  253, 217, 110, 58,  5,   228, 136, 87,
// 	215, 169, 14,  168, 73,  219, 167, 10,  148, 173, 100, 35,  222, 76,  221,
// 	139, 235, 16,  69,  166, 133, 210, 67,  30,  84,  43,  202, 161, 195, 223,
// 	53,  34,  232, 245, 237, 230, 59,  80,  191, 91,  66,  209, 75,  78,  44,
// 	65,  1,   188, 252, 107, 86,  177, 242, 134, 13,  246, 99,  20,  81,  111,
// 	68,  153, 37,  123, 216, 224, 19,  31,  82,  106, 201, 244, 60,  142, 94,
// 	25
// };
//
//
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
	// unsigned long sum = 0;
	// sum = ((digest->saddr * digest->ack_seq) +
	// 			(digest->daddr * digest->ack_seq) +
	// 			(digest->sport * digest->ack_seq) +
	// 			(digest->dport * digest->ack_seq) +
	// 			(digest->seq * digest->ack_seq)) /
	// 			(digest->ack_seq * digest->ack_seq);
	// return sum;
	// bpf_printk("HASH: %ull\n", sum);
	// return Pearson64((unsigned char *)digest, sizeof(struct message_digest));
	// return digest->ack_seq;
	return SuperFastHash((const char *)digest, sizeof(struct message_digest));
}

static unsigned long do_syn_verify(struct iphdr* iph, struct tcphdr* tcph, struct event* e) {
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
							unsigned long hash = do_syn_verify(iph, tcph, e);
							e->hash = hash;
							e->valid = hash >= POW_THRESHOLD;
							e->end_ts = bpf_ktime_get_ns();
							bpf_ringbuf_submit(e, 0);
							if(e->valid) {
								return XDP_PASS;
							} else{
								return XDP_PASS; // TODO: XDP_DROP
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
