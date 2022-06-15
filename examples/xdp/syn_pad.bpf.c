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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// struct pseudo_header {
// 	uint32_t source_address;
// 	uint32_t dest_address;
// 	uint8_t placeholder;
// 	uint8_t protocol;
// 	uint16_t tcp_length;
// };

static __always_inline bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

static __always_inline uint16_t csum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;
    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline uint16_t compute_ip_csum(struct iphdr *iph) {
	size_t len = sizeof(*iph);
	uint16_t * bytes = (uint16_t *)((void *)iph);
  register uint32_t sum = 0;
  while (len > 1) {
    sum += * bytes++;
    len -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(len > 0) {
    sum += ((*bytes)&bpf_htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((uint16_t)sum);
}

static __always_inline uint16_t pad_checksum(uint16_t old_sum, uint8_t* padding, size_t len) {
	uint16_t * bytes = (uint16_t *)padding;
  register uint32_t sum = (uint32_t)old_sum;
  while (len > 1) {
    sum += * bytes++;
    len -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(len > 0) {
    sum += ((*bytes)&bpf_htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((uint16_t)sum);
}

static __always_inline void bpf_memset(uint8_t *buff, uint8_t v, size_t n) {
	uint8_t *p = buff;
	#pragma unroll
	for (size_t i=0; i<n; i++) {
		*p=v;
		p++;
	}
}

static __always_inline void update_ip_csum(struct iphdr* iph, __be16 old_tot_len) {
  if (old_tot_len == iph->tot_len){
    return;
  }
  __sum16 sum =  + (~bpf_ntohs(*(unsigned short *)&iph->tot_len) & 0xffff);
  sum += bpf_ntohs(iph->check);
  sum = (sum & 0xffff) + (sum>>16);
  iph->check = bpf_htons(sum + (sum>>16) + 1);
}

static __always_inline void update_ip_csum_byte(struct iphdr* iph, void *p, uint8_t new_val) {
	unsigned long sum;
	unsigned short old;
	old = *(unsigned short *)p;
	*(uint8_t *)p = new_val;
	sum = old + (~*(unsigned short *)p & 0xffff);
	sum += bpf_ntohs(iph->check);
	sum = (sum & 0xffff) + (sum>>16);
	iph->check = bpf_htons(sum + (sum>>16));
}

static __always_inline void update_tcp_csum_byte(struct tcphdr* tcph, void *p, uint8_t new_val) {
	unsigned long sum;
	unsigned short old;
	old = *(unsigned short *)p;
	*(uint8_t *)p = new_val;
	sum = old + (~*(unsigned short *)p & 0xffff);
	sum += bpf_ntohs(tcph->check);
	sum = (sum & 0xffff) + (sum>>16);
	tcph->check = bpf_htons(sum + (sum>>16));
}

static __always_inline void update_ip_tot_len(struct iphdr* iph, uint16_t new_val) {
	void *p = (void *)&(iph->tot_len);
	update_ip_csum_byte(iph, p, *(uint8_t *)(&new_val));
	update_ip_csum_byte(iph, p+1, *((uint8_t *)(&new_val)+1));
}

static __always_inline void update_tcp_doff(struct tcphdr* tcph, uint16_t new_val) {
	void *p = (void *)tcph + 12;
	update_tcp_csum_byte(tcph, p, *(uint8_t *)(&new_val));
	update_tcp_csum_byte(tcph, p+1, *((uint8_t *)(&new_val)+1));
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	bool found_syn = false;
	unsigned char did_zero = 0;
	unsigned int padding_added = 0;

	unsigned long long start_time;
	unsigned long long end_time;
	#if MEASURE_TIME
		start_time = bpf_ktime_get_ns();
	#endif

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int packet_size = data_end - data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int n_tcp_op_bytes;
	uint8_t *tcpop;
	unsigned char *padding;
	size_t tcp_len;
	__be16 old_tot_len;

	// Parse Ethernet Header
	ethh = data;
	if ((void *)ethh + sizeof(*ethh) <= data_end) {
		if (bpf_htons(ethh->h_proto) == ETH_P_IP) {
			// Parse IPv4 Header
			iph = data + sizeof(*ethh);
			if ((void *)iph + sizeof(*iph) <= data_end) {
				if (iph->protocol == IPPROTO_TCP) {
					// Parse TCP Header
					tcph = (void *)iph + sizeof(*iph);
					if ((void *)tcph + sizeof(*tcph) <= data_end) {
						if (is_syn(tcph)) {
							found_syn = true;
							n_tcp_op_bytes = (tcph->doff - 5) * 4;

							// if (PAYLOAD_PAD) {
							// 	if (bpf_xdp_adjust_tail(ctx, PAYLOAD_PAD)) {
							// 			return XDP_PASS;
							// 	}
							// }
							// padding_added = PAYLOAD_PAD;

							unsigned int padding_needed = SYN_PAD_MIN_BYTES - n_tcp_op_bytes;
							if (padding_needed > 0 && padding_needed < 40) {
								if (bpf_xdp_adjust_tail(ctx, padding_needed)) {
										return XDP_PASS;
								}
								padding_added = padding_needed;
								padding = (void *)tcph + sizeof(*tcph) + n_tcp_op_bytes;
							}
						}
					}
				}
			}
		}
	}

	if (padding_added > 0) {
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		packet_size = data_end - data;

		ethh = data;
		if ((void *)ethh + sizeof(*ethh) <= data_end) {
			if (bpf_htons(ethh->h_proto) == ETH_P_IP) {
				// Parse IPv4 Header
				iph = data + sizeof(*ethh);
				if ((void *)iph + sizeof(*iph) <= data_end) {
					if (iph->protocol == IPPROTO_TCP) {
						// Parse TCP Header
						tcph = (void *)iph + sizeof(*iph);
						if ((void *)tcph + sizeof(*tcph) <= data_end) {
							// old_tot_len = iph->tot_len;
							// iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + padding_added);

							tcpop = (uint8_t *)((void *)tcph + sizeof(*tcph));
							if ((void *)tcpop + SYN_PAD_MIN_BYTES <= data_end) {
								bpf_memset(tcpop, NO_OP_VAL, SYN_PAD_MIN_BYTES-1);
								uint8_t *end_op = tcpop + (SYN_PAD_MIN_BYTES-1);
								*end_op = END_OP_VAL;
								did_zero=1;
							}

							uint16_t new_tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + padding_added);
							update_ip_tot_len(iph, new_tot_len);

							void * old_doff_p = (void *)tcph + 12;
							uint16_t old_doff_bits = *(uint16_t *)old_doff_p;
							uint16_t new_doff_bits = (bpf_htons(SYN_PAD_MIN_DOFF) << 12) || old_doff_bits;
							update_tcp_doff(tcph, new_doff_bits);
							pad_tcp_checksum(tcph, padding_added);
							tcph->check = bpf_htons(pad_checksum(bpf_ntohs(tcph->check), (uint8_t *)padding, (size_t)padding_added));
						}
					}
				}
			}
		}

		#if GENERATE_EVENTS
			#if MEASURE_TIME
				end_time = bpf_ktime_get_ns();
			#endif
			struct event *e;
			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
			if (!e) {
				bpf_printk("WARNING: Failed to reserve space in ring buffer\n");
				return XDP_PASS;
			}
			e->status = 1;
			e->start = start_time;
			e->end = end_time;
			e->padding = padding_added;
			e->tcp_len = tcp_len;
			bpf_ringbuf_submit(e, 0);
		#endif

	}
	return XDP_PASS;
}
