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

static __always_inline bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

static __always_inline void update_tcp_csum(struct tcphdr* tcph, __u32 old_ack_seq) {
  if (old_ack_seq == tcph->ack_seq) return;
  __sum16 sum = old_ack_seq + (~bpf_ntohs(*(unsigned short *)&tcph->ack_seq) & 0xffff);
  sum += bpf_ntohs(tcph->check);
  sum = (sum & 0xffff) + (sum>>16);
  tcph->check = bpf_htons(sum + (sum>>16) + 1);
}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static __always_inline unsigned short csum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
	#pragma unroll
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&bpf_htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
	#pragma unroll
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/
static __always_inline void set_ip_csum(struct iphdr* iph){
	//From https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
  iph->check = 0;
  iph->check = csum((unsigned short*)iph, iph->ihl<<2);
}

static __always_inline void set_tcp_csum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = bpf_ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += bpf_htons(IPPROTO_TCP);
    //the length
    sum += bpf_htons(tcpLen);

    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
		#pragma unroll
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&bpf_htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
			#pragma unroll
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

// static __always_inline void set_tcp_csum(struct iphdr *iph, struct tcphdr *tcph) {
// 	//From https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
//   register unsigned long sum = 0;
//   unsigned short tcpLen = bpf_ntohs(iph->tot_len) - (iph->ihl<<2);
//   //add the pseudo header
//   //the source ip
//   sum += (iph->saddr>>16)&0xFFFF;
//   sum += (iph->saddr)&0xFFFF;
//   //the dest ip
//   sum += (iph->daddr>>16)&0xFFFF;
//   sum += (iph->daddr)&0xFFFF;
//   //protocol and reserved: 6
//   sum += bpf_htons(IPPROTO_TCP);
//   //the length
//   sum += bpf_htons(tcpLen);
//
//   //add the IP payload
//   //initialize checksum to 0
//   tcph->check = 0;
//   while (tcpLen > 1) {
// 	  sum += * (unsigned long *)tcph++;
// 	  tcpLen -= 2;
//   }
//
// 	//if any bytes left, pad the bytes and add
//   if(tcpLen > 0) {
//     //printf("+++++++++++padding, %dn", tcpLen);
//     sum += ((*(unsigned long *)tcph)&bpf_htons(0xFF00));
//   }
//
//   //Fold 32-bit sum to 16 bits: add carrier to result
//   while (sum>>16) {
//     sum = (sum & 0xffff) + (sum >> 16);
//   }
//   sum = ~sum;
//
// 	//set computation result
//   tcph->check = (unsigned short)sum;
// }


SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	bool found_syn = false;
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
	unsigned char *padding;

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
							int n_tcp_op_bytes = (tcph->doff - 5) * 4;
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
						iph->tot_len += padding_added;
						// Parse TCP Header
						tcph = (void *)iph + sizeof(*iph);
						if ((void *)tcph + sizeof(*tcph) <= data_end) {
							tcph->doff = SYN_PAD_MIN_DOFF;

							// if ((void *)padding + padding_added <= data_end) {
							// 	#pragma unroll
							// 	for (int i=0; i < padding_added - 1; i++) {
							// 		*((unsigned char *)padding + i) = NO_OP_VAL;
							// 	}
							// 	*((unsigned char *)padding + padding_added - 1) = END_OP_VAL;
							// }
							// set_tcp_csum(iph, (unsigned short *)tcph);
							set_ip_csum(iph);
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
			e->status = 0;
			e->start = start_time;
			e->end = end_time;
			e->padding = padding_added;
			bpf_ringbuf_submit(e, 0);
		#endif

	}
	return XDP_PASS;
}
