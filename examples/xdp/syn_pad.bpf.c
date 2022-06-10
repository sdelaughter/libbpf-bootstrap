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

// struct tcp_options {
// 	unsigned char bytes[SYN_PAD_MIN_BYTES];
// };

struct tcp_options {
	unsigned char byte0;
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
	unsigned char byte5;
	unsigned char byte6;
	unsigned char byte7;
	unsigned char byte8;
	unsigned char byte9;
	unsigned char byte10;
	unsigned char byte11;
	unsigned char byte12;
	unsigned char byte13;
	unsigned char byte14;
	unsigned char byte15;
	unsigned char byte16;
	unsigned char byte17;
	unsigned char byte18;
	unsigned char byte19;
	unsigned char byte20;
	unsigned char byte21;
	unsigned char byte22;
	unsigned char byte23;
	unsigned char byte24;
	unsigned char byte25;
	unsigned char byte26;
	unsigned char byte27;
	unsigned char byte28;
	unsigned char byte29;
	unsigned char byte30;
	unsigned char byte31;
	unsigned char byte32;
	unsigned char byte33;
	unsigned char byte34;
	unsigned char byte35;
	unsigned char byte36;
	unsigned char byte37;
	unsigned char byte38;
	unsigned char byte39;
	unsigned char byte40;
};

static __always_inline void zero_op_bytes(struct tcp_options *tcpop) {
	tcpop->byte0=NO_OP_VAL;
	tcpop->byte1=NO_OP_VAL;
	tcpop->byte2=NO_OP_VAL;
	tcpop->byte3=NO_OP_VAL;
	tcpop->byte4=NO_OP_VAL;
	tcpop->byte5=NO_OP_VAL;
	tcpop->byte6=NO_OP_VAL;
	tcpop->byte7=NO_OP_VAL;
	tcpop->byte8=NO_OP_VAL;
	tcpop->byte9=NO_OP_VAL;
	tcpop->byte10=NO_OP_VAL;
	tcpop->byte11=NO_OP_VAL;
	tcpop->byte12=NO_OP_VAL;
	tcpop->byte13=NO_OP_VAL;
	tcpop->byte14=NO_OP_VAL;
	tcpop->byte15=NO_OP_VAL;
	tcpop->byte16=NO_OP_VAL;
	tcpop->byte17=NO_OP_VAL;
	tcpop->byte18=NO_OP_VAL;
	tcpop->byte19=NO_OP_VAL;
	tcpop->byte20=NO_OP_VAL;
	tcpop->byte21=NO_OP_VAL;
	tcpop->byte23=NO_OP_VAL;
	tcpop->byte22=NO_OP_VAL;
	tcpop->byte24=NO_OP_VAL;
	tcpop->byte25=NO_OP_VAL;
	tcpop->byte26=NO_OP_VAL;
	tcpop->byte27=NO_OP_VAL;
	tcpop->byte28=NO_OP_VAL;
	tcpop->byte29=NO_OP_VAL;
	tcpop->byte30=NO_OP_VAL;
	tcpop->byte31=NO_OP_VAL;
	tcpop->byte32=NO_OP_VAL;
	tcpop->byte33=NO_OP_VAL;
	tcpop->byte34=NO_OP_VAL;
	tcpop->byte35=NO_OP_VAL;
	tcpop->byte36=NO_OP_VAL;
	tcpop->byte37=NO_OP_VAL;
	tcpop->byte38=NO_OP_VAL;
	tcpop->byte39=NO_OP_VAL;
	tcpop->byte40=END_OP_VAL;
}


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

// static __always_inline void update_tcp_csum(struct tcphdr* tcph, __u32 old_doff) {
//   if (old_doff == tcph->ack_seq) return;
//   __sum16 sum = old_doff + (~bpf_ntohs(*(unsigned short *)&tcph->doff) & 0xffff);
//   sum += bpf_ntohs(tcph->check);
//   sum = (sum & 0xffff) + (sum>>16);
//   tcph->check = bpf_htons(sum + (sum>>16) + 1);
// }

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

static __always_inline uint16_t compute_checksum(struct iphdr *iph) {
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

static void update_ip_csum(struct iphdr* iph, __be16 old_tot_len) {
  if (old_tot_len == iph->tot_len){
    return;
  }
  __sum16 sum =  + (~bpf_ntohs(*(unsigned short *)&iph->tot_len) & 0xffff);
  sum += bpf_ntohs(iph->check);
  sum = (sum & 0xffff) + (sum>>16);
  iph->check = bpf_htons(sum + (sum>>16) + 1) + 60;
}

// static void update_tcp_csum(struct iphdr* iph, struct tcphdr* tcph, __be32 old_saddr) {
//   if (old_saddr == iph->saddr){
//     return;
//   }
//   __sum16 sum =  + (~ntohs(*(unsigned short *)&iph->saddr) & 0xffff);
//   sum += ntohs(tcph->check);
//   sum = (sum & 0xffff) + (sum>>16);
//   tcph->check = htons(sum + (sum>>16) + 1);
// }

// static __always_inline void set_tcp_csum(struct iphdr *pIph, unsigned short *ipPayload, void *data_end) {
//     register unsigned long sum = 0;
//     unsigned short tcpLen = bpf_ntohs(pIph->tot_len) - (pIph->ihl<<2);
//     struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
//     //add the pseudo header
//     //the source ip
//     sum += (pIph->saddr>>16)&0xFFFF;
//     sum += (pIph->saddr)&0xFFFF;
//     //the dest ip
//     sum += (pIph->daddr>>16)&0xFFFF;
//     sum += (pIph->daddr)&0xFFFF;
//     //protocol and reserved: 6
//     sum += bpf_htons(IPPROTO_TCP);
//     //the length
//     sum += bpf_htons(tcpLen);
//
//     //add the IP payload
//     //initialize checksum to 0
//     tcphdrp->check = 0;
//     while (tcpLen > 1) {
//         sum += * ipPayload++;
//         tcpLen -= 2;=NO_OP_VAL
//     }
//     //if any bytes left, pad the bytes and add
//     if(tcpLen > 0 && (void *)ipPayload <= data_end) {
//         //printf("+++++++++++padding, %dn", tcpLen);
//         sum += ((*ipPayload)&bpf_htons(0xFF00));
//     }
//     //Fold 32-bit sum to 16 bits: add carrier to result
//     while (sum>>16) {
//         sum = (sum & 0xffff) + (sum >> 16);
//     }
//     sum = ~sum;
//     //set computation result
//     tcphdrp->check = (unsigned short)sum;
// }

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
//   tcph->check = 0;padding_added
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

static __always_inline uint16_t tcp_csum(const void *buff, size_t len, uint32_t src_addr, uint32_t dest_addr) {
	const uint16_t *buf=buff;
	uint16_t *ip_src=(void *)&src_addr;
	uint16_t *ip_dst=(void *)&dest_addr;
	uint32_t sum;
	size_t length = len;

	// Calculate the sum                                            //
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		len -= 2;
	}

	// Don't need this, the padding we add already ensures the length won't be odd

	// if ( len & 1 ) {
	// 	// Add the padding if the packet length is odd          //
	// 	sum += *((uint8_t *)buf);
	// }

	// Add the pseudo-header                                        //
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += bpf_htons(IPPROTO_TCP);
	sum += bpf_htons(length);

	// Add the carries                                              //
	while (sum >> 16) {
	   sum = (sum & 0xFFFF) + (sum >> 16);
	}

	// Return the one's complement of sum                           //
	return ( (uint16_t)(~sum)  );
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
	struct tcp_options *tcpop;
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
							old_tot_len = iph->tot_len;
							iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + padding_added);
							tcph->doff = SYN_PAD_MIN_DOFF;

							tcpop = (void *)tcph + sizeof(*tcph);
							if ((void *)tcpop + sizeof(*tcpop) <= data_end) {
								zero_op_bytes(tcpop);
								did_zero=1;
								// #pragma unroll
								// for (int i=n_tcp_op_bytes+1; i < SYN_PAD_MIN_BYTES - 1; i++) {
								// 	tcpop->bytes[i] = NO_OP_VAL;
								// }
								// tcpop->bytes[SYN_PAD_MIN_BYTES - 1] = END_OP_VAL;
							}
							// iph->check = 0;
						  // iph->check = compute_checksum(iph);
							update_ip_csum(iph, old_tot_len);

							tcp_len = sizeof(*tcph);
							// uint32_t ip_saddr = bpf_ntohs(iph->saddr);
							// uint32_t ip_daddr = bpf_ntohs(iph->daddr);
							// tcph->check = 0;
							// tcph->check = tcp_csum((unsigned short *)tcph, tcp_len, ip_saddr, ip_daddr);
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
