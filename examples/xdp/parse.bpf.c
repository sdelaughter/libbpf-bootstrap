// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
// #include "vmlinux.h"
#include "parse.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// const volatile unsigned long long min_duration_ns = 0;
//
SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
		return XDP_PASS;
	}

	e->ts = bpf_ktime_get_ns();

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	int packet_size = data_end - data;
	e->packet_size = packet_size;

	// Parse Ethernet Header
  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) <= data_end) {
    // e->eth_src = eth->h_source;
    // e->eth_dst = eth->h_dest;
    // e->eth_protocol = eth->h_proto;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
      // Parse IPv4 Header
      struct iphdr *ip = data + sizeof(*eth);
      if ((void *)ip + sizeof(*ip) <= data_end) {
        // e->ihl = ip->ihl;
        // e->ip_version = ip->version;
        // e->tos = ip->tos;
        // e->ip_len = ip->tot_len;
        // e->ip_id = bpf_ntohs(ip->id);
        // e->flag_df = bpf_ntohs(ip->frag_off & 0x4000);
        // e->flag_mf = bpf_ntohs(ip->frag_off & 0x2000);
        // e->ip_offset = bpf_ntohs(ip->frag_off & 0x1FFF);
        e->ip_ttl = ip->ttl;
        e->ip_protocol = ip->protocol;
        // e->ip_checksum = ip->check;
        e->ip_saddr = bpf_ntohs(ip->saddr);
        e->ip_daddr = bpf_ntohs(ip->daddr);

        if (ip->protocol == IPPROTO_UDP) {
          // Parse UDP Header
          struct udphdr *udp = (void*)ip + sizeof(*ip);
          if ((void *)udp + sizeof(*udp) <= data_end) {
            e->sport = udp->source;
            e->dport = udp->dest;
            e->payload_size = udp->len - 8;
            // e->l4_checksum = udp->check;

						/*
            if ((void *)udp + sizeof(*udp) <= data_end) {
              char *payload = (void *)udp + sizeof(*udp);
              e->payload = payload;
            }
						*/
          }

        } else if (ip->protocol == IPPROTO_ICMP) {
          // Parse ICMP Header
          struct icmphdr *icmp = (void *)ip + sizeof(*ip);
          if ((void *)icmp + sizeof(*icmp) <= data_end) {
						e->payload_size = ip->tot_len - (sizeof(struct iphdr) + sizeof(struct icmphdr));
            // e->icmp_type = icmp->type;
            // e->icmp_code = icmp->code;
            // e->icmp_checksum = icmp->checksum;
            // e->icmp_un = icmp->un;
						e->sport = 0;
            e->dport = 0;

						/*
            if ((void *)icmp + sizeof(*icmp) <= data_end) {
              char *payload = (void *)icmp + sizeof(*icmp);
              e->payload = payload;
            }
						*/
          }

        } else if (ip->protocol == IPPROTO_TCP) {
          // Parse TCP Header
          struct tcphdr *tcp = (void *)ip + sizeof(*ip);
          if ((void *)tcp + sizeof(*tcp) <= data_end) {
						e->payload_size = ip->tot_len - (sizeof(struct iphdr) + sizeof(struct icmphdr));
            e->sport = bpf_ntohs(tcp->source);
            e->dport = bpf_ntohs(tcp->dest);
            // e->tcp_seq = bpf_ntohs(tcp->seq);
            // e->tcp_ack_seq = bpf_ntohs(tcp->ack_seq);
            // e->tcp_doff = tcp->doff;
            // e->tcp_res1 = tcp->res1;
            // e->tcp_cwr = tcp->cwr;
            // e->tcp_ece = tcp->ece;
            // e->tcp_urg = tcp->urg;
            // e->tcp_ack = tcp->ack;
            // e->tcp_psh = tcp->psh;
            // e->tcp_rst = tcp->rst;
            // e->tcp_syn = tcp->syn;
            // e->tcp_fin = tcp->fin;
            // e->tcp_window = tcp->window;
            // e->l4_checksum = tcp->check;
            // e->tcp_urg_ptr = tcp->urg_ptr;

            // int n_tcp_op_bytes = (tcp->doff - 5) * 4;
            // // TCP Option parsing is complicated...

						/*
            if ((void *)tcp + sizeof(*tcp) + n_tcp_op_bytes < data_end) {
              char *payload = (void *)tcp + sizeof(*tcp) + n_tcp_op_bytes;
              e-> payload;
            }
						*/
          }
        } else {
					e->payload_size = ip->tot_len - (sizeof(struct iphdr));
					e->sport = 0;
					e->dport = 0;
				}
      }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
      struct ipv6hdr *ip = data + sizeof(*eth);
      if ((void *)ip + sizeof(*ip) <= data_end) {
				e->ip_version=ip->version;
				e->ip_protocol=ip->nexthdr;
				e->ip_saddr=0;
				e->ip_daddr=0;
				e->sport=0;
				e->dport=0;
				e->payload_size=ip->payload_len;
      }
    } else {
      e->ip_version=0;
			e->ip_protocol=0;
			e->ip_saddr=0;
			e->ip_daddr=0;
			e->sport=0;
			e->dport=0;
			e->payload_size=0;
    }
	}

  bpf_ringbuf_submit(e, 0);

  return XDP_PASS;
}
