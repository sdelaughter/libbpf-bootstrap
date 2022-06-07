// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include "parse.h"
#include "parse.skel.h"
#include <bpf/libbpf.h>

unsigned long long start_ts = 0;

static struct env {
	bool verbose;
	long ifindex;
} env;

const char *argp_program_version = "parse 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF parse demo application.\n"
"\n"
"It prints the size of received packets\n"
"\n"
"USAGE: ./parse [-i <interface>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "ifindex", 'i', "INTERFACE", 1, "Network interface to attach" },
	{},
};

static int bpf_object__attach_skeleton_xdp(struct bpf_object_skeleton *s, int ifindex)
{
	int i, err;

	for (i = 0; i < s->prog_cnt; i++) {
		struct bpf_program *prog = *s->progs[i].prog;
		struct bpf_link **link = s->progs[i].link;

		*link = bpf_program__attach_xdp(prog, ifindex);
		err = libbpf_get_error(*link);
		if (err) {
			return err;
		}
	}
	return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		errno = 0;
		env.ifindex = strtol(arg, NULL, 10);
		if (errno || env.ifindex < 1) {
			fprintf(stderr, "Invalid interface: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
	const struct event *e = data;

	if(!start_ts) {
		start_ts = e->ts;
	}

	float norm_ts = (e->ts - start_ts) / 1000000000.0;

	unsigned char saddr_bytes[4];
  saddr_bytes[0] = e->ip_saddr & 0xFF;
  saddr_bytes[1] = (e->ip_saddr >> 8) & 0xFF;
  saddr_bytes[2] = (e->ip_saddr >> 16) & 0xFF;
  saddr_bytes[3] = (e->ip_saddr >> 24) & 0xFF;

	unsigned char daddr_bytes[4];
  daddr_bytes[0] = e->ip_daddr & 0xFF;
  daddr_bytes[1] = (e->ip_daddr >> 8) & 0xFF;
  daddr_bytes[2] = (e->ip_daddr >> 16) & 0xFF;
  daddr_bytes[3] = (e->ip_daddr >> 24) & 0xFF;


	char *proto_name_ipv4 = "IPv4";
	char *proto_name_ipv6 = "IPv6";
	char *proto_name_lldp = "LLDP";
	char *proto_name_arp = "ARP";
	char *proto_name_icmp = "ICMP";
	char *proto_name_udp = "UDP";
	char *proto_name_tcp = "TCP";
	char *proto_name_gre = "GRE";
	// char *proto_name_other = "UNKNOWN";

	char *eth_protocol;
	if (e->eth_protocol == 2048) {
		eth_protocol = proto_name_ipv4;
	} else if (e->eth_protocol == 34525) {
		eth_protocol = proto_name_ipv6;
	} else if (e->eth_protocol == 35020) {
		eth_protocol = proto_name_lldp;
	} else if (e->eth_protocol == 2054) {
		eth_protocol = proto_name_arp;
	} else {
		eth_protocol = l64a(e->eth_protocol);
	}

	char *ip_protocol;
	if (e->ip_protocol == 1) {
		ip_protocol = proto_name_icmp;
	} else if (e->eth_protocol == 6) {
		ip_protocol = proto_name_tcp;
	} else if (e->eth_protocol == 17) {
		ip_protocol = proto_name_udp;
	} else if (e->eth_protocol == 47) {
		ip_protocol = proto_name_gre;
	} else {
		ip_protocol = l64a(e->ip_protocol);
	}

	printf("{timestamp: %llu,\n"
				 " norm_ts: %f,\n"
				 " length: %u,\n"
				 " l2_header: {\n"
				 "\tl3_protocol: %s\n"
				 " },\n"
				 " l3_header: {\n"
				 "\tsrc: %u.%u.%u.%u,\n"
				 "\tdst: %u.%u.%u.%u,\n"
				 "\tttl: %u,\n"
			 	 "\tl4_protocol: %s\n"
				 " },\n"
				 " l4_header: {\n"
				 "\tsport: %u,\n"
				 "\tdport: %u\n"
				 " },\n"
				 " payload_size: %u\n"
				 "},\n",
		e->ts,
		norm_ts,
		e->packet_size,
		eth_protocol,
		saddr_bytes[0], saddr_bytes[1], saddr_bytes[2], saddr_bytes[3],
		daddr_bytes[0], daddr_bytes[1], daddr_bytes[2], daddr_bytes[3],
		e->ttl,
		ip_protocol,
		e->sport,
		e->dport,
		e->payload_size
	);

	// printf("%-8f, %-12u, %-8s, %-8s, %03d.%03d.%03d.%03d, %03d.%03d.%03d.%03d\n",
	//        norm_ts, e->packet_size, eth_protocol, ip_protocol,
	// 			 saddr_bytes[0], saddr_bytes[1], saddr_bytes[2], saddr_bytes[3],
	// 			 daddr_bytes[0], daddr_bytes[1], daddr_bytes[2], daddr_bytes[3]);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct parse_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = parse_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = parse_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// parse_bpf__set_type(skel, BPF_PROG_TYPE_XDP);

	/* Attach tracepoints */
	// err = parse_bpf__attach(skel);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach BPF skeleton\n");
	// 	goto cleanup;
	// }
	err = bpf_object__attach_skeleton_xdp(skel->skeleton, env.ifindex);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}


	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	// printf("%-8s | %-12s | %-8s | %-8s | %-15s | %-15s\n",
	//        "TIME", "PACKET SIZE", "ETH PROTO", "IP PROTO", "SOURCE", "DEST");
	printf("[")
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	printf("]");
	ring_buffer__free(rb);
	parse_bpf__detach(skel);
	parse_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
