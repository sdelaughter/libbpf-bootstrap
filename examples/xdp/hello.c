// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include "hello.h"
#include "hello.skel.h"
#include <bpf/libbpf.h>

unsigned long long start_ts = 0;

static struct env {
	bool verbose;
	long ifindex;
} env;

const char *argp_program_version = "hello 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF hello demo application.\n"
"\n"
"It prints the size of received packets\n"
"\n"
"USAGE: ./hello [-i <interface>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "ifindex", 'i', "INTERFACE", 1, "Network interface to attach" },
	{},
};

static int bpf_object__attach_skeleton_net(struct bpf_object_skeleton *s) {
	int i, err;

	for (i = 0; i < s->prog_cnt; i++) {
		struct bpf_program *prog = *s->progs[i].prog;
		struct bpf_link **link = s->progs[i].link;

		if (!prog->load)
			continue;

		/* auto-attaching not supported for this program */
		if (!prog->sec_def || !prog->sec_def->attach_fn)
			continue;

		*link = bpf_program__attach_tracepoint(prog, "net", "net_dev_xmit");//, ifindex);
		err = libbpf_get_error(*link);
		if (err) {
			pr_warn("failed to auto-attach program '%s': %d\n",
				bpf_program__name(prog), err);
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
	//
	// if(!start_ts){
	// 	start_ts = e->start_ts;
	// }
	// float norm_ts = (e->start_ts - start_ts) / 1000000000.0;
	// unsigned long long duration = (e->end_ts - e->start_ts);
	//
	if (env.verbose) {
		printf("%u, %llu, %llu\n",
		e->size, e->start, e->end);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct hello_bpf *skel;
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
	skel = hello_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = hello_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// hello_bpf__set_type(skel, BPF_PROG_TYPE_XDP);

	// /* Attach tracepoints */
	// err = hello_bpf__attach(skel);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach BPF skeleton\n");
	// 	goto cleanup;
	// }
	err = bpf_object__attach_skeleton_net(skel->skeleton);
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
	if (env.verbose) {
		printf("%s, %s, %s\n",
		"status", "start", "end");
	}
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
	ring_buffer__free(rb);
	hello_bpf__detach(skel);
	hello_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
