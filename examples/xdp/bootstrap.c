// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"


static struct env {
	bool verbose;
	// long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	printf("%llu, %llu, %u, %u\n", e->start, e->end, e->packet_size, e->protocol);
	return 0;
}

static int bpf_object__attach_skeleton_tp(struct bpf_object_skeleton *s) {
	int i, err = 0;

	for (i = 0; i < s->prog_cnt; i++) {
		struct bpf_program *prog = *s->progs[i].prog;
		struct bpf_link **link = s->progs[i].link;

		if (!prog->load)
			continue;

		/* auto-attaching not supported for this program */
		if (!prog->sec_def || !prog->sec_def->attach_fn)
			continue;

		*link = bpf_program__attach_tracepoint(prog, "net", "net_dev_queue");
		err = libbpf_get_error(*link);
		if (err) {
			pr_warn("failed to auto-attach program '%s': %d\n",
				bpf_program__name(prog), err);
			return err;
		}
	}
	return err;
}


//
// 	union bpf_attr attr = {};
// 	unsigned char log_buf[4096] = {};
// 	insn = (struct bpf_insn*)buf;
//   attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
//   attr.insns = (unsigned long)insn;
//   attr.insn_cnt = n / sizeof(struct bpf_insn);
//   attr.license = (unsigned long)"GPL";
//   attr.log_size = sizeof(log_buf);
//   attr.log_buf = (unsigned long)log_buf;
//   attr.log_level = 1;
//   attr.kern_version = 264656;
//   pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
//   if (pfd < 0) {
// 	  printf("bpf syscall error: %s\n", strerror(errno));
// 	  printf("log_buf = %s\n", log_buf);
// 	  exit(-1);
// }

int main(int argc, char **argv) {
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
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
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Parameterize BPF code with minimum duration parameter */
	// skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	// /* Load & attach BPF programs */
	err = bpf_object__attach_skeleton_tp(skel->skeleton);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	// err = bootstrap_bpf__attach_tracepoint(skel, "net", "net_dev_queue");
	// err = bootstrap_bpf__attach(skel);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach BPF skeleton\n");
	// 	goto cleanup;
	// }

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%s, %s, %s, %s\n", "start", "end", "size", "protocol");
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
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
