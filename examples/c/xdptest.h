/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#include <bpf/libbpf.h>

#ifndef __XDPTEST_H
#define __XDPTEST_H

struct event {
	int pkt_size;
};

int bpf_object__attach_skeleton_xdp(struct bpf_object_skeleton *s, int ifindex)
{
	int i, err;

	for (i = 0; i < s->prog_cnt; i++) {
		struct bpf_program *prog = *s->progs[i].prog;
		struct bpf_link **link = s->progs[i].link;

		if (!prog->load)
			continue;

		/* auto-attaching not supported for this program */
		if (!prog->sec_def || !prog->sec_def->attach_fn)
			continue;

		*link = bpf_program__attach_xdp(prog, ifindex);
		err = libbpf_get_error(*link);
		if (err) {
			pr_warn("failed to auto-attach program '%s': %d\n",
				bpf_program__name(prog), err);
			return libbpf_err(err);
		}
	}

	return 0;
}

#endif /* __XDPTEST_H */
