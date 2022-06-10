/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#include "xdp_common.h"

#ifndef __SYN_PAD_H
#define __SYN_PAD_H

#define GENERATE_EVENTS 1
#define MEASURE_TIME 1
#define SYN_PAD_MIN_DOFF 15

const unsigned int SYN_PAD_MIN_BYTES = 40;

const unsigned char END_OP_VAL = 0;
const unsigned char NO_OP_VAL = 1;


struct event {
	unsigned char status;
	unsigned long long start;
	unsigned long long end;
	unsigned int padding;
	size_t tcp_len;
};

#endif /* __SYN_PAD_H */
