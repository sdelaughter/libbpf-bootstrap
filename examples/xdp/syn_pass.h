/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __SYN_PASS_H
#define __SYN_PASS_H

const unsigned long ETH_P_IP = 2048;
const unsigned long ETH_P_IPV6 = 34525;

struct event {
	unsigned char status;
	unsigned long long start;
	unsigned long long end;
};

#endif /* __SYN_PASS_H */
