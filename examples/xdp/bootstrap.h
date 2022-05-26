/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

const unsigned long ETH_P_IP = 2048;
const unsigned long ETH_P_IPV6 = 34525;

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7


struct event {
	unsigned long long start;
	unsigned long long end;
	unsigned int packet_size;
	unsigned char protocol;
};

#endif /* __BOOTSTRAP_H */
