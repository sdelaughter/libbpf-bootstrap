/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __SYN_VERIFY_H
#define __SYN_VERIFY_H

const unsigned long ETH_P_IP = 2048;
const unsigned long ETH_P_IPV6 = 34525;

// const unsigned long POW_THRESHOLD  = 0; // k=1
// const unsigned long POW_THRESHOLD  = 2147483648; // k=2
// const unsigned long POW_THRESHOLD  = 3221225472; // k=4
// const unsigned long POW_THRESHOLD  = 3758096384; // k=8
// const unsigned long POW_THRESHOLD  = 4026531840; // k=16
const unsigned long POW_THRESHOLD  = 4160749568; // k=32
// const unsigned long POW_THRESHOLD  = 4227858432; // k=64


struct event {
	unsigned long long start_ts;
	unsigned long long end_ts;
	unsigned long hash;
	unsigned char valid;
};

#endif /* __SYN_VERIFY_H */``
