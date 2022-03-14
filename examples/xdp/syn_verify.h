/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __SYN_VERIFY_H
#define __SYN_VERIFY_H

#include "syn_verify.h"

struct event {
	unsigned long long start_ts;
	unsigned long long end_ts;
	unsigned long hash;
	unsigned char valid;
};

#endif /* __SYN_VERIFY_H */
