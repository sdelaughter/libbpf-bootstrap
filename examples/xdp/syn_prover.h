/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __SYN_PROVER_H
#define __SYN_PROVER_H

const int POW_ITERS = 10;

#include "syn_pow.h"

struct event {
	unsigned long long start_ts;
	unsigned long long end_ts;
	unsigned long best_nonce;
	unsigned long best_hash;
	unsigned int hash_iters;
};

#endif /* __SYN_PROVER_H */
