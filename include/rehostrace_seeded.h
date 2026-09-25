/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REHOSTRACE_SEEDED_H
#define REHOSTRACE_SEEDED_H

#define REHOSTRACE_SEED_MAGIC 0x52534545U
#define REHOSTRACE_SEED_VERSION 1U

#define REHOSTRACE_SEED_A_WAITING       (1U << 0)
#define REHOSTRACE_SEED_B_LOCK_PRE      (1U << 1)
#define REHOSTRACE_SEED_A_RELEASED      (1U << 2)
#define REHOSTRACE_SEED_B_OBJECT_HELD   (1U << 3)
#define REHOSTRACE_SEED_A_LIST_HELD     (1U << 4)
#define REHOSTRACE_SEED_SECOND_FREE     (1U << 5)
#define REHOSTRACE_SEED_TIMEOUT         (1U << 31)

struct rehostrace_seed_state {
	unsigned int magic;
	unsigned short version;
	unsigned short size;
	unsigned int bits;
	unsigned int free_entries;
	unsigned int timeouts;
	unsigned long object;
};

#endif
