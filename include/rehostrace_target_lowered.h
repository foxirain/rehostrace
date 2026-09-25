/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REHOSTRACE_TARGET_LOWERED_H
#define REHOSTRACE_TARGET_LOWERED_H

#define REHOSTRACE_TARGET_MAGIC 0x52544c57U
#define REHOSTRACE_TARGET_VERSION 1U
#define REHOSTRACE_TARGET_MAX_COUNTERS 8U
#define REHOSTRACE_TARGET_TIMEOUT_BIT (1U << 31)

struct rehostrace_lowered_role_config {
	const char *id;
	const char *symbol;
	unsigned long offset;
	unsigned int predicate_offset;
	unsigned int predicate_count;
};

struct rehostrace_lowered_predicate_config {
	unsigned int kind;
	unsigned int argument;
	unsigned int offset;
	unsigned long value;
};

struct rehostrace_lowered_counter_config {
	const char *id;
	unsigned int threshold;
	unsigned int threshold_mask;
};

struct rehostrace_lowered_point_config {
	const char *id;
	const char *symbol;
	unsigned long offset;
	int role_index;
	unsigned int capture_kind;
	unsigned int capture_index;
	unsigned int enter_mask;
	unsigned int wait_mask;
	unsigned int release_mask;
	int counter_index;
};

struct rehostrace_lowered_observer_config {
	const char *id;
	const char *symbol;
	unsigned long offset;
	int role_index;
	unsigned int capture_kind;
	unsigned int capture_index;
};

struct rehostrace_lowered_relation_config {
	const char *left;
	const char *right;
	long delta;
};

struct rehostrace_target_state {
	unsigned int magic;
	unsigned short version;
	unsigned short size;
	unsigned int bits;
	unsigned int timeouts;
	unsigned int point_count;
	unsigned int counter_count;
	unsigned int counters[REHOSTRACE_TARGET_MAX_COUNTERS];
	unsigned long object;
};

#endif
