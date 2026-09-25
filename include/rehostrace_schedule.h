/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REHOSTRACE_SCHEDULE_H
#define REHOSTRACE_SCHEDULE_H

#define REHOSTRACE_SCHEDULE_MAGIC 0x52534348U
#define REHOSTRACE_SCHEDULE_VERSION 1U
#define REHOSTRACE_SCHEDULE_MAX_COUNTERS 8U
#define REHOSTRACE_SCHEDULE_TIMEOUT_BIT (1U << 31)

struct rehostrace_schedule_state {
	unsigned int magic;
	unsigned short version;
	unsigned short size;
	unsigned int bits;
	unsigned int timeouts;
	unsigned int point_count;
	unsigned int counter_count;
	unsigned int counters[REHOSTRACE_SCHEDULE_MAX_COUNTERS];
	unsigned long object;
};

#endif
