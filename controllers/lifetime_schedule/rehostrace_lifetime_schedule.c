// SPDX-License-Identifier: GPL-2.0-only
/* Generic, data-driven kprobe schedule controller for public RehostRace runs. */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>

#include "rehostrace_schedule.h"

struct rehostrace_schedule_point_config {
	const char *id;
	const char *symbol;
	u32 enter_mask;
	u32 wait_mask;
	u32 release_mask;
	int counter_index;
};

struct rehostrace_schedule_counter_config {
	const char *id;
	u32 threshold;
	u32 threshold_mask;
};

#include "rehostrace_schedule_generated.h"

struct rehostrace_schedule_probe {
	struct kprobe probe;
	const struct rehostrace_schedule_point_config *config;
};

static struct rehostrace_schedule_probe runtime_probes[REHOSTRACE_SCHEDULE_POINT_COUNT];
static atomic_long_t schedule_bits = ATOMIC_LONG_INIT(0);
static atomic_long_t schedule_object = ATOMIC_LONG_INIT(0);
static atomic_t schedule_timeouts = ATOMIC_INIT(0);
static atomic_t schedule_counters[REHOSTRACE_SCHEDULE_MAX_COUNTERS];
static bool controller_armed;

static void emit_bits(u32 bits)
{
	atomic_long_or(bits, &schedule_bits);
}

static bool wait_for_bits(u32 required, const char *point)
{
	unsigned long timeout = msecs_to_jiffies(REHOSTRACE_SCHEDULE_TIMEOUT_MS);
	unsigned long deadline = jiffies + max_t(unsigned long, timeout, 1);

	while (((u32)atomic_long_read(&schedule_bits) & required) != required) {
		if (time_after(jiffies, deadline)) {
			atomic_inc(&schedule_timeouts);
			emit_bits(REHOSTRACE_SCHEDULE_TIMEOUT_BIT);
			pr_err("REHOSTRACE_SCHEDULE_TIMEOUT point=%s wait=0x%x bits=0x%lx\n",
			       point, required, atomic_long_read(&schedule_bits));
			return false;
		}
		cpu_relax();
	}
	return true;
}

static unsigned long captured_identity(struct pt_regs *regs)
{
	return regs_get_kernel_argument(regs, REHOSTRACE_SCHEDULE_IDENTITY_ARGUMENT);
}

static bool check_identity(const char *point, unsigned long object)
{
	unsigned long expected;

	if (!REHOSTRACE_SCHEDULE_IDENTITY_SAME)
		return true;
	expected = (unsigned long)atomic_long_read(&schedule_object);
	if (!expected) {
		atomic_long_cmpxchg(&schedule_object, 0, object);
		expected = (unsigned long)atomic_long_read(&schedule_object);
	}
	if (expected == object)
		return true;
	emit_bits(REHOSTRACE_SCHEDULE_TIMEOUT_BIT);
	pr_err("REHOSTRACE_SCHEDULE_OBJECT_MISMATCH point=%s got=%px expected=%px\n",
	       point, (void *)object, (void *)expected);
	return false;
}

static int schedule_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct rehostrace_schedule_probe *runtime;
	const struct rehostrace_schedule_point_config *config;
	unsigned long object;
	int value;

	runtime = container_of(probe, struct rehostrace_schedule_probe, probe);
	config = runtime->config;
	object = captured_identity(regs);
	if (!check_identity(config->id, object))
		return 0;

	emit_bits(config->enter_mask);
	pr_info("REHOSTRACE_SCHEDULE_POINT phase=enter point=%s obj=%px bits=0x%lx\n",
		config->id, (void *)object, atomic_long_read(&schedule_bits));
	if (config->wait_mask && !wait_for_bits(config->wait_mask, config->id))
		return 0;
	emit_bits(config->release_mask);
	if (config->release_mask)
		pr_info("REHOSTRACE_SCHEDULE_POINT phase=release point=%s obj=%px bits=0x%lx\n",
			config->id, (void *)object, atomic_long_read(&schedule_bits));

	if (config->counter_index >= 0) {
		const struct rehostrace_schedule_counter_config *counter;

		counter = &rehostrace_schedule_counters[config->counter_index];
		value = atomic_inc_return(&schedule_counters[config->counter_index]);
		if (value >= counter->threshold)
			emit_bits(counter->threshold_mask);
		pr_info("REHOSTRACE_SCHEDULE_COUNTER id=%s value=%d obj=%px bits=0x%lx\n",
			counter->id, value, (void *)object,
			atomic_long_read(&schedule_bits));
	}
	return 0;
}

static ssize_t state_read(struct file *file, char __user *buffer, size_t length,
			  loff_t *position)
{
	struct rehostrace_schedule_state state = {
		.magic = REHOSTRACE_SCHEDULE_MAGIC,
		.version = REHOSTRACE_SCHEDULE_VERSION,
		.size = sizeof(state),
		.bits = (u32)atomic_long_read(&schedule_bits),
		.timeouts = (u32)atomic_read(&schedule_timeouts),
		.point_count = REHOSTRACE_SCHEDULE_POINT_COUNT,
		.counter_count = REHOSTRACE_SCHEDULE_COUNTER_COUNT,
		.object = (unsigned long)atomic_long_read(&schedule_object),
	};
	unsigned int index;

	for (index = 0; index < REHOSTRACE_SCHEDULE_COUNTER_COUNT; index++)
		state.counters[index] = (u32)atomic_read(&schedule_counters[index]);
	if (length < sizeof(state))
		return -EINVAL;
	if (copy_to_user(buffer, &state, sizeof(state)))
		return -EFAULT;
	return sizeof(state);
}

static const struct file_operations state_fops = {
	.owner = THIS_MODULE,
	.read = state_read,
};

static struct miscdevice state_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "rehostrace_schedule",
	.fops = &state_fops,
	.mode = 0400,
};

static void unregister_runtime_probes(unsigned int count)
{
	while (count)
		unregister_kprobe(&runtime_probes[--count].probe);
}

static int __init schedule_init(void)
{
	unsigned int index;
	int rc;

	if (REHOSTRACE_SCHEDULE_COUNTER_COUNT > REHOSTRACE_SCHEDULE_MAX_COUNTERS)
		return -E2BIG;
	for (index = 0; index < REHOSTRACE_SCHEDULE_POINT_COUNT; index++) {
		runtime_probes[index].config = &rehostrace_schedule_points[index];
		runtime_probes[index].probe.symbol_name = rehostrace_schedule_points[index].symbol;
		runtime_probes[index].probe.pre_handler = schedule_pre;
		rc = register_kprobe(&runtime_probes[index].probe);
		if (rc)
			goto fail;
	}
	rc = misc_register(&state_device);
	if (rc)
		goto fail;
	controller_armed = true;
	pr_info("REHOSTRACE_SCHEDULE_READY id=%s source_sha256=%s points=%u counters=%u\n",
		REHOSTRACE_SCHEDULE_ID, REHOSTRACE_SCHEDULE_SOURCE_SHA256,
		REHOSTRACE_SCHEDULE_POINT_COUNT, REHOSTRACE_SCHEDULE_COUNTER_COUNT);
	return 0;

fail:
	unregister_runtime_probes(index);
	pr_err("REHOSTRACE_SCHEDULE_REFUSED id=%s rc=%d registered=%u\n",
	       REHOSTRACE_SCHEDULE_ID, rc, index);
	return rc;
}

static void __exit schedule_exit(void)
{
	if (controller_armed) {
		misc_deregister(&state_device);
		unregister_runtime_probes(REHOSTRACE_SCHEDULE_POINT_COUNT);
	}
}

module_init(schedule_init);
module_exit(schedule_exit);

MODULE_DESCRIPTION("Generic data-driven RehostRace lifetime schedule controller");
MODULE_LICENSE("GPL");
