// SPDX-License-Identifier: GPL-2.0-only
/* External deterministic scheduler for the redistributable seeded fixture. */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>

#include "rehostrace_seeded.h"

#define GATE_TIMEOUT (5 * HZ)

enum seed_stage {
	SEED_A_OBJECT_RELEASED = 1,
	SEED_B_OBJECT_LOCK_PRE,
	SEED_B_OBJECT_HELD,
	SEED_A_LIST_HELD,
	SEED_FREE_PRE,
};

struct seed_probe {
	struct kprobe probe;
	enum seed_stage stage;
};

static atomic_long_t seed_bits = ATOMIC_LONG_INIT(0);
static atomic_long_t seed_object = ATOMIC_LONG_INIT(0);
static atomic_t free_entries = ATOMIC_INIT(0);
static atomic_t timeouts = ATOMIC_INIT(0);
static bool controller_armed;

static void set_bits(unsigned long bits)
{
	atomic_long_or(bits, &seed_bits);
}

static bool wait_bits(unsigned long required, const char *label)
{
	unsigned long deadline = jiffies + GATE_TIMEOUT;

	while ((atomic_long_read(&seed_bits) & required) != required) {
		if (time_after(jiffies, deadline)) {
			atomic_inc(&timeouts);
			set_bits(REHOSTRACE_SEED_TIMEOUT);
			pr_err("REHOSTRACE_SEED_TIMEOUT label=%s bits=0x%lx\n",
			       label, atomic_long_read(&seed_bits));
			return false;
		}
		cpu_relax();
	}
	return true;
}

static int seed_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct seed_probe *seed = container_of(probe, struct seed_probe, probe);
	unsigned long object = regs_get_kernel_argument(regs, 0);
	unsigned long expected = (unsigned long)atomic_long_read(&seed_object);
	int count;

	if (seed->stage == SEED_A_OBJECT_RELEASED)
		atomic_long_cmpxchg(&seed_object, 0, object);
	else if (expected && object != expected) {
		set_bits(REHOSTRACE_SEED_TIMEOUT);
		pr_err("REHOSTRACE_SEED_OBJECT_MISMATCH got=%px expected=%px\n",
		       (void *)object, (void *)expected);
		return 0;
	}

	switch (seed->stage) {
	case SEED_A_OBJECT_RELEASED:
		set_bits(REHOSTRACE_SEED_A_WAITING);
		pr_info("REHOSTRACE_SEED_GATE stage=a_object_released obj=%px\n",
			(void *)object);
		if (wait_bits(REHOSTRACE_SEED_B_LOCK_PRE, "b_object_lock_pre"))
			set_bits(REHOSTRACE_SEED_A_RELEASED);
		break;
	case SEED_B_OBJECT_LOCK_PRE:
		set_bits(REHOSTRACE_SEED_B_LOCK_PRE);
		pr_info("REHOSTRACE_SEED_GATE stage=b_object_lock_pre obj=%px\n",
			(void *)object);
		wait_bits(REHOSTRACE_SEED_A_RELEASED, "a_released");
		break;
	case SEED_B_OBJECT_HELD:
		set_bits(REHOSTRACE_SEED_B_OBJECT_HELD);
		pr_info("REHOSTRACE_SEED_GATE stage=b_object_held obj=%px\n",
			(void *)object);
		wait_bits(REHOSTRACE_SEED_A_LIST_HELD, "a_list_held");
		break;
	case SEED_A_LIST_HELD:
		set_bits(REHOSTRACE_SEED_A_LIST_HELD);
		pr_info("REHOSTRACE_SEED_GATE stage=a_list_held obj=%px\n",
			(void *)object);
		break;
	case SEED_FREE_PRE:
		count = atomic_inc_return(&free_entries);
		if (count >= 2)
			set_bits(REHOSTRACE_SEED_SECOND_FREE);
		pr_info("REHOSTRACE_SEED_FREE_PRE count=%d obj=%px\n",
			count, (void *)object);
		break;
	}
	return 0;
}

static struct seed_probe probes[] = {
	{ .probe = { .symbol_name = "rehostrace_seed_a_object_released",
		     .pre_handler = seed_pre }, .stage = SEED_A_OBJECT_RELEASED },
	{ .probe = { .symbol_name = "rehostrace_seed_b_object_lock_pre",
		     .pre_handler = seed_pre }, .stage = SEED_B_OBJECT_LOCK_PRE },
	{ .probe = { .symbol_name = "rehostrace_seed_b_object_held",
		     .pre_handler = seed_pre }, .stage = SEED_B_OBJECT_HELD },
	{ .probe = { .symbol_name = "rehostrace_seed_a_list_held",
		     .pre_handler = seed_pre }, .stage = SEED_A_LIST_HELD },
	{ .probe = { .symbol_name = "rehostrace_seed_free_pre",
		     .pre_handler = seed_pre }, .stage = SEED_FREE_PRE },
};

static ssize_t state_read(struct file *file, char __user *buffer, size_t length,
			  loff_t *position)
{
	struct rehostrace_seed_state state = {
		.magic = REHOSTRACE_SEED_MAGIC,
		.version = REHOSTRACE_SEED_VERSION,
		.size = sizeof(state),
		.bits = (unsigned int)atomic_long_read(&seed_bits),
		.free_entries = (unsigned int)atomic_read(&free_entries),
		.timeouts = (unsigned int)atomic_read(&timeouts),
		.object = (unsigned long)atomic_long_read(&seed_object),
	};

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
	.name = "rehostrace_seed_schedule",
	.fops = &state_fops,
	.mode = 0400,
};

static void unregister_seed_probes(size_t count)
{
	while (count)
		unregister_kprobe(&probes[--count].probe);
}

static int __init seed_schedule_init(void)
{
	size_t count;
	int rc;

	for (count = 0; count < ARRAY_SIZE(probes); count++) {
		rc = register_kprobe(&probes[count].probe);
		if (rc)
			goto fail;
	}
	rc = misc_register(&state_device);
	if (rc)
		goto fail;
	controller_armed = true;
	pr_info("REHOSTRACE_SEED_CONTROLLER_READY version=1 gates=%zu\n",
		ARRAY_SIZE(probes));
	return 0;

fail:
	unregister_seed_probes(count);
	pr_err("REHOSTRACE_SEED_CONTROLLER_REFUSED rc=%d gates=%zu\n", rc, count);
	return rc;
}

static void __exit seed_schedule_exit(void)
{
	if (controller_armed) {
		misc_deregister(&state_device);
		unregister_seed_probes(ARRAY_SIZE(probes));
	}
}

module_init(seed_schedule_init);
module_exit(seed_schedule_exit);

MODULE_DESCRIPTION("External scheduler for the RehostRace seeded fixture");
MODULE_LICENSE("GPL");
