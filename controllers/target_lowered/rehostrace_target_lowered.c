// SPDX-License-Identifier: GPL-2.0-only
/* Generic kprobe backend for a RehostRace controller-plan/v1 header. */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>

#include "rehostrace_target_lowered.h"
#include "rehostrace_target_lowered_generated.h"

struct runtime_role_probe {
	struct kprobe probe;
	unsigned int index;
};

struct runtime_point_probe {
	struct kprobe probe;
	const struct rehostrace_lowered_point_config *config;
};

struct runtime_observer_probe {
	struct kprobe probe;
	const struct rehostrace_lowered_observer_config *config;
};

static struct runtime_role_probe role_probes[REHOSTRACE_TARGET_ROLE_COUNT];
static struct runtime_point_probe point_probes[REHOSTRACE_TARGET_POINT_COUNT];
static struct runtime_observer_probe observer_probes[REHOSTRACE_TARGET_OBSERVER_COUNT];
static atomic_t role_pids[REHOSTRACE_TARGET_ROLE_COUNT];
static atomic_t counters[REHOSTRACE_TARGET_COUNTER_COUNT];
static atomic_long_t schedule_bits = ATOMIC_LONG_INIT(0);
static atomic_long_t schedule_object = ATOMIC_LONG_INIT(0);
static atomic_t schedule_timeouts = ATOMIC_INIT(0);
static bool controller_armed;

static void emit_bits(unsigned int bits)
{
	atomic_long_or(bits, &schedule_bits);
}

static bool wait_for_bits(unsigned int required, const char *point)
{
	unsigned long timeout = msecs_to_jiffies(REHOSTRACE_TARGET_TIMEOUT_MS);
	unsigned long deadline = jiffies + max_t(unsigned long, timeout, 1);

	while (((unsigned int)atomic_long_read(&schedule_bits) & required) != required) {
		if (time_after(jiffies, deadline)) {
			atomic_inc(&schedule_timeouts);
			emit_bits(REHOSTRACE_TARGET_TIMEOUT_BIT);
			pr_err("REHOSTRACE_TARGET_TIMEOUT point=%s wait=0x%x bits=0x%lx\n",
			       point, required, atomic_long_read(&schedule_bits));
			return false;
		}
		cpu_relax();
	}
	return true;
}

static unsigned long capture_value(struct pt_regs *regs, unsigned int kind,
				   unsigned int index)
{
	if (kind == REHOSTRACE_CAPTURE_ARGUMENT)
		return regs_get_kernel_argument(regs, index);
	if (kind == REHOSTRACE_CAPTURE_REGISTER && index < 31)
		return regs->regs[index];
	return 0;
}

static bool predicate_matches(const struct rehostrace_lowered_predicate_config *item,
			      struct pt_regs *regs)
{
	unsigned long argument = regs_get_kernel_argument(regs, item->argument);
	u16 word;
	u8 byte;

	switch (item->kind) {
	case 1:
		return argument == item->value;
	case 2:
		return argument >= item->value;
	case 3:
		if (!argument || copy_from_kernel_nofault(&byte,
							 (const void *)(argument + item->offset),
							 sizeof(byte)))
			return false;
		return byte == item->value;
	case 4:
		if (!argument || copy_from_kernel_nofault(&word,
							 (const void *)(argument + item->offset),
							 sizeof(word)))
			return false;
		return le16_to_cpu(word) == item->value;
	default:
		return false;
	}
}

static int role_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct runtime_role_probe *runtime;
	const struct rehostrace_lowered_role_config *config;
	unsigned int index;

	runtime = container_of(probe, struct runtime_role_probe, probe);
	config = &rehostrace_lowered_roles[runtime->index];
	for (index = 0; index < config->predicate_count; index++) {
		if (!predicate_matches(
			    &rehostrace_lowered_predicates[config->predicate_offset + index],
			    regs))
			return 0;
	}
	atomic_cmpxchg(&role_pids[runtime->index], 0, current->pid);
	pr_info("REHOSTRACE_TARGET_ROLE id=%s index=%u pid=%d\n",
		config->id, runtime->index, current->pid);
	return 0;
}

static bool role_matches(int role_index)
{
	return role_index < 0 ||
		(role_index < REHOSTRACE_TARGET_ROLE_COUNT &&
		 current->pid == atomic_read(&role_pids[role_index]));
}

static bool identity_matches(const char *point, unsigned long object)
{
	unsigned long expected;

	if (!REHOSTRACE_TARGET_IDENTITY_SAME)
		return true;
	if (!object) {
		emit_bits(REHOSTRACE_TARGET_TIMEOUT_BIT);
		pr_err("REHOSTRACE_TARGET_OBJECT_MISSING point=%s\n", point);
		return false;
	}
	expected = (unsigned long)atomic_long_read(&schedule_object);
	if (!expected) {
		atomic_long_cmpxchg(&schedule_object, 0, object);
		expected = (unsigned long)atomic_long_read(&schedule_object);
	}
	if (expected == object)
		return true;
	emit_bits(REHOSTRACE_TARGET_TIMEOUT_BIT);
	pr_err("REHOSTRACE_TARGET_OBJECT_MISMATCH point=%s got=%px expected=%px\n",
	       point, (void *)object, (void *)expected);
	return false;
}

static int point_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct runtime_point_probe *runtime;
	const struct rehostrace_lowered_point_config *config;
	unsigned long object;
	int value;

	runtime = container_of(probe, struct runtime_point_probe, probe);
	config = runtime->config;
	if (!role_matches(config->role_index))
		return 0;
	object = capture_value(regs, config->capture_kind, config->capture_index);
	if (!identity_matches(config->id, object))
		return 0;
	emit_bits(config->enter_mask);
	pr_info("REHOSTRACE_TARGET_POINT phase=enter point=%s pid=%d obj=%px bits=0x%lx\n",
		config->id, current->pid, (void *)object,
		atomic_long_read(&schedule_bits));
	if (config->wait_mask && !wait_for_bits(config->wait_mask, config->id))
		return 0;
	emit_bits(config->release_mask);
	if (config->counter_index >= 0) {
		const struct rehostrace_lowered_counter_config *counter;

		counter = &rehostrace_lowered_counters[config->counter_index];
		value = atomic_inc_return(&counters[config->counter_index]);
		if (value >= counter->threshold)
			emit_bits(counter->threshold_mask);
		pr_info("REHOSTRACE_TARGET_COUNTER id=%s value=%d obj=%px\n",
			counter->id, value, (void *)object);
	}
	return 0;
}

static int observer_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct runtime_observer_probe *runtime;
	const struct rehostrace_lowered_observer_config *config;
	unsigned long object;

	runtime = container_of(probe, struct runtime_observer_probe, probe);
	config = runtime->config;
	if (!role_matches(config->role_index))
		return 0;
	object = capture_value(regs, config->capture_kind, config->capture_index);
	pr_info("REHOSTRACE_TARGET_OBSERVER id=%s pid=%d obj=%px\n",
		config->id, current->pid, (void *)object);
	return 0;
}

static int resolve_symbol(const char *symbol, unsigned long *address)
{
	struct kprobe probe = { .symbol_name = symbol };
	int rc = register_kprobe(&probe);

	if (rc)
		return rc;
	*address = (unsigned long)probe.addr;
	unregister_kprobe(&probe);
	return 0;
}

static int verify_relations(void)
{
	unsigned int index;

	for (index = 0; index < REHOSTRACE_TARGET_RELATION_COUNT; index++) {
		const struct rehostrace_lowered_relation_config *relation;
		unsigned long left;
		unsigned long right;
		int rc;

		relation = &rehostrace_lowered_relations[index];
		rc = resolve_symbol(relation->left, &left);
		if (rc)
			return rc;
		rc = resolve_symbol(relation->right, &right);
		if (rc)
			return rc;
		if ((long)right - (long)left != relation->delta)
			return -ESTALE;
	}
	return 0;
}

static ssize_t state_read(struct file *file, char __user *buffer, size_t length,
			  loff_t *position)
{
	struct rehostrace_target_state state = {
		.magic = REHOSTRACE_TARGET_MAGIC,
		.version = REHOSTRACE_TARGET_VERSION,
		.size = sizeof(state),
		.bits = (unsigned int)atomic_long_read(&schedule_bits),
		.timeouts = (unsigned int)atomic_read(&schedule_timeouts),
		.point_count = REHOSTRACE_TARGET_POINT_COUNT,
		.counter_count = REHOSTRACE_TARGET_COUNTER_COUNT,
		.object = (unsigned long)atomic_long_read(&schedule_object),
	};
	unsigned int index;

	for (index = 0; index < REHOSTRACE_TARGET_COUNTER_COUNT; index++)
		state.counters[index] = (unsigned int)atomic_read(&counters[index]);
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
	.name = "rehostrace_target",
	.fops = &state_fops,
	.mode = 0400,
};

static void unregister_all(unsigned int observers, unsigned int points,
			   unsigned int roles)
{
	while (observers)
		unregister_kprobe(&observer_probes[--observers].probe);
	while (points)
		unregister_kprobe(&point_probes[--points].probe);
	while (roles)
		unregister_kprobe(&role_probes[--roles].probe);
}

static int __init target_init(void)
{
	unsigned int roles = 0;
	unsigned int points = 0;
	unsigned int observers = 0;
	int rc;

	if (REHOSTRACE_TARGET_COUNTER_COUNT > REHOSTRACE_TARGET_MAX_COUNTERS)
		return -E2BIG;
	rc = verify_relations();
	if (rc)
		goto fail;
	for (roles = 0; roles < REHOSTRACE_TARGET_ROLE_COUNT; roles++) {
		role_probes[roles].index = roles;
		role_probes[roles].probe.symbol_name = rehostrace_lowered_roles[roles].symbol;
		role_probes[roles].probe.offset = rehostrace_lowered_roles[roles].offset;
		role_probes[roles].probe.pre_handler = role_pre;
		rc = register_kprobe(&role_probes[roles].probe);
		if (rc)
			goto fail;
	}
	for (points = 0; points < REHOSTRACE_TARGET_POINT_COUNT; points++) {
		point_probes[points].config = &rehostrace_lowered_points[points];
		point_probes[points].probe.symbol_name = rehostrace_lowered_points[points].symbol;
		point_probes[points].probe.offset = rehostrace_lowered_points[points].offset;
		point_probes[points].probe.pre_handler = point_pre;
		rc = register_kprobe(&point_probes[points].probe);
		if (rc)
			goto fail;
	}
	for (observers = 0; observers < REHOSTRACE_TARGET_OBSERVER_COUNT; observers++) {
		observer_probes[observers].config = &rehostrace_lowered_observers[observers];
		observer_probes[observers].probe.symbol_name =
			rehostrace_lowered_observers[observers].symbol;
		observer_probes[observers].probe.offset =
			rehostrace_lowered_observers[observers].offset;
		observer_probes[observers].probe.pre_handler = observer_pre;
		rc = register_kprobe(&observer_probes[observers].probe);
		if (rc)
			goto fail;
	}
	rc = misc_register(&state_device);
	if (rc)
		goto fail;
	controller_armed = true;
	pr_info("REHOSTRACE_TARGET_READY id=%s module=%s target_sha256=%s plan_sha256=%s points=%u roles=%u\n",
		REHOSTRACE_TARGET_ID, REHOSTRACE_TARGET_MODULE,
		REHOSTRACE_TARGET_BINARY_SHA256,
		REHOSTRACE_CONTROLLER_PLAN_SHA256,
		REHOSTRACE_TARGET_POINT_COUNT, REHOSTRACE_TARGET_ROLE_COUNT);
	return 0;

fail:
	unregister_all(observers, points, roles);
	pr_err("REHOSTRACE_TARGET_REFUSED rc=%d plan_sha256=%s\n",
	       rc, REHOSTRACE_CONTROLLER_PLAN_SHA256);
	return rc;
}

static void __exit target_exit(void)
{
	if (controller_armed) {
		misc_deregister(&state_device);
		unregister_all(REHOSTRACE_TARGET_OBSERVER_COUNT,
			       REHOSTRACE_TARGET_POINT_COUNT,
			       REHOSTRACE_TARGET_ROLE_COUNT);
	}
}

module_init(target_init);
module_exit(target_exit);

MODULE_DESCRIPTION("Generic RehostRace lowered target controller");
MODULE_LICENSE("GPL");
