// SPDX-License-Identifier: GPL-2.0-only
/* Redistributable deferred-work versus teardown lifetime-race fixture. */

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

struct deferred_object {
	struct work_struct work;
	u32 state;
};

static DEFINE_MUTEX(deferred_lock);
static struct deferred_object *deferred_current;

#define DEFINE_MARKER(name) \
	noinline void name(struct deferred_object *object) \
	{ \
		asm volatile("" : : "r"(object) : "memory"); \
	}

DEFINE_MARKER(rehostrace_deferred_worker_access_pre)
DEFINE_MARKER(rehostrace_deferred_worker_access_done)
DEFINE_MARKER(rehostrace_deferred_teardown_free_pre)
DEFINE_MARKER(rehostrace_deferred_teardown_free_done)

static void deferred_worker(struct work_struct *work)
{
	struct deferred_object *object;

	object = container_of(work, struct deferred_object, work);
	rehostrace_deferred_worker_access_pre(object);
	WRITE_ONCE(object->state, READ_ONCE(object->state) + 1);
	rehostrace_deferred_worker_access_done(object);
}

static ssize_t deferred_write(struct file *file, const char __user *buffer,
			      size_t length, loff_t *position)
{
	struct deferred_object *object;
	char command;

	if (length != 1 || copy_from_user(&command, buffer, 1))
		return -EINVAL;
	if (command == 'Q') {
		mutex_lock(&deferred_lock);
		object = deferred_current;
		if (object)
			schedule_work(&object->work);
		mutex_unlock(&deferred_lock);
		return object ? 1 : -ENOENT;
	}
	if (command == 'F') {
		mutex_lock(&deferred_lock);
		object = deferred_current;
		deferred_current = NULL;
		mutex_unlock(&deferred_lock);
		if (!object)
			return -ENOENT;
		rehostrace_deferred_teardown_free_pre(object);
		kfree(object);
		rehostrace_deferred_teardown_free_done(object);
		return 1;
	}
	return -EINVAL;
}

static const struct file_operations deferred_fops = {
	.owner = THIS_MODULE,
	.write = deferred_write,
};

static struct miscdevice deferred_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "rehostrace_deferred",
	.fops = &deferred_fops,
	.mode = 0200,
};

static int __init deferred_init(void)
{
	struct deferred_object *object;
	int rc;

	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return -ENOMEM;
	INIT_WORK(&object->work, deferred_worker);
	object->state = 1;
	deferred_current = object;
	rc = misc_register(&deferred_device);
	if (rc) {
		deferred_current = NULL;
		kfree(object);
		return rc;
	}
	pr_info("REHOSTRACE_DEFERRED_TARGET_READY object=%px\n", object);
	return 0;
}

static void __exit deferred_exit(void)
{
	struct deferred_object *object;

	misc_deregister(&deferred_device);
	mutex_lock(&deferred_lock);
	object = deferred_current;
	deferred_current = NULL;
	mutex_unlock(&deferred_lock);
	if (object) {
		cancel_work_sync(&object->work);
		kfree(object);
	}
}

module_init(deferred_init);
module_exit(deferred_exit);

MODULE_DESCRIPTION("RehostRace redistributable deferred-work teardown race fixture");
MODULE_AUTHOR("RehostRace contributors");
MODULE_LICENSE("GPL");
