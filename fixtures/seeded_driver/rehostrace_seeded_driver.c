// SPDX-License-Identifier: GPL-2.0-only
/*
 * Redistributable lock-handoff lifetime-race fixture for RehostRace.
 *
 * The semantic marker functions are passive no-ops.  They make stable
 * schedule boundaries visible to an external kprobe controller but never
 * block, branch, or change target state themselves.
 */

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define SEEDED_OBJECT_ID 0x53454544U

struct seeded_object {
	struct mutex lock;
	struct list_head node;
	u32 id;
	u32 state;
};

static DEFINE_MUTEX(seeded_list_lock);
static LIST_HEAD(seeded_objects);

#define DEFINE_MARKER(name) \
	noinline void name(struct seeded_object *object) \
	{ \
		asm volatile("" : : "r"(object) : "memory"); \
	}

DEFINE_MARKER(rehostrace_seed_a_object_released)
DEFINE_MARKER(rehostrace_seed_b_object_lock_pre)
DEFINE_MARKER(rehostrace_seed_b_object_held)
DEFINE_MARKER(rehostrace_seed_a_list_held)
DEFINE_MARKER(rehostrace_seed_free_pre)

static struct seeded_object *seeded_find_locked(u32 id)
{
	struct seeded_object *object;

	list_for_each_entry(object, &seeded_objects, node)
		if (object->id == id)
			return object;
	return NULL;
}

/* Actor A: object lock -> release -> global list lock -> object lock. */
noinline void seeded_reset(struct seeded_object *object)
{
	mutex_lock(&object->lock);
	object->state = 0;
	mutex_unlock(&object->lock);
	rehostrace_seed_a_object_released(object);

	mutex_lock(&seeded_list_lock);
	rehostrace_seed_a_list_held(object);
	if (!list_empty(&object->node))
		list_del_init(&object->node);
	mutex_unlock(&seeded_list_lock);

	mutex_lock(&object->lock);
	mutex_unlock(&object->lock);
	rehostrace_seed_free_pre(object);
	kfree(object);
}

/* Actor B: global list lock -> object lock -> release global -> free. */
noinline void seeded_reset_by_id(u32 id)
{
	struct seeded_object *object;

	mutex_lock(&seeded_list_lock);
	object = seeded_find_locked(id);
	if (!object) {
		mutex_unlock(&seeded_list_lock);
		return;
	}
	rehostrace_seed_b_object_lock_pre(object);
	mutex_lock(&object->lock);
	list_del_init(&object->node);
	mutex_unlock(&seeded_list_lock);
	rehostrace_seed_b_object_held(object);
	object->state = 0;
	mutex_unlock(&object->lock);
	rehostrace_seed_free_pre(object);
	kfree(object);
}

static ssize_t seeded_write(struct file *file, const char __user *buffer,
			    size_t length, loff_t *position)
{
	struct seeded_object *object;
	char command;

	if (length != 1 || copy_from_user(&command, buffer, 1))
		return -EINVAL;
	if (command == 'A') {
		mutex_lock(&seeded_list_lock);
		object = seeded_find_locked(SEEDED_OBJECT_ID);
		mutex_unlock(&seeded_list_lock);
		if (!object)
			return -ENOENT;
		seeded_reset(object);
	} else if (command == 'B') {
		seeded_reset_by_id(SEEDED_OBJECT_ID);
	} else {
		return -EINVAL;
	}
	return 1;
}

static const struct file_operations seeded_fops = {
	.owner = THIS_MODULE,
	.write = seeded_write,
};

static struct miscdevice seeded_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "rehostrace_seeded",
	.fops = &seeded_fops,
	.mode = 0200,
};

static int __init seeded_init(void)
{
	struct seeded_object *object;
	int rc;

	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return -ENOMEM;
	mutex_init(&object->lock);
	INIT_LIST_HEAD(&object->node);
	object->id = SEEDED_OBJECT_ID;
	object->state = 1;
	list_add_tail(&object->node, &seeded_objects);
	rc = misc_register(&seeded_device);
	if (rc) {
		list_del(&object->node);
		kfree(object);
		return rc;
	}
	pr_info("REHOSTRACE_SEED_TARGET_READY object=%px id=0x%x\n",
		object, object->id);
	return 0;
}

static void __exit seeded_exit(void)
{
	struct seeded_object *object;
	struct seeded_object *next;

	misc_deregister(&seeded_device);
	list_for_each_entry_safe(object, next, &seeded_objects, node) {
		list_del(&object->node);
		kfree(object);
	}
}

module_init(seeded_init);
module_exit(seeded_exit);

MODULE_DESCRIPTION("RehostRace redistributable lock-handoff race fixture");
MODULE_AUTHOR("RehostRace contributors");
MODULE_LICENSE("GPL");
