/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Andrei Botila <andreibotila95@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "tracer.h"

/* /proc/tracer entry */
struct proc_dir_entry *proc_tracer;

/* kretprobe */
struct kretprobe kretp_kmalloc;
/* kprobes */
struct kprobe kp_kfree;
struct kprobe kp_schedule;
struct kprobe kp_up;
struct kprobe kp_down;
struct kprobe kp_mutex_lock;
struct kprobe kp_mutex_unlock;

/* Size given to kmalloc and the returned addr. */
struct kmalloc_data {
	size_t addr;
	size_t size;
	struct list_head list;
};

struct tracer_data {
	pid_t pid;
	atomic_t kmalloc;
	atomic_t kfree;
	atomic_t kmalloc_mem;
	atomic_t kfree_mem;
	atomic_t sched;
	atomic_t up;
	atomic_t down;
	atomic_t lock;
	atomic_t unlock;
	/* Used for keeping allocations made by each process. */
	struct list_head head_kmalloc;
	/* Linked list with all pids. */
	struct list_head list;
};

struct list_head head;

static int
kmalloc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			struct kmalloc_data *km_data;

			/* GFP_ATOMIC because GFP_KERNEL may sleeps. */
			km_data = kzalloc(sizeof(*km_data), GFP_ATOMIC);
			if (km_data == NULL)
				return -ENOMEM;

			km_data->size = regs->ax;
			list_add(&km_data->list, &tr_data->head_kmalloc);

			atomic_inc(&tr_data->kmalloc);
			atomic_add(regs->ax, &tr_data->kmalloc_mem);
			break;
		}
	}

	return 0;
}

static int
kmalloc_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			struct kmalloc_data *km_data;

			list_for_each_entry(km_data, &tr_data->head_kmalloc,
					list) {
				if (km_data->addr == 0) {
					km_data->addr = regs->ax;
					break;
				}
			}
			break;
		}
	}

	return 0;
}

/* Incomplete, calculate the memory to be freed also */
static int
kfree_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			struct kmalloc_data *km_data, *km_tmp;

			list_for_each_entry_safe(km_data, km_tmp,
					&tr_data->head_kmalloc, list) {
				if (km_data->addr == regs->ax) {
					atomic_add(km_data->size,
						&tr_data->kfree_mem);
					list_del(&km_data->list);
					kfree(km_data);
					break;
				}
			}
			atomic_inc(&tr_data->kfree);
			break;
		}
	}

	return 0;
}

static int
schedule_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			atomic_inc(&tr_data->sched);
			break;
		}
	}

	return 0;
}

static int
up_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			atomic_inc(&tr_data->up);
			break;
		}
	}

	return 0;
}

static int
down_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			atomic_inc(&tr_data->down);
			break;
		}
	}

	return 0;
}

static int
mutex_lock_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			atomic_inc(&tr_data->lock);
			break;
		}
	}

	return 0;
}

static int
mutex_unlock_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tracer_data *tr_data;

	list_for_each_entry(tr_data, &head, list) {
		if (current->pid == tr_data->pid) {
			atomic_inc(&tr_data->unlock);
			break;
		}
	}

	return 0;
}

/* Return content of /proc/tracer */
static int tracer_proc_show(struct seq_file *m, void *v)
{
	struct tracer_data *tr_data;

	seq_puts(m, "PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unlock\n");

	list_for_each_entry(tr_data, &head, list) {
		char line[100];

		snprintf(line, 100, "%d %d %d %d %d %d %d %d %d %d\n",
			tr_data->pid, atomic_read(&tr_data->kmalloc),
			atomic_read(&tr_data->kfree),
			atomic_read(&tr_data->kmalloc_mem),
			atomic_read(&tr_data->kfree_mem),
			atomic_read(&tr_data->sched),
			atomic_read(&tr_data->up),
			atomic_read(&tr_data->down),
			atomic_read(&tr_data->lock),
			atomic_read(&tr_data->unlock));
		seq_puts(m, line);
	}

	return 0;
}

/* Open function for /proc/tracer */
static int tracer_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

/* IOCTL operations on /dev/tracer */
static long
tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tracer_data *tr_data, *tr_tmp;
	struct kmalloc_data *km_data, *km_tmp;
	int ret = 0;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		tr_data = kzalloc(sizeof(*tr_data), GFP_KERNEL);
		if (tr_data == NULL)
			return -ENOMEM;

		tr_data->pid = arg;
		list_add(&tr_data->list, &head);

		INIT_LIST_HEAD(&tr_data->head_kmalloc);

		break;
	case TRACER_REMOVE_PROCESS:
		list_for_each_entry_safe(tr_data, tr_tmp, &head, list) {
			if (tr_data->pid == cmd) {
				list_for_each_entry_safe(km_data, km_tmp,
					&tr_data->head_kmalloc, list) {
					list_del(&km_data->list);
					kfree(km_data);
				};
				list_del(&tr_data->list);
				list_del(&tr_data->head_kmalloc);
				kfree(tr_data);
			}
		}

		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

/* Operations on /proc/tracer */
static const struct file_operations tracer_proc_fops = {
	.owner			= THIS_MODULE,
	.open			= tracer_proc_open,
	.read			= seq_read,
	.release		= single_release,
};

/* Operations on /dev/tracer */
static const struct file_operations tracer_dev_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= tracer_ioctl,
};

/* Misc device initialization */
static struct miscdevice tracer_dev = {
	.minor			= TRACER_DEV_MINOR,
	.name			= TRACER_DEV_NAME,
	.fops			= &tracer_dev_fops,
};

static int tracer_init(void)
{
	int err;
	int ret;

	/* Register misc device */
	err = misc_register(&tracer_dev);
	if (err != 0)
		return err;

	/* Create /proc/tracer file */
	proc_tracer = proc_create("tracer", 0000, NULL, &tracer_proc_fops);
	if (!proc_tracer) {
		proc_remove(proc_tracer);
		return -ENOMEM;
	}

	/* Initialize linked list. */
	INIT_LIST_HEAD(&head);

	/* kmalloc kretprobe */
	kretp_kmalloc.entry_handler = kmalloc_entry_handler;
	kretp_kmalloc.handler = kmalloc_ret_handler;
	kretp_kmalloc.kp.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("__kmalloc");
	if (kretp_kmalloc.kp.addr == NULL) {
		pr_info("Coudn't find %s to plant kretprobe", "__kmalloc");
		return -1;
	}

	ret = register_kretprobe(&kretp_kmalloc);
	if (ret < 0)
		pr_info("register_kretprobe __kmalloc failed, ret  %d", ret);

	/* kfree kprobe */
	kp_kfree.pre_handler = kfree_handler;
	kp_kfree.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("kfree");
	if (kp_kfree.addr == NULL) {
		pr_info("Coudn't find %s to plant kprobe", "kfree");
		return -1;
	}

	ret = register_kprobe(&kp_kfree);
	if (ret < 0)
		pr_info("register_kprobe kfree failed, ret %d", ret);

	/* schedule kprobe */
	kp_schedule.pre_handler = schedule_handler;
	kp_schedule.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("schedule");
	if (kp_schedule.addr == NULL) {
		pr_info("Coudn't find %s to plant kprobe", "schedule");
		return -1;
	}

	ret = register_kprobe(&kp_schedule);
	if (ret < 0)
		pr_info("register_kprobe schedule failed, ret %d", ret);

	/* up kprobe */
	kp_up.pre_handler = up_handler;
	kp_up.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("up");
	if (kp_up.addr == NULL) {
		pr_info("Coudn't find %s to plant kprobe", "up");
		return -1;
	}

	ret = register_kprobe(&kp_up);
	if (ret < 0)
		pr_info("register_kprobe up failed, returned %d", ret);

	/* down_interruptible kprobe */
	kp_down.pre_handler = down_handler;
	kp_down.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("down_interruptible");
	if (kp_down.addr == NULL) {
		pr_info("Coudn't find %s to plant kprobe", "down_intr");
		return -1;
	}

	ret = register_kprobe(&kp_down);
	if (ret < 0)
		pr_info("register_kprobe down_intr failed, ret %d", ret);

	/* mutex_lock kprobe */
	kp_mutex_lock.pre_handler = mutex_lock_handler;
	kp_mutex_lock.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("mutex_lock_nested");
	if (kp_mutex_lock.addr == NULL) {
		pr_info("Coudn't find %s to plant kprobe", "mutex_lock_nested");
		return -1;
	}

	ret = register_kprobe(&kp_mutex_lock);
	if (ret < 0)
		pr_info("register_kprobe mutex_lock_neste failed, ret %d", ret);

	/* mutex_unlock kprobe */
	kp_mutex_unlock.pre_handler = mutex_unlock_handler;
	kp_mutex_unlock.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("mutex_unlock");
	if (kp_mutex_unlock.addr == NULL) {
		pr_info("Coudn't find %s to plant kprobe", "mutex_unlock");
		return -1;
	}

	ret = register_kprobe(&kp_mutex_unlock);
	if (ret < 0)
		pr_info("register_kprobe mutex_unlock failed, ret %d", ret);

	return 0;
}

static void tracer_exit(void)
{
	struct tracer_data *tr_data, *tr_tmp;
	struct kmalloc_data *km_data, *km_tmp;

	/* Unregister kretprobe */
	unregister_kretprobe(&kretp_kmalloc);
	/* Unregister kprobes */
	unregister_kprobe(&kp_kfree);
	unregister_kprobe(&kp_schedule);
	unregister_kprobe(&kp_up);
	unregister_kprobe(&kp_down);
	unregister_kprobe(&kp_mutex_lock);
	unregister_kprobe(&kp_mutex_unlock);

	/* Empty the list of monitored processes. */
	list_for_each_entry_safe(tr_data, tr_tmp, &head, list) {
		list_for_each_entry_safe(km_data, km_tmp,
			&tr_data->head_kmalloc, list) {
			list_del(&km_data->list);
			kfree(km_data);
		}
		list_del(&tr_data->head_kmalloc);
		list_del(&tr_data->list);
		kfree(tr_data);
	}

	/* Unregister misc device and delete linked list. */
	misc_deregister(&tracer_dev);
	list_del(&head);
	proc_remove(proc_tracer);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("");
MODULE_AUTHOR("Andrei Botila <andreibotila95@gmail.com>");
MODULE_LICENSE("GPL v2");
