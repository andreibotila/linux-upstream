#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

MODULE_DESCRIPTION("Probes module");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

#if 0
/*
 * Pre-entry point for do_execveat_common.
 */
static int my_do_execveat_common(int fd, struct filename * filename,
				 char __user *__user *argv,
				 char __user *__user *envp,
				 int flags)
{
	pr_info("do_execveat_common for %s %s(%d) \n",
		filename->name, current->comm, current->pid);
	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	/*NOTREACHED*/
	return 0;
}

static struct jprobe my_jprobe = {
	.entry = (kprobe_opcode_t *) my_do_execveat_common
};
#endif

static int my_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/* print return value, parent process PID and process PID. */
	int retval = regs_return_value(regs);

	pr_info("Return value = %d, parent process PID = %d, process PID = %d",
		retval, current->parent->pid, current->pid);
	return 0;
}

static struct kretprobe my_kretprobe = {
	.handler = my_ret_handler,
};

static int my_probe_init(void)
{
	int ret;

	/*my_jprobe.kp.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("do_execveat_common");
	if (my_jprobe.kp.addr == NULL) {
		pr_info("Couldn't find %s to plant jprobe\n", "do_execveat_common");
		return -1;
	}

	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		pr_info("register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	pr_info("Planted jprobe at %p, handler addr %p\n", my_jprobe.kp.addr,
		my_jprobe.entry);*/

	/* Find address of do_fork and register kretprobe. */
	my_kretprobe.kp.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("_do_fork");
	if (my_kretprobe.kp.addr == NULL) {
		pr_info("Couldn't find %s to plant kretprobe\n", "_do_fork");
                return -1;
	}

	ret = register_kretprobe(&my_kretprobe);
        if (ret < 0) {
                pr_info("register_kretprobe failed, returned %d\n", ret);
                return -1;
        }
        pr_info("Planted kretprobe at %p, handler addr %p\n", my_kretprobe.kp.addr,
                my_kretprobe.handler);

	return 0;
}

static void my_probe_exit(void)
{
	/*unregister_jprobe(&my_jprobe);
	pr_info("jprobe unregistered\n");*/
	/* Unregister kretprobe. */
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe unregistered\n");
}

module_init(my_probe_init);
module_exit(my_probe_exit);
