#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
/* add missing headers */
#include <linux/sched.h>
#include <linux/sched/signal.h>

MODULE_DESCRIPTION("List current processes");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_proc_init(void)
{
	struct task_struct *p;

	/* print current process pid and its name */
	pr_info("Current process name = %s and pid = %d at init",
			current->comm, current->pid);

	/* print the pid and name of all processes */
	for_each_process(p) {
		pr_info("Process with name = %s and pid = %d", p->comm, p->pid);
	}

	return 0;
}

static void my_proc_exit(void)
{
	/* print current process pid and name */
	pr_info("Current process name = %s and pid = %d at exit",
                        current->comm, current->pid);
}

module_init(my_proc_init);
module_exit(my_proc_exit);
