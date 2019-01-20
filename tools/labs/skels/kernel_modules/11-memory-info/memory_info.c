#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
/* add missing headers */
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm_types.h>

MODULE_DESCRIPTION("List current processes");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_proc_init(void)
{

	/* print current process virtual memory areas */
	unsigned long vma_end_addr = current->mm->highest_vm_end;
	struct vm_area_struct *current_area = current->mm->mmap;

	while (current_area != NULL) {
		pr_info("Current process area start = %lu / end = %lu",
			current_area->vm_start,
			current_area->vm_end);

		current_area = current_area->vm_next;
	}

	return 0;
}

static void my_proc_exit(void)
{
	pr_info();
}

module_init(my_proc_init);
module_exit(my_proc_exit);
