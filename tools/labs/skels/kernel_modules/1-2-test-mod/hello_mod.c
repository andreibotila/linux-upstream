#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

MODULE_DESCRIPTION("Simple module");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_hello_init(void)
{
	//pr_debug("Hello!\n");
	printk(KERN_NOTICE "Hello!\n");
	return 0;
}

static void hello_exit(void)
{
	printk(KERN_NOTICE "Goodbye!\n");
	//pr_debug("Goodbye!\n");
}

module_init(my_hello_init);
module_exit(hello_exit);
