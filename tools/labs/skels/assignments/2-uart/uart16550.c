/*
 * uart16550.c - Driver UART
 *
 * Author: Andrei Botila <andreibotila95@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/wait.h>

#include "uart16550.h"

#define MODULE_NAME			"uart16550"
#define FIFO_SIZE			4096

#define WRITE_TO_REG(value, port, reg)	outb(value, port + reg)
#define READ_FROM_REG(port, reg)	inb(port + reg)

static int major = 42;
module_param(major, int, 0444);
MODULE_PARM_DESC(major, "Major used for registering the device.");

static int option = OPTION_BOTH;
module_param(option, int, 0444);
MODULE_PARM_DESC(option, "1 for COM1, 2 for COM2, 3 for both COM1 and COM2");

struct uart16550_dev {
	struct cdev cdev;
	struct kfifo read_buf;
	struct kfifo write_buf;
	wait_queue_head_t wq_reads, wq_writes;
	spinlock_t lock;
} devs[MAX_NUMBER_DEVICES];

static uint32_t device_port(struct uart16550_dev *uart16550)
{
	int device_minor;

	device_minor = MINOR(uart16550->cdev.dev);

	return (device_minor == 0) ? COM1_BASEPORT : COM2_BASEPORT;
}

static int uart16550_open(struct inode *inode, struct file *file)
{
	struct uart16550_dev *uart16550 =
		container_of(inode->i_cdev, struct uart16550_dev, cdev);
	file->private_data = uart16550;

	return 0;
}

static ssize_t uart16550_read(struct file *file, char __user *user_buffer,
	size_t size, loff_t *offset)
{
	struct uart16550_dev *uart16550 =
		(struct uart16550_dev *)file->private_data;
	unsigned int copied;
	int ret;

	/* Block reading until the driver writes something in the buffer. */
	wait_event_interruptible(uart16550->wq_reads,
		kfifo_is_empty(&uart16550->read_buf) != 1);

	/* Write to user space buffer, data received from device. */
	ret = kfifo_to_user(&uart16550->read_buf, user_buffer, size, &copied);

	return ret ? ret : copied;
}

static ssize_t uart16550_write(struct file *file,
	const char __user *user_buffer,	size_t size, loff_t *offset)
{
	struct uart16550_dev *uart16550 =
		(struct uart16550_dev *)file->private_data;
	unsigned int copied;
	int ret;
	u32 port;

	/* Block writing until there is space in the buffer. */
	wait_event_interruptible(uart16550->wq_writes,
		kfifo_is_full(&uart16550->write_buf) != 1);

	/* Save to kernel buffer, data for the device */
	ret = kfifo_from_user(&uart16550->write_buf, user_buffer,
				size, &copied);

	port = device_port(uart16550);
	/* Disable and re-enable UART interrupts after writing to write_buf
	 * This way interrupts that didn't complete because write_buf was
	 * empty can be fulfilled.
	 */
	WRITE_TO_REG(0x00, port, IER);
	WRITE_TO_REG(0x03, port, IER);

	return ret ? ret : copied;
}

static int uart16550_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long uart16550_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	struct uart16550_dev *uart16550 =
		(struct uart16550_dev *)file->private_data;

	struct uart16550_line_info *uart16550_line_info =
		kmalloc(sizeof(struct uart16550_line_info), GFP_KERNEL);

	unsigned long remains;
	int ret = 0;
	u32 port;

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		remains = copy_from_user(uart16550_line_info,
			(struct uart16550_line_info *) arg,
			sizeof(*uart16550_line_info));
		if (remains)
			ret = -EFAULT;

		port = device_port(uart16550);

		/* Set line parameters  : baud, length, stop, par.*/
		// Disable interrupts
		WRITE_TO_REG(0x00, port, IER);
		// Enable DLAB for baud modification
		WRITE_TO_REG(READ_FROM_REG(port, LCR) | 0x80, port, LCR);
		// Write baud rate
		WRITE_TO_REG(uart16550_line_info->baud, port, DLL);
		// Divisor Latch High Byte always 0 for baud rates over 600
		WRITE_TO_REG(0x00, port, DLH);
		// Write word len, stop bits, parity select.
		WRITE_TO_REG(uart16550_line_info->len |
			uart16550_line_info->stop | uart16550_line_info->par,
			port, LCR);
		// Disable DLAB after baud modification
		WRITE_TO_REG(READ_FROM_REG(port, LCR) & 0x7f, port, LCR);
		 // Re-enable interrupts, RDAI and THREI
		WRITE_TO_REG(0x03, port, IER);

		break;
	default:
		ret = -ENOTTY;
	}

	kfree(uart16550_line_info);

	return ret;
}

irqreturn_t uart_interrupt_handler(int irq_no, void *dev_id)
{
	struct uart16550_dev *uart16550 =
		(struct uart16550_dev *)dev_id;
	int port;

	port = device_port(uart16550);

	/* Bit 0, Data Ready tells that data is available for reading */
	while ((READ_FROM_REG(port, LSR) & 0x01) != 0) {
		u8 byte_rx;
		/* Read from device and write in read_buf */
		byte_rx = READ_FROM_REG(port, RBR);
		kfifo_in_spinlocked(&uart16550->read_buf, &byte_rx, 1,
			&uart16550->lock);
	}
	/* After reading from device, wake reading processes. */
	wake_up(&uart16550->wq_reads);

	/* Bit 5 from LSR, ETHR tells that device is ready to receive */
	while ((READ_FROM_REG(port, LSR) & 0x20) != 0) {
		u8 byte_tx;
		/* If write_buf is not empty, get next byte. */
		if (kfifo_len(&uart16550->write_buf))
			kfifo_out_spinlocked(&uart16550->write_buf, &byte_tx, 1,
				&uart16550->lock);
		else
			break;

		WRITE_TO_REG(byte_tx, port, THR);
	}
	/* After writting to device, wake writing processes. */
	wake_up(&uart16550->wq_writes);

	return IRQ_HANDLED;
}

static const struct file_operations uart16550_fops = {
	.owner			= THIS_MODULE,
	.open			= uart16550_open,
	.read			= uart16550_read,
	.write			= uart16550_write,
	.release		= uart16550_release,
	.unlocked_ioctl		= uart16550_ioctl
};

static int uart16550_init(void)
{
	int err, i;

	switch (option) {
	case OPTION_COM1:
		err = register_chrdev_region(MKDEV(major, 0), 1, MODULE_NAME);
		if (err) {
			pr_err("register_region COM1 failed: %d\n", err);
			goto out;
		}

		if (!request_region(COM1_BASEPORT, 8, MODULE_NAME)) {
			err = -EBUSY;
			goto out_unregister;
		}

		err = request_irq(COM1_IRQ, uart_interrupt_handler,
			IRQF_SHARED, MODULE_NAME, &devs[0]);
		if (err) {
			pr_err("request_irq COM1 failed: %d\n", err);
			goto out_release_region;
		}

		cdev_init(&devs[0].cdev, &uart16550_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

		err = kfifo_alloc(&devs[0].read_buf, FIFO_SIZE, GFP_KERNEL);
		if (err) {
			pr_err("kfifo_alloc read_buf failed : %d\n", err);
			goto out_release_dev;
		}

		err = kfifo_alloc(&devs[0].write_buf, FIFO_SIZE, GFP_KERNEL);
		if (err) {
			pr_err("kfifo_alloc write_buf failed : %d\n", err);
			kfifo_free(&devs[0].read_buf);
			goto out_release_dev;
		}

		init_waitqueue_head(&devs[0].wq_reads);
		init_waitqueue_head(&devs[0].wq_writes);
		spin_lock_init(&devs[0].lock);

		break;
	case OPTION_COM2:
		err = register_chrdev_region(MKDEV(major, 1), 1, MODULE_NAME);
		if (err) {
			pr_err("register_region COM2 failed: %d\n",
				err);
			goto out;
		}

		if (!request_region(COM2_BASEPORT, 8, MODULE_NAME)) {
			err = -EBUSY;
			goto out_unregister;
		}

		err = request_irq(COM2_IRQ, uart_interrupt_handler,
			IRQF_SHARED, MODULE_NAME, &devs[1]);
		if (err) {
			pr_err("request_irq COM2 failed: %d\n", err);
			goto out_release_region;
		}

		cdev_init(&devs[1].cdev, &uart16550_fops);
		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);

		err = kfifo_alloc(&devs[1].read_buf, FIFO_SIZE, GFP_KERNEL);
		if (err) {
			pr_err("kfifo_alloc read_buf failed : %d\n", err);
			goto out_release_dev;
		}

		err = kfifo_alloc(&devs[1].write_buf, FIFO_SIZE, GFP_KERNEL);
		if (err) {
			pr_err("kfifo_alloc write_buf failed : %d\n", err);
			kfifo_free(&devs[1].read_buf);
			goto out_release_dev;
		}

		init_waitqueue_head(&devs[1].wq_reads);
		init_waitqueue_head(&devs[1].wq_writes);
		spin_lock_init(&devs[1].lock);

		break;
	case OPTION_BOTH:
		err = register_chrdev_region(MKDEV(major, 0), 2, MODULE_NAME);
		if (err)
			pr_err("register_region COM1&COM2 failed:%d\n", err);

		if (!request_region(COM1_BASEPORT, 8, MODULE_NAME)) {
			err = -EBUSY;
			goto out_unregister;
		}

		if (!request_region(COM2_BASEPORT, 8, MODULE_NAME)) {
			err = -EBUSY;
			goto out_unregister;
		}

		err = request_irq(COM1_IRQ, uart_interrupt_handler,
			IRQF_SHARED, MODULE_NAME, &devs[0]);
		if (err) {
			pr_err("request_irq COM1 failed: %d\n", err);
			goto out_release_region;
		}

		err = request_irq(COM2_IRQ, uart_interrupt_handler,
			IRQF_SHARED, MODULE_NAME, &devs[1]);
		if (err) {
			pr_err("request_irq COM2 failed: %d\n", err);
			goto out_release_region;
		}

		for (i = 0; i < MAX_NUMBER_DEVICES; i++) {
			cdev_init(&devs[i].cdev, &uart16550_fops);
			cdev_add(&devs[i].cdev, MKDEV(major, i), 1);

			err = kfifo_alloc(&devs[i].read_buf, FIFO_SIZE,
				GFP_KERNEL);
			if (err) {
				pr_err("kfifo_alloc read_buf failed : %d\n",
					err);
				goto out_release_dev;
			}

			err = kfifo_alloc(&devs[i].write_buf, FIFO_SIZE,
				GFP_KERNEL);
			if (err) {
				pr_err("kfifo_alloc write_buf failed : %d\n",
					err);
				kfifo_free(&devs[i].read_buf);
				goto out_release_dev;
			}

			init_waitqueue_head(&devs[i].wq_reads);
			init_waitqueue_head(&devs[i].wq_writes);
			spin_lock_init(&devs[i].lock);
		}

		break;
	default:
		break;
	}

	return 0;

out_release_dev:
	cdev_del(&devs[0].cdev);
	cdev_del(&devs[1].cdev);
	free_irq(COM1_IRQ, &devs[0]);
	free_irq(COM2_IRQ, &devs[1]);

out_release_region:
	release_region(COM1_BASEPORT, 8);
	release_region(COM2_BASEPORT, 8);

out_unregister:
	unregister_chrdev_region(MKDEV(major, 0), 2);

out:
	return err;
}

static void uart16550_exit(void)
{
	int i;

	switch (option) {
	case OPTION_COM1:
		kfifo_free(&devs[0].read_buf);
		kfifo_free(&devs[0].write_buf);
		cdev_del(&devs[0].cdev);
		free_irq(COM1_IRQ, &devs[0]);
		release_region(COM1_BASEPORT, 8);
		unregister_chrdev_region(MKDEV(major, 0), 1);
		break;
	case OPTION_COM2:
		kfifo_free(&devs[1].read_buf);
		kfifo_free(&devs[1].write_buf);
		cdev_del(&devs[1].cdev);
		free_irq(COM2_IRQ, &devs[1]);
		release_region(COM2_BASEPORT, 8);
		unregister_chrdev_region(MKDEV(major, 1), 1);
		break;
	case OPTION_BOTH:
		for (i = 0; i < MAX_NUMBER_DEVICES; i++) {
			kfifo_free(&devs[i].read_buf);
			kfifo_free(&devs[i].write_buf);
			cdev_del(&devs[i].cdev);
		}

		free_irq(COM1_IRQ, &devs[0]);
		free_irq(COM2_IRQ, &devs[1]);

		release_region(COM1_BASEPORT, 8);
		release_region(COM2_BASEPORT, 8);

		unregister_chrdev_region(MKDEV(major, 0), 2);
		break;
	default:
		break;
	}
}

module_init(uart16550_init);
module_exit(uart16550_exit);

MODULE_DESCRIPTION("Driver for UART16550 serial port");
MODULE_AUTHOR("Andrei Botila <andreibotila95@gmail.com>");
MODULE_LICENSE("GPL v2");
