#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>

MODULE_LICENSE("Dual BSD/GPL");

struct cdev cdev;
struct class *class;

int test_open(struct inode *inode, struct file *file)
{
	printk("Hello world !!\n");
	return 0;
}

int test_release(struct inode *inode, struct file *file)
{
	printk("Bye bye !!\n");
	return 0;
}

long test_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	printk("cmd = %u\n", cmd);
	return 0;
}

struct file_operations test_fops = {
	.owner = THIS_MODULE,
	.open = test_open,
	.release = test_release,
	.unlocked_ioctl = test_ioctl,
};

static int __init chrdev_init(void)
{
	char *dev_name = "test_device";
	dev_t dev_id;
	int err = 0;

	/* 1.alloc dev_id */
	err = alloc_chrdev_region(&dev_id, 0, 1, dev_name);
	if (err < 0) {
		printk("ERROR: can't alloc a cdev!\n");
		return err;
	}

	/* 2.register cdev */
	cdev_init(&cdev, &test_fops);
	err = cdev_add(&cdev, dev_id, 1);
	if (err < 0) {
		printk("ERROR: add dev failed.\n");
		return err;
	}

	class = class_create(THIS_MODULE, dev_name);
	if (IS_ERR(class)) {
		printk("ERROR: creat class failed.\n");
		return err;
	}

	device_create(class, NULL, dev_id, NULL, "page_pin");

	return 0;
}

static void __exit chrdev_exit(void)
{
	dev_t dev_id = cdev.dev;

	device_destroy(class, dev_id);
	class_destroy(class);
	cdev_del(&cdev);
}

module_init(chrdev_init);
module_exit(chrdev_exit);

MODULE_AUTHOR("mzk");
MODULE_DESCRIPTION("Char dev test");
