#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
 
MODULE_LICENSE("Unlicense");
MODULE_AUTHOR("nyaacate");
 
static struct proc_dir_entry *ent;
 
static ssize_t careless_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
	char buf[1];
	if (raw_copy_from_user(buf, ubuf, count))
		return -EFAULT;
	return count;
}
 
static ssize_t careless_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) 
{
	char buf[1];

	if (raw_copy_to_user(ubuf, buf, count))
		return -EFAULT;
	
	return count;
}
 
static struct file_operations operations = 
{
	.owner = THIS_MODULE,
	.read = careless_read,
	.write = careless_write,
};
 
static int havoc_init(void)
{
	ent = proc_create("havoc", 0777, NULL, &operations);
	printk(KERN_ALERT "havoc module initialized");
	return 0;
}
 
static void havoc_cleanup(void)
{
	proc_remove(ent);
	printk(KERN_WARNING "havoc module disposed");
}
 
module_init(havoc_init);
module_exit(havoc_cleanup);
