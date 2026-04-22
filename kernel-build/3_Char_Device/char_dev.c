
/*


From monster.c we need to :
    - register a char device 
    - Allocate a major/minor number with alloc_chrdev_region()
    - create a /dev/.. device node (class_create() + device_create())
    - implement open, read, write, release callbacks for user programs (cdev_init() + cdev_add() to register file operations)
    - use copy_to_user() and copy_from_user()  so user-space programs can exchange bytes with the driver

*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>  // alsoimported later
/* gives 'current' */
#include <asm/current.h>
/* 'current' has a pointer to 'struct task_struct'*/
#include <linux/sched.h>

/* Meta information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("VASS");
MODULE_DESCRIPTION("Read an write on a device.");


#define DRIVER_NAME "dummydriver"
#define DRIVER_CLASS "MyModuleClass"

static dev_t my_device_number;
static struct class *my_class;
static struct cdev my_device;


// ------------------------------------------
// Now we can do something with the device, i.e. read and write data. 
// The function names have already been set in the file operations structure.
// ------------------------------------------

#define BUFFER_SIZE 255

static char buffer[BUFFER_SIZE];
static size_t buffer_pointer;

/* Read callback */
static ssize_t driver_read(struct file *File, char *user_buffer, size_t count, loff_t *offs) {
	size_t to_copy, not_copied, delta;

	/* Amount of data to copy */
	to_copy = min(count, buffer_pointer);

	/* Copy data to user, returns the amount of byte that weren't copied. */
	not_copied = copy_to_user(user_buffer, buffer, to_copy);

	/* Calculate delta */
	delta = to_copy - not_copied;

	return delta;
}

/* Write callback */
static ssize_t driver_write(struct file *File, const char *user_buffer, size_t count, loff_t *offs) {
	size_t to_copy, not_copied, delta;

	/* Amount of data to copy */
	to_copy = min(count, sizeof(buffer));

	/* Copy data to user, returns the amount of byte that weren't copied. */
	not_copied = copy_from_user(buffer, user_buffer, to_copy);
	buffer_pointer = to_copy;

	/* Calculate delta */
	delta = to_copy - not_copied;

	return delta;
}
/* Open callback. */
static int driver_open(struct inode *device_file, struct file *instance){
	printk("read-write module - open was called!\n");
	return 0;
}

static int driver_close(struct inode *device_file, struct file *instance){
	printk("read-write module - close was called!\n");
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = driver_open,
	.release = driver_close,
	.read = driver_read,
	.write = driver_write
};




static int __init ModuleInit(void) {
	/* printk writes to dmesg */
	printk("Hi, I'm a new LKM!\n");

	// 1. Allocate a device number with alloc_chrdev_region(). This is a 32-bit value where the 12 high order bits are the major number and the 20 low order bits are the minor number. This is undone with unregister_chrdev().
	if( alloc_chrdev_region(&my_device_number, 0, 1, DRIVER_NAME) < 0) {
		printk("Device number could not be allocated\n");
		return -1;
	}
	printk("read-write: Device number major: %d, minor: %d registered\n", MAJOR(my_device_number), MINOR(my_device_number));

	// 2. Create a class for the device with class_create(). Undone with class_destroy().
	if ( (my_class = class_create(DRIVER_CLASS)) == NULL) {
		printk("Device class can't be created\n");
		goto ClassError;
	}

	// 3. Create the device file itself with device_create(). Undone with device_destroy().
	if (device_create(my_class, NULL, my_device_number, NULL, DRIVER_NAME) == NULL) {
		printk("Can't create device file\n");
		goto FileError;
	}

	// 4. Initialise the device file with cdev_init(). the function does not return anything, so no verification needs to be done for this step.
	cdev_init(&my_device, &fops);

    // 5. Register the device to the kernel with cdev_add(). Undone with cdev_del().	if (cdev_add(&my_device, my_device_number, 1) == -1) {
	if (cdev_add(&my_device, my_device_number, 1) == -1) {
		printk("Can't register device to kernel\n");
		goto AddError;
	}

	buffer_pointer = 0;

	return 0;

AddError:
	device_destroy(my_class, my_device_number);

FileError:
	class_destroy(my_class);

ClassError:
	unregister_chrdev(my_device_number, DRIVER_NAME);
	return -1;
}





// When removing the LKM from the kernel, we need to undo everything that has been created and registered in the function above.
static void __exit ModuleExit(void) {
	cdev_del(&my_device);
	device_destroy(my_class, my_device_number);
	class_destroy(my_class);
	unregister_chrdev(my_device_number, DRIVER_NAME);
}

/* Define entry point */
module_init(ModuleInit);
/* Define exit point */
module_exit(ModuleExit);


