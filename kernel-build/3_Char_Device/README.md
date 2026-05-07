
# Character Device Driver 

 

One of the fundamental devices we can control using a driver is a character device. By registering a device as such, we can communicate with it using basic read and write system calls. 

In this first introduction, we will create a dummy device that simply stores what we send it (write) and can spit it back upon request (read). 

 

Write the char_dev.c and Makefile 

Add to toolchain dependencies to PATH (temporary):  

>> export PATH=/opt/arm-gnu-toolchain/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-linux-gnueabihf/bin:$PATH 

>> export PATH=/opt/arm-gnu-toolchain/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-linux-gnueabihf/bin:$PATH 

 

Run 'make' 

make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- 

 

 

Transfer the char_dev.o to the citro board : (see earlier) 

 

 

Insert the mod 

 

Then :  

> citro@citronics:~/my_modules$ ls /dev/ | grep dummy 

dummydriver 

 

 

 

 

Make the device user-accessible 

 
 

 

As the device is created from within the kernel module that requires superuser privileges to be inserted into the kernel, its access privileges are set for the root user: 

citro@citronics:~/my_modules$ ls -l /dev/dummydriver 

crw-rw---- 1 root root 241, 0 Mar 17 22:38 /dev/dummydriver 

 

Add a udev rule : 

 

Create a rule file on the board : >> sudo nano /etc/udev/rules.d/99-my-rw-lkm.rules 

Add this inside : >> KERNEL=="dummydriver", SUBSYSTEM=="MyModuleClass", MODE="0666" 

Reload the rule :  

>> sudo udevadm control --reload-rules 

>> sudo udevadm trigger 

Or unload/reload the module :  

>> sudo rmmod char_dev.ko 

>> sudo insmod char_dev.ko 

 

Verify the permission changed :  

>> ls -l /dev/dummydriver 

crw-rw-rw- 1 root root 240, 0 Mar 17 22:48 /dev/dummydriver 

 

Test from the CLI :  

>> echo "Hello" > /dev/dummydriver 

>> head -n 1 /dev/dummydriver 

Hello 

 

 

 

 

 

 

