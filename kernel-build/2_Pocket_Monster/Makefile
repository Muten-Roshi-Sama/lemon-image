# MakeFile

obj-m += hello.o    # build hello.c as a module

# KDIR = "/home/vass/dev/OS/linux-kernel-modules/LKM"
# KDIR := /lib/modules/$(shell uname -r)/build
KDIR := "/home/vass/dev/OS/citro/lemon-image/build/6.12.y"

all:
	make -C $(KDIR) M=$(PWD) modules  
clean:
	make -C $(KDIR) M=$(PWD) clean