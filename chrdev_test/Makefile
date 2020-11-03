obj-m:=test_chrdev.o
KERNEL:=/home/mizhenkun/linux-kernel-warpdrive
PWD:=$(shell pwd)
modules :
	$(MAKE) -C $(KERNEL) M=$(PWD) modules
.PHONEY:clean
clean :
	rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions *.order *symvers *Module.markers *.mod
