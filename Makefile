obj-m := sch_colo.o

sch_colo-objs := colo.o connections.o ipv4_fragment.o ip_fragment.o \
		 compare.o compare_device.o

KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions *.unsigned

