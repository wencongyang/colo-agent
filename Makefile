obj-m := sch_colo.o sch_colo_arp.o sch_colo_ipv4.o sch_colo_icmp.o \
	 sch_colo_udp.o sch_colo_tcp.o

sch_colo-objs := colo.o connections.o ipv4_fragment.o ip_fragment.o \
		 compare.o compare_device.o compare_debugfs.o

# default compare ops implementation
sch_colo_arp-objs := compare_arp.o
sch_colo_ipv4-objs := compare_ipv4.o
sch_colo_icmp-objs := compare_icmp.o
sch_colo_udp-objs := compare_udp.o
sch_colo_tcp-objs := compare_tcp.o

KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions *.unsigned

