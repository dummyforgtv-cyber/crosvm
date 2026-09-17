# Out-of-tree guest module. Build against the guest's kernel headers /
# build tree (the kernel that runs *inside* the crosvm VM), not the host.
#
#   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
# or:
#   make KERNELDIR=/path/to/guest-linux modules

obj-m += bus_partial_overlap.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: all clean
