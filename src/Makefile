# Copyright (c) 2021, NVIDIA CORPORATION. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

KVER ?= $(shell uname -r)
# Try to get it based on available nvidia module version (just in case there are sources for couple of versions)
nv_version=$(shell /sbin/modinfo -F version -k $(KVER) nvidia 2>/dev/null)
nv_sources=$(shell /bin/ls -d /usr/src/nvidia-$(nv_version)/ 2>/dev/null)
ifneq ($(shell test -d "$(nv_sources)" && echo "true" || echo "" ),)
	NVIDIA_SRC_DIR ?= $(shell find "$(nv_sources)" -name "nv-p2p.h"|head -1|xargs dirname || echo "NVIDIA_DRIVER_MISSING")
else
	NVIDIA_SRC_DIR ?= $(shell find /usr/src/nvidia-* -name "nv-p2p.h"|head -1|xargs dirname || echo "NVIDIA_DRIVER_MISSING")
endif
KBUILD_MODPOST_WARN=1
obj-m += nvidia-fs.o

ARCH ?= $(shell uname -m)

ifeq ($(ARCH),aarch64)
ccflags-y += -DAARCH64_PLATFORM
endif

ifeq ($(CONFIG_AARCH64),1)
ccflags-y += -DAARCH64_PLATFORM
endif

ccflags-y += -Wall
ccflags-y += -I$(NVIDIA_SRC_DIR)

ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/7/include/
nvidia-fs-y = nvfs-core.o nvfs-dma.o nvfs-mmap.o nvfs-pci.o nvfs-proc.o nvfs-mod.o nvfs-kernel-interface.o
nvidia-fs-$(CONFIG_NVFS_STATS) += nvfs-stat.o
nvidia-fs-$(CONFIG_FAULT_INJECTION) += nvfs-fault.o
GDS_VERSION ?= $(shell cat GDS_VERSION)
NVFS_MODULE_FLAGS = -DCONFIG_NVFS_STATS=y -DGDS_VERSION=$(GDS_VERSION)
# Enable to debug issues with decrementing counters
#NVFS_MODULE_FLAGS = -DCONFIG_NVFS_STATS=y -DCONFIG_NVFS_DEBUG_STATS=y

#By default we will enable kernel rdma support
ifneq ($(CONFIG_DISABLE_NVFS_KERN_RDMA_SUPPORT),1)
        NVFS_MODULE_FLAGS += -DNVFS_ENABLE_KERN_RDMA_SUPPORT
        nvidia-fs-y += nvfs-rdma.o
endif
ifeq ($(CONFIG_NVFS_BATCH_SUPPORT),y)
        NVFS_MODULE_FLAGS += -DNVFS_BATCH_SUPPORT=y
        nvidia-fs-y += nvfs-batch.o
endif

# **************************************
# Enable following three lines for GCOV based
# code coverage

ifneq ($(CONFIG_CODE_COVERAGE),)
GCOV_PROFILE := y
CCFLAGS-y :=-ftest-coverage -fprofile-arcs
export CCFLAGS
endif

#***************************************

# ************************************
# Enable following lines for KASAN kernel
#
#CCFLAGS-y +=-fsanitize=kernel-address
#export CCFLAGS
#
# ***********************************
DEST_DIR ?= /usr/src/
MODULES_DIR := /lib/modules/$(KVER)
KDIR := $(MODULES_DIR)/build
MODULE_DESTDIR := $(MODULES_DIR)/extra/
DEPMOD := /sbin/depmod

REL := $(subst ., , $(subst -, , $(shell uname -r)))
REL_MAJOR  := $(word 1,$(REL))
REL_MEDIUM := $(word 2,$(REL))
REL_MINOR  := $(word 3,$(REL))

all: module

nv_configure:
	@ ./configure $(KVER)

nv_symbols:
	@ echo "Picking NVIDIA driver sources from NVIDIA_SRC_DIR=$(NVIDIA_SRC_DIR). If that does not meet your expectation, you might have a stale driver still around and that might cause problems."
	@ chmod +x ./create_nv.symvers.sh
	@ ./create_nv.symvers.sh
	@ cat nv.symvers >> Module.symvers

module: nv_symbols nv_configure
	@ KCPPFLAGS="$(NVFS_MODULE_FLAGS) -DNVFS_BATCH_SUPPORT=y" CONFIG_NVFS_BATCH_SUPPORT=y CONFIG_NVFS_STATS=y $(MAKE) -j4 -C $(KDIR) $(MAKE_PARAMS) M=$$PWD modules

install:
	[ -d $(DESTDIR)/$(MODULE_DESTDIR) ] || mkdir -p $(DESTDIR)/$(MODULE_DESTDIR)
	cp $$PWD/nvidia-fs.ko $(DESTDIR)/$(MODULE_DESTDIR)
	if [ ! -n "$(DESTDIR)" ]; then $(DEPMOD) -a $(KVER); fi

uninstall:
	/bin/rm -f $(DESTDIR)/$(MODULE_DESTDIR)/nvidia_fs.ko
	if [ ! -n "$(DESTDIR)" ]; then $(DEPMOD) -r -ae $(KVER);fi;

help:
	$(MAKE) -C $(KDIR) M=$$PWD help

clean:
	rm -rf *.o *.ko* *.mod.* .*.cmd nv.symvers Module.symvers modules.order .tmp_versions/ *~ core .depend TAGS .cache.mk *.o.ur-safe
	rm -f config-host.h
	rm -f nvidia-fs.mod

TAGS:
	find $(KERNELDIR) -follow -name \*.h -o -name \*.c  |xargs etags

.PHONY: nv_symbols clean all help install default linksyms nvidia_src_dir
