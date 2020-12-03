/*
 * Copyright (c) 2020, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#ifndef NVFS_KERNEL_INTERFACE_H
#define NVFS_KERNEL_INTERFACE_H

#include <linux/bio.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-pci.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

#include "config-host.h"

// check NVFS page contiguity
#define GPU_BIOVEC_PHYS_MERGEABLE(bvprv, bvcurr) \
        (page_index((bvprv)->bv_page) == (page_index((bvcurr)->bv_page) - 1))

#ifdef HAVE_VM_FAULT
	typedef vm_fault_t nvfs_vma_fault_t;
#else
	typedef int nvfs_vma_fault_t;
#endif

bool nvfs_check_access(int type, char __user *buf, size_t count);
int nvfs_extend_sg_markers(struct scatterlist **sg);

#endif
