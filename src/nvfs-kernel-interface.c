/*
 * Copyright (c) 2021, NVIDIA CORPORATION. All rights reserved.
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
 *
 *
 */
#include "nvfs-kernel-interface.h"

bool nvfs_check_access(int type, char __user *buf, size_t count)
{
#ifdef HAVE_ACCESS_OK_3_PARAMS
	{
		if (type == READ) {
			if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
				return false;
		} else if (type == WRITE) {
			if (unlikely(!access_ok(VERIFY_READ, buf, count)))
				return false;
		}
		return true;
	}
#endif

#ifdef HAVE_ACCESS_OK_2_PARAMS
	{
		if (unlikely(!access_ok(buf, count)))
			return false;
		return true;
	}
#endif

	return false;
}

int nvfs_extend_sg_markers(struct scatterlist **sg)
{
// This is hard coded to 4.18 kernel because of macro NVME_MAX_SEGS. See nvfs-dma.c for more
// details.

#if LINUX_VERSION_CODE <  KERNEL_VERSION(4,18,0)
	return -1;
#else
	sg_unmark_end(*sg);
	//As the NVMe driver only memsets the sglist upto blk_rq_nr_phys_segments, there is a good change that the next sg
	//might have some stale data and calling a sg_next instead of the below fix can cause it to return a sg pointer 
	//that is stable(Refer to sg chaining logic in sg_next). That's why incrementing and memseting the sg pointer here 
	//is safer choice
	*sg = *sg + 1;
	memset(*sg, 0, sizeof(struct scatterlist));
	sg_mark_end(*sg);
	return 0;
#endif
}
