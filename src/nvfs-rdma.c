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

#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT	

#include "nvfs-core.h"
#include "nvfs-dma.h"
#include "nvfs-mmap.h"


int nvfs_set_rdma_reg_info_to_mgroup(
		nvfs_ioctl_set_rdma_reg_info_args_t* rdma_reg_info_args)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	struct nvfs_gpu_args* gpu_info;
	struct nvfs_rdma_info* rdma_infop;
        unsigned long shadow_buf_size;
	uint64_t gpuvaddr;
	uint32_t nkeys;
	int ret = -EINVAL;

	nvfs_dbg("SG: %s CPU vaddr: %llx \n", __func__, rdma_reg_info_args->cpuvaddr);	
	
	nvfs_mgroup = nvfs_get_mgroup_from_vaddr(rdma_reg_info_args->cpuvaddr);
	if(nvfs_mgroup == NULL || unlikely(IS_ERR(nvfs_mgroup))) {
		nvfs_err("Error: nvfs_mgroup NULL\n");
		return -EINVAL;
	}

	nkeys = rdma_reg_info_args->nkeys;

	if((nkeys <= 0) || (nkeys > 1)) {
		nvfs_err("Invalid number of rkeys passed: %d\n", nkeys);
		goto error;
	}
	
	shadow_buf_size = (nvfs_mgroup->nvfs_blocks_count) * NVFS_BLOCK_SIZE;

	
	nvfs_dbg("SG: %s nvfs_mgroup = %p\n GPU vaddr: %llx", __func__,
		 nvfs_mgroup, nvfs_mgroup->gpu_info.gpuvaddr);
	
	
	rdma_infop = &nvfs_mgroup->rdma_info;

        if(rdma_reg_info_args->version < NVFS_RDMA_MIN_SUPPORTED_VERSION)
        {
		nvfs_err("RDMA registration version %d is not supported by this driver.\n",
                          rdma_reg_info_args->version);
		goto error;
        }
	//Copy the device info to mgroup
	rdma_infop->version 	= rdma_reg_info_args->version;
	rdma_infop->flags 	= rdma_reg_info_args->flags;
	rdma_infop->lid	= rdma_reg_info_args->lid;
	rdma_infop->qp_num 	= rdma_reg_info_args->qp_num;
	rdma_infop->gid[0] 	= rdma_reg_info_args->gid[0];
	rdma_infop->gid[1] 	= rdma_reg_info_args->gid[1];
	rdma_infop->dc_key	= rdma_reg_info_args->dc_key;	
	//Fill in the rkey, rem_vaddr and size information in the mgroup
	gpu_info =  &nvfs_mgroup->gpu_info;
	gpuvaddr = gpu_info->gpuvaddr;

	rdma_infop->rkey = rdma_reg_info_args->rkey[0];
	rdma_infop->rem_vaddr = gpuvaddr;
	rdma_infop->size = gpu_info->gpu_buf_len;

	nvfs_dbg("%s:RDMA Info version = %d, flags = %d, lid %x, qp_num %x, gid %llx:%llx\
			dckey: %x, rkey %x, size %d, rem_vaddr %llx\n",
			__func__,
			rdma_infop->version,
			rdma_infop->flags,
			rdma_infop->lid,
			rdma_infop->qp_num,
			rdma_infop->gid[0],
			rdma_infop->gid[1],
			rdma_infop->dc_key,
			rdma_infop->rkey,
			rdma_infop->size,
	       		rdma_infop->rem_vaddr);
	
	nvfs_mgroup_put(nvfs_mgroup);
	return 0;
error:
	memset(&nvfs_mgroup->rdma_info, 0 , sizeof(struct nvfs_rdma_info));
	nvfs_mgroup_put(nvfs_mgroup);
	return ret;
}

#ifdef NVFS_TEST_GPFS_CALLBACK
extern int nvfs_get_gpu_sglist_rdma_info(struct scatterlist *, int, struct nvfs_rdma_info*);
#endif

int nvfs_get_rdma_reg_info_from_mgroup(
		nvfs_ioctl_get_rdma_reg_info_args_t* rdma_reg_info_args)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	struct nvfs_rdma_info* rdma_infop = NULL;
        uint64_t shadow_buf_size;
#ifdef NVFS_TEST_GPFS_CALLBACK	
	struct scatterlist *sg, *sgl;
	uint64_t tmp_offset, tmp_size, tmp_vaddr;
       	int tmp_nents;
	struct page *tmp_page = NULL;
	struct nvfs_rdma_info* tmp_nvfs_rdma_info = NULL;
	uint32_t i = 0;
#endif
	nvfs_dbg("%s CPU addr received %llx\n", __func__, rdma_reg_info_args->cpuvaddr);	
	
	nvfs_mgroup = nvfs_get_mgroup_from_vaddr(rdma_reg_info_args->cpuvaddr);
	if(nvfs_mgroup == NULL || unlikely(IS_ERR(nvfs_mgroup))) {
		printk("SG Error: nvfs_mgroup NULL\n");
		return -EINVAL;
	}
	shadow_buf_size = (nvfs_mgroup->nvfs_blocks_count) * NVFS_BLOCK_SIZE;
	
	nvfs_dbg("%s nvfs_mgroup = %p sbuf size = %llu\n", __func__,
			nvfs_mgroup, shadow_buf_size);
	
	rdma_infop = &nvfs_mgroup->rdma_info;
	rdma_reg_info_args->nvfs_rdma_info = *rdma_infop;
	
	nvfs_dbg("%s Rdma Dev info: ver: %d flags: %x lid: %x qp_num: %x gid: %llx%llx,\
			rkey: %x rem_vaddr: %llx size: %x\n",
			__func__,
			rdma_reg_info_args->nvfs_rdma_info.version,
			rdma_reg_info_args->nvfs_rdma_info.flags,
			rdma_reg_info_args->nvfs_rdma_info.lid,
			rdma_reg_info_args->nvfs_rdma_info.qp_num,
			rdma_reg_info_args->nvfs_rdma_info.gid[0],
			rdma_reg_info_args->nvfs_rdma_info.gid[1],
			rdma_reg_info_args->nvfs_rdma_info.rkey,
			rdma_reg_info_args->nvfs_rdma_info.rem_vaddr,
			rdma_reg_info_args->nvfs_rdma_info.size);
#ifdef NVFS_TEST_GPFS_CALLBACK
	////////////////////////////////////////////////////////////////////////
	// Create a sgl for this size and shadow buffer offset. Make a call
	// to nvfs_get_gpu_sglist_rdma_info() to get the nvfs_info. This is to test
	// nvfs_get_gpu_sglist_rdma_info()
	sgl = sgl_alloc(rdma_reg_info_args->nvfs_rdma_info.size, GFP_KERNEL, &tmp_nents);
	tmp_vaddr = rdma_reg_info_args->nvfs_rdma_info.rem_vaddr;
	i = 0;
	for_each_sg(sgl, sg, tmp_nents, i) {
		tmp_offset = tmp_vaddr % NVFS_BLOCK_SIZE;
	       	tmp_size = NVFS_BLOCK_SIZE - tmp_offset;
#ifdef HAVE_PIN_USER_PAGES_FAST
		if(pin_user_pages_fast(tmp_vaddr, 1, 1, &tmp_page) < 0) {
#else
		if(get_user_pages_fast(tmp_vaddr, 1, 1, &tmp_page) < 0) {
#endif
			nvfs_dbg("user pages returned -ve\n");
			return -EINVAL;
		}
		sg_set_page(sg, tmp_page, tmp_size, tmp_offset);
		tmp_vaddr = (u64)tmp_vaddr + tmp_size;
		nvfs_dbg("%s off: %llu, size %llu, page %p, tmp_vaddr %llx\n",
				__func__, tmp_offset, tmp_size, tmp_page, tmp_vaddr);
	}
	nvfs_dbg("Num entries %d\n", tmp_nents);
	tmp_nvfs_rdma_info = kzalloc(sizeof(struct nvfs_rdma_info), GFP_KERNEL);
	tmp_nents = nvfs_get_gpu_sglist_rdma_info(sgl, tmp_nents, tmp_nvfs_rdma_info);

	nvfs_dbg("Nents returned %d\n", tmp_nents);
	rdma_reg_info_args->nvfs_rdma_info = *tmp_nvfs_rdma_info;
	nvfs_dbg("%s Rdma Dev info: ver: %d flags: %x lid: %x qp_num: %x gid: %llx%llx,\
			rkey: %x rem_vaddr: %llx size: %x\n",
			__func__,
			rdma_reg_info_args->nvfs_rdma_info.version,
			rdma_reg_info_args->nvfs_rdma_info.flags,
			rdma_reg_info_args->nvfs_rdma_info.lid,
			rdma_reg_info_args->nvfs_rdma_info.qp_num,
			rdma_reg_info_args->nvfs_rdma_info.gid[0],
			rdma_reg_info_args->nvfs_rdma_info.gid[1],
			rdma_reg_info_args->nvfs_rdma_info.rkey,
			rdma_reg_info_args->nvfs_rdma_info.rem_vaddr,
			rdma_reg_info_args->nvfs_rdma_info.size);
	////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////
#endif	
	
	nvfs_mgroup_put(nvfs_mgroup);

	return 0;
}

int nvfs_clear_rdma_reg_info_in_mgroup(
		nvfs_ioctl_clear_rdma_reg_info_args_t* rdma_clear_info_args)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	
	nvfs_dbg("%s CPU addr received %llx\n", __func__, rdma_clear_info_args->cpuvaddr);	
	
	nvfs_mgroup = nvfs_get_mgroup_from_vaddr(rdma_clear_info_args->cpuvaddr);
	if(nvfs_mgroup == NULL || unlikely(IS_ERR(nvfs_mgroup))) {
		nvfs_err("%s Error:  nvfs_mgroup NULL\n", __func__);
		printk("SG Error: nvfs_mgroup NULL\n");
		return -1;
	}

	memset(&nvfs_mgroup->rdma_info, 0, sizeof(struct nvfs_rdma_info ));
	nvfs_mgroup_put(nvfs_mgroup);
	
	return 0;
}

#endif
