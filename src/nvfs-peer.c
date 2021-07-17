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
#include "nvfs-core.h"
#include "nvfs-peer.h"
#include <rdma/peer_mem.h>
#include <linux/pci.h>
#include <linux/module.h>

invalidate_peer_memory mem_invalidate_callback;
static void *reg_handle;
struct nvfs_peer_mem_ctx {
#ifndef PEER_MEM_U64_CORE_CONTEXT
	void *core_ctx;
#else
	u64 core_ctx;
#endif
        nvfs_mgroup_ptr_t nvfs_mgroup;
	u64 page_virt_start;
	unsigned long page_size;
	unsigned int segment;
	int is_callback;
	int sg_allocated;
};

/* acquire return code: 1 mine, 0 - not mine */
static int nvfs_peer_mem_acquire(unsigned long addr, size_t size, void *peer_mem_private_data,
					char *peer_mem_name, void **client_ctx)
{

	int ret = 0;
	struct nvfs_peer_mem_ctx *nvfs_peer_mem_ctx;
        nvfs_mgroup_ptr_t nvfs_mgroup;
	unsigned long int page_start = 0;
	unsigned int next_segment=0;
        u64 gpu_page_start, gpu_start_offset;

	nvfs_peer_mem_ctx = kzalloc(sizeof *nvfs_peer_mem_ctx, GFP_KERNEL);
	if (!nvfs_peer_mem_ctx)
		/* Error case handled as not mine */
		return 0;

	nvfs_peer_mem_ctx->page_virt_start = addr & PAGE_MASK;
        nvfs_peer_mem_ctx->nvfs_mgroup = NULL;

        // check if already acquired with nvidia-fs
	nvfs_mgroup = nvfs_get_mgroup_from_vaddr(nvfs_peer_mem_ctx->page_virt_start);

	if (nvfs_mgroup == NULL) {
		nvfs_err("%s:%d Invalid addr passed\n",
			__func__, __LINE__);
		ret = -1;
	}

	if (ret < 0)
		goto err;

	next_segment = atomic_read(&nvfs_mgroup->next_segment);
	page_start = nvfs_mgroup->nvfs_pages_count * next_segment ;
	gpu_page_start  = nvfs_mgroup->gpu_info.gpuvaddr & GPU_PAGE_MASK;
	gpu_start_offset = nvfs_mgroup->gpu_info.gpuvaddr - gpu_page_start;
	// check the registration if for at two shadow pages
	if (page_start > ((nvfs_mgroup->gpu_info.gpu_buf_len + gpu_start_offset) >> PAGE_SHIFT)) {
		nvfs_err("%s:%d nvfs_mgroup: %p max segments %u reached for gpu buffer size %lld \n",
			__func__, __LINE__,
			nvfs_mgroup,
			next_segment,
			nvfs_mgroup->gpu_info.gpu_buf_len);
		goto err;
	}

	// check the registration size is beyond the gpu memory size
	if (((page_start << PAGE_SHIFT) + size)  > (nvfs_mgroup->gpu_info.gpu_buf_len + gpu_start_offset)) {
		nvfs_err("%s:%d mgroup: %p next_segment %u + size %ld beyond gpu buffer size %lld \n",
			__func__, __LINE__,
			nvfs_mgroup,
			next_segment,
			size,
			nvfs_mgroup->gpu_info.gpu_buf_len);
		goto err;
	}

	// check the registration if for at max shadow_buffer size
	if(size > (nvfs_mgroup->nvfs_pages_count * PAGE_SIZE)) {
		nvfs_err("%s:%d segment size %ld exceeds max shadow buffer size %ld pages\n",
			__func__, __LINE__,
			size,
			nvfs_mgroup->nvfs_pages_count * PAGE_SIZE);
		goto err;
	}

        nvfs_peer_mem_ctx->nvfs_mgroup = nvfs_mgroup;
	/* 1 means mine */
	*client_ctx = nvfs_peer_mem_ctx;

	nvfs_peer_mem_ctx->segment = next_segment;
	atomic_inc(&nvfs_mgroup->next_segment);
	nvfs_dbg("Acquire on addr: %ld  size: %ld  segment: %d\n", addr, size, nvfs_peer_mem_ctx->segment);

	__module_get(THIS_MODULE);
	return 1;

err:
        nvfs_mgroup_put(nvfs_mgroup);
	kfree(nvfs_peer_mem_ctx);

	/* Error case handled as not mine */
	return 0;
}

static int nvfs_peer_dma_map(struct sg_table *sg_head, void *ctx,
			      struct device *dma_device, int dmasync,
			      int *nmap)
{
	int i, ret;
	struct scatterlist *sg;
	struct nvfs_peer_mem_ctx *nvfs_peer_mem_ctx =
		(struct nvfs_peer_mem_ctx *) ctx;


        if(nvfs_peer_mem_ctx->nvfs_mgroup)
	{
		struct pci_dev *peer = to_pci_dev(dma_device);
                struct nvidia_p2p_dma_mapping *dma_mapping;
	        struct nvfs_gpu_args *gpu_info;
                struct nvfs_io* nvfsio;
		int n_dma_chunks;

	        gpu_info = &nvfs_peer_mem_ctx->nvfs_mgroup->gpu_info;
	        nvfsio = &nvfs_peer_mem_ctx->nvfs_mgroup->nvfsio;

		if (!peer) {
			nvfs_err("nvfs_peer_dma_map -- invalid pci_dev\n");
			return -EINVAL;
		}

		nvfs_dbg("dma_map on addr: %lld segment %u \n",
			nvfs_peer_mem_ctx->page_virt_start,
			nvfs_peer_mem_ctx->segment);
                *nmap = 0;
                dma_mapping = nvfs_get_p2p_dma_mapping(peer, gpu_info, nvfsio, &n_dma_chunks);
                if(dma_mapping) {
			unsigned int spage_count = nvfs_peer_mem_ctx->nvfs_mgroup->nvfs_pages_count;
			unsigned int start_page = nvfs_peer_mem_ctx->segment * spage_count;
                        unsigned int num_sg_entries = min(spage_count, (dma_mapping->entries << 4) - start_page);
                        ret = sg_alloc_table(sg_head, num_sg_entries, GFP_KERNEL);
                        if (ret) {
                                return ret;
                        }

                        nvfs_peer_mem_ctx->sg_allocated = 1;
                        for_each_sg(sg_head->sgl, sg, num_sg_entries, i) {
                                sg_set_page(sg, NULL, nvfs_peer_mem_ctx->page_size, 0);
                                sg->dma_address = dma_mapping->dma_addresses[(start_page + i)>>4] + PAGE_SIZE * ((start_page + i) % 16);
                                sg->dma_length = nvfs_peer_mem_ctx->page_size;
				nvfs_dbg("dma_map on addr: %llx length %u \n", sg->dma_address , sg->dma_length);
                        }
                        *nmap = num_sg_entries;
                        return 0;
                }
	}
        return -1;
}

static int nvfs_peer_dma_unmap(struct sg_table *sg_head, void *ctx,
			   struct device  *dma_device)
{
	struct nvfs_peer_mem_ctx *nvfs_peer_mem_ctx =
		(struct nvfs_peer_mem_ctx *)ctx;

	if (!nvfs_peer_mem_ctx) {
		nvfs_err("nvfs_peer_dma_unmap -- invalid nvfs_peer_mem_ctx\n");
		return -EINVAL;
	}

	if (READ_ONCE(nvfs_peer_mem_ctx->is_callback))
		goto out;

out:
	return 0;
}


static void nvfs_peer_mem_put_pages(struct sg_table *sg_head, void *ctx)
{
	struct nvfs_peer_mem_ctx *nvfs_peer_mem_ctx =
		(struct nvfs_peer_mem_ctx *) ctx;

	if (READ_ONCE(nvfs_peer_mem_ctx->is_callback))
		goto out;

out:
	if (nvfs_peer_mem_ctx->sg_allocated) {
		sg_free_table(sg_head);
		nvfs_peer_mem_ctx->sg_allocated = 0;
	}

	return;
}

static void nvfs_peer_mem_release(void *ctx)
{
	struct nvfs_peer_mem_ctx *nvfs_peer_mem_ctx =
		(struct nvfs_peer_mem_ctx *) ctx;

        if(nvfs_peer_mem_ctx->nvfs_mgroup) {
		atomic_dec(&nvfs_peer_mem_ctx->nvfs_mgroup->next_segment);
	        nvfs_mgroup_put(nvfs_peer_mem_ctx->nvfs_mgroup);
	}
	nvfs_dbg("release on addr: %lld segment :%u\n", nvfs_peer_mem_ctx->page_virt_start,
		 nvfs_peer_mem_ctx->segment);
	kfree(nvfs_peer_mem_ctx);
	module_put(THIS_MODULE);
	return;
}

static int nvfs_peer_mem_get_pages(unsigned long addr,
			  size_t size, int write, int force,
			  struct sg_table *sg_head,
			  void *client_ctx,
			  u64 core_ctx)
{
	struct nvfs_peer_mem_ctx *nvfs_peer_mem_ctx;

	nvfs_peer_mem_ctx = (struct nvfs_peer_mem_ctx *)client_ctx;
	if (!nvfs_peer_mem_ctx)
		return -EINVAL;

	nvfs_peer_mem_ctx->core_ctx = core_ctx;
	nvfs_peer_mem_ctx->page_size = PAGE_SIZE;

        if(nvfs_peer_mem_ctx->nvfs_mgroup) {
	        return 0;
        }
	return -EINVAL;
}

static unsigned long nvfs_peer_mem_get_page_size(void *ctx)
{
	struct nvfs_peer_mem_ctx *nvfs_peer_mem_ctx =
				(struct nvfs_peer_mem_ctx *)ctx;

	return nvfs_peer_mem_ctx->page_size;
}

static struct peer_memory_client nvfs_peer_client = {
	.acquire	= nvfs_peer_mem_acquire,
	.get_pages	= nvfs_peer_mem_get_pages,
	.dma_map	= nvfs_peer_dma_map,
	.dma_unmap	= nvfs_peer_dma_unmap,
	.put_pages	= nvfs_peer_mem_put_pages,
	.get_page_size	= nvfs_peer_mem_get_page_size,
	.release	= nvfs_peer_mem_release,
};


int nvfs_peer_client_init(void)
{
	strcpy(nvfs_peer_client.name, NVFS_PEER_DRV_NAME);
	strcpy(nvfs_peer_client.version, NVFS_PEER_DRV_VERSION);
	reg_handle = ib_register_peer_memory_client(&nvfs_peer_client,
					     &mem_invalidate_callback);
	if (!reg_handle)
		return -EINVAL;

	return 0;
}

void nvfs_peer_client_exit(void)
{
	ib_unregister_peer_memory_client(reg_handle);
}
