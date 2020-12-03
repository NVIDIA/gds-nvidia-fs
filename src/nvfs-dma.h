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
#ifndef NVFS_BLK_H
#define NVFS_BLK_H

#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-pci.h>
#include <linux/scatterlist.h>
#include <linux/page-flags.h>
#include <linux/dma-direction.h>

#define NVFS_IO_ERR	-1
#define NVFS_BAD_REQ	-2

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 12
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

struct nvfs_dma_rw_ops {
	unsigned long long ft_bmap; // feature bitmap

	int (*nvfs_blk_rq_map_sg) (struct request_queue *q,
                                   struct request *req, 
                                   struct scatterlist *sglist);

        int (*nvfs_dma_map_sg_attrs) (struct device *device,
                                      struct scatterlist *sglist,
			              int nents,
                                      enum dma_data_direction dma_dir,
                                      unsigned long attrs);

        int (*nvfs_dma_unmap_sg) (struct device *device,
                                   struct scatterlist *sglist,
                                   int nents,
                                   enum dma_data_direction dma_dir);

	bool (*nvfs_is_gpu_page) (struct page *page);

	unsigned int (*nvfs_gpu_index) (struct page *page);

	unsigned int (*nvfs_device_priority) (struct device *dev, unsigned int gpu_index);
};

// feature list for dma_ops, values indicate bit pos
enum ft_bits {
	nvfs_ft_prep_sglist         = 1ULL << 0,
	nvfs_ft_map_sglist          = 1ULL << 1,
	nvfs_ft_is_gpu_page         = 1ULL << 2,
	nvfs_ft_device_priority     = 1ULL << 3,
};

// check features for use in registration with vendor drivers
#define NVIDIA_FS_CHECK_FT_SGLIST_PREP(ops)         ((ops)->ft_bmap & nvfs_ft_prep_sglist)
#define NVIDIA_FS_CHECK_FT_SGLIST_DMA(ops)          ((ops)->ft_bmap & nvfs_ft_map_sglist)
#define NVIDIA_FS_CHECK_FT_GPU_PAGE(ops)            ((ops)->ft_bmap & nvfs_ft_is_gpu_page)
#define NVIDIA_FS_CHECK_FT_DEVICE_PRIORITY(ops)     ((ops)->ft_bmap & nvfs_ft_device_priority)

// publish features
#define NVIDIA_FS_SET_FT_ALL  (nvfs_ft_prep_sglist | nvfs_ft_map_sglist | nvfs_ft_is_gpu_page | nvfs_ft_device_priority)

typedef int (*nvfs_register_dma_ops_fn_t) (struct nvfs_dma_rw_ops *ops);
typedef void (*nvfs_unregister_dma_ops_fn_t) (void);

// Auto probing
struct module_entry {
	bool is_mod;   // scsi_mod is not built as a module
	bool found;
        const char *name;    // module owner
        const char *version; // module version number
        const char *reg_ksym; // registration symbol from symbol table above
        nvfs_register_dma_ops_fn_t reg_func; // register function pointer
        const char *dreg_ksym; //deregister symbol
        nvfs_unregister_dma_ops_fn_t dreg_func; // deregister function pointer
        struct nvfs_dma_rw_ops *ops; // args
};

int nr_modules(void);
int probe_module_list(void);
void cleanup_module_list(void);

int nvfs_blk_register_dma_ops(void);
void nvfs_blk_unregister_dma_ops(void);

#define BVEC_FMT "page-flags :0x%lx index :%lu off :%u len :%u"
#define BVEC_ARG(args) bvec.bv_page->flags, page_index(bvec.bv_page), \
                       bvec.bv_offset, bvec.bv_len

//#define TEST_DISCONTIG_ADDR

#ifdef TEST_DISCONTIG_ADDR
void nvfs_init_simulated_address(void);
uint64_t nvfs_get_simulated_address(int key, int index);
int nvfs_get_simulated_key_index(void);
#endif

#endif /* NVFS_H */
