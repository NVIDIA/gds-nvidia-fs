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
 */
#ifndef NVFS_CORE_H
#define NVFS_CORE_H
#define DEVICE_NAME "nvidia-fs"
#define CLASS_NAME "nvidia-fs-class"

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include "nvfs-mmap.h"
#include "config-host.h"

#ifdef CONFIG_KUSP_NVFS_DSKI
#include <linux/kusp/dski.h>
#define NVFS_DEBUG(fmt, args...) DSTRM_DEBUG(NVFS, DEBUG, fmt, ## args)
#else
#define NVFS_DEBUG(fmt, args...)
#endif /* CONFIG_KUSP_NVFS_DSKI */


#endif /* __KERNEL__*/

#include <linux/list.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define NVFS_GET_PCI_DEVID(pci_dev) PCI_DEVID(pci_dev->bus->number, pci_dev->devfn)

#define nvfs_msg(KRNLVL, FMT, ARGS...) printk(KRNLVL DEVICE_NAME ":" FMT, ## ARGS)
//#define nvfs_msg(KRNLVL, FMT, ARGS...) printk_ratelimited(KRNLVL DEVNAME ":" FMT, ## ARGS)

extern int nvfs_dbg_enabled;
#define nvfs_dbg(FMT, ARGS...)                               \
    do {                                                    \
        if (unlikely(nvfs_dbg_enabled))                                    \
            nvfs_msg(KERN_DEBUG, FMT, ## ARGS);              \
    } while(0)

extern int nvfs_info_enabled;
#define nvfs_info(FMT, ARGS...)                               \
    do {                                                     \
        if (unlikely(nvfs_info_enabled))                                    \
            nvfs_msg(KERN_INFO, FMT, ## ARGS);                \
    } while(0)

#define nvfs_warn(FMT, ARGS...)                               \
    nvfs_msg(KERN_WARNING, FMT, ## ARGS)

#define nvfs_err(FMT, ARGS...)                               \
    nvfs_msg(KERN_ERR, FMT, ## ARGS)

extern int nvfs_rw_stats_enabled;
extern int nvfs_peer_stats_enabled;

typedef unsigned long long u64;

/*
 * IOCTL structures
 */
struct nvfs_ioctl_map_s {
    s64    size;		// GPU Buffer size
    u64    pdevinfo;		// pci domain(upper 4 bytes)/bus/device/func info
    u64    cpuvaddr;		// Shadow buffer address
    u64    gpuvaddr;		// GPU Buffer address
    u64    end_fence_addr;      // end fence addr
    u32    sbuf_block;	        // Number of 4k block
    u16    is_bounce_buffer;	// Bounce buffer
    u8     padding[2];          // padding
} __attribute__((packed, aligned(8)));
typedef struct nvfs_ioctl_map_s nvfs_ioctl_map_t;

struct nvfs_file_args {
	ino_t inum;		// inode number
	u32 generation;         // inode generation for need for cache validation
	u32 majdev;	        // device major
	u32 mindev;             // device minor
	u64 devptroff;          // device buffer offset
}__attribute__((packed, aligned(8)));
typedef struct nvfs_file_args nvfs_file_args_t;

struct nvfs_ioctl_ioargs {
    u64 cpuvaddr;		// shadow buffer VA
    loff_t offset;		// File offset
    u64 size;		        // Read/Write length
    u64 end_fence_value;        // End fence value for DMA completion
    s64  ioctl_return;	        // IOCTL return
    nvfs_file_args_t file_args;	// optional
    int fd;			// File descriptor
    uint8_t sync:1;		// perform sync IO
    uint8_t hipri:1;		// set hipri flag in IO path
    uint8_t allowreads:1;	// allow reads for O_WRONLY
    uint8_t use_rkeys:1;	// use RDMA rkey for IO 
    uint8_t optype:3;		// optype (READ:0 | WRITE:1) 
    uint8_t reserved:1;		// reserved for future
    u8 padding[3];              // padding
} __attribute__((packed, aligned(8)));
typedef struct nvfs_ioctl_ioargs nvfs_ioctl_ioargs_t;

#ifdef NVFS_BATCH_SUPPORT
struct nvfs_ioctl_batch_ioargs {
  uint64_t ctx_id;
  uint64_t nents;
  nvfs_ioctl_ioargs_t *io_entries;
} __attribute__((packed, aligned(8)));
typedef struct nvfs_ioctl_batch_ioargs nvfs_ioctl_batch_ioargs_t;
#endif

#define NVFS_RDMA_MIN_SUPPORTED_VERSION 2
struct nvfs_ioctl_set_rdma_reg_info_args {
	uint64_t 	cpuvaddr;
	uint64_t  	gid[2];
	uint32_t  	qp_num;
	uint16_t  	lid;
	uint8_t   	flags;
	uint8_t	  	version;
	uint32_t	dc_key;
	uint32_t 	rkey[MAX_RDMA_REGS_SUPPORTED];
	uint32_t	nkeys;
} __attribute__((packed, aligned(8)));
typedef struct nvfs_ioctl_set_rdma_reg_info_args nvfs_ioctl_set_rdma_reg_info_args_t;

struct nvfs_ioctl_get_rdma_reg_info_args {
	uint64_t 		cpuvaddr;
	uint64_t		gpu_buf_offset;
	struct nvfs_rdma_info 	nvfs_rdma_info;
} __attribute__((packed, aligned(8)));
typedef struct nvfs_ioctl_get_rdma_reg_info_args nvfs_ioctl_get_rdma_reg_info_args_t;

struct nvfs_ioctl_clear_rdma_reg_info_args {
	uint64_t cpuvaddr;
} __attribute__((packed, aligned(8)));
typedef struct nvfs_ioctl_clear_rdma_reg_info_args nvfs_ioctl_clear_rdma_reg_info_args_t;

union nvfs_ioctl_param_u {
    nvfs_ioctl_map_t map_args;	  // Map
    nvfs_ioctl_ioargs_t ioargs;   // Read/Write
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
    nvfs_ioctl_set_rdma_reg_info_args_t rdma_set_reg_info; //Set RDMA reg info in kernel(mgroup)
    nvfs_ioctl_get_rdma_reg_info_args_t rdma_get_reg_info; //Get RDMA reg info from kernel(mgroup)
    nvfs_ioctl_clear_rdma_reg_info_args_t rdma_clear_reg_info; //Clear RDMA reg info in the kernel
#endif
#ifdef NVFS_BATCH_SUPPORT
    nvfs_ioctl_batch_ioargs_t batch_ioargs;   // Read/Write
#endif
} __attribute__((packed, aligned(8)));
typedef union nvfs_ioctl_param_u nvfs_ioctl_param_union;

// worst case scenario is every alternate page is a HOLE,
// 768 = (4096-1024)/sizeof(nvfs_io_hole)
// so NVFS_MAX_HOLE_REGIONS can cover an IO of NVFS_MAX_HOLE_REGIONS * 2 * 4K
// for 768 it will be 6MB
#define NVFS_MAX_HOLE_REGIONS 768
struct nvfs_io_hole{
        u16 start; // start offset from  start_fd_offset in nvfs_io_sparse_data
        u16 npages; // npages from the above offset
} __attribute__((packed, aligned(4)));

struct nvfs_io_sparse_data {
	u64 nvfs_start_magic;
        u32 nvfs_meta_version;
        u32 nholes;
        loff_t start_fd_offset; // absolute offset of the fd
        struct nvfs_io_hole hole[1];
} __attribute__((packed, aligned(8)));
typedef struct nvfs_io_sparse_data* nvfs_io_sparse_dptr_t;

struct nvfs_ioctl_metapage {
   volatile u64 end_fence_val;
   volatile u64 result;
   volatile nvfs_metastate_enum state;
   struct nvfs_io_sparse_data sparse_data;
};
typedef struct nvfs_ioctl_metapage* nvfs_ioctl_metapage_ptr_t;


struct nvfs_io* nvfs_io_init(int op, nvfs_ioctl_ioargs_t *ioargs);
long nvfs_io_start_op(nvfs_io_t *nvfsio);
void nvfs_io_free(nvfs_io_t *nvfsio, long res);

nvfs_io_sparse_dptr_t nvfs_io_map_sparse_data(nvfs_mgroup_ptr_t nvfs_mgroup);
void nvfs_io_unmap_sparse_data(nvfs_io_sparse_dptr_t ptr, nvfs_metastate_enum state);

int nvfs_get_dma(void *, struct page *, void **, int );

bool nvfs_free_gpu_info(struct nvfs_gpu_args* gpu_info, bool from_dma);
bool nvfs_io_terminate_requested(struct nvfs_gpu_args *gpu_info, bool);
void nvfs_io_process_exiting(nvfs_mgroup_ptr_t nvfs_mgroup);

#define NVFS_MAGIC 't'

#define NVFS_START_MAGIC	0xabc0cba1abc2cba3ULL
#define NVFS_END_MAGIC		0x3abc2cba1abc0cbaULL

#define NVFS_IOCTL_REMOVE    		_IOW(NVFS_MAGIC, 1, int)
#define NVFS_IOCTL_READ    		_IOW(NVFS_MAGIC, 2, int)
#define NVFS_IOCTL_MAP    		_IOW(NVFS_MAGIC, 3, int)
#define NVFS_IOCTL_WRITE    		_IOW(NVFS_MAGIC, 4, int)

#define NVFS_IOCTL_SET_RDMA_REG_INFO	_IOW(NVFS_MAGIC, 5, int)
#define NVFS_IOCTL_GET_RDMA_REG_INFO	_IOW(NVFS_MAGIC, 6, int)
#define NVFS_IOCTL_CLEAR_RDMA_REG_INFO	_IOW(NVFS_MAGIC, 7, int)

#ifdef NVFS_BATCH_SUPPORT
#define NVFS_IOCTL_BATCH_IO     	_IOW(NVFS_MAGIC, 8, int)
#endif

//Max contiguous physical GPU memory for P2P is (4GiB - 64k) or 65535 64k pages
#define NVFS_P2P_MAX_CONTIG_GPU_PAGES 65535
#define PAGE_PER_GPU_PAGE_SHIFT  ilog2(GPU_PAGE_SIZE / PAGE_SIZE)
#define GPU_PAGE_SHIFT   16
#define GPU_PAGE_SIZE    ((u64)1 << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)
#define MAX_IO_RETRY 5

#define ALIGN_UP(x, align_to)   (((x) + ((align_to)-1)) & ~((align_to)-1))

// File-system magics which are not part of linux/magic.h
#define LUSTRE_SUPER_MAGIC 0x0bd00bd0U
#define BEEGFS_SUPER_MAGIC  0x19830326U

#define NVFS_MAY_SLEEP()                  (!irqs_disabled() && !in_interrupt() && !in_atomic() && !in_nmi())

static inline unsigned int get_major(struct inode *inode) {
	return (S_ISBLK(inode->i_mode)) ?
		MAJOR(inode->i_rdev) : MAJOR(inode->i_sb->s_dev);
}

static inline unsigned int get_minor(struct inode *inode) {
	return (S_ISBLK(inode->i_mode)) ?
		MINOR(inode->i_rdev) : MINOR(inode->i_sb->s_dev);
}

static inline bool gpu_page_aligned(unsigned long size)
{
	return ((size & (GPU_PAGE_SIZE - 1)) == 0);
}

struct nvidia_p2p_dma_mapping *
nvfs_get_p2p_dma_mapping(struct pci_dev *peer, struct nvfs_gpu_args *gpu_info, struct nvfs_io* nvfsio,
				int *n_dma_chunks);
unsigned int nvfs_get_device_count(void);

/* Proc Settings */
int nvfs_proc_init(void);

void nvfs_proc_cleanup(void);

#endif /* NVFS_CORE_H */

