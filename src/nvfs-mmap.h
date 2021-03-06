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
#ifndef NVFS_MMAP_H
#define NVFS_MMAP_H

#include <linux/hashtable.h>
#include <linux/rculist.h>
#include "nv-p2p.h"

#define NVFS_MIN_BASE_INDEX   ((unsigned long)1L<<32)
#define NVFS_MAX_SHADOW_PAGES_ORDER 12
#define NVFS_MAX_SHADOW_ALLOCS_ORDER 12
#define NVFS_MAX_SHADOW_PAGES (1 << NVFS_MAX_SHADOW_PAGES_ORDER)

#define MAX_PCI_BUCKETS 32
#define MAX_PCI_BUCKETS_BITS ilog2(MAX_PCI_BUCKETS)

struct nvfs_gpu_args;

enum nvfs_page_state {
      NVFS_IO_FREE = 0,  // set on init
      NVFS_IO_ALLOC,
      NVFS_IO_INIT,
      NVFS_IO_QUEUED,
      NVFS_IO_DMA_START,
      NVFS_IO_DONE,
      NVFS_IO_DMA_ERROR,
      NVFS_IO_LAST_STATE = NVFS_IO_DMA_ERROR,
};

#define NVFS_IO_STATE_ENTRIES \
X(0, IO_FREE, FREE) \
X(1, IO_INIT, INIT) \
X(2, IO_READY, READY) \
X(3, IO_IN_PROGRESS, IN_PROGRESS) \
X(4, IO_TERMINATE_REQ, TERMINATE_REQ) \
X(5, IO_TERMINATED, TERMINATED) \
X(6, IO_CALLBACK_END, CALLBACK_END)

typedef enum nvfs_io_state {
#define X(code, name, string) name = code,
	NVFS_IO_STATE_ENTRIES
#undef X
} nvfs_io_state;

typedef enum nvfs_metastate {
        NVFS_IO_META_CLEAN=0,
        NVFS_IO_META_SPARSE=1,
        NVFS_IO_META_DIED=2,
}nvfs_metastate_enum;

static inline const char *nvfs_io_state_status(int state)
{
	switch (state) {
#define X(code, name, string) \
		case name : return #string;
			    NVFS_IO_STATE_ENTRIES
#undef X
		default: return "illegal io state";
	}
}

struct nvfs_io {
        char __user *cpuvaddr;          // Shadow buffer address (4k aligned)
        u64 length;                     // IO length
        ssize_t ret;                    // ret from IO
        loff_t fd_offset;               // file offset
        loff_t gpu_page_offset;         // GPU page offset for gpu vaddr
        u64    end_fence_value;         // Value to be set after DMA completion
        struct fd fd;                   // File descriptor for read/write
        int op;                         // op type
        bool sync;                      // sync flag
        bool hipri;                     // send IO as hipri
        bool check_sparse;              // set if file is sparse
        unsigned long cur_gpu_base_index;   // starting gpu index in this op
        unsigned long nvfs_active_pages_start;
        unsigned long nvfs_active_pages_end;
        nvfs_metastate_enum state;      // set if the io encountered sparse data
        int retrycnt;                   // retry count for retriable errors
        wait_queue_head_t rw_wq;        // wait queue for serializing parallel dma req
        struct kiocb common;		// kiocb structure used for read/write operation
	ktime_t start_io;		// Start time of IO for latency calculation
};

struct pci_dev_mapping {
        struct nvidia_p2p_dma_mapping *dma_mapping; // p2p dma mappint entries
        struct pci_dev *pci_dev;                    // NVMe device
	int n_dma_chunks;			    // Number of DMA chunks
	struct hlist_node hentry;
};

struct nvfs_gpu_args {
        nvidia_p2p_page_table_t *page_table;        // p2p pages table entries
        u64 gpuvaddr;                               // GPU Buffer address
        u64 gpu_buf_len;                            // length of gpu buffer
        struct page *end_fence_page;                // end fence addr pinned page
        atomic_t io_state;                    	    // IO state transitions
        atomic_t dma_mapping_in_progress;	    // Mapping in progress for a specific PCI device
        wait_queue_head_t callback_wq;              // wait queue for IO completion
        bool is_bounce_buffer;			    // is this memory used for bounce buffer
	int n_phys_chunks;			    // number of contiguous physical address range
        u64 pdevinfo;				    // pci domain(upper 4 bytes), bus, device, function for pci ranking
        unsigned int gpu_hash_index;                // cache gpu hash index for pci rank lookups 
        DECLARE_HASHTABLE(buckets, MAX_PCI_BUCKETS_BITS);
};

struct nvfs_io_metadata {
	u64 nvfs_start_magic;                       // start magic of metadata
	enum nvfs_page_state nvfs_state;
	struct page *page;
} __attribute__((packed, aligned(8)));

struct nvfs_io_mgroup {
        atomic_t ref;
        struct hlist_node hash_link;
	u64 cpu_base_vaddr;
        unsigned long base_index;
        unsigned long nvfs_pages_count;
        struct page **nvfs_ppages;
        struct nvfs_io_metadata *nvfs_metadata;
	struct nvfs_gpu_args gpu_info;
	struct nvfs_io nvfsio;
	atomic_t next_segment;
#ifdef CONFIG_FAULT_INJECTION
	bool fault_injected;
#endif
};

typedef struct nvfs_io_mgroup* nvfs_mgroup_ptr_t;
typedef struct nvfs_io_metadata* nvfs_mgroup_page_ptr_t;

void nvfs_mgroup_init(void);
int nvfs_mgroup_mmap(struct file *filp, struct vm_area_struct *vma);
nvfs_mgroup_ptr_t nvfs_mgroup_get(unsigned long base_index);
void nvfs_mgroup_put(nvfs_mgroup_ptr_t nvfs_mgroup);
int nvfs_mgroup_check_and_set(nvfs_mgroup_ptr_t nvfs_mgroup, enum nvfs_page_state state, bool validate);
nvfs_mgroup_ptr_t nvfs_mgroup_from_page(struct page* page);
bool nvfs_is_gpu_page(struct page *page);
unsigned int nvfs_gpu_index(struct page *page);
int nvfs_check_gpu_page_and_error(struct page *page);
unsigned int nvfs_device_priority(struct device *dev, unsigned int gpu_index);

void nvfs_mgroup_fill_mpages(nvfs_mgroup_ptr_t nvfs_mgroup, unsigned nr_pages);
nvfs_mgroup_ptr_t nvfs_mgroup_pin_shadow_pages(u64 cpuvaddr, unsigned long length);
void nvfs_mgroup_unpin_shadow_pages(nvfs_mgroup_ptr_t nvfs_mgroup);
nvfs_mgroup_ptr_t nvfs_get_mgroup_from_vaddr(u64 cpuvaddr);
void nvfs_mgroup_get_gpu_index_and_off(nvfs_mgroup_ptr_t nvfs_mgroup, struct page* page, unsigned long *gpu_index, pgoff_t *offset);
uint64_t nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup_ptr_t nvfs_mgroup, struct page* page);
#endif /* NVFS_MMAP_H */
