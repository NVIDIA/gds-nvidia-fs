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
#include <linux/init.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/notifier.h>
#include <linux/mmu_notifier.h>
#include <linux/radix-tree.h>
#include <linux/pci.h>
#include <linux/rwlock.h>
#include <linux/uio.h>
#include <linux/wait_bit.h>
#include <linux/security.h>
#include <linux/ktime.h>
#include <linux/mutex.h>

#include <linux/ktime.h>
#include <linux/delay.h>

#include "nvfs-core.h"
#include "nvfs-batch.h"
#include "nvfs-dma.h"
#include "nvfs-pci.h"
#include "nvfs-stat.h"
#include "nvfs-fault.h"
#include "nvfs-kernel-interface.h"
#include "nvfs-p2p.h"
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
#include "nvfs-rdma.h"
#endif
#include "nvfs-vers.h"

#include <linux/magic.h>

// module exit (ms)
#define NVFS_HOLD_TIME 200

// We choose 16 as we have 16 GPU devices; This is
// to optimize 4K IOs wherein we have 1024 threads
// for max bandwidth.
#define MAX_NVFS_DEVICES 16U

//#define SIMULATE_BUG_RW_VERIFY_FAILURE
//#define SIMULATE_LESS_BYTES

#define SYMTOSTR(symbol) #symbol
#define TO_STR(A) SYMTOSTR(A)
#define MAJ_MIN_P_V(maj, min, patch) maj##.##min##.##patch
#define MOD_VERS(major, minor, p) MAJ_MIN_P_V(major, minor, p)

static int major_number;
static struct class* nvfs_class = NULL;
static struct device* nvfs_device[MAX_NVFS_DEVICES];
static atomic_t nvfs_shutdown;
static wait_queue_head_t wq;
DEFINE_MUTEX(nvfs_module_mutex);

static DEFINE_PER_CPU(long, nvfs_n_ops);

// mod parameters
int nvfs_dbg_enabled = 0;
int nvfs_info_enabled = 1;
int nvfs_rw_stats_enabled = 0;
int nvfs_peer_stats_enabled = 0;
unsigned int nvfs_max_devices = MAX_NVFS_DEVICES;

// for storing real device count
static unsigned int nvfs_curr_devices = 1;

static inline long nvfs_count_ops(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nvfs_n_ops, i);
	return sum < 0 ? 0 : sum;
}

static inline void nvfs_get_ops(void)
{
       this_cpu_inc(nvfs_n_ops);
}

static inline void nvfs_put_ops(void)
{
       this_cpu_dec(nvfs_n_ops);
}

static inline void nvfs_set_device_count(unsigned int max_devices_param) {
	nvfs_curr_devices = min_t(unsigned int, max_devices_param,
					MAX_NVFS_DEVICES);
	if (nvfs_curr_devices == 0)
		nvfs_curr_devices = MAX_NVFS_DEVICES;
	nvfs_dbg("nvfs device count: %u\n", nvfs_curr_devices);
}

unsigned int nvfs_get_device_count(void) {
	return nvfs_curr_devices;
}

static inline bool nvfs_transit_state(struct nvfs_gpu_args *gpu_info,
	bool sync, int from, int to)
{
	bool io_transit = true;
	nvfs_mgroup_ptr_t nvfs_mgroup = container_of(gpu_info, struct nvfs_io_mgroup,
				gpu_info);
	nvfs_io_t* nvfsio = &nvfs_mgroup->nvfsio;
	nvfs_dbg("IO Transit requested from %s->%s nvfsio :%p\n",
			nvfs_io_state_status(from), nvfs_io_state_status(to), nvfsio);

#ifdef CONFIG_FAULT_INJECTION
	if (nvfs_fault_trigger(&nvfs_io_transit_state_fail)) {
		if ((from == IO_INIT) && (to == IO_FREE)) {
			// We are simulating the error path. Theoretically,
			// nvidia driver will invoke p2p callback and we
			// will put the ref in the callback function.
			// Since this is simulation, we will explicitly put
			// the reference as callback will not be invoked
        		nvfs_mgroup_ptr_t nvfs_mgroup = container_of(gpu_info,
                                                struct nvfs_io_mgroup,
                                                gpu_info);
			nvfs_mgroup->fault_injected = true;
			nvfs_mgroup_put(nvfs_mgroup);
		}

		nvfs_err("nvfs_io_transit_state_fail fault trigger\n");
		io_transit = false;
        }
        else
#endif
	{
		if (unlikely(atomic_cmpxchg(&gpu_info->io_state, from,
						to) != from)) {
			io_transit = false;
		}
	}

	if (unlikely(!io_transit))

	{
		nvfs_err("IO Transit failed from %s->%s; "
			"moving IO state from %s-%s\n",
			nvfs_io_state_status(from),
			nvfs_io_state_status(to),
			nvfs_io_state_status(from),
			nvfs_io_state_status(IO_TERMINATED));
                // free the nvfs_mgroup if the io thread is sync and callback has not taken ownership 
                if(sync && atomic_cmpxchg(&gpu_info->io_state, IO_TERMINATE_REQ, IO_TERMINATED) == IO_TERMINATE_REQ) {
                        wake_up_all(&gpu_info->callback_wq);
                        nvfs_mgroup_put(nvfs_mgroup);
                } else {
                        atomic_set(&gpu_info->io_state, IO_CALLBACK_END);
                        wake_up_all(&gpu_info->callback_wq);
                }
		nvfs_err("Set current state to %s\n", 
			nvfs_io_state_status(atomic_read(&gpu_info->io_state)));
		return io_transit;
	}

	nvfs_dbg("IO Transit success %s->%s nvfsio :%p\n",
			nvfs_io_state_status(from), nvfs_io_state_status(to), nvfsio);
	return io_transit;
}

bool nvfs_io_terminate_requested(struct nvfs_gpu_args *gpu_info, bool callback)
{
        int tstate = (callback) ? IO_CALLBACK_END : IO_TERMINATED;

       
        //In the following there scenarios no IO would be on-going, it's safe to mark the 
        //state as termiated and return false, so that the caller doesn't wait 
        //of IOs to be finished	
	if(atomic_cmpxchg(&gpu_info->io_state, IO_FREE,
				IO_TERMINATED) == IO_FREE)
		return false;
	
	if (atomic_cmpxchg(&gpu_info->io_state, IO_INIT,
                        tstate) == IO_INIT)
		return false;

	if(atomic_cmpxchg(&gpu_info->io_state, IO_READY,
				tstate) == IO_READY)
		return false;

        
        //Callback will take the responsibilty of freeing up if terminate is requested
        //by the callback and the current state is either IO_PROGRESS or TERMINATED_REQ
        //TERMINATE_REQ would be requested by the nvfs_vma_close and if we do not take ownership,
        //a sync IO can try to do a put after callback is finished which can lead to errors or
        //panics 
	if (callback) {
                 if(atomic_cmpxchg(&gpu_info->io_state,
                    IO_IN_PROGRESS, IO_CALLBACK_REQ) == IO_IN_PROGRESS) 
                        return true;
                 // io in progress and terminate started by vma_close
                 // callback takes ownership of the termination
                 if (atomic_cmpxchg(&gpu_info->io_state,
                    IO_TERMINATE_REQ, IO_CALLBACK_REQ) == IO_TERMINATE_REQ)
                        return true;
                 
        } else {
	        if (atomic_cmpxchg(&gpu_info->io_state,
                    IO_IN_PROGRESS, IO_TERMINATE_REQ) == IO_IN_PROGRESS)
		        return true;
        }

        //The caller needs to wait for IOs to finish if any of the below state is set
	if (atomic_read(&gpu_info->io_state) == IO_TERMINATE_REQ 
	    || atomic_read(&gpu_info->io_state) == IO_CALLBACK_REQ)
		return true;

	return false;	
}

static void nvfs_io_terminate(struct nvfs_gpu_args *gpu_info, bool callback)
{
	if (gpu_info) {
		if (nvfs_io_terminate_requested(gpu_info, callback)) {
			nvfs_mgroup_ptr_t nvfs_mgroup = container_of(gpu_info, struct nvfs_io_mgroup,
						gpu_info);
			nvfs_io_t* nvfsio = &nvfs_mgroup->nvfsio;
			nvfs_err("%s:%d Waiting for IO to be terminated nvfsio :%p\n",
				__func__, __LINE__, nvfsio);
                      
                        do { 
                                if (atomic_read(&gpu_info->io_state) == IO_CALLBACK_REQ) {
                                        wait_event_interruptible_timeout(gpu_info->callback_wq,
                                                        (atomic_read(&gpu_info->io_state) ==
                                                         IO_CALLBACK_END),
                                                        msecs_to_jiffies(1));
                                } else {
                                        wait_event_interruptible_timeout(gpu_info->callback_wq,
                                                        (atomic_read(&gpu_info->io_state) ==
                                                         IO_TERMINATED),
                                                        msecs_to_jiffies(1));
                                }
                        } while ((atomic_read(&gpu_info->io_state) != IO_CALLBACK_END &&
                                  atomic_read(&gpu_info->io_state) != IO_TERMINATED)); 
                                 
		}
	}
}

/*
 * This callback gets invoked:
 * 1: If the userspace program explicitly deallocates corresponding GPU memory
 * 2: Early exit of the process
 */
static void nvfs_get_pages_free_callback(void *data)
{
	int ret = 0;
	nvfs_mgroup_ptr_t nvfs_mgroup = data;
	struct nvfs_gpu_args *gpu_info = &nvfs_mgroup->gpu_info;
	nvidia_p2p_page_table_t *page_table = NULL;
	struct hlist_node *tmp;
	int bkt = 0;
	struct pci_dev_mapping *pci_dev_mapping;
	nvfs_ioctl_metapage_ptr_t nvfs_ioctl_mpage_ptr;
	void *kaddr, *orig_kaddr;

	nvfs_stat(&nvfs_n_callbacks);

	nvfs_dbg("%s:%d invoked IO state %s\n",
		__func__, __LINE__,
		nvfs_io_state_status(atomic_read(&gpu_info->io_state)));

	nvfs_io_terminate(gpu_info, 1);


        // vma_close or sync io thread will free the memory 
	if (atomic_read(&gpu_info->io_state) != IO_CALLBACK_END) {
		//wait for completion state. After that delay for 1us to give nvfs_mgroup_put 
		//to invoke unpin pages and return
		while(atomic_read(&gpu_info->io_state) != IO_UNPIN_PAGES_ALREADY_INVOKED);
		udelay(5);
		return;
        }

	nvfs_dbg("Clearing hash tables for mgroup %p state %s \n", 
			nvfs_mgroup, nvfs_io_state_status(atomic_read(&gpu_info->io_state)));
	//From this moment onwards, no new
	// IOs can be submitted

	// We don't need locks here as by this time there
	// shouldn't be any inflight IO and hence no reads on
	// hash tables
	hash_for_each_safe(gpu_info->buckets, bkt, tmp, pci_dev_mapping,
				hentry) {
		BUG_ON(pci_dev_mapping->dma_mapping == NULL);
		ret = nvfs_nvidia_p2p_free_dma_mapping(
				pci_dev_mapping->dma_mapping);
		if (ret) {
			nvfs_err("Error when freeing dma mapping\n");
		}
		hash_del(&pci_dev_mapping->hentry);
		kfree(pci_dev_mapping);
		pci_dev_mapping = NULL;
	}
	nvfs_update_free_gpustat(gpu_info);

	page_table = xchg(&gpu_info->page_table, NULL);
	if (page_table) {
		nvfs_dbg("callback freeing page tables\n");
		ret = nvfs_nvidia_p2p_free_page_table(page_table);
		if (ret)
			nvfs_err("Error when freeing page table\n");
	}

	kaddr = kmap_atomic(gpu_info->end_fence_page);
	orig_kaddr = kaddr;
	kaddr = (void*)((char*)kaddr + gpu_info->offset_in_page);
	nvfs_ioctl_mpage_ptr = (nvfs_ioctl_metapage_ptr_t) kaddr;
	nvfs_ioctl_mpage_ptr->state = NVFS_IO_META_DIED;
	kunmap_atomic(orig_kaddr);
	nvfs_dbg("marking end fence state dead\n");

	// Reference taken during nvfs_map()
	nvfs_mgroup_put(nvfs_mgroup);
}

/*
 * Retrieve DMA Addresses through nvidia_p2p_dma_map_pages.
 * This will map the GPU BAR pages into device I/O address space.
 */
static int
nvfs_get_dma_address(nvfs_io_t* nvfsio,
		struct pci_dev *peer,
		struct nvidia_p2p_dma_mapping **dma_mapping, int *n_dma_chunks)
{
	int ret;
	struct nvfs_gpu_args *gpu_info;
	nvfs_mgroup_ptr_t nvfs_mgroup;
    	struct nvidia_p2p_page_table *page_table;
	int i;
	int ndmachunks = 1;

	nvfs_mgroup = container_of(nvfsio, struct nvfs_io_mgroup, nvfsio);
        gpu_info = &nvfs_mgroup->gpu_info;
	page_table = gpu_info->page_table;

	nvfs_dbg("get_dma_address %p-%p PCI-DEVID %d\n",
			gpu_info, peer,
			NVFS_GET_PCI_DEVID(peer));

#ifdef CONFIG_FAULT_INJECTION
	if (nvfs_fault_trigger(&nvfs_dma_error)) {
		ret = -EFAULT;
	}
	else
#endif
	{
		if (!NVFS_MAY_SLEEP()) {
			nvfs_err("nvidia_p2p_dma_map_pages() cannot be invoked in interrrupt context or with IRQ disabled\n");
			WARN_ON_ONCE(1);
			return -EIO;
		}
		ret = nvfs_nvidia_p2p_dma_map_pages(peer,
                                        page_table, dma_mapping);
	}

	if (ret) {
		nvfs_info("Unable to obtain dma_mapping :%d for %p-%p "
			  "PCI_DEVID %d\n", ret, gpu_info, peer,
			   NVFS_GET_PCI_DEVID(peer));
		goto out;
	}

	nvfs_dbg("Number of DMA Entries %d %p-%p PCI-DEVID %d \n",
			(*dma_mapping)->entries,
			gpu_info, peer,
			NVFS_GET_PCI_DEVID(peer));


	for (i = 0; i < (*dma_mapping)->entries - 1; i++) {
		nvfs_dbg("%d DMA Addr: 0x%016llx PHY Addr: 0x%016llx\n", i,
			(*dma_mapping)->dma_addresses[i],
			page_table->pages[i]->physical_address);
		if((*dma_mapping)->dma_addresses[i] + GPU_PAGE_SIZE !=
			(*dma_mapping)->dma_addresses[i + 1])
			ndmachunks += 1;
	}

	*n_dma_chunks = ndmachunks;

	/*
	 * The purpose of this check is to ensure that the number of discontiguous
	 * chunks of the GPU Physical address and GPU DMA address are the same.
	 *
	 * nvidia_p2p_get_page() get the GPU Physical address (BAR Memory). When this physical address
	 * is mapped per PCI Device to get the DMA Address using nvidia_p2p_dma_map_pages(), we may or
	 * may not get the same addresss range. If the number of discontiguous DMA address range
	 * is greater than the actual GPU Physical address, then we cannot handle it.
	 *
	 * Ex:
	 *
	 * GPU Physical Address:
	 *
	 * |***************|xxxxxxxx|****************|
	 * 0               64k      128k             192k
	 *
	 * We have 2 GPU Pages physical address which are dis-contiguous 0-64k and 128k-192k. Thus, we will
	 * have 2 scatter gather entry with segment size set to 64k each.
	 *
	 * DMA address for the above range can look something like this:
	 *
	 * |*******|xxx|*******|xxxxxxx|******|xxxxxxxx|********|
	 * 0      32k  64k    96k     128k    160k     192k     224k
	 *
	 * We get 4 DMA chunks viz:
	 *
	 * 0-32k and 64k-96k -> which maps to 0-64k GPU Phys address
	 * 128k-160k and 192k-224k -> which maps to 128k-192k GPU Phys address
	 *
	 * We may have a SG entry with 64k as segment size, but the DMA addresses for the entire 64k segment
	 * are not contiguous.
	 */
	if (ndmachunks != gpu_info->n_phys_chunks) {
		if (ndmachunks > gpu_info->n_phys_chunks) {
			nvfs_stat(&nvfs_n_err_dma_map);
			nvfs_err("DMA Address chunks %d != GPU Physical address chunks %d\n",
				ndmachunks, gpu_info->n_phys_chunks);
			return -1;
		}
	}

	return 0;
out:
	return -1;
}

static struct pci_dev_mapping *nvfs_get_pci_dev_mapping(
			struct nvfs_gpu_args *gpu_info, int pci_devid)
{
	struct pci_dev_mapping *pci_dev_mapping;

	hash_for_each_possible_rcu(gpu_info->buckets,
			pci_dev_mapping, hentry, pci_devid) {
		if (NVFS_GET_PCI_DEVID(pci_dev_mapping->pci_dev) == pci_devid)
			return pci_dev_mapping;
	}

	return NULL;
}

struct nvidia_p2p_dma_mapping*
nvfs_get_p2p_dma_mapping(struct pci_dev *peer, struct nvfs_gpu_args *gpu_info,
		struct nvfs_io* nvfsio, int *n_dma_chunks)
{
        struct nvidia_p2p_dma_mapping *dma_mapping = NULL;
        struct pci_dev_mapping *pci_dev_mapping;
	*n_dma_chunks = 0;
retry:
        rcu_read_lock();
        pci_dev_mapping = nvfs_get_pci_dev_mapping(gpu_info,
                        NVFS_GET_PCI_DEVID(peer));
        rcu_read_unlock();
        if (pci_dev_mapping) {
		*n_dma_chunks = pci_dev_mapping->n_dma_chunks;
                return pci_dev_mapping->dma_mapping;
        }

        if (atomic_cmpxchg(&gpu_info->dma_mapping_in_progress, 0, 1) == 0) {
                struct pci_dev_mapping *pci_mapping = NULL;

                pci_dev_mapping = kmalloc(sizeof(struct pci_dev_mapping), GFP_KERNEL);
                if (!pci_dev_mapping)
                        goto done;

                /* Check if we are not racing with someone else */
                pci_mapping = nvfs_get_pci_dev_mapping(gpu_info, NVFS_GET_PCI_DEVID(peer));
                if (pci_mapping) {
                        kfree(pci_dev_mapping);
                        pci_dev_mapping = NULL;
                        dma_mapping = pci_mapping->dma_mapping;
			*n_dma_chunks = pci_mapping->n_dma_chunks;
                        goto done;
                }

                if (nvfs_get_dma_address(nvfsio, peer, &dma_mapping, n_dma_chunks)) {
                        kfree(pci_dev_mapping);
                        pci_dev_mapping = NULL;
                        dma_mapping = NULL;
                        goto done;
                }

                pci_dev_mapping->pci_dev = peer;
                pci_dev_mapping->dma_mapping = dma_mapping;
		pci_dev_mapping->n_dma_chunks = *n_dma_chunks;

		nvfs_dbg("Adding to hash-table gpu_info-nvfsio: %p-%p "
				 "PCI_DEVID %d \n",
				  gpu_info, nvfsio, NVFS_GET_PCI_DEVID(peer));

		nvfs_dbg("nvfs dma device affinity gpu:"PCI_INFO_FMT
                                  " peer: %04x:%02x:%02x:%d\n",
                                  PCI_INFO_ARGS(gpu_info->pdevinfo),
                                  peer->bus ? pci_domain_nr(peer->bus) : 0,
                                  peer->bus ? peer->bus->number : 0,
                                  PCI_SLOT(peer->devfn),
                                  PCI_FUNC(peer->devfn));

                hash_add_rcu(gpu_info->buckets,
                             &pci_dev_mapping->hentry,
                             NVFS_GET_PCI_DEVID(peer));
        } else {
                wait_event(gpu_info->callback_wq, (atomic_read(&gpu_info->dma_mapping_in_progress) == 0));
                goto retry;
        }
done:
        atomic_set(&gpu_info->dma_mapping_in_progress, 0);
	wake_up_all(&gpu_info->callback_wq);
        return dma_mapping;
}

/*
 * Get the DMA address. This function gets invoked for each 4k pages
 * in the block I/O request
 */
int nvfs_get_dma(void *device, struct page *page, void **gpu_base_dma, int dma_length)
{
        struct nvidia_p2p_dma_mapping *dma_mapping;
        struct pci_dev *peer = device;
        dma_addr_t dma_base_addr, dma_start_addr;
        unsigned long gpu_page_index = ULONG_MAX;
        struct nvfs_io* nvfsio;
        pgoff_t pgoff = 0;
	nvfs_mgroup_ptr_t nvfs_mgroup;
	struct nvfs_gpu_args *gpu_info;
	uint64_t pdevinfo;
	int n_dma_chunks;

        if(gpu_base_dma == NULL) {
		goto bad_request;
        }
	*gpu_base_dma = NULL;

        // check and get the metadata in page if in correct state,
	// otherwise bailout

        nvfs_mgroup = nvfs_mgroup_from_page(page);
        if(nvfs_mgroup == NULL) {
                goto bad_request;
        }

        if(unlikely(IS_ERR(nvfs_mgroup))) {
                goto exit;
        }

        // get the gpu_index and page offset within the gpu page
	// for this shadow page
	nvfs_mgroup_get_gpu_index_and_off(nvfs_mgroup, page,
				&gpu_page_index, &pgoff);
	nvfsio = &nvfs_mgroup->nvfsio;
	gpu_info = &nvfs_mgroup->gpu_info;

	// peer affinity stat
	pdevinfo = nvfs_pdevinfo(peer);
	if (nvfs_peer_stats_enabled)
		nvfs_update_peer_usage(gpu_info->gpu_hash_index, pdevinfo);

        dma_mapping = nvfs_get_p2p_dma_mapping(peer, gpu_info, nvfsio, &n_dma_chunks);

        if(dma_mapping == NULL) {
                goto exit;
        }
        nvfs_dbg("Found GPU Mapping for page index %lx, %lx "
		 "gpu_page_index %lu/%u page_offset %lx\n",
                  page->index,
		  (unsigned long)nvfsio, gpu_page_index,
		  (dma_mapping->entries - 1),
		  (unsigned long)pgoff);

        // gpu page aligned, 64K
        if (unlikely(gpu_page_index >= dma_mapping->entries)) {
		pr_err("gpu_page_index :%lu dma_mapping->entries :%u\n",
				gpu_page_index, dma_mapping->entries);
		BUG();
	}
        dma_base_addr = dma_mapping->dma_addresses[gpu_page_index];
        BUG_ON(dma_base_addr == 0);
	// 4K page-level offset
	// for 64K page we expect pgoff to be 0
        BUG_ON(pgoff > (GPU_PAGE_SIZE - PAGE_SIZE));
        dma_start_addr = dma_base_addr + pgoff;

	#ifdef SIMULATE_BUG_DMA_DISCONTIG
	dma_start_addr = dma_base_addr + DMA_DISCONTIG_OFF;
	#endif

        atomic_inc(&nvfs_mgroup->dma_ref);
	// The mgroup reference is dropped in nvfs_dma_unmap call

	/*
	 * nvidia_p2p_get_page() get the GPU Physical address (BAR Memory). When this physical address
	 * is mapped per PCI Device to get the DMA Address using nvidia_p2p_dma_map_pages(), we may or
	 * may not get the same addresss range. If the number of discontiguous DMA address range
	 * is greater than the actual GPU Physical address, then we cannot handle it.
	 *
	 * Ex:
	 *
	 * GPU Physical Address:
	 *
	 * |***************|xxxxxxxx|****************|
	 * 0               64k      128k             192k
	 *
	 * We have 2 GPU Pages physical address which are dis-contiguous 0-64k and 128k-192k. Thus, we will
	 * have 2 scatter gather entry with segment size set to 64k each.
	 *
	 * DMA address for the above range can look something like this:
	 *
	 * |*******|xxx|*******|xxxxxxx|******|xxxxxxxx|********|
	 * 0      32k  64k    96k     128k    160k     192k     224k
	 *
	 * We get 4 DMA chunks viz:
	 *
	 * 0-32k and 64k-96k -> which maps to 0-64k GPU Phys address
	 * 128k-160k and 192k-224k -> which maps to 128k-192k GPU Phys address
	 *
	 * We may have a SG entry with 64k as segment size, but the DMA addresses for the entire 64k segment
	 * are not contiguous.
	 */
	if ((dma_length > GPU_PAGE_SIZE) && (n_dma_chunks > 1)) {
		dma_addr_t start_addr = dma_start_addr;
		int gpu_iter_index = gpu_page_index;
		size_t sg_length = dma_length;

		while (dma_length > 0) {
			if (dma_length > GPU_PAGE_SIZE) {
				dma_length -= GPU_PAGE_SIZE;
				start_addr += GPU_PAGE_SIZE;
				gpu_iter_index += 1;

				// If this is true, then sg->length isn't right
				if (gpu_iter_index >= dma_mapping->entries) {
					nvfs_err("Invalid sg->length %ld set as it is beyond the DMA address range\n",
							sg_length);
					goto exit;
				}

				if (start_addr != dma_mapping->dma_addresses[gpu_iter_index]) {
					nvfs_err("DMA Address range are not contiguous for the give sg->length. sg->length %ld "
						"gpu_iter_index %ld dma_length %ld start_addr %ld next_addr %ld "
						"n_dma_chunks %d\n",
						(unsigned long)sg_length, (unsigned long)gpu_iter_index,
						(unsigned long)dma_length, (unsigned long)start_addr,
						(unsigned long)dma_mapping->dma_addresses[gpu_iter_index],
						n_dma_chunks);
					goto exit;
				}
			} else {
				break;
			}
		}
	}

        nvfs_dbg("%s gpu page :%lu dma_base_addr :0x%llx "
		 "dma_start_addr :0x%llx",
             	  __func__, gpu_page_index, dma_base_addr,
		  dma_start_addr);
	*gpu_base_dma = (void *)dma_start_addr;
        return 0;

exit:
	if(nvfs_mgroup && !IS_ERR(nvfs_mgroup)) {
		nvfs_mgroup_put_dma(nvfs_mgroup);
	}
        nvfs_err("Unable to obtain dma_mapping for %lx\n", gpu_page_index);
        return NVFS_IO_ERR;
bad_request:
	return NVFS_BAD_REQ;
}

nvfs_io_sparse_dptr_t nvfs_io_map_sparse_data(nvfs_mgroup_ptr_t nvfs_mgroup)
{
        nvfs_ioctl_metapage_ptr_t nvfs_ioctl_mpage_ptr;
        nvfs_io_sparse_dptr_t sparse_ptr;
	void *kaddr = kmap_atomic(nvfs_mgroup->gpu_info.end_fence_page);
	kaddr = (void*)((char*)kaddr + nvfs_mgroup->gpu_info.offset_in_page);
	nvfs_ioctl_mpage_ptr = (nvfs_ioctl_metapage_ptr_t) kaddr;
        sparse_ptr = &nvfs_ioctl_mpage_ptr->sparse_data;
        sparse_ptr->nvfs_start_magic = NVFS_START_MAGIC;
        sparse_ptr->nvfs_meta_version = 1;
        sparse_ptr->nholes = 0;
        return sparse_ptr;
}

void nvfs_io_unmap_sparse_data(nvfs_io_sparse_dptr_t ptr,
				nvfs_metastate_enum state)
{
	nvfs_ioctl_metapage_ptr_t kaddr = container_of(ptr,
						struct nvfs_ioctl_metapage,
						sparse_data);
        kaddr->state = state;
        kunmap_atomic(kaddr);
}

void nvfs_io_free(nvfs_io_t* nvfsio, long res)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = container_of(nvfsio,
					struct nvfs_io_mgroup, nvfsio);
	struct nvfs_gpu_args *gpu_info = &nvfs_mgroup->gpu_info;
	bool sync = 0;

	nvfs_dbg("%s:%d IO State %s nvfsio :%p\n",
			__func__,
			__LINE__,
			nvfs_io_state_status(
				atomic_read(&gpu_info->io_state)),
				nvfsio);

	if (nvfsio->op == WRITE) {
		if (res >= 0) {
			if (nvfsio->rw_stats_enabled)
				nvfs_stat64(&nvfs_n_writes_ok);
        	} else {
			nvfs_stat(&nvfs_n_write_err);
		}

		if (nvfsio->rw_stats_enabled)
			nvfs_stat_d(&nvfs_n_op_writes);
	} else {
		if (res >= 0) {
			if (nvfsio->rw_stats_enabled)
				nvfs_stat64(&nvfs_n_reads_ok);
		} else {
			nvfs_stat(&nvfs_n_read_err);
		}

		if (nvfsio->rw_stats_enabled) {
			nvfs_stat_d(&nvfs_n_op_reads);
		}
	}

	fdput(nvfsio->fd);


	//Because the below combination of mgroup put and transit state can
	//free up the mgroup, it's better to catch the sync state in a local variable
	//so that we do not access any junk memory.
	sync = nvfsio->sync;

	nvfs_mgroup_put(nvfs_mgroup);
	nvfs_transit_state(gpu_info, sync, IO_IN_PROGRESS, IO_READY);
	// Do not use nvfsio object after we update the end fence page
	// for user-space
	
	//For Async case, it's certain that mgroup wouldn't have been freed and hence 
	//we can mark the state Async state as Done after mgroup put as well
	if (!sync) {
		nvfs_ioctl_metapage_ptr_t mpage_ptr;
		void *kaddr = kmap_atomic(gpu_info->end_fence_page);
		void *orig_kaddr = kaddr;
		kaddr = (void*)((char*)kaddr + gpu_info->offset_in_page);
		mpage_ptr = (nvfs_ioctl_metapage_ptr_t) kaddr;
                //User space library is polling on these values
		mpage_ptr->result = res;
		wmb();
		nvfs_dbg("freeing nvfs io end_fence_page: %llx and offset in page : %u in kernel\n", (u64)gpu_info->end_fence_page, gpu_info->offset_in_page);
		mpage_ptr->end_fence_val = nvfsio->end_fence_value;
		kunmap_atomic(orig_kaddr);
		nvfs_dbg("Async - nvfs_io complete. res %ld\n",
				res);
	}
}

/*
 * Async IO completion callback; This is invoked from interrupt context
 */
#ifdef KI_COMPLETE_HAS_3_PARAMETERS
static void nvfs_io_complete(struct kiocb *kiocb, long res, long res2)
#else
static void nvfs_io_complete(struct kiocb *kiocb, long res)
#endif
{
	nvfs_io_t* nvfsio = container_of(kiocb, struct nvfs_io, common);
	nvfs_mgroup_ptr_t nvfs_mgroup = container_of(nvfsio,
						struct nvfs_io_mgroup,
						nvfsio);

        nvfsio->ret = res;
        nvfs_mgroup_check_and_set(nvfs_mgroup, NVFS_IO_DONE, res>=0, true);
        res = nvfsio->ret;

        if (nvfsio->common.ki_flags & IOCB_WRITE) {
                struct file *file = kiocb->ki_filp;

                if (S_ISREG(file_inode(file)->i_mode))
                        __sb_writers_acquired(file_inode(file)->i_sb,
                                        SB_FREEZE_WRITE);
                file_end_write(file);

                if (res < 0)
                        nvfs_stat(&nvfs_n_write_iostate_err);
                else if (nvfsio->rw_stats_enabled) {
                        nvfs_stat64_add(res, &nvfs_n_write_bytes);
                        nvfs_update_write_throughput(res,
                                        &nvfs_write_bytes_per_sec);

                        nvfs_update_write_latency(ktime_us_delta(ktime_get(),
                                                nvfsio->start_io),
                                        &nvfs_write_latency_per_sec);
                }

        } else {

                if (res < 0)
                        nvfs_stat(&nvfs_n_read_iostate_err);
                else if (nvfsio->rw_stats_enabled) {
                        nvfs_stat64_add(res, &nvfs_n_read_bytes);
                        nvfs_update_read_throughput(res,
                                        &nvfs_read_bytes_per_sec);

                        nvfs_update_read_latency(ktime_us_delta(ktime_get(),
                                                nvfsio->start_io),
                                        &nvfs_read_latency_per_sec);
                }
        }

	if (!nvfsio->sync)
		nvfs_io_free(nvfsio, res);

	nvfs_put_ops();
	nvfs_dbg("nvfs_io_complete %ld\n", res);
}

static inline ssize_t nvfs_io_ret(struct kiocb *req, ssize_t ret)
{
	nvfs_io_t* nvfsio = container_of(req,
					struct nvfs_io, common);

	switch (ret) {
	case -EIOCBQUEUED:
		return ret;
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
		/* coverity[fallthrough] */
	case -ERESTART_RESTARTBLOCK:
		/*
		 * There's no easy way to restart the IO.
		 * Just fail this IO.
		 */
	default:
		nvfs_dbg("%s:%d status :%ld\n",
				__func__, __LINE__, ret);
		req->private = NULL;
		#ifdef KI_COMPLETE_HAS_3_PARAMETERS
                nvfs_io_complete(req, ret, 0);
                #else
                nvfs_io_complete(req, ret);
		#endif
                if (nvfsio->sync && ret != nvfsio->ret) {
			if (nvfsio->ret < 0) {
				ret = PTR_ERR(req->private);
				if(ret != -EOPNOTSUPP) {
					nvfs_err("%s:%d IO failed with %ld\n",
                            	__func__, __LINE__, ret);
				} else {
					nvfs_dbg("%s:%d IO failed with %ld\n",
                            	__func__, __LINE__, ret);

				}
			} else
				ret = nvfsio->ret;
		}
		return ret;
	}
}

static inline void set_write_flag(struct kiocb *ki)
{
	ki->ki_flags |= IOCB_WRITE;
}

static inline const char* opstr(int op)
{
	return((op == READ) ? "read" : "write");
}

static inline bool unsigned_offsets(struct file *file)
{
        return file->f_mode & FMODE_UNSIGNED_OFFSET;
}

int nvfs_rw_verify_area(int read_write, struct file *file,
		char __user *buf, const loff_t *ppos, size_t count)
{
        struct inode *inode;
        loff_t pos;
        int retval = -EINVAL;

	if (!nvfs_check_access(read_write, buf, count))
		return -EFAULT;

        inode = file_inode(file);
	// If read/write length is negative
        if (unlikely((ssize_t) count < 0))
                return retval;
        pos = *ppos;

	// If offset is negative
        if (unlikely(pos < 0)) {
                if (!unsigned_offsets(file))
                        return retval;
                if (count >= -pos) /* both values are in 0..LLONG_MAX */
                        return -EOVERFLOW;
        } else if (unlikely((loff_t) (pos + count) < 0)) {
                if (!unsigned_offsets(file))
                        return retval;
        }
#ifdef CONFIG_MANDATORY_FILE_LOCKING
        if (unlikely(inode->i_flctx && mandatory_lock(inode))) {
                retval = locks_mandatory_area(inode, file, pos,
				pos + count - 1,
                                read_write == READ ? F_RDLCK : F_WRLCK);
                if (retval < 0)
                        return retval;
        }
#endif

#ifdef HAVE_SECURITY_FILE_PERMISSION
        nvfs_dbg("Checking file permission.... for %s\n",
			read_write == READ ? "read" : "write");
        return security_file_permission(file,
                                read_write == READ ? MAY_READ : MAY_WRITE);
#else
	return 0;
#endif
}

static inline bool nvfs_is_sparse(struct file *f)
{
     struct inode *inode = file_inode(f);
     loff_t size = i_size_read(inode);
     unsigned int block_size = (1 << 9);
     nvfs_dbg("sparse: blk sz:%d blks: %ld fle sz:%lld \n", block_size,
		(unsigned long)inode->i_blocks, (unsigned long long)size);
     if ((block_size * inode->i_blocks) < size) {
        nvfs_dbg("sparse: encountered a sparse file \n");
        return true;
     }
     return false;
}

/*
 * Start IO operation
 */
static ssize_t
nvfs_direct_io(int op, struct file *filp, char __user *buf,
		size_t len, loff_t ppos, nvfs_io_t* nvfsio)
{
        struct iovec iov = { .iov_base = buf, .iov_len = len };
        struct iov_iter iter;
        ssize_t ret;

	init_sync_kiocb(&nvfsio->common, filp);
        nvfsio->common.ki_pos = ppos;
	nvfsio->common.private = NULL;

#ifdef HAVE_KI_COMPLETE
	if(nvfsio->sync) {
                nvfsio->common.ki_complete = NULL;
        } else {
                nvfsio->common.ki_complete = nvfs_io_complete;
        }
#else
	nvfsio->sync = true;
#endif

#ifdef CONFIG_FAULT_INJECTION
        if (nvfs_fault_trigger(&nvfs_rw_verify_area_error)) {
                ret = -EFAULT;
        }
        else
#endif
        {
		ret = nvfs_rw_verify_area(op, filp, buf, &ppos, len);
		#ifdef SIMULATE_BUG_RW_VERIFY_FAILURE
		ret = -EINVAL;
		#endif
	}

	if (ret) {
		nvfs_err("rw_verify_area failed with %zd\n", ret);
		// reset attached mgroup state for failed IO.
		nvfs_io_ret(&nvfsio->common, ret);
		return ret;
	}

        iov_iter_init(&iter, op, &iov, 1, len);

//TODO: If the config is not present fallback to vfs_read/vfs_write
#ifdef HAVE_CALL_READ_WRITE_ITER
        if(op == WRITE) {
                set_write_flag(&nvfsio->common);
                file_start_write(filp);

                ret = nvfs_io_ret(&nvfsio->common,
				call_write_iter(filp, &nvfsio->common, &iter));
                if (S_ISREG(file_inode(filp)->i_mode))
                        __sb_writers_release(file_inode(filp)->i_sb,
				SB_FREEZE_WRITE);
        } else {
                ret = nvfs_io_ret(&nvfsio->common,
				call_read_iter(filp, &nvfsio->common, &iter));
        }
#endif

        nvfs_dbg("nvfs_direct_io : ret = %ld len = %lu\n" , ret, len);
        if (ret == -EIOCBQUEUED) {
                BUG_ON(nvfsio->sync);
                nvfs_dbg("%s queued\n", opstr(op));
        }
        return ret;
}

static int nvfs_open(struct inode *inode, struct file *file)
{
	int ret;

	if (atomic_read(&nvfs_shutdown) == 1)
		return -EINVAL;

	mutex_lock(&nvfs_module_mutex);
	nvfs_get_ops();

	ret = nvfs_blk_register_dma_ops();
	if (ret < 0) {
		nvfs_err("nvfs modules probe failed with error :%d\n", ret);
		nvfs_put_ops();
		goto out;
	}
out:
	mutex_unlock(&nvfs_module_mutex);

	nvfs_stat(&nvfs_n_op_process);
	nvfs_dbg("nvfs_open %d\n", ret);
	return ret;
}

static int nvfs_close(struct inode *inode, struct file *file)
{
	mutex_lock(&nvfs_module_mutex);
	nvfs_put_ops();
	if (nvfs_count_ops() == 0) {
		nvfs_blk_unregister_dma_ops();
		nvfs_dbg("Unregistering dma ops and nvidia p2p ops\n");
	}
	mutex_unlock(&nvfs_module_mutex);
	nvfs_stat_d(&nvfs_n_op_process);
	nvfs_dbg("nvfs_close\n");
	return 0;
}

static void nvfs_remove(int pid, struct mm_struct* mm)
{
    nvfs_dbg("nvfs_remove\n");
}

static void nvfs_free_put_endfence_page(struct nvfs_gpu_args *gpu_info)
{
	if (gpu_info->end_fence_page) {
#ifdef HAVE_PIN_USER_PAGES_FAST
		unpin_user_page(gpu_info->end_fence_page);
#else
		put_page(gpu_info->end_fence_page);
#endif
		gpu_info->end_fence_page = NULL;
	}
}

/*
 * setup end_fence buffer for Async IO operations
 */
static int nvfs_get_endfence_page(nvfs_ioctl_map_t *input_param,
	struct nvfs_gpu_args *gpu_info)
{
	int ret = -EINVAL;
	void *end_fence;

	end_fence = (void *)input_param->end_fence_addr;

	if (!end_fence) {
		nvfs_err("%s:%d Invalid end_fence address\n",
				__func__, __LINE__);
		goto out;
	}

	if ((unsigned long) end_fence & (NVFS_BLOCK_SIZE -1)) {
		nvfs_err("%s:%d end_fence address not aligned\n",
				__func__, __LINE__);
		goto out;
	}

#ifdef CONFIG_FAULT_INJECTION
        if (nvfs_fault_trigger(&nvfs_end_fence_get_user_pages_fast_error)) {
                ret = -EFAULT;
        }
        else
#endif
	{
#ifdef HAVE_PIN_USER_PAGES_FAST
		ret = pin_user_pages_fast((unsigned long) end_fence, 1, 1,
			&gpu_info->end_fence_page);
#else
		ret = get_user_pages_fast((unsigned long) end_fence, 1, 1,
			&gpu_info->end_fence_page);
#endif
	}

	if (ret != 1) {
		nvfs_err("%s:%d unable to pin end_fence page ret = %d\n",
				__func__, __LINE__, ret);
		goto out;
	}

	gpu_info->offset_in_page = (u32)((u64)end_fence % PAGE_SIZE);
	nvfs_dbg("successfully pinned end fence address : %llx, end_fence_page : %llx offset in page : %ux in kernel\n", (u64)end_fence, (u64)gpu_info->end_fence_page, gpu_info->offset_in_page);
	return 0;
out:
	return ret;
}

/*
 * Unmap the physcial pages previously mapped.
 */
static int nvfs_unpin_gpu_pages(struct nvfs_gpu_args *gpu_info)
{
	int ret = 0;

	if (gpu_info) {
		struct pci_dev_mapping *pci_dev_mapping;
		struct hlist_node *tmp;
		int bkt = 0;
	        u64 gpu_page_start  = gpu_info->gpuvaddr & GPU_PAGE_MASK;

		// We don't need locks here as by this time there
		// shouldn't be any inflight IOs
		hash_for_each_safe(gpu_info->buckets, bkt, tmp,
					pci_dev_mapping, hentry) {
			BUG_ON(pci_dev_mapping->dma_mapping == NULL);
			BUG_ON((
			atomic_read(&gpu_info->dma_mapping_in_progress) != 0));
			
			ret = nvfs_nvidia_p2p_dma_unmap_pages(
					pci_dev_mapping->pci_dev,
					gpu_info->page_table,
					pci_dev_mapping->dma_mapping);
			if (ret) {
				nvfs_err("%s:%d error while invoking "
						"unmap pages\n",
						__func__, __LINE__);
				return ret;
			}

			hash_del(&pci_dev_mapping->hentry);	
			kfree(pci_dev_mapping);
			pci_dev_mapping = NULL;
		}

		if (gpu_info->page_table && gpu_page_start) {
			nvfs_dbg("unpin device physical pages\n");

			nvfs_update_free_gpustat(gpu_info);

			ret = nvfs_nvidia_p2p_put_pages(0, 0, gpu_page_start,
					gpu_info->page_table);
			if (ret) {
				nvfs_err("%s:%d error while calling "
						"put_pages\n",
						__func__, __LINE__);
			}
		}
	}
	return ret;
}

static int nvfs_pin_gpu_pages(nvfs_ioctl_map_t *input_param,
		struct nvfs_gpu_args *gpu_info)
{
    	u64 gpu_virt_start;
    	u64 gpu_virt_end;
    	size_t rounded_size;
	int ret = -EINVAL;
	int i;
	u64 gpuvaddr = (u64)input_param->gpuvaddr;
	u64 gpu_buf_len = input_param->size;
	bool is_invalid_page_table_version = false;
	bool is_invalid_page_size = false;
	int n_phys_chunks = 1;
	nvfs_mgroup_ptr_t nvfs_mgroup = container_of(gpu_info,
						struct nvfs_io_mgroup,
						gpu_info);

	init_waitqueue_head(&gpu_info->callback_wq);

	if(!nvfs_transit_state(gpu_info, true, IO_FREE, IO_INIT)) {
		nvfs_err("%s:%d gpu_info is in invalid state %d "
			 "mgroup_ref %d mgroup %p\n",
			 __func__, __LINE__,
			atomic_read(&gpu_info->io_state),
			atomic_read(&nvfs_mgroup->ref),
			nvfs_mgroup);
		return ret;
	}

	nvfs_dbg("%s:%d IO State moved from %s to %s\n",
		__func__, __LINE__, nvfs_io_state_status(IO_FREE),
		nvfs_io_state_status(IO_INIT));

	gpu_virt_start  = gpuvaddr & GPU_PAGE_MASK;
	gpu_virt_end    = gpuvaddr + gpu_buf_len - 1;
        if(gpu_virt_end < gpu_virt_start) {
		nvfs_err("invalid gpu buf size provided %lld \n ",
			 gpu_buf_len);
		goto error;
        }

        if(gpu_buf_len < GPU_PAGE_SIZE &&
		(input_param->sbuf_block * NVFS_BLOCK_SIZE) <
		(gpuvaddr - gpu_virt_start + gpu_buf_len))
        {
		nvfs_err("invalid shadow buf size provided %u, gpu_buf_len: %lld, gpuvaddr: %llx \n",
				input_param->sbuf_block * NVFS_BLOCK_SIZE, gpu_buf_len, gpuvaddr);
		goto error;
        }

	rounded_size = round_up((gpu_virt_end - gpu_virt_start + 1),
				GPU_PAGE_SIZE);

	nvfs_dbg("gpu_addr 0x%llx cpu_addr 0x%llx gpu_buf_len %llu\n",
			input_param->gpuvaddr,
			input_param->cpuvaddr,
			gpu_buf_len);

        gpu_info->gpu_buf_len = gpu_buf_len;
	gpu_info->gpuvaddr = gpuvaddr;
	gpu_info->page_table = NULL;
	gpu_info->is_bounce_buffer = (input_param->is_bounce_buffer == 1) ?
					true : false;

	atomic_set(&gpu_info->dma_mapping_in_progress, 0);
	hash_init(gpu_info->buckets);

	nvfs_dbg("Invoking p2p_get_pages pages (0x%lx - 0x%lx) "
		 "rounded size %lx\n",
		 (unsigned long)gpu_virt_start,
		 (unsigned long)gpu_virt_end, (unsigned long)rounded_size);

	ret = nvfs_nvidia_p2p_get_pages(0, 0, gpu_virt_start, rounded_size,
			       &gpu_info->page_table,
                               nvfs_get_pages_free_callback, nvfs_mgroup);
	if (ret < 0) {
		nvfs_err("%s:%d Error ret %d invoking nvidia_p2p_get_pages\n "
				"va_start=0x%llx/va_end=0x%llx/"
				"rounded_size=0x%lx/gpu_buf_length=0x%llx\n",
				__func__, __LINE__, ret,
				gpu_virt_start, gpu_virt_end,
				rounded_size, gpu_buf_len);
		goto error;
	}

        nvfs_dbg("GPU page table entries: %d\n", gpu_info->page_table->entries);

	for (i = 0; i < gpu_info->page_table->entries - 1; i++) {
            nvfs_dbg("GPU Physical page[%d]=0x%016llx\n",
                i, gpu_info->page_table->pages[i]->physical_address);

            //create a new segment when the physical addresses are non contiguous
            // or force a new segment at physical address boundary of (4G - 64k) 
            // to handle possible SMMU mappings being non-contiguous
            if ((gpu_info->page_table->pages[i]->physical_address + GPU_PAGE_SIZE) !=
                            gpu_info->page_table->pages[i + 1]->physical_address)
                    n_phys_chunks += 1;
            else if (i > 0 && (i % NVFS_P2P_MAX_CONTIG_GPU_PAGES == 0))
                    n_phys_chunks += 1;
        }

	gpu_info->n_phys_chunks = n_phys_chunks;

#ifdef CONFIG_FAULT_INJECTION
        if (nvfs_fault_trigger(&nvfs_invalid_p2p_get_page)) {
                ret = -EFAULT;
        }
        else
#endif
	{
		is_invalid_page_table_version =
			(!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(
					gpu_info->page_table));
		// we are not ready for a different page size
		is_invalid_page_size = (gpu_info->page_table->page_size !=
						NVIDIA_P2P_PAGE_SIZE_64KB);
		ret = -EINVAL;
	}

	if (is_invalid_page_table_version || is_invalid_page_size ||
			(ret == -EFAULT)) {
		if (is_invalid_page_table_version)
			nvfs_err("%s:%d Incompatible page table "
				 "version 0x%08x\n",
				__func__, __LINE__,
				gpu_info->page_table->version);
		else if (is_invalid_page_size)
			nvfs_err("%s:%d nvidia_p2p_get_pages "
				 "assumption of 64KB pages failed "
				 "size_id=%d\n",
				 __func__, __LINE__,
				 gpu_info->page_table->page_size);
		else
			nvfs_err("%s:%d nvfs_invalid_p2p_get_page "
				 "fault trigger\n",
				 __func__, __LINE__);

		goto unpin_gpu_pages;
	}

	nvfs_update_alloc_gpustat(gpu_info);
	nvfs_dbg("GPU pages pinned successfully gpu_info %p\n", gpu_info);
	return 0;

unpin_gpu_pages:
	// If we received callback by this time, then
	// we need to notify the callback
	if(!nvfs_transit_state(gpu_info, true, IO_INIT, IO_FREE)) {
			nvfs_err("%s:%d: Transition failed mgroup_ref %d mgroup %p\n",
			__func__, __LINE__, atomic_read(&nvfs_mgroup->ref),
			nvfs_mgroup);
	} else {
		nvfs_unpin_gpu_pages(gpu_info);
	}
error:
	return ret;
}

bool nvfs_free_gpu_info(struct nvfs_gpu_args* gpu_info, bool from_dma)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = container_of(gpu_info,
			struct nvfs_io_mgroup,
			gpu_info);
	nvfs_dbg("%s state = %s\n", __func__, nvfs_io_state_status(atomic_read(&gpu_info->io_state))); 
	

        //Setting the state to IO_UNPIN_PAGES_ALREADY_INVOKED first, so that
        //if nvfs_get_pages_free_callback is waiting on this state it 
        //can be immediately woken up. The put pages blocks until nnvfs_get_pages_free_callback
        //returns, so if we set this state afterwards, the callback will wait 
        //for the below state to be set which will never be set
        //As a result we will be blocked and eventually this will cause a deadlock.
        //The nvfs_get_pages_free_callback will wait for 1 us after seeing this state and
        //then return. This 5us gives us an extra cushion that put pages will be invoked in 
        //that time frame (but there is no guarantee). If put pages gets invoked before callback
        //returns then p2p put pages will return successfully. If p2p put pages fails to get invoked 
        //in that 1us, then behaviour of put pages is unknown(it might crash) 
	atomic_set(&gpu_info->io_state, IO_UNPIN_PAGES_ALREADY_INVOKED);
	if(nvfs_unpin_gpu_pages(gpu_info) != 0) {
		nvfs_dbg("nvfs_unpin_gpu_pages failed %p to %s"
			 "and returning\n", 
			 nvfs_mgroup, 
		  	 nvfs_io_state_status(IO_UNPIN_PAGES_ALREADY_INVOKED));

	}		
	// Reference taken during nvfs_map()
	nvfs_free_put_endfence_page(gpu_info);
	nvfs_put_ops();

	if (nvfs_count_ops() == 0) {
		mutex_lock(&nvfs_module_mutex);
                // check if the count has not gone up
		if (nvfs_count_ops() == 0) {
                        
                        //If put is called from dma map/unmap, then we do not want to unregister the 
                        //dma_ops because it can cause a dead lock where unregister is waiting for a 
                        //put and that put won't happen until we return from here
			if(!from_dma) {
				nvfs_blk_unregister_dma_ops();
			} else {
				nvfs_info("%s Not calling nvfs_blk_unregister_dma_ops from"
					  "nvfs_free_gpu_info because put is called from map/unmap dma"
				 	  "for mgroup %p\n",
					   __func__,
					    nvfs_mgroup);
			}
		}
		mutex_unlock(&nvfs_module_mutex);
	}
	return 0;
}

static int nvfs_map_gpu_info(nvfs_ioctl_map_t *input_param,
		struct nvfs_gpu_args *gpu_info)
{
	int ret;

	ret = nvfs_get_endfence_page(input_param, gpu_info);
	if (ret) {
		nvfs_err("%s:%d Error nvfs_get_endfence_page: %d\n",
				__func__, __LINE__, ret);
		goto out;
	}

	ret = nvfs_pin_gpu_pages(input_param, gpu_info);
	if (ret)
		goto free_end_fence_buffer;

	return 0;

free_end_fence_buffer:
	nvfs_free_put_endfence_page(gpu_info);
out:
	return ret;
}

static int nvfs_map(nvfs_ioctl_map_t *input_param)
{
	int ret = -EINVAL;
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	struct nvfs_gpu_args *gpu_info;

	nvfs_get_ops();

        nvfs_mgroup = nvfs_mgroup_pin_shadow_pages(input_param->cpuvaddr,
				input_param->sbuf_block * NVFS_BLOCK_SIZE);
	if (!nvfs_mgroup) {
		nvfs_err("%s:%d Error nvfs_setup_shadow_buffer\n",
				__func__, __LINE__);
		goto error;
	}

	gpu_info = &nvfs_mgroup->gpu_info;

	// attach device info to mgroup
	gpu_info->pdevinfo = input_param->pdevinfo;
	gpu_info->gpu_hash_index = nvfs_get_gpu_hash_index(gpu_info->pdevinfo);
	// This is mainly for peer stats, does not have any bearing on IO path
	if (gpu_info->gpu_hash_index == UINT_MAX) {
		nvfs_warn("Invalid pci device info for mapping buffer\n");
	}

	ret = nvfs_map_gpu_info(input_param, gpu_info);
	if (ret)
		goto error;

	if (!nvfs_transit_state(gpu_info, true, IO_INIT, IO_READY)) {
		nvfs_err("%s:%d: Transition failed mgroup_ref %d\n",
			__func__, __LINE__, atomic_read(&nvfs_mgroup->ref));
		goto error;
	}

	nvfs_dbg("mmap gpu_info=%p mgroup %p pdevinfo :"PCI_INFO_FMT
        " ref %d IO state %s\n",
		gpu_info, nvfs_mgroup,
		PCI_INFO_ARGS(gpu_info->pdevinfo),
		atomic_read(&nvfs_mgroup->ref),
		nvfs_io_state_status(atomic_read(&gpu_info->io_state)));

	return 0;

error:
	// Do not unpin shaodw pages here; There is only one point where
	// ref count is decremented and it is in nvfs_vma_close()
	nvfs_put_ops();
	return ret;
}

static inline int nvfs_check_file_permissions(int op, struct file *file, bool allow_read_on_wronly)
{
	if (op == READ) {
		if (!(file->f_mode & FMODE_READ)) {
			if (allow_read_on_wronly) {
				if(!(file->f_mode & FMODE_WRITE))
					return -EBADF;
				else if (!(file->f_mode & FMODE_CAN_WRITE))
					return -EINVAL;
				else
					nvfs_dbg("Allowing read on O_WRONLY based on setting %d \n", allow_read_on_wronly);
			} else {
				return -EBADF;
			}
		} else if (!(file->f_mode & FMODE_CAN_READ))
			return -EINVAL;
	} else if (op == WRITE) {
		if (!(file->f_mode & FMODE_WRITE))
			return -EBADF;
		if (!(file->f_mode & FMODE_CAN_WRITE))
			return -EINVAL;
	}

	return 0;
}

/*
 * Setup nvfsio for reach READ/WRITE IOCTL operation.
 */
struct nvfs_io* nvfs_io_init(int op, nvfs_ioctl_ioargs_t *ioargs)
{
	int ret = -EINVAL;
	struct nvfs_io* nvfsio = NULL;
	struct fd fd;
	struct nvfs_gpu_args *gpu_info = NULL;
	nvfs_file_args_t *file_args = &(ioargs->file_args);
	u64 va_offset = 0;
        u64 gpu_virt_start = 0;
	struct inode *inode;
	nvfs_mgroup_ptr_t nvfs_mgroup;
	uint64_t devptroff = 0;
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
	uint32_t shadow_buf_size = 0;
	ssize_t rdma_seg_offset = 0;
#endif
	if (ioargs->offset < 0) {
		nvfs_err("bad file offset %lld\n", ioargs->offset);
		return ERR_PTR(ret);
	}

	if (ioargs->offset % NVFS_BLOCK_SIZE ||
			ioargs->size % NVFS_BLOCK_SIZE) {
		nvfs_err("%s:%d offset = %lld size = %llu not sector aligned\n",
				__func__, __LINE__,
				ioargs->offset,
				ioargs->size);
		return ERR_PTR(ret);
	}

	if (ioargs->offset > S64_MAX - (long long)ioargs->size) {
		nvfs_err("Invalid range offset, overflow detected %lld size %llu\n",
			ioargs->offset,
			ioargs->size);
		return ERR_PTR(ret);
	}

	fd = fdget(ioargs->fd);
	if (!fd.file) {
		nvfs_err("%s:%d invalid file descriptor:%d\n",
				__func__, __LINE__, ioargs->fd);
		return ERR_PTR(ret);
	}

	ret = nvfs_check_file_permissions(op, fd.file,
                                       ioargs->allowreads);
	if (ret) {
		nvfs_err("Invalid file permissions\n");
		goto fd_put;
	}

	inode = file_inode(fd.file);
	// we already have a valid fd
	BUG_ON(inode == NULL);

	if (file_args->inum) {
		// for NFS majdev is zero
		if (S_ISREG(file_inode(fd.file)->i_mode) &&
				file_args->majdev) {
                        #if 0
			if (file_args->generation == 0) {
				ret = -EINVAL;
				nvfs_err("invalid file_args for regular file, "
					"inum=%lu/%lu gen=%u/%u\n",
					file_args->inum, inode->i_ino,
					file_args->generation,
					inode->i_generation);
				goto fd_put;
			}
                        #endif
		} else if ((S_ISBLK(file_inode(fd.file)->i_mode)) &&
				(file_args->majdev == 0)) {
			ret = -EINVAL;
			nvfs_err("invalid file_args, no major number for block device file\n");
			goto fd_put;
		}

		// block device files are special files
		if (file_args->generation &&
				(file_args->generation !=
					inode->i_generation)) {
			ret = -ESTALE;
			nvfs_err("%s:%d (%u) file generation mismatch\n",
					__func__, __LINE__,
					file_args->generation);
			goto fd_put;
		}

		if (file_args->inum != inode->i_ino) {
			ret = -ESTALE;
			nvfs_err("%s:%d (%lu) file inode mismatch\n",
					__func__, __LINE__, file_args->inum);
			goto fd_put;
		}

		if ((file_args->majdev != get_major(inode)) ||
		    (file_args->mindev != get_minor(inode))) {
			ret = -ESTALE;
			nvfs_err("%s:%d (%u/%u)file device "
				 "major/minor mismatch expected (%u/%u)\n",
				 __func__, __LINE__,
				 file_args->majdev, file_args->mindev,
                                 get_major(inode), get_minor(inode));
			goto fd_put;
		}

		devptroff = file_args->devptroff;
	} else {
		nvfs_err("%s:%d invalid file_args\n", __func__, __LINE__);
		ret = -EINVAL;
		goto fd_put;
	}


	nvfs_mgroup = nvfs_get_mgroup_from_vaddr(ioargs->cpuvaddr);
	if (nvfs_mgroup == NULL) {
		ret = -EINVAL;
		nvfs_err("%s:%d Invalid addr passed\n",
			__func__, __LINE__);
		goto fd_put;
	}

	gpu_info = &nvfs_mgroup->gpu_info;
	if(!nvfs_transit_state(gpu_info, (ioargs->sync == 1), IO_READY, IO_IN_PROGRESS)) {
		ret = -EBUSY;
		nvfs_dbg("Teardown in progress\n");
		goto mgroup_put;
	}

	nvfs_dbg("%s:%d IO State moved from %s->%s\n",
		__func__, __LINE__,
		nvfs_io_state_status(IO_READY),
			nvfs_io_state_status(IO_IN_PROGRESS));

	// Initialize nvfsio structure
	nvfsio = &nvfs_mgroup->nvfsio;
	memset(nvfsio, 0, sizeof(struct nvfs_io));

	nvfsio->start_io = ktime_get();
	nvfsio->cpuvaddr = (char __user *) ioargs->cpuvaddr;
	nvfsio->sync = (ioargs->sync == 1);
	nvfsio->hipri = (ioargs->hipri == 1);
	nvfsio->use_rkeys = (ioargs->use_rkeys == 1);
        nvfsio->op  = op;

#ifndef SIMULATE_INLINE_READS
	if ((fd.file->f_flags & O_DIRECT) == 0) {
		nvfs_err("O_DIRECT flag is not set\n");
		ret = -EINVAL;
                goto mgroup_put;
        }
#endif

	nvfsio->fd = fd;
	nvfsio->fd_offset = ioargs->offset;
	nvfsio->length = ioargs->size;

        nvfsio->check_sparse = false;
        nvfsio->state = NVFS_IO_META_CLEAN;
        nvfsio->ret = -EINVAL;

	//XXX
	nvfs_dbg("nvfsio init nvfsio :0x%p fd_offset :%llu use rkey: %d\n",
		nvfsio, ioargs->offset, nvfsio->use_rkeys);

	if(!nvfsio->sync) {
		if (ioargs->end_fence_value == 0) {
			nvfs_err("end_fence_value should be positive\n");
			ret = -EINVAL;
			goto mgroup_put;
		}
		nvfsio->end_fence_value = ioargs->end_fence_value;
		nvfs_dbg("nvfs_io_init. Setting end fence value %lld\n",
				ioargs->end_fence_value);
	}

	nvfsio->retrycnt = 0;

	gpu_virt_start  = (gpu_info->gpuvaddr & GPU_PAGE_MASK);
        va_offset = ((u64)gpu_info->gpuvaddr - gpu_virt_start) +
		file_args->devptroff;
	nvfs_dbg("gpuvaddr : %llu, gpu_virt_start : %llu, devptroff : %llu, va_offset : %llu\n",
			(u64)gpu_info->gpuvaddr, (u64)gpu_virt_start, (u64) file_args->devptroff, va_offset);

	if (va_offset % NVFS_BLOCK_SIZE) {
		nvfs_err("gpu_va_offset not aligned va_offset %ld "
			"devptroff %ld\n",
			(unsigned long)va_offset,
			(unsigned long)devptroff);
		ret = -EINVAL;
		goto mgroup_put;
	}

        // if offset > (size mapped - len), return error
	if ((gpu_info->gpu_buf_len < (u64)ioargs->size) ||
		(file_args->devptroff >
		(gpu_info->gpu_buf_len - (u64)ioargs->size)))
        {
		nvfs_err("invalid iosize, devptroff :%lu "
			 "size %lu > buf_len %lu\n",
			 (unsigned long)devptroff,
			 (unsigned long)ioargs->size,
			 (unsigned long)gpu_info->gpu_buf_len);
		ret = -EINVAL;
                goto mgroup_put;
        }

	// if there is gpu_page_offset,
	// the size should be (GPU_PAGE_SIZE - gpu_page_offset)
	nvfsio->gpu_page_offset = va_offset & (GPU_PAGE_SIZE - 1);
	if (nvfsio->gpu_page_offset &&
	    (ioargs->size >
	    (GPU_PAGE_SIZE - nvfsio->gpu_page_offset))) {
		nvfs_err("invalid size, gpu_page_offset %llu size %llu \n",
			nvfsio->gpu_page_offset, ioargs->size);
		ret = -EINVAL;
		goto mgroup_put;
	}

	// set the cur_gpu_base_index to GPU page
	// index corresponding to the gpu_page_offset
	nvfsio->cur_gpu_base_index = va_offset >> GPU_PAGE_SHIFT;
	init_waitqueue_head(&nvfsio->rw_wq);
	if (!file_args->devptroff)
	        BUG_ON(nvfsio->cur_gpu_base_index != 0);
	
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT	
	//If use_rkey is set, then set the appropriate segments for this IO
	if(nvfsio->use_rkeys) {
		shadow_buf_size = nvfs_mgroup->nvfs_blocks_count * NVFS_BLOCK_SIZE;
		rdma_seg_offset = va_offset % shadow_buf_size;
		nvfsio->rdma_seg_offset = rdma_seg_offset;
		nvfs_dbg("%s: set curr rdma segment offset = %lu\n",
			__func__, rdma_seg_offset);
	}
#endif
	return nvfsio;

mgroup_put:
	nvfs_dbg("%s:%d IO State moved from %s->%s\n",
		__func__, __LINE__,
		 nvfs_io_state_status(IO_IN_PROGRESS),
		 nvfs_io_state_status(IO_READY));
	nvfs_transit_state(gpu_info, (ioargs->sync == 1), IO_IN_PROGRESS, IO_READY);

	nvfs_dbg("*****nvfs_io_init failed.. put calling ref %d\n",
			atomic_read(&nvfs_mgroup->ref));
	nvfs_mgroup_put(nvfs_mgroup);
fd_put:
	fdput(fd);
	return ERR_PTR(ret);
}

static int flush_dirty_pages(struct file *file,
		loff_t offset, size_t size, nvfs_io_t* nvfsio)
{
	struct inode *inode = file_inode(file);
	loff_t endbyte;
	int ret;

	endbyte = offset + size - 1;

	do {
		/*
		 * DIRECT IO writes falls back to buffered IO
		 * if the page invalidation fails with -EBUSY.
		 * See generic_file_direct_write(). We don't
		 * want writes to fall back to bufferred IO.
		 * Hence, we explicitly flush the dirty pages
		 * from page cache and invalidate the
		 * data before issuing the IO for this region.
		 *
		 */
#ifdef HAVE_FILEMAP_RANGE_HAS_PAGE
		if (filemap_range_has_page(inode->i_mapping, offset,
					offset + size)) {
#else
		// TODO: On older kernel (3.x), filemap_range_has_page API does not
		// exist. We need to look if there are other APIs. For now, try
		// to flush explicitly
		if (true) {
#endif
			nvfs_dbg("Found page in page-cache during write "
				 "for offset %ld size %ld\n",
				 (unsigned long)offset, (unsigned long) size);

			nvfs_stat(&nvfs_n_pg_cache);
			/*
			 * We will take a inode lock here as we are about
			 * to flush the data.
			 */
			inode_lock(inode);

			/*
			 * Write the dirty pages back
			 */
			ret = filemap_write_and_wait_range(file->f_mapping,
					offset, endbyte);
			if (ret == 0) {

				nvfs_dbg("Dirty page write success "
					 "for offset %ld size %ld\n",
					 (unsigned long)offset,
					 (unsigned long) size);

				/*
				 * Invalidate the cached pages in the region
				 * we are about to write
				 */
				ret = invalidate_inode_pages2_range(
						file->f_mapping,
						offset >> PAGE_SHIFT,
						endbyte >> PAGE_SHIFT);
				if (ret < 0) {
					nvfs_dbg("Page invalidation from "
						 "page-cache failed offset "
						 "%ld size %ld ret = %d\n",
						 (unsigned long)offset,
						 (unsigned long) size, ret);
				} else {
					/*
					 * All good; we wrote the data
					 * and invalidated the mapping
					 * entries in page cache.
					 */
					nvfs_dbg("Page invalidation from "
						 "page-cache success offset "
						 "%ld size %ld ret = %d\n",
						 (unsigned long)offset,
						 (unsigned long) size, ret);
					inode_unlock(inode);
					goto done;
				}
			} else {
				nvfs_stat(&nvfs_n_pg_cache_fail);
				nvfs_dbg("Dirty page write-back to disk "
					 "failed at offset %ld size %ld "
					 "ret %d\n",
					  (unsigned long)offset,
					  (unsigned long) size, ret);
			}
			inode_unlock(inode);

			/*
			 * Wait before retrying again; Perhaps,
			 * buffered IO was in progress and we couldn't
			 * invalidate the region.
			 */
			wait_event_interruptible_timeout(nvfsio->rw_wq,
					false,
					msecs_to_jiffies(1));
		} else {
			nvfs_dbg("Found no page in page cache for offset "
					"%ld size %ld\n",
					(unsigned long)offset,
					(unsigned long)size);
			goto done;
		}
	} while (++nvfsio->retrycnt < MAX_IO_RETRY);

	/*
	 * We couldn't invalidate or flush the dirty page. There
	 * is no point issuing the IO as we know it will fall back
	 * to bufferred IO; just fail the IO.
	 */
	nvfs_stat(&nvfs_n_pg_cache_eio);
	return -EIO;
done:
	return 0;
}

// check fs for which fallocate is mandatory otherwise
// dio may fall back to buffered read/writes (e.g. ext4)
static inline bool nvfs_need_fallocate(struct inode *inode) {
	unsigned long magic = inode->i_sb->s_magic;
	return ((magic != NFS_SUPER_MAGIC) &&
		(magic != LUSTRE_SUPER_MAGIC) && (magic != BEEGFS_SUPER_MAGIC));
}

long nvfs_io_start_op(nvfs_io_t* nvfsio)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = container_of(nvfsio,
						struct nvfs_io_mgroup, nvfsio);
	struct nvfs_gpu_args  *gpu_info = &nvfs_mgroup->gpu_info;
        ssize_t ret = 0, bytes_done = 0, bytes_left = nvfsio->length;
        struct file *f = nvfsio->fd.file;
        struct inode *inode = file_inode(f);
        loff_t fd_offset = nvfsio->fd_offset;
	u64 va_offset = 0;
        int op = nvfsio->op;
        unsigned long shadow_buf_size = (nvfs_mgroup->nvfs_blocks_count) *
						NVFS_BLOCK_SIZE;
	ssize_t rdma_seg_offset = 0;

        nvfs_dbg("Ring %s: m_pDBuffer=%lx BufferSize=%lu TotalRWSize:%ld "
                "fileOffset:%lld gpu_page_offset %llu "
                "GPU page entries=%u cur_gpu_base_index=%ld mode :%s nvfsio :%p\n",
                 opstr(op),
                 (unsigned long)nvfsio->cpuvaddr,
                 shadow_buf_size,
                 bytes_left,
                 fd_offset,
                 nvfsio->gpu_page_offset,
                 gpu_info->page_table->entries,
                 nvfsio->cur_gpu_base_index,
                 nvfsio->sync ? "sync" : "async",
		 nvfsio);

	if (op == WRITE) {
		bool file_is_bdev = S_ISBLK(file_inode(f)->i_mode);

		// skip fallocate check for raw block device files and some file systems
                if (!file_is_bdev && nvfs_need_fallocate(file_inode(f))) {
				        if (!f->f_op->fallocate) {
                            ret = -EIO;
                            nvfs_err("%s fallocate failed :%ld\n", opstr(op), ret);
                            nvfs_io_free(nvfsio, ret);
                            goto failed;
                        }

                        /* fallocate if the file size is 0*/
                        if (i_size_read(inode) == 0) {
                            ret = f->f_op->fallocate(f, 0, 0, 1);
                            if(ret < 0) {
                                    nvfs_err("%s fallocate failed :%ld\n", opstr(op), ret);
                                    nvfs_io_free(nvfsio, ret);
                                    goto failed;
                            }
                            nvfs_dbg("fallocate success\n");
                        }
                }

		ret = flush_dirty_pages(f, fd_offset, bytes_left, nvfsio);
		if (ret) {
                          nvfs_err("%s unable to flush dirty pages :%ld\n",
			  	opstr(op), ret);
                          nvfs_io_free(nvfsio, ret);
                          goto failed;
                }
	}
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT	
	//If this is a read operation for RDMA based file system,
	//then set the segment offset in the RDMA Buffer
	if(nvfsio->use_rkeys) {
		rdma_seg_offset = nvfsio->rdma_seg_offset;
	}
#endif
	
	nvfs_dbg("%s rdma offset = %lu\n", __func__, rdma_seg_offset);

	while (bytes_left) {
                int nr_blocks;
                size_t bytes_issued;

		// Check if there are any callbacks or munmaps
		if (unlikely(atomic_read(&gpu_info->io_state) !=
				IO_IN_PROGRESS)) {
			nvfs_err("%s:%d IO requested for termination; "
				 " returning -EIO\n",
				__func__, __LINE__);
			ret = -EIO;
			nvfs_io_free(nvfsio, ret);
			goto failed;
		}

		bytes_issued = min((long) bytes_left, (long)shadow_buf_size - (long)rdma_seg_offset);
		//BUG_ON(offset_in_page(bytes_issued));
		BUG_ON(bytes_issued % NVFS_BLOCK_SIZE);

		nr_blocks = DIV_ROUND_UP(bytes_issued, NVFS_BLOCK_SIZE);
                nvfs_dbg("Num blocks in process address "
			"nr_blocks=%d bytes_left=%lu "
                        "%s bytes_issued=%lu nvfsio 0x%p rdma_seg_offset %lu use_rkey:%d\n",
                        nr_blocks, bytes_left, opstr(op), bytes_issued, nvfsio,
			rdma_seg_offset, nvfsio->use_rkeys);

                ret = nvfs_mgroup_fill_mpages(nvfs_mgroup, nr_blocks);
		// Check if there are any callbacks or munmaps
		if (ret < 0) {
			nvfs_err("%s:%d shadow buffer misaligned for gpu page_offset: 0x%llx bytes_issued: %ld bytes"
				 " returning -EIO\n",
				__func__, __LINE__, nvfsio->gpu_page_offset, bytes_issued);
			ret = -EIO;
			nvfs_io_free(nvfsio, ret);
			goto failed;
		}

                nvfsio->state = NVFS_IO_META_CLEAN;
                nvfsio->ret = -EINVAL;
                if(op == READ && nvfs_is_sparse(f)) {
                        nvfsio->check_sparse = true;
		        nvfs_stat64(&nvfs_n_reads_sparse_files);
                } else {
                        nvfsio->check_sparse = false;
                }

                if (f->f_op->read_iter && f->f_op->write_iter) {
			nvfs_get_ops();
			ret = nvfs_direct_io(op, f,
                                        nvfsio->cpuvaddr,
                                        bytes_issued,
                                        fd_offset,
                                        nvfsio);
                } else
                        ret = -EINVAL;

                if (ret < 0 && ret != -EIOCBQUEUED) {
			//For IBM GPFS this can happen frequently and hence instead of logging to error,
			//we will log to debug
			if((ret == -EOPNOTSUPP) && (nvfsio->use_rkeys)) {
                        	nvfs_dbg("%s IO failed :%ld\n", opstr(op), ret);
			} else {
                        	nvfs_err("%s IO failed :%ld\n", opstr(op), ret);
			}
                        goto err;
                } else if (ret == -EIOCBQUEUED) {
                        nvfs_dbg("%s IO is enqueued\n", opstr(op));
                        if(nvfsio->sync) {
                                nvfs_err("%s detected async IO for sync request\n", opstr(op));
                                goto err;
                        } else {
                                ret = 0;
                                break;
                        }
                }

                if (ret >= 0) {
                        bytes_done += ret;
                        bytes_left -= ret;
                        fd_offset += ret;
                        nvfsio->fd_offset = fd_offset;

                        if (ret != bytes_issued) {
                                nvfs_dbg("%s - IO done %ld bytes "
                                                "Expected %ld bytes; We reached EOF\n",
                                                opstr(op), (unsigned long)ret,
                                                (unsigned long)bytes_issued);
                                break;
                        }
                        nvfs_dbg("%s bytes_issued :%lu bytes_done :%lu "
                                        "bytes_left :%lu",
                                        opstr(op), bytes_issued, bytes_done, bytes_left);

                        if(nvfsio->state == NVFS_IO_META_SPARSE) {
                                nvfs_stat64(&nvfs_n_reads_sparse_io);
                                break;
                        }

                        /* update the offset for next batch if bytes_left for sync use case */
                        if(bytes_left) {
                                BUG_ON(!nvfsio->sync);
                                /* advance the gpu offsets */
                                va_offset =  nvfsio->gpu_page_offset + bytes_issued;
                                nvfsio->gpu_page_offset = va_offset & (GPU_PAGE_SIZE - 1);
                                nvfsio->cur_gpu_base_index += va_offset >> GPU_PAGE_SHIFT;
				
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT	
				// clear the rdma_seg_offset
				if(nvfsio->use_rkeys) {
					rdma_seg_offset = 0;
					nvfsio->rdma_seg_offset = 0;
				}
#endif
                        }
                }
        }

        if (nvfsio->sync) {
                nvfs_dbg("IO %s complete for size %lu. "
                                "Number of GPU Entries DMA'ed %d\n",
                                opstr(op), bytes_done, gpu_info->page_table->entries);
        } else {
                nvfs_dbg("IO %s queued for size %lu. "
                                "Number of GPU Entries DMA'ed %d\n",
                                opstr(op), bytes_done, gpu_info->page_table->entries);
        }

#ifdef SIMULATE_LESS_BYTES
    if (bytes_done > NVFS_BLOCK_SIZE) {
	bytes_done -= 4091;
	nvfs_info("truncate request size :%lu\n", bytes_done);
    }
#endif

err:
	if (nvfsio->sync)
		nvfs_io_free(nvfsio, bytes_done);

failed:
	if (ret < 0)
                return ret;
	else
                return bytes_done;
}

static inline int get_rwop(unsigned int ioctl_num)
{
	if (ioctl_num == NVFS_IOCTL_READ)
		return READ;
	else if (ioctl_num == NVFS_IOCTL_WRITE)
		return WRITE;
#ifdef NVFS_BATCH_SUPPORT
	else if (ioctl_num == NVFS_IOCTL_BATCH_IO)
		return READ;
#endif
	return -1;
}

/*
 * IOCTL entry from user space
 */
static long nvfs_ioctl(struct file *file, unsigned int ioctl_num,
			unsigned long ioctl_param)
{
	int pid = current->tgid;
	nvfs_ioctl_param_union local_param;

	if (copy_from_user((void *) &local_param, (void *) ioctl_param,
		sizeof(nvfs_ioctl_param_union))) {
		nvfs_err("%s:%d copy_from_user failed\n", __func__, __LINE__);
		return -ENOMEM;
	}

	if (atomic_read(&nvfs_shutdown) == 1)
		return -EINVAL;

	switch (ioctl_num) {

	case NVFS_IOCTL_REMOVE:
	{
		nvfs_dbg("nvfs ioctl remove invoked\n");
		nvfs_remove(pid, NULL);
		return 0;
	}

	case NVFS_IOCTL_READ:
	case NVFS_IOCTL_WRITE:
	{
                nvfs_io_t* nvfsio = NULL;
		int op = get_rwop(ioctl_num);
		const char *io = (op == READ) ? "Read" : "Write";
                bool rw_stats_enabled = 0;

                if(nvfs_rw_stats_enabled > 0) {
                    rw_stats_enabled = 1;
                }
		
		if(op == READ) {
			if (rw_stats_enabled) {
				nvfs_stat64(&nvfs_n_reads);
				nvfs_stat(&nvfs_n_op_reads);
			}
			nvfs_dbg("nvfs ioctl %s invoked\n", io);
		} else {
			if (rw_stats_enabled) {
				nvfs_stat64(&nvfs_n_writes);
				nvfs_stat(&nvfs_n_op_writes);
			}
			nvfs_dbg("nvfs ioctl %s invoked\n", io);
		}

		nvfsio = nvfs_io_init(op, &local_param.ioargs);

		if (IS_ERR(nvfsio)) {
			local_param.ioargs.ioctl_return = PTR_ERR(nvfsio);
			if (copy_to_user((void *) ioctl_param,
						(void*) &local_param,
						sizeof(nvfs_ioctl_param_union))) {
				nvfs_err("%s:%d copy_to_user failed\n", __func__, __LINE__);
			}
			if(op == READ) {
				nvfs_stat(&nvfs_n_read_err);
				if (rw_stats_enabled)
					nvfs_stat_d(&nvfs_n_op_reads);
				nvfs_err("nvfs ioctl %s ret = %ld\n",
						io, PTR_ERR(nvfsio));
			} else {
				nvfs_stat(&nvfs_n_write_err);
				if (rw_stats_enabled)
					nvfs_stat_d(&nvfs_n_op_writes);
				nvfs_err("nvfs ioctl %s ret = %ld\n",
						io, PTR_ERR(nvfsio));
			}
			return -1;
		}
                nvfsio->rw_stats_enabled = rw_stats_enabled;

                local_param.ioargs.ioctl_return = nvfs_io_start_op(nvfsio);
                if (copy_to_user((void *) ioctl_param, (void*) &local_param,
					sizeof(nvfs_ioctl_param_union))) {
			local_param.ioargs.ioctl_return = -EFAULT;
			nvfs_err("%s:%d copy_to_user failed\n", __func__, __LINE__);
		}
                nvfs_dbg("nvfs ioctl %s ret = %llu\\n", io,
					local_param.ioargs.ioctl_return);

                return ((local_param.ioargs.ioctl_return < 0) ? -1 : 0);
	}
#ifdef NVFS_BATCH_SUPPORT
        case NVFS_IOCTL_BATCH_IO:
        {
                nvfs_batch_io_t* nvfs_batch = NULL;
                bool rw_stats_enabled = 0;
                
                if(nvfs_rw_stats_enabled > 0) {
                        rw_stats_enabled = 1;
                }
                nvfs_dbg("nvfs batch ioctl invoked\n");
                if (rw_stats_enabled) {
                        nvfs_stat64(&nvfs_n_batches);
                        nvfs_stat(&nvfs_n_op_batches);
                }
                nvfs_batch = nvfs_io_batch_init(&local_param);

                if (IS_ERR(nvfs_batch)) {
                        local_param.ioargs.ioctl_return = PTR_ERR(nvfs_batch);
                        if (copy_to_user((void *) ioctl_param,
                                                (void*) &local_param,
                                                sizeof(nvfs_ioctl_param_union))) {
                                nvfs_err("%s:%d copy_to_user failed\n", __func__, __LINE__);
                        }
                        nvfs_stat(&nvfs_n_batch_err);
                        if (rw_stats_enabled)
                                nvfs_stat_d(&nvfs_n_op_batches);
                        nvfs_err("nvfs batch ioctl ret = %ld\n", PTR_ERR(nvfs_batch));
			return -1;
		}

                local_param.ioargs.ioctl_return = nvfs_io_batch_submit(nvfs_batch);
                nvfs_batch = NULL;

                if(local_param.ioargs.ioctl_return < 0) {
                        nvfs_stat(&nvfs_n_batch_err);
                } else {
                        nvfs_stat64(&nvfs_n_batches_ok);
                }
                if (copy_to_user((void *) ioctl_param, (void*) &local_param,
					sizeof(nvfs_ioctl_param_union))) {
			local_param.ioargs.ioctl_return = -EFAULT;
                        nvfs_stat(&nvfs_n_batch_err);
			nvfs_err("%s:%d copy_to_user failed\n", __func__, __LINE__);
		} else {
                        nvfs_dbg("nvfs batch ioctl ret = %llu\\n", local_param.ioargs.ioctl_return);
                }

                if (rw_stats_enabled)
                        nvfs_stat_d(&nvfs_n_op_batches);

                return ((local_param.ioargs.ioctl_return < 0) ? -1 : 0);
        }
#endif
	case NVFS_IOCTL_MAP:
	{
		int ret;

		nvfs_stat64(&nvfs_n_maps);
		nvfs_stat(&nvfs_n_op_maps);
		
		ret = nvfs_map(&(local_param.map_args));
		if (ret) {
			local_param.ioargs.ioctl_return = ret;
			if (copy_to_user((void *) ioctl_param,
				(void*) &local_param,
				sizeof(nvfs_ioctl_param_union))) {
				nvfs_err("%s:%d copy_to_user failed\n", __func__, __LINE__);
			}
			nvfs_stat(&nvfs_n_map_err);
			nvfs_stat_d(&nvfs_n_op_maps);
			return -1;
		}

		nvfs_dbg("nvfs ioctl map success\n");
		nvfs_stat64(&nvfs_n_maps_ok);
		if (copy_to_user((void *) ioctl_param, (void*) &local_param,
				sizeof(nvfs_ioctl_param_union))) {
			nvfs_err("%s:%d copy_to_user failed\n", __func__, __LINE__);
			return -EFAULT;
		}
		return 0;
	}
	case NVFS_IOCTL_SET_RDMA_REG_INFO:
	{
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
		int ret = 0;

		ret = nvfs_set_rdma_reg_info_to_mgroup(
					(nvfs_ioctl_set_rdma_reg_info_args_t*)&local_param.rdma_set_reg_info);
		if(ret) {
			nvfs_err("nvfs_set_rdma_device_info_to_mgroup() returned %d\n",
					ret);
			return ret;
		}
		
		nvfs_dbg("NVFS_IOCTL_SET_RDMA_DEVICE_INFO ioctl success\n");
		return 0;
#else
		return -1;
#endif
	}
	case NVFS_IOCTL_GET_RDMA_REG_INFO:
	{
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
		int ret = 0;	
		ret = nvfs_get_rdma_reg_info_from_mgroup(
				(nvfs_ioctl_get_rdma_reg_info_args_t*)&local_param.rdma_get_reg_info);
		if(ret) {
			nvfs_err("Error in getting RDMA Reg info\n");
			return ret;
		}
		ret = copy_to_user((void *) ioctl_param, (void*) &local_param,
				sizeof(nvfs_ioctl_param_union));
		if (!ret)
			nvfs_dbg("NVFS_IOCTL_GET_RDMA_REG_INFO ioctl success\n");
		else
			nvfs_err("%s:%d copy_to_user failed\n", __func__, __LINE__);
		return ret;
#else
		return -1;
#endif
	}
	case NVFS_IOCTL_CLEAR_RDMA_REG_INFO:
	{
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
		int ret = 0;
		ret = nvfs_clear_rdma_reg_info_in_mgroup(
				(nvfs_ioctl_clear_rdma_reg_info_args_t*)&local_param.rdma_clear_reg_info);

		if(ret) {
			nvfs_err("Error in clearing RDMA info information in mgroup\n");
			return ret;
		}
		nvfs_dbg("NVFS_IOCTL_CLEAR_RDMA_REG_INFO success \n");
		return 0;
#else
		return -1;
#endif
	}
	default:
	{
		nvfs_err("%s:%d Invalid IOCTL invoked\n", __func__, __LINE__);
		return -ENOTTY;
	}
	}

	return 0;
}

struct file_operations nvfs_dev_fops = {
	.compat_ioctl = nvfs_ioctl,
	.unlocked_ioctl = nvfs_ioctl,
	.open = nvfs_open,
	.release = nvfs_close,
        .mmap = nvfs_mgroup_mmap,
        .owner = THIS_MODULE,
};

#ifdef HAVE_NO_CONST_DEVICE_IN_DEVNODE
static char *nvfs_devnode(struct device *dev, umode_t *mode)
#else
static char *nvfs_devnode(const struct device *dev, umode_t *mode)
#endif
{
        if (!mode)
                return NULL;
        *mode = 0666;
        return NULL;
}

/*
 * Initialize nvfs driver
 */
static int __init nvfs_init(void)
{
	int i;

	pr_info("nvidia_fs: Initializing nvfs driver module\n");

	major_number = register_chrdev(0, DEVICE_NAME, &nvfs_dev_fops);

	if (major_number < 0) {
		pr_err("nvidia_fs: failed to register a major number\n");
		return major_number;
	}

	pr_info("nvidia_fs: registered correctly with major number %d\n",
			major_number);

    #ifdef CLASS_CREATE_HAS_TWO_PARAMS
	nvfs_class = class_create(THIS_MODULE, CLASS_NAME);
    #else
	nvfs_class = class_create(CLASS_NAME);
    #endif

	if (IS_ERR(nvfs_class)) {
		unregister_chrdev(major_number, DEVICE_NAME);
		pr_err("nvidia_fs: Failed to register device class\n");
		return PTR_ERR(nvfs_class);
	}

	nvfs_class->devnode = nvfs_devnode;

	nvfs_set_device_count(nvfs_max_devices);

	nvfs_curr_devices = nvfs_get_device_count();

	for (i = 0; i < nvfs_curr_devices; i++) {
		nvfs_device[i] = device_create(nvfs_class, NULL,
				MKDEV(major_number, i),
				NULL, DEVICE_NAME"%d", i);
		if (IS_ERR(nvfs_device[i])) {
			class_destroy(nvfs_class);
			unregister_chrdev(major_number, DEVICE_NAME);
			pr_err("nvidia_fs: Failed to create the device\n");
			i -= 1;
			// Cleanup all the previous devices
			goto error;
		}
	}

        // initialize meta group data structures
        nvfs_mgroup_init();
	atomic_set(&nvfs_shutdown, 0);
	init_waitqueue_head(&wq);
	nvfs_proc_init();
#ifdef CONFIG_FAULT_INJECTION
	nvfs_init_debugfs();
#endif
	nvfs_stat_init();
#ifdef TEST_DISCONTIG_ADDR
	nvfs_init_simulated_address();
#endif
	nvfs_fill_gpu2peer_distance_table_once();

	return 0;

error:
	while (i >= 0) {
		device_destroy(nvfs_class, MKDEV(major_number,i));
		i -= 1;
	}

	return -1;
}

static void __exit nvfs_exit(void)
{
	int i;

	atomic_set(&nvfs_shutdown, 1);
	do {
		wait_event_interruptible_timeout(wq,
			(nvfs_count_ops() == 0),
			msecs_to_jiffies(NVFS_HOLD_TIME));
			nvfs_dbg("count_ops :%lu\n", nvfs_count_ops());
	} while (nvfs_count_ops());
	nvfs_proc_cleanup();
#ifdef CONFIG_FAULT_INJECTION
	nvfs_free_debugfs();
#endif
	nvfs_stat_destroy();

	for (i = 0; i < nvfs_curr_devices; i++) {
		device_destroy(nvfs_class, MKDEV(major_number, i));
	}
	class_destroy(nvfs_class);
	unregister_chrdev(major_number, DEVICE_NAME);
	pr_info("nvidia_fs: driver unloaded successfully\n");
}

module_init(nvfs_init);
module_exit(nvfs_exit);

MODULE_VERSION(TO_STR(MOD_VERS(NVFS_DRIVER_MAJOR_VERSION, NVFS_DRIVER_MINOR_VERSION, NVFS_DRIVER_PATCH_VERSION)));
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("NVIDIA GPUDirect Storage");
module_param_named(max_devices, nvfs_max_devices, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(nvfs_max_devices, "number of character devices to expose");
module_param_named(dbg_enabled, nvfs_dbg_enabled, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(nvfs_dbg_enabled, "enable debug tracing");
module_param_named(info_enabled, nvfs_info_enabled, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(nvfs_info_enabled, "enable info tracing");
module_param_named(peer_stats_enabled, nvfs_peer_stats_enabled, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(nvfs_peer_stats_enabled, "enable peer stats");
module_param_named(rw_stats_enabled, nvfs_rw_stats_enabled, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(nvfs_rw_stats_enabled, "enable read-write stats");
