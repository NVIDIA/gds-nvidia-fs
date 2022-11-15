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
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/hash.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/interval_tree_generic.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/delay.h>

#include "nvfs-pci.h"
#include "nvfs-mmap.h"
#include "nvfs-core.h"
#include "nvfs-stat.h"
#include "nvfs-fault.h"
#include "nvfs-kernel-interface.h"
#include "config-host.h"

static DEFINE_HASHTABLE(nvfs_io_mgroup_hash, NVFS_MAX_SHADOW_ALLOCS_ORDER);
static spinlock_t lock ____cacheline_aligned;

static inline bool nvfs_check_process_context(void)
{
	if(irqs_disabled() || 
			in_interrupt() || 
			in_atomic() || 
			in_nmi() || 
			current->mm == NULL) {
		nvfs_dbg("irq_disabled = %d, in intr = %d, in atomic = %d, in nmi = %d current->mm = %d\n",
				(int)irqs_disabled(), 
                                (int)in_interrupt(), 
                                (int)in_atomic(), 
                                (int)in_nmi(), 
                                (int)(current->mm == NULL));
		return 0;
	}
	return 1;
}

void nvfs_mgroup_get_ref(nvfs_mgroup_ptr_t mgroup)
{
	atomic_inc(&mgroup->ref);
}

bool nvfs_mgroup_put_ref(nvfs_mgroup_ptr_t mgroup)
{
	return atomic_dec_and_test(&mgroup->ref);
}

static inline nvfs_mgroup_ptr_t nvfs_mgroup_get_unlocked(unsigned long base_index)
{
        nvfs_mgroup_ptr_t nvfs_mgroup;
	struct nvfs_gpu_args *gpu_info;

        hash_for_each_possible_rcu(nvfs_io_mgroup_hash,
                               nvfs_mgroup, hash_link, base_index)
        {
                if(nvfs_mgroup->base_index == base_index) {
			// If the backing buffer is released, there
			// is no point in bumping the reference. Any new
			// IO should never get hold of nvfs_mgroup
			gpu_info = &nvfs_mgroup->gpu_info;
			if (unlikely(atomic_read(&gpu_info->io_state) >
			        IO_IN_PROGRESS)) {
				nvfs_info("%s:%d nvfs_mgroup found but IO is "
					 "in %s state\n",
					__func__, __LINE__,
					nvfs_io_state_status(atomic_read(&gpu_info->io_state)));
			}

                        //nvfs_dbg("base_index %lx (ref:%d) found \n",
			//	base_index, atomic_read(&nvfs_mgroup->ref));
			nvfs_mgroup_get_ref(nvfs_mgroup);
                        return nvfs_mgroup;
                }
        }
        nvfs_dbg("base_index %lx not found \n", base_index);
        return NULL;
}

nvfs_mgroup_ptr_t nvfs_mgroup_get(unsigned long base_index)
{
        nvfs_mgroup_ptr_t nvfs_mgroup;
	rcu_read_lock();
        nvfs_mgroup = nvfs_mgroup_get_unlocked(base_index);
	rcu_read_unlock();

        return nvfs_mgroup;
}

static void nvfs_mgroup_free(nvfs_mgroup_ptr_t nvfs_mgroup, bool from_dma)
{
        int i;
      	struct nvfs_gpu_args *gpu_info = NULL;
        gpu_info = &nvfs_mgroup->gpu_info;


	if (atomic_read(&gpu_info->io_state) > IO_INIT) {
		if(nvfs_free_gpu_info(gpu_info, from_dma) != 0) {
			nvfs_info("nvfs_free_gpu_info failed. for mgroup %p, ref cnt %d\n", 
                                  nvfs_mgroup, atomic_read(&nvfs_mgroup->ref));
			return;
		}
	}
        spin_lock(&lock);	
        hash_del_rcu(&nvfs_mgroup->hash_link);
        spin_unlock(&lock);

	nvfs_dbg("irq_disabled = %d, in intr = %d, in atomic = %d, in nmi = %d current->mm = %d\n",
			(int)irqs_disabled(), 
			(int)in_interrupt(), 
			(int)in_atomic(), 
			(int)in_nmi(), 
			(int)(current->mm == NULL));
        // don't use rcu expedited version when calling in IRQ context
        if (unlikely(!NVFS_MAY_SLEEP())) {
                synchronize_rcu();
        } else  {
                synchronize_rcu_expedited();
        }


	if (atomic_read(&gpu_info->io_state) > IO_INIT) {
		nvfs_stat_d(&nvfs_n_op_maps);
	}

	if(nvfs_mgroup->nvfs_metadata)
                kfree(nvfs_mgroup->nvfs_metadata);
        if(nvfs_mgroup->nvfs_ppages) {
                for(i=0; i< nvfs_mgroup->nvfs_pages_count; i++) {
                        if(nvfs_mgroup->nvfs_ppages[i] != NULL)
                                put_page(nvfs_mgroup->nvfs_ppages[i]);
                }
                kfree(nvfs_mgroup->nvfs_ppages);
                nvfs_mgroup->nvfs_pages_count = 0;
                nvfs_mgroup->nvfs_ppages = NULL;
        }
        nvfs_mgroup->base_index = 0;
        nvfs_dbg("freeing base_index %lx(ref:%d) found \n",
                  nvfs_mgroup->base_index, atomic_read(&nvfs_mgroup->ref));
        kfree(nvfs_mgroup);
	nvfs_mgroup = NULL;
}


/*
void nvfs_mgroup_put_callback(nvfs_mgroup_ptr_t nvfs_mgroup)
*/
static void nvfs_mgroup_put_internal(nvfs_mgroup_ptr_t nvfs_mgroup, bool from_dma)
{
        if(nvfs_mgroup == NULL)
                return;
        nvfs_dbg("nvfs_mgroup_put called %d \n",
			atomic_read(&nvfs_mgroup->ref));

        if(nvfs_mgroup_put_ref(nvfs_mgroup)) {
		/* The nvidia_p2p_put_pages is only allowed from the 
		 * same process context as the nvidia_p2p_get_pages*.
		 * So here we are checking if the nvfs_mgroup_put() is called
		 * from the process conext or not and if not then atleast it should 
		 * be called from the nvfs_get_pages_free_callback which indicates that 
		 * the GPU memory and it's mapping are being freed in the kernel
		 */
#if 0
                if(nvfs_check_process_context() || 
				atomic_read(&nvfs_mgroup->gpu_info.io_state) == IO_CALLBACK_END) {
			nvfs_dbg("Freeing mgroup %p\n", nvfs_mgroup);
			nvfs_mgroup_free(nvfs_mgroup);
		} else {
			//Dake the ref back othe mgroup, for it to be eventually freed by the callback.
			nvfs_dbg("Ignoring free from async context and taking \
					back the dropped reference for mgroup %p\n", (void*) nvfs_mgroup);
			//Add mgroup to a list or mark the mgroup for deffered completion
			//nvfs_mgroup->deffered_free = 1;
			nvfs_stat64(&nvfs_n_delayed_frees);
			nvfs_mgroup_get_ref(nvfs_mgroup);
		}
#else
		nvfs_mgroup_free(nvfs_mgroup, from_dma);
#endif
        }
}

void nvfs_mgroup_put(nvfs_mgroup_ptr_t nvfs_mgroup) {
	return nvfs_mgroup_put_internal(nvfs_mgroup, false);
}

void nvfs_mgroup_put_dma(nvfs_mgroup_ptr_t nvfs_mgroup) {
	return nvfs_mgroup_put_internal(nvfs_mgroup, true);
}

static nvfs_mgroup_ptr_t nvfs_get_mgroup_from_vaddr_internal(u64 cpuvaddr)
{
	struct page *page;
	int ret;
	unsigned long cur_base_index  = 0;
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	nvfs_mgroup_page_ptr_t nvfs_mpage;

        if (!cpuvaddr) {
                nvfs_err("%s:%d Invalid shadow buffer address\n",
                                __func__, __LINE__);
                goto out;
        }

        if (offset_in_page(cpuvaddr)) {
                nvfs_err("%s:%d Shadow buffer allocation not aligned\n",
                                __func__, __LINE__);
                goto out;
        }
#ifdef HAVE_PIN_USER_PAGES_FAST
	ret = pin_user_pages_fast(cpuvaddr, 1, 1, &page);
#else
	ret = get_user_pages_fast(cpuvaddr, 1, 1, &page);
#endif
	if (ret <= 0) {
		nvfs_err("%s:%d invalid VA %llx ret %d\n",
				__func__, __LINE__,
				cpuvaddr, ret);
		goto out;
	}

	cur_base_index = page->index >> NVFS_MAX_SHADOW_PAGES_ORDER;

	nvfs_mgroup = nvfs_mgroup_get(cur_base_index);
	if (nvfs_mgroup == NULL || unlikely(IS_ERR(nvfs_mgroup))) {
		nvfs_err("%s:%d nvfs_mgroup is invalid for index %ld cpuvaddr %llx\n",
			__func__, __LINE__, (unsigned long)page->index,
			cpuvaddr);
		goto release_page;
	}

        if (cpuvaddr != nvfs_mgroup->cpu_base_vaddr) {
                nvfs_err("%s:%d shadow buffer address mismatch %llx vs %llx \n",
                                __func__, __LINE__, cpuvaddr,
				nvfs_mgroup->cpu_base_vaddr);
		goto failed;
        }


	nvfs_mpage = &nvfs_mgroup->nvfs_metadata[page->index % NVFS_MAX_SHADOW_PAGES];
	if (nvfs_mpage == NULL || nvfs_mpage->nvfs_start_magic != NVFS_START_MAGIC ||
	    nvfs_mpage->page != page) {
		nvfs_err("%s:%d found invalid page %p\n",
			__func__, __LINE__, page);
		goto failed;
	}

	put_page(page);

	return nvfs_mgroup;

failed:
	nvfs_mgroup_put(nvfs_mgroup);
release_page:
	put_page(page);

out:
	return NULL;
}

nvfs_mgroup_ptr_t nvfs_get_mgroup_from_vaddr(u64 cpuvaddr)
{
	nvfs_mgroup_ptr_t nvfs_mgroup_s;
#if 0
	void *addr;
	unsigned long page_count;
	nvfs_mgroup_ptr_t nvfs_mgroup_e;
#endif
	// Check the first page	
	nvfs_mgroup_s = nvfs_get_mgroup_from_vaddr_internal(cpuvaddr);

	if (!nvfs_mgroup_s) {
		nvfs_err("%s:%d Invalid vaddr %llx\n",
			__func__, __LINE__, cpuvaddr);
		goto out;
	}

#if 0
	nvfs_mgroup_put(nvfs_mgroup_s);

	// Check the last page
	page_count = nvfs_mgroup_s->nvfs_pages_count;

	addr = (((char *)cpuvaddr) + ((page_count - 1) * PAGE_SIZE));

	nvfs_mgroup_e = nvfs_validate_vaddr(addr);

	if (!nvfs_mgroup_e) {
		nvfs_err("%s:%d Invalid vaddr %lx\n",
			__func__, __LINE__, (unsigned long)addr);
		goto out;
	}

	WARN_ON_ONCE(nvfs_mgroup_s != nvfs_mgroup_e);
#endif

	return nvfs_mgroup_s;
out:
	return NULL;
}

/*
 * verify and pin the shadow buffer user pages.
 */
nvfs_mgroup_ptr_t nvfs_mgroup_pin_shadow_pages(u64 cpuvaddr, unsigned long length)
{
	int ret = 0;
	struct page** pages = NULL;
        unsigned long count, j, cur_base_index = 0;
        nvfs_mgroup_ptr_t nvfs_mgroup = NULL;

	if (!cpuvaddr) {
		nvfs_err("%s:%d Invalid shadow buffer address\n",
				__func__, __LINE__);
		goto out;
	}

	if (!(cpuvaddr) && offset_in_page(cpuvaddr)) {
		nvfs_err("%s:%d Shadow buffer allocation not aligned\n",
				__func__, __LINE__);
		goto out;
	}

	nvfs_dbg("Pinning shadow buffer %llx length = %ld\n",
		  cpuvaddr, length);

	count = DIV_ROUND_UP(length, PAGE_SIZE);
	pages = (struct page **) kmalloc(count * sizeof(struct page *), GFP_KERNEL);

	if (!pages) {
		nvfs_err("%s:%d shadow buffer pages allocation failed\n",
				__func__, __LINE__);
		goto out;
	}

#ifdef CONFIG_FAULT_INJECTION
        if (nvfs_fault_trigger(&nvfs_pin_shadow_pages_error)) {
                ret = -EFAULT;
        }
        else
#endif
	{
#ifdef HAVE_PIN_USER_PAGES_FAST
		ret = pin_user_pages_fast(cpuvaddr, count, 1, pages);
#else
		ret = get_user_pages_fast(cpuvaddr, count, 1, pages);
#endif
	}

        // fail if the number of pages pinned is not equal to requested count
	if(ret != count || count > NVFS_MAX_SHADOW_PAGES) {
		nvfs_err("%s:%d Unable to pin shadow buffer pages %ld ret= %d\n",
					__func__, __LINE__, count, ret);
		goto failed;
	} else {
	        nvfs_dbg("Pinned Addr: %llx %ld pages for process id %d \n",
                         cpuvaddr, count, current->pid);
        }

	for (j = 0; j < count; j++) {
                // mapping should be NULL
                if(pages[j]->mapping != NULL) {
	                nvfs_err("Page: %p page->mapping: %p page->flags: %lx \n",
				pages[j], pages[j]->mapping, pages[j]->flags);
                        goto out;
                }
                cur_base_index = (pages[j]->index >> NVFS_MAX_SHADOW_PAGES_ORDER);
                if(j == 0) {
                        nvfs_mgroup = nvfs_mgroup_get(cur_base_index);
                        if(nvfs_mgroup == NULL || unlikely(IS_ERR(nvfs_mgroup)))
                                goto out;
                        BUG_ON((nvfs_mgroup->nvfs_pages_count != count));
                }
                BUG_ON((nvfs_mgroup->base_index != cur_base_index));
                BUG_ON(j != (pages[j]->index % NVFS_MAX_SHADOW_PAGES));
                BUG_ON((nvfs_mgroup->nvfs_ppages[j] != pages[j]));

	        nvfs_dbg("Page: %lx , nvfs_mgroup: %p, base_index: %lx page-index: %lx page->flags: %lx \n",
                   (unsigned long)pages[j], nvfs_mgroup, cur_base_index,
                   pages[j]->index, pages[j]->flags);
		// No need of page reference as we already have one when inserting page to VMA
                put_page(pages[j]);
	}

        BUG_ON(nvfs_mgroup->nvfs_ppages == NULL);
	nvfs_mgroup->cpu_base_vaddr = cpuvaddr;
        nvfs_mgroup_check_and_set(nvfs_mgroup, NVFS_IO_INIT, true, false);
        kfree(pages);
	return nvfs_mgroup;

failed:
	if ((ret > 0) && (ret != count)) {
		for (j = 0; j < ret; j++) {
			put_page(pages[j]);
		}
	}
out:
	if (pages)
	    kfree(pages);
	return NULL;
}

void nvfs_mgroup_unpin_shadow_pages(nvfs_mgroup_ptr_t nvfs_mgroup)
{
	//nvfs_mgroup_check_and_set(nvfs_mgroup, NVFS_IO_FREE, true, false);
        nvfs_mgroup_put(nvfs_mgroup);
}

/*
 * NVFS VMA ops.
 */

static int nvfs_vma_split(struct vm_area_struct *vma, unsigned long addr)
{
	nvfs_err("ERR: Attempted VMA split, virt %lx, vm_pg_off:%lx  split_start %lx\n",
			vma->vm_start, vma->vm_pgoff, addr);
        WARN_ON_ONCE(1);
        return -ENOMEM;
}
#ifdef HAVE_VM_OPS_MREMAP_ONE_PARAM
static int nvfs_vma_mremap(struct vm_area_struct *vma) 
#endif
#ifdef HAVE_VM_OPS_MREMAP_TWO_PARAM 
static int nvfs_vma_mremap(struct vm_area_struct *vma, unsigned long flags)
#endif
{
	nvfs_err("ERR: Attempted VMA remap, virt %lx, vm_pg_off:%lx\n",
			vma->vm_start, vma->vm_pgoff);
        WARN_ON_ONCE(1);
        return -ENOMEM;
}


static void nvfs_vma_open(struct vm_area_struct *vma)
{

        vma->vm_private_data = NULL;
	nvfs_err("ERR: NVFS VMA open, virt %lx, vm_pg_off %lx\n",
			vma->vm_start, vma->vm_pgoff);
        WARN_ON_ONCE(1);
}

static void nvfs_vma_close(struct vm_area_struct *vma)
{
        nvfs_mgroup_ptr_t nvfs_mgroup;
	bool callback_invoked = false;
#ifdef CONFIG_NVFS_STATS
	unsigned long length = vma->vm_end - vma->vm_start;
#endif
        if (vma->vm_private_data != NULL) {
		struct nvfs_gpu_args *gpu_info;

                nvfs_mgroup = (nvfs_mgroup_ptr_t)vma->vm_private_data;
		gpu_info = &nvfs_mgroup->gpu_info;

		nvfs_dbg("NVFS VMA close vma:%p nvfs_mgroup %p\n", vma, nvfs_mgroup);
		if (atomic_read(&gpu_info->io_state) > IO_INIT) {
			// cudaFree was already invoked and hence callback was done
			if(atomic_read(&gpu_info->io_state) == IO_CALLBACK_END) {
				nvfs_dbg("%s:%d Callback was already invoked.. ref=%d\n",
					__func__, __LINE__,
					atomic_read(&nvfs_mgroup->ref));
				callback_invoked = true;
			}

#ifdef CONFIG_FAULT_INJECTION
				if (nvfs_mgroup->fault_injected) {
					nvfs_err("*******fault injected ref %d mgroup %p\n",
							atomic_read(&nvfs_mgroup->ref), nvfs_mgroup);
					goto done;
				}
#endif
			if (callback_invoked) {
				goto done;
			} else {
				// We don't wait for the IO to terminate as we cannot
				// sleep in this function. We will just mark the
				// IO to IO_TERMINATE_REQ and move on; the last
				// reference on nvfs_mgroup will ensure cleaning up
				// the structure
				(void)nvfs_io_terminate_requested(gpu_info, false);	
                                // free the memory only if sucessfully terminated by vma_close
			        if(atomic_read(&gpu_info->io_state) != IO_TERMINATED) {
                                        goto done;
                                }
			}

			nvfs_dbg("munmap invoked - IO state %s %d %d\n",
				nvfs_io_state_status(atomic_read(&gpu_info->io_state)), 
						     atomic_read(&gpu_info->io_state),
						     IO_TERMINATED);

			if (atomic_read(&gpu_info->io_state) == IO_TERMINATED){
				// We should have atmost 3 references
				// 1: ref from mmap()
				// 2: ref from nvfs_mgroup_pin_shadow_pages()
				// 3: from In-flight IO

				nvfs_dbg("*****************munmap invoked - nvfs_mgroup ref %d mgroup %p\n",
					atomic_read(&nvfs_mgroup->ref), nvfs_mgroup);

				// We will release reference taken during
				// nvfs_mgroup_pin_shadow_pages()
				nvfs_stat64(&nvfs_n_free);
				nvfs_mgroup_unpin_shadow_pages(nvfs_mgroup);
			}
		} else {
			nvfs_dbg("nvfs_map() was never invoked... io_state %s\n",
					nvfs_io_state_status(atomic_read(&gpu_info->io_state)));
		}

done:
		//nvfs_mgroup_check_and_set(nvfs_mgroup, NVFS_IO_FREE, true, false);

		// ref from mmap()
		BUG_ON(nvfs_mgroup == NULL);
		BUG_ON(atomic_read(&nvfs_mgroup->ref) < 1);
                nvfs_mgroup_put(nvfs_mgroup);
		nvfs_stat64_sub(length, &nvfs_n_active_shadow_buf_sz);
                vma->vm_private_data = NULL;
		nvfs_stat64(&nvfs_n_munmap);
        }
}

static nvfs_vma_fault_t nvfs_vma_fault(struct vm_fault *vmf)
{
        nvfs_err("ERR: NVFS VMA fault: %p , vmf:%p .\n", vmf->vma, vmf);
        WARN_ON_ONCE(1);
        return 0;
}

static nvfs_vma_fault_t nvfs_page_mkwrite(struct vm_fault *vmf)
{
        nvfs_err("ERR: VMA pg_mkwrite: %p vmf:%p .\n", vmf->vma, vmf);
        WARN_ON_ONCE(1);
        return 0;
}

static nvfs_vma_fault_t nvfs_pfn_mkwrite(struct vm_fault *vmf)
{
        nvfs_err("ERR: VMA pfn_mkwrite: %p vmf:%p .\n", vmf->vma, vmf);
        WARN_ON_ONCE(1);
        return 0;
}

static const struct vm_operations_struct nvfs_mmap_ops = {
	.open = nvfs_vma_open,
#ifdef HAVE_VM_OPS_SPLIT
	.split = nvfs_vma_split,
#else
	.may_split = nvfs_vma_split,
#endif
	.mremap = nvfs_vma_mremap,
	.close = nvfs_vma_close,
        .fault = nvfs_vma_fault,
        .pfn_mkwrite = nvfs_pfn_mkwrite,
        .page_mkwrite = nvfs_page_mkwrite,
};

static int nvfs_mgroup_mmap_internal(struct file *filp, struct vm_area_struct *vma)
{
        int ret = -EINVAL, i, tries = 10;
        unsigned long length = vma->vm_end - vma->vm_start;
        unsigned long base_index;
        unsigned long nvfs_pages_count;
        nvfs_mgroup_ptr_t nvfs_mgroup, nvfs_new_mgroup;
	struct nvfs_gpu_args *gpu_info;

	nvfs_stat64(&nvfs_n_mmap);
        /* check length - do not allow larger mappings than the number of
           pages allocated */
        if (length > NVFS_MAX_SHADOW_PAGES * PAGE_SIZE)
                goto error;
        /* if the length is less than 64K, check for 4K alignment */
        if (length < GPU_PAGE_SIZE && (length % PAGE_SIZE)) {
	        nvfs_err("mmap size not a multiple of 4K for size < 64K : 0x%lx \n", length);
                goto error;
        }
        /* if the length is greater than 64K, check for 64K alignment */
        if (length > GPU_PAGE_SIZE && (length % GPU_PAGE_SIZE)) {
	        nvfs_err("mmap size not a multiple of 64K: 0x%lx for size >64k \n", length);
                goto error;
        }

        if ((vma->vm_flags & (VM_MAYREAD|VM_READ|VM_MAYWRITE|VM_WRITE)) != (VM_MAYREAD|VM_READ|VM_MAYWRITE|VM_WRITE))
        {
	        nvfs_err("cannot open vma without PROTO_WRITE|PROT_READ flags: %lx \n", vma->vm_flags);
                goto error;
        }

        if ((vma->vm_flags & (VM_EXEC)) != 0)
        {
	        nvfs_err("cannot open vma with MAP_EXEC flags: %lx \n", vma->vm_flags);
                goto error;
        }

        /* if VM_SHARED is not set the page->mapping is not NULL */
        if ((vma->vm_flags & (VM_SHARED)) == 0)
        {
	       nvfs_err("cannot open vma without MAP_SHARED: %lx \n", vma->vm_flags);
               goto error;
        }

        /* dont allow mremap to expand and dont allow copy on fork */
        vma->vm_flags |= VM_IO | VM_MIXEDMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY;
        vma->vm_ops = &nvfs_mmap_ops;

        nvfs_new_mgroup = (nvfs_mgroup_ptr_t)kzalloc(sizeof(struct nvfs_io_mgroup), GFP_KERNEL);
	if (!nvfs_new_mgroup) {
		ret = -ENOMEM;
        	goto error;
        }

        /* allocate a base index for the group starting from NVFS_MIN_BASE_INDEX
         * to next 2^32 entries. prandom_u32 makes sure the hash table collisions
         * are minimum.
         *
         */
	spin_lock(&lock);
        tries = 10;
        do {
                base_index = NVFS_MIN_BASE_INDEX + (unsigned long)prandom_u32();
                nvfs_mgroup = nvfs_mgroup_get_unlocked(base_index);
                if (unlikely(nvfs_mgroup && tries--)) {
                        nvfs_mgroup_put(nvfs_mgroup);
                        continue;
                } else {
                        nvfs_new_mgroup->base_index = base_index;
                        atomic_set(&nvfs_new_mgroup->ref,1);
                        hash_add_rcu(nvfs_io_mgroup_hash, &nvfs_new_mgroup->hash_link, base_index);
                        nvfs_mgroup = nvfs_new_mgroup;
                        nvfs_new_mgroup = NULL;
                        break;
                }
        } while(tries);
	spin_unlock(&lock);

        if(nvfs_new_mgroup != NULL)
        {
                kfree(nvfs_new_mgroup);
		ret = -ENOMEM;
        	goto error;
        }

        nvfs_pages_count = DIV_ROUND_UP(length, PAGE_SIZE);
        nvfs_mgroup->nvfs_ppages = (struct page**)kzalloc(nvfs_pages_count *
					sizeof(struct page*), GFP_KERNEL);
	if (!nvfs_mgroup->nvfs_ppages) {
                nvfs_mgroup_put(nvfs_mgroup);
		ret = -ENOMEM;
        	goto error;
        }

        nvfs_mgroup->nvfs_metadata = (struct nvfs_io_metadata*)kzalloc(nvfs_pages_count *
					sizeof(struct nvfs_io_metadata), GFP_KERNEL);
	if (!nvfs_mgroup->nvfs_metadata) {
                nvfs_mgroup_put(nvfs_mgroup);
		ret = -ENOMEM;
        	goto error;
        }

        if(vma->vm_private_data == NULL) {
		nvfs_dbg("Assigning nvfs_mgroup %p to vma %p\n",
				nvfs_mgroup, vma);
                vma->vm_private_data = (void *)nvfs_mgroup;
        } else {
                BUG_ON(vma->vm_private_data != NULL);
        }

        for (i = 0; i < nvfs_pages_count; i++) {
                nvfs_mgroup->nvfs_ppages[i] = alloc_page(GFP_USER|__GFP_ZERO);
                if (nvfs_mgroup->nvfs_ppages[i]) {
                        nvfs_mgroup->nvfs_ppages[i]->index = (base_index * NVFS_MAX_SHADOW_PAGES) + i;
#ifdef CONFIG_FAULT_INJECTION
			if (nvfs_fault_trigger(&nvfs_vm_insert_page_error)) {
				ret = -EFAULT;
			}
			else
#endif
			{
				// This will take a page reference which is released in mgroup_put
                        	ret = vm_insert_page(vma, vma->vm_start + i * PAGE_SIZE,
					nvfs_mgroup->nvfs_ppages[i]);
			}

                        nvfs_dbg("vm_insert_page : %d pages: %lx mapping: %p, "
				  "index: %lx (%lx - %lx) ret: %d  \n",
                                        i, (unsigned long)nvfs_mgroup->nvfs_ppages[i],
					nvfs_mgroup->nvfs_ppages[i]->mapping,
					nvfs_mgroup->nvfs_ppages[i]->index,
                                        vma->vm_start + (i * PAGE_SIZE) ,
					vma->vm_start + (i + 1) * PAGE_SIZE,
					ret);
                        if (ret) {
                                nvfs_mgroup->nvfs_pages_count = i+1;
                                nvfs_mgroup_put(nvfs_mgroup);
				ret = -ENOMEM;
        			goto error;
                        }
                } else {
                        nvfs_mgroup->nvfs_pages_count = i;
                        nvfs_mgroup_put(nvfs_mgroup);
			ret = -ENOMEM;
        		goto error;
                }
                //fill the nvfs metadata header
                nvfs_mgroup->nvfs_metadata[i].nvfs_start_magic = NVFS_START_MAGIC;
                nvfs_mgroup->nvfs_metadata[i].nvfs_state = NVFS_IO_ALLOC;
                nvfs_mgroup->nvfs_metadata[i].page = nvfs_mgroup->nvfs_ppages[i];
        }
        nvfs_mgroup->nvfs_pages_count = nvfs_pages_count;
       	gpu_info = &nvfs_mgroup->gpu_info;
	atomic_set(&gpu_info->io_state, IO_FREE);
	nvfs_stat64_add(length, &nvfs_n_active_shadow_buf_sz);
	nvfs_dbg("page %lx mmap (%lx - %lx), len:%ld  success vma:%p, file:%p ref %d\n",
		(unsigned long)nvfs_mgroup->nvfs_ppages, vma->vm_start,
		vma->vm_end, length, vma, vma->vm_file,
		atomic_read(&nvfs_mgroup->ref));

	nvfs_stat64(&nvfs_n_mmap_ok);
        return 0;

error:
	nvfs_stat(&nvfs_n_mmap_err);
	return ret;
}

/* character device mmap method */
int nvfs_mgroup_mmap(struct file *filp, struct vm_area_struct *vma)
{
        /* at offset 0 we map the vmalloc'd area */
        if (vma->vm_pgoff == 0) {
                nvfs_dbg("mmap %p, file:%p \n", vma, vma->vm_file);
                if(vma->vm_file && vma->vm_file->f_path.dentry) {
                        nvfs_dbg("mmap request for file: %s\n", vma->vm_file->f_path.dentry->d_iname);
                }
                return nvfs_mgroup_mmap_internal(filp, vma);
        } else {
             nvfs_err("ERR: mmap %p, vma->vm_pgoff: %lu file:%p \n", vma, vma->vm_pgoff, vma->vm_file);
        }
        /* at any other offset we return an error */
        return -EIO;
}

void nvfs_mgroup_init()
{
	spin_lock_init(&lock);
        hash_init(nvfs_io_mgroup_hash);
}

void nvfs_mgroup_check_and_set(nvfs_mgroup_ptr_t nvfs_mgroup, enum nvfs_page_state state, bool validate,
	bool update_nvfsio)
{
        struct nvfs_io_metadata  *nvfs_mpages = nvfs_mgroup->nvfs_metadata;
        nvfs_io_sparse_dptr_t sparse_ptr = NULL;
        int last_sparse_index = -1;
        struct nvfs_io* nvfsio = &nvfs_mgroup->nvfsio;
        unsigned done_pages = DIV_ROUND_UP(nvfsio->ret, PAGE_SIZE); // roundup to next 4K page
        unsigned issued_pages = (nvfsio->nvfs_active_pages_end - nvfsio->nvfs_active_pages_start +1);
        int i, nholes = -1;
        int  last_done_page = 0; // needs to be int to handle 0 bytes done.
        int sparse_read_bytes_limit = 0; // set only if we reach max hole regions
        int ret = 0;

        if (validate && (state == NVFS_IO_DONE)) {
                BUG_ON(nvfsio->ret < 0);
                BUG_ON(nvfsio->ret > nvfsio->length);

                /* setup sparse metadata structure */
                if(nvfsio->op == READ && nvfsio->check_sparse == true)  {
                        sparse_ptr = nvfs_io_map_sparse_data(nvfs_mgroup);
                }

                /*setup the last page IO was seen based on the ret value */
                if(done_pages < issued_pages) {
                        last_done_page = nvfsio->nvfs_active_pages_start + done_pages - 1;
                        nvfs_dbg("EOF detected, sparse: %p, done_pages:%d issued_pages:%d start:%ld last_done:%d end:%ld \n",
                                 sparse_ptr,
                                 done_pages, issued_pages,
                                 nvfsio->nvfs_active_pages_start,
                                 last_done_page,
                                 nvfsio->nvfs_active_pages_end);
                } else {
                        last_done_page = nvfsio->nvfs_active_pages_end;
                }
        }

        // check that every page has seen the dma mapping call on success
        for(i=0; i < nvfs_mgroup->nvfs_pages_count ; i++) {
                if(state == NVFS_IO_FREE) {
                        WARN_ON_ONCE(validate && nvfs_mpages[i].nvfs_state != NVFS_IO_INIT
                                         && nvfs_mpages[i].nvfs_state != NVFS_IO_ALLOC
                                         && nvfs_mpages[i].nvfs_state != NVFS_IO_DONE);
                } else if(state == NVFS_IO_ALLOC) {
                        WARN_ON_ONCE(validate && nvfs_mpages[i].nvfs_state != NVFS_IO_FREE);
                } else if(state == NVFS_IO_INIT) {
                        WARN_ON_ONCE(validate && nvfs_mpages[i].nvfs_state != NVFS_IO_ALLOC);
                } else if(state == NVFS_IO_QUEUED) {
                        WARN_ON_ONCE(validate && nvfs_mpages[i].nvfs_state != NVFS_IO_INIT
                                    && nvfs_mpages[i].nvfs_state != NVFS_IO_DONE);
                } else if(state == NVFS_IO_DMA_START || state == NVFS_IO_DMA_ERROR) {
                        WARN_ON_ONCE(validate && nvfs_mpages[i].nvfs_state != NVFS_IO_QUEUED
                                     && nvfs_mpages[i].nvfs_state != NVFS_IO_DMA_START);
                } else if(state == NVFS_IO_DONE
                          && i>= nvfsio->nvfs_active_pages_start && i <= nvfsio->nvfs_active_pages_end) {
			if(validate && nvfs_mpages[i].nvfs_state != NVFS_IO_DMA_START) {
				// This page was not issued to block layer as the file ended
				if(i > last_done_page) {
					if (validate && nvfs_mpages[i].nvfs_state != NVFS_IO_QUEUED) {
						ret = -EIO;
						WARN_ON_ONCE(1);
					}
				// This page was not issued to block layer and the file is not sparse, BUG
				}else {
					if(nvfsio->op == READ) {
						// handle fallocate case with unwritten extents
						if (sparse_ptr == false) {
							BUG_ON(nvfsio->check_sparse == true);
							nvfsio->check_sparse = true;
							sparse_ptr = nvfs_io_map_sparse_data(nvfs_mgroup);
						}
						// holes
						if(last_sparse_index < 0 || (last_sparse_index + 1) != i) {
							if (sparse_read_bytes_limit) {
								last_sparse_index = i;
							// we stop further hole processing, and record the current page index for
							// mimicking a partial read to nvfs_io_complete
							} else if (nholes + 1 >= NVFS_MAX_HOLE_REGIONS) {
								sparse_read_bytes_limit = (i - nvfsio->nvfs_active_pages_start) * PAGE_SIZE;
								last_sparse_index = i;
								nvfs_info("detected max hole region count: %u", nholes);
								nvfs_info("sparse read current page index: %u, read_bytes: %d", i,
									sparse_read_bytes_limit);
							} else {
							// start a new sparse region
								nholes++;
								BUG_ON(nholes >= NVFS_MAX_HOLE_REGIONS);
								sparse_ptr->hole[nholes].start = i - nvfsio->nvfs_active_pages_start;
								sparse_ptr->hole[nholes].npages = 1;
								last_sparse_index = i;
							}
						} else {
							sparse_ptr->hole[nholes].npages++;
							last_sparse_index = i;
						}
					} else {
						//WARN_ON(validate && nvfs_mpages[i].nvfs_state != NVFS_IO_DMA_START);
						nvfs_dbg("WRITE: page index: %d, expected NVFS_IO_DMA_START,"
								"current state: %x\n", i, nvfs_mpages[i].nvfs_state);
						ret = -EIO;
					}
				}
			}
		} else if(state == NVFS_IO_DONE &&
                         (i > nvfsio->nvfs_active_pages_end || i < nvfsio->nvfs_active_pages_start)) {
			  // We shouldn't be seeing a page which are out of bounds
			  if (validate && nvfs_mpages[i].nvfs_state != NVFS_IO_INIT)
				BUG_ON(1);	
                          // don't update the state to DONE.
                          continue;
                } else {
                        WARN_ON_ONCE(1);
			ret = -EIO;
                }

		// Donot transition an active page to IO_DONE state,
		// if process is exiting or the thread is interrupted
		if (state == NVFS_IO_DONE &&
				(i>= nvfsio->nvfs_active_pages_start && i <= nvfsio->nvfs_active_pages_end) &&
				((!in_interrupt() && current->flags & PF_EXITING) || nvfsio->ret == -ERESTARTSYS )) {
			if(nvfs_mpages[i].nvfs_state < NVFS_IO_QUEUED ||
					nvfs_mpages[i].nvfs_state > NVFS_IO_DMA_START) {
				nvfs_err("page %d in unexpected state: %d \n", i, nvfs_mpages[i].nvfs_state);
			}
		} else {
			nvfs_mpages[i].nvfs_state = state;
		}
        }

        if(state == NVFS_IO_DONE) {
		// skip cleaning the page metadata if exiting
		if ((nvfsio->ret != -ERESTARTSYS) &&
                    !(current->flags & PF_EXITING)) {
			nvfsio->nvfs_active_pages_start = 0;
			nvfsio->nvfs_active_pages_end = 0;
		}
        }

        // unmap the sparse ptr
        if(sparse_ptr) {
                nvfs_metastate_enum state;
               //update the nholes, state to the user structure.
                sparse_ptr->nholes = (nholes + 1);
                state = sparse_ptr->nholes ? NVFS_IO_META_SPARSE : NVFS_IO_META_CLEAN;
                nvfsio->state = state;
                sparse_ptr->start_fd_offset = nvfsio->fd_offset;
                nvfs_dbg("found: %d holes at fd start_offset %lld \n", sparse_ptr->nholes, sparse_ptr->start_fd_offset);
		nvfs_stat64_add(sparse_ptr->nholes, &nvfs_n_reads_sparse_region);
                for(i=0;i<sparse_ptr->nholes;i++) {
		        nvfs_stat64_add(sparse_ptr->hole[i].npages, &nvfs_n_reads_sparse_pages);
                        nvfs_dbg("Hole: start:%d npages: %d \n",sparse_ptr->hole[i].start, sparse_ptr->hole[i].npages);
                }
                nvfs_io_unmap_sparse_data(sparse_ptr, state);
                sparse_ptr = NULL;
        }

	if (!update_nvfsio || nvfsio->ret < 0)
		return;
	// detected error
	else if (ret < 0)
		nvfsio->ret = ret;
	// partial read due to sparse read reaching max holes capacity
	else if (sparse_read_bytes_limit > 0)
		nvfsio->ret = sparse_read_bytes_limit;
}

static void nvfs_mgroup_fill_mpage(struct page* page, nvfs_mgroup_page_ptr_t nvfs_mdata, nvfs_io_t *nvfsio)
{
        BUG_ON(!page);
	BUG_ON(nvfs_mdata->nvfs_start_magic != NVFS_START_MAGIC);
	BUG_ON(nvfs_mdata->nvfs_state != NVFS_IO_INIT && nvfs_mdata->nvfs_state != NVFS_IO_DONE);
	BUG_ON(nvfs_mdata->page != page);

        nvfs_mdata->nvfs_state = NVFS_IO_QUEUED;
        nvfs_dbg("page %p page->mapping: %lx, page->flags: %lx\n",
                          page, (unsigned long)page->mapping, page->flags);
}


int nvfs_mgroup_fill_mpages(nvfs_mgroup_ptr_t nvfs_mgroup, unsigned nr_pages)
{
        struct nvfs_io* nvfsio = &nvfs_mgroup->nvfsio;
        int j;
        unsigned long pgoff = 0;

        if (unlikely(nr_pages > nvfs_mgroup->nvfs_pages_count)) {
		nvfs_err("nr_pages :%u nvfs_pages_count :%lu\n", nr_pages, nvfs_mgroup->nvfs_pages_count);
	        return -EIO;
	}
	
	if (nvfsio->gpu_page_offset) {
                // check page offset is less than or equal to 60K
                if (nvfsio->gpu_page_offset > (GPU_PAGE_SIZE - PAGE_SIZE))
                      return -EIO;
                // check page offset is 4K aligned
                if (nvfsio->gpu_page_offset % PAGE_SIZE)
                      return -EIO;
                // check total io size is less than or equal to 60K
                if ((nvfsio->gpu_page_offset +  ((loff_t)nr_pages << PAGE_SHIFT)) > GPU_PAGE_SIZE)
                      return -EIO;
                pgoff = nvfsio->gpu_page_offset >> PAGE_SHIFT;
                // check shadow buffer pages are big enough to map the (gpu base address + offset)
                if (((pgoff + nr_pages) > nvfs_mgroup->nvfs_pages_count))
                      return -EIO;
                for (j = 0; j < pgoff; ++j) {
                        nvfs_mgroup->nvfs_metadata[j].nvfs_state = NVFS_IO_INIT;
                }
        }

        nvfsio->nvfs_active_pages_start = pgoff;
        for (j = pgoff; j < nr_pages + pgoff; ++j) {
                nvfs_mgroup_fill_mpage(nvfs_mgroup->nvfs_ppages[j],
			&nvfs_mgroup->nvfs_metadata[j], nvfsio);
        }
        nvfsio->nvfs_active_pages_end = j-1;

        // clear the state for unqueued pages
        for (; j < nvfs_mgroup->nvfs_pages_count ; j++) {
                nvfs_mgroup->nvfs_metadata[j].nvfs_state = NVFS_IO_INIT;
        }

	nvfsio->cpuvaddr += nvfsio->nvfs_active_pages_start << PAGE_SHIFT;
        nvfs_dbg("cpuvaddr: %llx active shadow pages range set to (%ld -  %ld) \n",
                  (u64)nvfsio->cpuvaddr,
                  nvfsio->nvfs_active_pages_start,
                  nvfsio->nvfs_active_pages_end);
        return 0;
}

// eg: page->index relative to base_index (16 + 1) will return 1, 4K
// eg: page->index relative to base_index (32 + 2) will return 2, 8K
void nvfs_mgroup_get_gpu_index_and_off(nvfs_mgroup_ptr_t nvfs_mgroup, struct page* page, unsigned long *gpu_index, pgoff_t *offset)
{
  unsigned long rel_page_index = (page->index % NVFS_MAX_SHADOW_PAGES);
  *gpu_index = nvfs_mgroup->nvfsio.cur_gpu_base_index + (rel_page_index >> PAGE_PER_GPU_PAGE_SHIFT);
  *offset = (rel_page_index % GPU_PAGE_SHIFT) << PAGE_SHIFT;
}

uint64_t nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup_ptr_t nvfs_mgroup, struct page* page)
{
	struct nvfs_gpu_args *gpu_info = &nvfs_mgroup->gpu_info;
	unsigned long gpu_page_index = ULONG_MAX;
	pgoff_t pgoff;
	dma_addr_t phys_base_addr, phys_start_addr;

	nvfs_mgroup_get_gpu_index_and_off(nvfs_mgroup, page,
			&gpu_page_index, &pgoff);

	phys_base_addr = gpu_info->page_table->pages[gpu_page_index]->physical_address;
	phys_start_addr = phys_base_addr + pgoff;

	return phys_start_addr;
}

static nvfs_mgroup_ptr_t __nvfs_mgroup_from_page(struct page* page, bool check_dma_error) {
	unsigned long base_index;
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	nvfs_mgroup_page_ptr_t nvfs_mpage;
	struct nvfs_io* nvfsio = NULL;

	// bailout if page mapping is not NULL
	if(page == NULL || page->mapping != NULL) {
		return NULL;
	}

	base_index = (page->index >> NVFS_MAX_SHADOW_PAGES_ORDER);
	if(base_index < NVFS_MIN_BASE_INDEX)
	{
		return NULL;
	}

	nvfs_mgroup = nvfs_mgroup_get(base_index);
	// check if the nvfs page group exists.
	if(nvfs_mgroup == NULL) {
		return NULL;
	}

	if (unlikely(IS_ERR(nvfs_mgroup)))
		return ERR_PTR(-EIO);

	// check if this is a valid metadata pointing to same page
	nvfs_mpage = &nvfs_mgroup->nvfs_metadata[page->index % NVFS_MAX_SHADOW_PAGES];
	if (nvfs_mpage == NULL || nvfs_mpage->nvfs_start_magic != NVFS_START_MAGIC ||
	    nvfs_mpage->page != page) {
		nvfs_mgroup_put(nvfs_mgroup);
		WARN_ON_ONCE(1);
		return NULL;
	}

	nvfsio = &nvfs_mgroup->nvfsio;

	// check if the page start offset is correct within the group
	if(nvfsio->nvfs_active_pages_start > (page->index % NVFS_MAX_SHADOW_PAGES)) {
		nvfs_mgroup_put(nvfs_mgroup);
		return ERR_PTR(-EIO);
	}

	// check if the page end offset is correct within the group
	if(nvfsio->nvfs_active_pages_end < (page->index % NVFS_MAX_SHADOW_PAGES)) {
		nvfs_mgroup_put(nvfs_mgroup);
		return ERR_PTR(-EIO);
	}

	if (check_dma_error && nvfs_mpage->nvfs_state == NVFS_IO_DMA_ERROR) {
		nvfs_mgroup_put(nvfs_mgroup);
		return ERR_PTR(-EIO);
	}

	return nvfs_mgroup;
}

nvfs_mgroup_ptr_t nvfs_mgroup_from_page_range(struct page* page, int npages)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	nvfs_mgroup_page_ptr_t nvfs_mpage = NULL, prev_mpage = NULL;
        struct nvfs_io* nvfsio = NULL;
        unsigned i = 0;

        nvfs_dbg("setting for %d npages from page: %p \n", npages, page);
	nvfs_mgroup = __nvfs_mgroup_from_page(page, false);
	if (!nvfs_mgroup)
	       return NULL;

	if (unlikely(IS_ERR(nvfs_mgroup)))
		return ERR_PTR(-EIO);

        for (i = 0; i < npages ; i++) {
                // check the page range is not beyond the issued range
                nvfsio = &nvfs_mgroup->nvfsio;
                if(((page->index + i) % NVFS_MAX_SHADOW_PAGES) > nvfsio->nvfs_active_pages_end) {
                        WARN_ON_ONCE(1);
                        goto err;
                }

	        nvfs_mpage = &nvfs_mgroup->nvfs_metadata[(page->index +i) % NVFS_MAX_SHADOW_PAGES];

                // check the pages are indeed contiguous
                if (prev_mpage && page_to_pfn(nvfs_mpage->page) !=
			    (page_to_pfn(prev_mpage->page) + 1)) {

                        WARN_ON_ONCE(1);
                        goto err;
                }

                if(nvfs_mpage->nvfs_state != NVFS_IO_QUEUED &&
                   nvfs_mpage->nvfs_state != NVFS_IO_DMA_START)
                {
                        WARN_ON_ONCE(1);
                        goto err;
                }

                nvfs_dbg("%ld page dma start %p\n", (page->index + i), nvfs_mpage);
                nvfs_mpage->nvfs_state = NVFS_IO_DMA_START;
                prev_mpage = nvfs_mpage;
        }
	return nvfs_mgroup;
err:
        if(nvfs_mpage) {
                nvfs_mpage->nvfs_state = NVFS_IO_DMA_ERROR;
        }
        if(nvfs_mgroup) {
                nvfs_mgroup_put(nvfs_mgroup);
        }
        return ERR_PTR(-EIO);
}

nvfs_mgroup_ptr_t nvfs_mgroup_from_page(struct page* page)
{
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	nvfs_mgroup_page_ptr_t nvfs_mpage;

	nvfs_mgroup = __nvfs_mgroup_from_page(page, false);
	if (!nvfs_mgroup)
	       return NULL;

	if (unlikely(IS_ERR(nvfs_mgroup)))
		return ERR_PTR(-EIO);

	nvfs_mpage = &nvfs_mgroup->nvfs_metadata[page->index % NVFS_MAX_SHADOW_PAGES];

        if(nvfs_mpage->nvfs_state != NVFS_IO_QUEUED &&
           nvfs_mpage->nvfs_state != NVFS_IO_DMA_START)
        {
		nvfs_err("%s: found page in wrong state: %d, page->index: %ld \n",
			 __func__, nvfs_mpage->nvfs_state, page->index % NVFS_MAX_SHADOW_PAGES);
                nvfs_mpage->nvfs_state = NVFS_IO_DMA_ERROR;
                nvfs_mgroup_put(nvfs_mgroup);
                WARN_ON_ONCE(1);
                return ERR_PTR(-EIO);
        }

	if (nvfs_mpage->nvfs_state == NVFS_IO_QUEUED) {
                nvfs_mpage->nvfs_state = NVFS_IO_DMA_START;
		nvfs_dbg("%s : setting page in IO_QUEUED, page->index: %ld \n",
			 __func__, page->index % NVFS_MAX_SHADOW_PAGES);
	} else if (nvfs_mpage->nvfs_state == NVFS_IO_DMA_START) {
		nvfs_dbg("%s : setting page in IO_DMA_START, page->index: %ld \n",
			 __func__, page->index % NVFS_MAX_SHADOW_PAGES);
	}

	return nvfs_mgroup;
}

/* nvfs_is_gpu_page : checks if a page belongs to a GPU request
 * @page (in)       : page pointer
 * @returns         : true if page belongs to a GPU request
 * Note             : This function does not check for associated DMA state of the page.
 */
bool nvfs_is_gpu_page(struct page *page)
{
	nvfs_mgroup_ptr_t nvfs_mgroup;

	nvfs_mgroup = __nvfs_mgroup_from_page(page, false);
	if (nvfs_mgroup == NULL) {
		return false;
	} else if (unlikely(IS_ERR(nvfs_mgroup))) {
		// This is a GPU page but we did not take reference as we are in shutdown path
		// But, we will return true to the caller so that caller doesn't think it is a
		// CPU page and fall back to CPU path
		return true;
	} else {
		nvfs_mgroup_put(nvfs_mgroup);
		return true;
	}
}

/* nvfs_check_gpu_page_and_error : checks if a page belongs to a GPU request and if it has any gpu dma mapping error
 * @page (in)       : start page pointer
 * @nr_pages (in)   : number of pages from the start page
 * @returns         :  1 on GPU page without error
 *                    -1 on GPU page with dma mapping error
 *                     0 on a non-GPU page
 */
int nvfs_check_gpu_page_and_error(struct page *page)
{
	nvfs_mgroup_ptr_t nvfs_mgroup;

	nvfs_mgroup = __nvfs_mgroup_from_page(page, true);
	if (nvfs_mgroup == NULL)
		return 0;
	else if (unlikely(IS_ERR(nvfs_mgroup)))
		return -1;
	else {
                if(atomic_dec_if_positive(&nvfs_mgroup->dma_ref) < 0) {
		        nvfs_stat_d(&nvfs_n_err_dma_ref);
                } else {
                        // drop the reference taken from the nvfs_mgroup_from_page call
                        nvfs_mgroup_put_dma(nvfs_mgroup);
                }
                nvfs_mgroup_put_dma(nvfs_mgroup);
                return 1;
	}
}

/* Description      : get gpu index key given a GPU page.
                      The index key is used for pci-distance lookups
 * @page (in)       : struct page pointer *
 * @returns         : gpu index on success, UINT_MAX on error or invalid input
 */
unsigned int nvfs_gpu_index(struct page *page)
{
	u64 pdevinfo;
	nvfs_mgroup_ptr_t nvfs_mgroup;

	nvfs_mgroup = __nvfs_mgroup_from_page(page, false);
	// not a gpu page
	if (nvfs_mgroup == NULL || unlikely(IS_ERR(nvfs_mgroup))) {
		nvfs_err("%s : invalid gpu page\n", __func__);
		return UINT_MAX;
	}

	// does not contain gpu info
	pdevinfo = nvfs_mgroup->gpu_info.pdevinfo;
	if (!pdevinfo) {
        nvfs_err("%s : gpu bdf info not found in mgroup\n", __func__);
		nvfs_mgroup_put(nvfs_mgroup);
		return UINT_MAX;
	}

	nvfs_mgroup_put(nvfs_mgroup);
	return nvfs_get_gpu_hash_index(pdevinfo);
}

/* Description      : get device priority
 * @dev*(in)        : dma_device
 * @gpu index (in)  : gpu key
 * @returns         : rank on success, UINT_MAX on error
 */
unsigned int nvfs_device_priority(struct device *dev, unsigned int gpu_index)
{
	return nvfs_get_gpu2peer_distance(dev, gpu_index);
}
