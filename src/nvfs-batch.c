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
#ifdef NVFS_BATCH_SUPPORT
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
#include "nvfs-dma.h"
#include "nvfs-pci.h"
#include "nvfs-stat.h"
#include "nvfs-fault.h"
#include "nvfs-kernel-interface.h"
#include "nvfs-p2p.h"
#include "nvfs-batch.h"


/*
 * Setup nvfsio for reach READ/WRITE IOCTL operation.
 */
nvfs_batch_io_t* nvfs_io_batch_init(nvfs_ioctl_param_union *input_param)
{
	nvfs_ioctl_batch_ioargs_t *batch_args = &(input_param->batch_ioargs);
        nvfs_batch_io_t *nvfs_batch = NULL; 
        int i, ret = -EINVAL;
        bool rw_stats_enabled = 0;
        
        if(nvfs_rw_stats_enabled > 0) {
                rw_stats_enabled = 1;
        }

        if (batch_args->nents <= 0 || batch_args->nents > NVFS_MAX_BATCH_ENTRIES) {
                nvfs_err("number of batch entries exceeds max supported entries %lld \n", batch_args->nents);
                return ERR_PTR(ret);
        }

        nvfs_batch = kzalloc(sizeof(nvfs_batch_io_t), GFP_KERNEL); 
        if (nvfs_batch == NULL) {
	        return ERR_PTR(-ENOMEM);
        }
        nvfs_batch->ctx_id = batch_args->ctx_id;
	nvfs_batch->start_io = ktime_get(); 
        nvfs_batch->nents = batch_args->nents;

        nvfs_dbg("batch_submit ctx_id:%lld  nents:%lld \n", batch_args->ctx_id, batch_args->nents);
        for (i=0; i < batch_args->nents; i++) {
                nvfs_ioctl_ioargs_t __user *io_entry_p;
	        nvfs_ioctl_ioargs_t io_entry;

                io_entry_p = &(batch_args->io_entries[i]);
                if (copy_from_user((void *) &io_entry, (void *) io_entry_p,
                              sizeof(nvfs_ioctl_ioargs_t))) {
                        nvfs_err("%s:%d copy_from_user failed\n", __func__, __LINE__);
                        ret = -EFAULT;
                        goto cleanup; 
                }

                nvfs_dbg (" %d) op: %d, cpuvaddr = 0x%llx foffset= 0x%llx size=0x%llx, sync:%d \n"
                           " hipri: %d, allow_reads = %d use_rkeys= %d \n,"
                           "fd: %d inum: %ld, generation: %d  majdev:0x%x, mindev:0x%x, devptr_off: 0x%llx \n",
                           i, io_entry.optype, io_entry.cpuvaddr, io_entry.offset, io_entry.size,
                           io_entry.sync, io_entry.hipri, io_entry.allowreads, io_entry.use_rkeys,
                           io_entry.fd, io_entry.file_args.inum, io_entry.file_args.generation, io_entry.file_args.majdev,
                           io_entry.file_args.mindev, io_entry.file_args.devptroff);

                nvfs_batch->nvfsio[i] = nvfs_io_init(io_entry.optype, &io_entry);
		if (IS_ERR(nvfs_batch->nvfsio[i])) {
                        ret = PTR_ERR(nvfs_batch->nvfsio[i]);
                        goto cleanup; 
                }
		if (io_entry.optype == READ) {
			if (rw_stats_enabled) {
				nvfs_stat64(&nvfs_n_reads);
				nvfs_stat(&nvfs_n_op_reads);
			}
		} else {
			if (rw_stats_enabled) {
				nvfs_stat64(&nvfs_n_writes);
				nvfs_stat(&nvfs_n_op_writes);
			}
		}
		nvfs_batch->nvfsio[i]->rw_stats_enabled = rw_stats_enabled;
        }
        
        return nvfs_batch;

cleanup:
        if (nvfs_batch) {
                for (i = 0; i < nvfs_batch->nents; i++) {
                        if (nvfs_batch->nvfsio[i] && !IS_ERR(nvfs_batch->nvfsio[i]))
                                nvfs_io_free(nvfs_batch->nvfsio[i], -EINVAL);
                }
                kfree(nvfs_batch);
        }
	return ERR_PTR(ret);
}

long nvfs_io_batch_submit(nvfs_batch_io_t *nvfs_batch)
{
         unsigned i;
         long ret = 0;
         for (i =0; i < nvfs_batch->nents; ++i) {
                ret = nvfs_io_start_op(nvfs_batch->nvfsio[i]);
                if (ret < 0) {
			nvfs_err("%s:%d failed to start nvfs batch io entry: %d\n", __func__, __LINE__, i);
                        nvfs_batch->nvfsio[i] = NULL;
                        goto cleanup;
                }
	 }

	 nvfs_update_batch_latency(ktime_us_delta(ktime_get(),
				 nvfs_batch->start_io),
			 &nvfs_batch_submit_latency_per_sec);
	 kfree(nvfs_batch);
         return ret;;

cleanup:
        if (nvfs_batch) {
                for (i = 0; i < nvfs_batch->nents; i++) {
                        if (nvfs_batch->nvfsio[i] && !IS_ERR(nvfs_batch->nvfsio[i]))
                                nvfs_io_free(nvfs_batch->nvfsio[i], -EINVAL);
                }
                //XXX: wait for the ongoing ops, or cancel them.
                kfree(nvfs_batch);
        }
        return ret;;

}
#endif
