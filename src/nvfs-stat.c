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

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include "nvfs-vers.h"
#include "nvfs-stat.h"
#include "nvfs-core.h"
#include "nvfs-pci.h"
#include "config-host.h"
#include <linux/version.h>
static DEFINE_HASHTABLE(nvfs_gpu_stat_hash, NVFS_MAX_GPU_BITS);
static spinlock_t lock ____cacheline_aligned;

/*
 * Operation counters - Definition
 */
atomic64_t nvfs_n_reads;
atomic64_t nvfs_n_reads_ok;
atomic_t nvfs_n_read_err;
atomic_t nvfs_n_read_iostate_err;
atomic64_t nvfs_n_read_bytes;
atomic_t nvfs_read_throughput;
atomic64_t nvfs_read_bytes_per_sec;
atomic_t nvfs_read_ops_per_sec;
atomic64_t nvfs_read_latency_per_sec;
atomic_t nvfs_avg_read_latency;

atomic_t nvfs_batch_ops_per_sec;
atomic64_t nvfs_batch_submit_latency_per_sec;
atomic_t nvfs_batch_submit_avg_latency;

atomic64_t nvfs_n_batches;
atomic64_t nvfs_n_batches_ok;
atomic_t nvfs_n_batch_err;

atomic64_t nvfs_n_reads_sparse_files;
atomic64_t nvfs_n_reads_sparse_io;
atomic64_t nvfs_n_reads_sparse_region;
atomic64_t nvfs_n_reads_sparse_pages;

atomic64_t nvfs_n_writes;
atomic64_t nvfs_n_writes_ok;
atomic_t nvfs_n_write_err;
atomic_t nvfs_n_write_iostate_err;
atomic64_t nvfs_n_write_bytes;
atomic_t nvfs_write_throughput;
atomic64_t nvfs_write_bytes_per_sec;
atomic_t nvfs_write_ops_per_sec;
atomic64_t nvfs_write_latency_per_sec;
atomic_t nvfs_avg_write_latency;

atomic64_t nvfs_n_mmap;
atomic64_t nvfs_n_mmap_ok;
atomic_t nvfs_n_mmap_err;
atomic64_t nvfs_n_munmap;

atomic64_t nvfs_n_maps;
atomic64_t nvfs_n_maps_ok;
atomic_t nvfs_n_map_err;
atomic64_t nvfs_n_free;
atomic_t nvfs_n_callbacks;
atomic64_t nvfs_n_delayed_frees;

atomic64_t nvfs_n_active_shadow_buf_sz;
atomic_t nvfs_n_op_reads;
atomic_t nvfs_n_op_writes;
atomic_t nvfs_n_op_maps;
atomic_t nvfs_n_op_process;
atomic_t nvfs_n_op_batches;
atomic64_t prev_batch_submit_avg_latency;

atomic_t nvfs_n_err_mix_cpu_gpu;
atomic_t nvfs_n_err_sg_err;
atomic_t nvfs_n_err_dma_map;
atomic_t nvfs_n_err_dma_ref;

atomic_t prev_read_throughput;
atomic_t prev_write_throughput;

atomic64_t prev_read_latency;
atomic64_t prev_write_latency;

atomic_t nvfs_n_pg_cache;
atomic_t nvfs_n_pg_cache_fail;
atomic_t nvfs_n_pg_cache_eio;


static void nvfs_reset_gpuinfo_stats(void)
{
	struct nvfs_gpu_stat *gpustat;
	unsigned int temp = 0;

	rcu_read_lock();
	hash_for_each_rcu(nvfs_gpu_stat_hash, temp, gpustat, hash_link)
	{
              nvfs_stat64_reset(&gpustat->max_bar_memory_pinned);
        }
	rcu_read_unlock();
}

static void nvfs_print_gpuinfo(struct seq_file *m)
{
	struct nvfs_gpu_stat *gpustat;
	unsigned int temp = 0;

	rcu_read_lock();

	hash_for_each_rcu(nvfs_gpu_stat_hash, temp, gpustat, hash_link)
	{
        seq_printf(m, "GPU "PCI_INFO_FMT" uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x : "
#ifdef HAVE_ATOMIC64_LONG
                "Registered_MiB=%lu Cache_MiB=%lu max_pinned_MiB=%lu ",
#else
                "Registered_MiB=%llu Cache_MiB=%llu max_pinned_MiB=%llu ",
#endif
                    PCI_INFO_ARGS(nvfs_lookup_gpu_hash_index_entry(gpustat->gpu_index)),
                    gpustat->gpu_uuid[0], gpustat->gpu_uuid[1], gpustat->gpu_uuid[2], gpustat->gpu_uuid[3],
                    gpustat->gpu_uuid[4], gpustat->gpu_uuid[5], gpustat->gpu_uuid[6], gpustat->gpu_uuid[7],
                    gpustat->gpu_uuid[8], gpustat->gpu_uuid[9], gpustat->gpu_uuid[10], gpustat->gpu_uuid[11],
                    gpustat->gpu_uuid[12], gpustat->gpu_uuid[13], gpustat->gpu_uuid[14], gpustat->gpu_uuid[15],
                    BYTES_TO_MB(atomic64_read(&gpustat->active_bar_memory_pinned)),
                    BYTES_TO_MB(atomic64_read(&gpustat->active_bounce_buffer_memory)),
                    BYTES_TO_MB(atomic64_read(&gpustat->max_bar_memory_pinned)));

		// stats for cross traffic
		if (nvfs_peer_stats_enabled) {
		    seq_printf(m, "cross_root_port(%%)=%u\n", nvfs_aggregate_cross_peer_usage(gpustat->gpu_index));
		} else {
		    seq_printf(m, "\n");
		}
	}

	rcu_read_unlock();
}

/*
 * display the general statistics
 */
static int nvfs_stats_show(struct seq_file *m, void *v) {
#ifdef GDS_VERSION
#define GDS_STRING2(x) #x
#define GDS_STRING(x) GDS_STRING2(x)
    seq_printf(m, "GDS Version: %s \n", GDS_STRING(GDS_VERSION));
#undef GDS_STRING2
#undef GDS_STRING
#endif
        seq_printf(m, "NVFS statistics(ver: %d.0)\n", NVFS_STAT_VERSION);
	seq_printf(m, "NVFS Driver(version: %u.%u.%u)\n",
			nvfs_major_version(nvfs_driver_version()),
			nvfs_minor_version(nvfs_driver_version()),
			NVFS_DRIVER_PATCH_VERSION);
#ifdef GDS_DMABUF_SUPPORTED 
        seq_printf(m, "Mellanox PeerDirect Supported: %s\n", "True");
#else
        {
                struct path path;
                int ret = kern_path("/sys/kernel/mm/memory_peers/nv_mem/version", LOOKUP_FOLLOW, &path);
                if(ret)
                        seq_printf(m, "Mellanox PeerDirect Supported: %s\n", "False");
                else
                        seq_printf(m, "Mellanox PeerDirect Supported: %s\n", "True");
        }
#endif
        seq_printf(m, "IO stats: %s, peer IO stats: %s\n",
                   nvfs_rw_stats_enabled ? "Enabled" : "Disabled",
                   nvfs_peer_stats_enabled ? "Enabled" : "Disabled");

        seq_printf(m, "Logging level: %s\n\n",
                   (nvfs_dbg_enabled ? "debug" : (nvfs_info_enabled ? "info" : "warn")));

#ifdef HAVE_ATOMIC64_LONG
	seq_printf(m, "Active Shadow-Buffer (MiB): %lu\n",
#else
	seq_printf(m, "Active Shadow-Buffer (MiB): %llu\n",
#endif
	    BYTES_TO_MB(atomic64_read(&nvfs_n_active_shadow_buf_sz)));
	seq_printf(m, "Active Process: %u\n", atomic_read(&nvfs_n_op_process) / nvfs_get_device_count());


        if (nvfs_rw_stats_enabled) {
#ifdef HAVE_ATOMIC64_LONG
	seq_printf(m, "Batches				: n=%lu ok=%lu err=%u Avg-Submit-Latency(usec)=%u\n",
#else
	seq_printf(m, "Batches				: n=%llu ok=%llu err=%u Avg-Submit-Latency(usec)=%u\n",
#endif
	    atomic64_read(&nvfs_n_batches),
	    atomic64_read(&nvfs_n_batches_ok),
	    atomic_read(&nvfs_n_batch_err),
	    atomic_read(&nvfs_batch_submit_avg_latency));
        }
        if (nvfs_rw_stats_enabled) {
#ifdef HAVE_ATOMIC64_LONG
	seq_printf(m, "Reads				: n=%lu ok=%lu err=%u readMiB=%lu io_state_err=%u\n",
#else
	seq_printf(m, "Reads				: n=%llu ok=%llu err=%u readMiB=%llu io_state_err=%u\n",
#endif
	    atomic64_read(&nvfs_n_reads),
	    atomic64_read(&nvfs_n_reads_ok),
	    atomic_read(&nvfs_n_read_err),
	    BYTES_TO_MB(atomic64_read(&nvfs_n_read_bytes)),
	    atomic_read(&nvfs_n_read_iostate_err));

	seq_printf(m, "Reads				: Bandwidth(MiB/s)=%u Avg-Latency(usec)=%u\n",
	    atomic_read(&nvfs_read_throughput),
	    atomic_read(&nvfs_avg_read_latency));
        } else {
	seq_printf(m, "Reads				: err=%u io_state_err=%u\n",
	    atomic_read(&nvfs_n_read_err),
	    atomic_read(&nvfs_n_read_iostate_err));
        }

#ifdef HAVE_ATOMIC64_LONG
	seq_printf(m, "Sparse Reads		        : n=%lu io=%lu holes=%lu pages=%lu \n",
#else
	seq_printf(m, "Sparse Reads		        : n=%llu io=%llu holes=%llu pages=%llu \n",
#endif
	    atomic64_read(&nvfs_n_reads_sparse_files),
	    atomic64_read(&nvfs_n_reads_sparse_io),
	    atomic64_read(&nvfs_n_reads_sparse_region),
	    atomic64_read(&nvfs_n_reads_sparse_pages));

        if (nvfs_rw_stats_enabled) {
#ifdef HAVE_ATOMIC64_LONG
	seq_printf(m, "Writes				: n=%lu ok=%lu err=%u writeMiB=%lu io_state_err=%u pg-cache=%u pg-cache-fail=%u pg-cache-eio=%u\n",
#else
	seq_printf(m, "Writes				: n=%llu ok=%llu err=%u writeMiB=%llu io_state_err=%u pg-cache=%u pg-cache-fail=%u pg-cache-eio=%u\n",
#endif
	    atomic64_read(&nvfs_n_writes),
	    atomic64_read(&nvfs_n_writes_ok),
	    atomic_read(&nvfs_n_write_err),
	    BYTES_TO_MB(atomic64_read(&nvfs_n_write_bytes)),
	    atomic_read(&nvfs_n_write_iostate_err),
	    atomic_read(&nvfs_n_pg_cache),
	    atomic_read(&nvfs_n_pg_cache_fail),
	    atomic_read(&nvfs_n_pg_cache_eio));

	seq_printf(m, "Writes				: Bandwidth(MiB/s)=%u Avg-Latency(usec)=%u\n",
	    atomic_read(&nvfs_write_throughput),
	    atomic_read(&nvfs_avg_write_latency));
        } else {
	seq_printf(m, "Writes				: err=%u io_state_err=%u pg-cache=%u pg-cache-fail=%u pg-cache-eio=%u\n",
	    atomic_read(&nvfs_n_write_err),
	    atomic_read(&nvfs_n_write_iostate_err),
	    atomic_read(&nvfs_n_pg_cache),
	    atomic_read(&nvfs_n_pg_cache_fail),
	    atomic_read(&nvfs_n_pg_cache_eio));
        }

#ifdef HAVE_ATOMIC64_LONG
	seq_printf(m, "Mmap				: n=%lu ok=%lu err=%u munmap=%lu\n",
#else
	seq_printf(m, "Mmap				: n=%llu ok=%llu err=%u munmap=%llu\n",
#endif
	    atomic64_read(&nvfs_n_mmap),
	    atomic64_read(&nvfs_n_mmap_ok),
	    atomic_read(&nvfs_n_mmap_err),
	    atomic64_read(&nvfs_n_munmap));

#ifdef HAVE_ATOMIC64_LONG
	seq_printf(m, "Bar1-map			: n=%lu ok=%lu err=%u free=%lu callbacks=%u active=%u delay-frees=%lu\n",
#else
	seq_printf(m, "Bar1-map			: n=%llu ok=%llu err=%u free=%llu callbacks=%u active=%u delay-frees=%llu\n",
#endif
	    atomic64_read(&nvfs_n_maps),
	    atomic64_read(&nvfs_n_maps_ok),
	    atomic_read(&nvfs_n_map_err),
	    atomic64_read(&nvfs_n_free),
	    atomic_read(&nvfs_n_callbacks),
	    atomic_read(&nvfs_n_op_maps),
	    atomic64_read(&nvfs_n_delayed_frees));

	seq_printf(m, "Error				: cpu-gpu-pages=%u sg-ext=%u dma-map=%u dma-ref=%u\n",
		atomic_read(&nvfs_n_err_mix_cpu_gpu),
		atomic_read(&nvfs_n_err_sg_err),
		atomic_read(&nvfs_n_err_dma_map),
		atomic_read(&nvfs_n_err_dma_ref));

        seq_printf(m, "Ops				: Read=%u Write=%u BatchIO=%u\n",
	    atomic_read(&nvfs_n_op_reads),
	    atomic_read(&nvfs_n_op_writes),
	    atomic_read(&nvfs_n_op_batches));

	nvfs_print_gpuinfo(m);

	return 0;
}

/*
 * Description: resets any cumulative counters including errors;
 *              self managed counters are not reset
 * 
 */
static int nvfs_stats_reset(void) {

	nvfs_stat64_reset(&nvfs_n_reads);
	nvfs_stat64_reset(&nvfs_n_reads_ok);
	nvfs_stat_reset(&nvfs_n_read_err);
	nvfs_stat64_reset(&nvfs_n_read_bytes);
	nvfs_stat_reset(&nvfs_n_read_iostate_err);

	nvfs_stat_reset(&nvfs_read_throughput);
	nvfs_stat_reset(&nvfs_avg_read_latency);

	nvfs_stat64_reset(&nvfs_n_reads_sparse_files);
	nvfs_stat64_reset(&nvfs_n_reads_sparse_io);
	nvfs_stat64_reset(&nvfs_n_reads_sparse_region);
	nvfs_stat64_reset(&nvfs_n_reads_sparse_pages);

	nvfs_stat64_reset(&nvfs_n_writes);
	nvfs_stat64_reset(&nvfs_n_writes_ok);
	nvfs_stat_reset(&nvfs_n_write_err);
	nvfs_stat64_reset(&nvfs_n_write_bytes);
	nvfs_stat_reset(&nvfs_n_write_iostate_err);

	nvfs_stat_reset(&nvfs_write_throughput);
	nvfs_stat_reset(&nvfs_avg_write_latency);

	nvfs_stat64_reset(&nvfs_n_mmap);
	nvfs_stat64_reset(&nvfs_n_mmap_ok);
	nvfs_stat64_reset(&nvfs_n_munmap);

	nvfs_stat_reset(&nvfs_n_mmap_err);
	nvfs_stat_reset(&nvfs_n_err_mix_cpu_gpu);
	nvfs_stat_reset(&nvfs_n_err_sg_err);
	nvfs_stat_reset(&nvfs_n_err_dma_map);
	nvfs_stat_reset(&nvfs_n_err_dma_ref);

	nvfs_stat64_reset(&nvfs_n_maps);
	nvfs_stat64_reset(&nvfs_n_maps_ok);
	nvfs_stat_reset(&nvfs_n_map_err);
	nvfs_stat64_reset(&nvfs_n_free);
	nvfs_stat_reset(&nvfs_n_callbacks);
	nvfs_stat64_reset(&nvfs_n_delayed_frees);

	nvfs_stat64_reset(&nvfs_n_batches);
	nvfs_stat64_reset(&nvfs_n_batches_ok);
	nvfs_stat_reset(&nvfs_n_batch_err);
	nvfs_stat_reset(&nvfs_batch_submit_avg_latency);
	nvfs_stat_reset(&nvfs_batch_ops_per_sec);
	nvfs_stat_reset(&nvfs_n_op_batches);

	nvfs_stat_reset(&nvfs_read_ops_per_sec);
	nvfs_stat_reset(&nvfs_write_ops_per_sec);

	nvfs_stat64_reset(&nvfs_read_latency_per_sec);
	nvfs_stat64_reset(&nvfs_write_latency_per_sec);

	nvfs_stat_reset(&nvfs_n_pg_cache);
	nvfs_stat_reset(&nvfs_n_pg_cache_fail);
	nvfs_stat_reset(&nvfs_n_pg_cache_eio);

        nvfs_reset_gpuinfo_stats();
	nvfs_reset_peer_affinity_stats();
	return 0;
}

static struct nvfs_gpu_stat *nvfs_get_gpustat_unlocked(uint64_t gpu_uuid_hash)
{
	struct nvfs_gpu_stat *gpustat;

	hash_for_each_possible_rcu(nvfs_gpu_stat_hash, gpustat, hash_link, gpu_uuid_hash)
	{
		if (*(uint64_t *)gpustat->gpu_uuid == gpu_uuid_hash) {
			return gpustat;
		}
	}

	return NULL; 
}

void nvfs_update_free_gpustat(struct nvfs_gpu_args *gpuinfo) {
	struct nvfs_gpu_stat *gpustat;
	uint64_t gpu_uuid_hash;

	if (gpuinfo->page_table == NULL || gpuinfo->page_table->gpu_uuid == NULL)
		return;

	rcu_read_lock();
	gpu_uuid_hash = *(uint64_t *)gpuinfo->page_table->gpu_uuid;
	gpustat = nvfs_get_gpustat_unlocked(gpu_uuid_hash);
	rcu_read_unlock();

	BUG_ON(gpustat == NULL);

	if (gpuinfo->is_bounce_buffer) {
		nvfs_stat64_sub(gpuinfo->gpu_buf_len, &(gpustat->active_bounce_buffer_memory));
	} else {
		nvfs_stat64_sub(gpuinfo->gpu_buf_len, &(gpustat->active_bar_memory_pinned));
	}
}

void nvfs_update_alloc_gpustat(struct nvfs_gpu_args *gpuinfo) {
	struct nvfs_gpu_stat *gpustat;
	uint64_t gpu_uuid_hash;
	uint64_t active_memory;

	if (gpuinfo->page_table == NULL || gpuinfo->page_table->gpu_uuid == NULL)
		return;

	gpu_uuid_hash = *(uint64_t *)gpuinfo->page_table->gpu_uuid;
	spin_lock(&lock);
	gpustat = nvfs_get_gpustat_unlocked(gpu_uuid_hash);	
	if (gpustat == NULL) {
		gpustat = kzalloc(sizeof(struct nvfs_gpu_stat), GFP_KERNEL);
		if (!gpustat) {
			nvfs_err("Failed to allocated memory\n");
			spin_unlock(&lock);
			return;
		}
		atomic64_set(&gpustat->max_bar_memory_pinned, 0);
		memcpy(gpustat->gpu_uuid, gpuinfo->page_table->gpu_uuid, 16);
		hash_add_rcu(nvfs_gpu_stat_hash, &gpustat->hash_link, gpu_uuid_hash);
		gpustat->gpu_index = gpuinfo->gpu_hash_index;
	}

	spin_unlock(&lock);
	
	if (gpuinfo->is_bounce_buffer) {
		nvfs_stat64_add(gpuinfo->gpu_buf_len, &(gpustat->active_bounce_buffer_memory));
	} else {
		nvfs_stat64_add(gpuinfo->gpu_buf_len, &(gpustat->active_bar_memory_pinned));
	}

	active_memory = atomic64_read(&(gpustat->active_bar_memory_pinned));
	if (active_memory > atomic64_read(&gpustat->max_bar_memory_pinned))
		atomic64_set(&gpustat->max_bar_memory_pinned, active_memory);
}

void nvfs_update_read_throughput(unsigned long total_bytes,
                                atomic64_t *stat)
{
        int delta;
        int throughput;

        if (atomic_read(&prev_read_throughput) == 0) {
                atomic_set(&prev_read_throughput, ktime_to_ms(ktime_get()));
                nvfs_stat64_add(total_bytes, stat);
                return;
        }

        delta = ktime_to_ms(ktime_get()) - atomic_read(&prev_read_throughput);

        if (delta > MSEC_PER_SEC) {
                nvfs_stat64_add(total_bytes, stat);
                throughput = (BYTES_TO_MB(atomic64_read(stat)) /
                                (delta / MSEC_PER_SEC));
                atomic_set(&nvfs_read_throughput, throughput);
                nvfs_stat64_reset(stat);
                atomic_set(&prev_read_throughput, ktime_to_ms(ktime_get()));
        } else {
                nvfs_stat64_add(total_bytes, stat);
        }
}

void nvfs_update_read_latency(unsigned long avg_latency,
                                atomic64_t *stat)
{
        int delta;
        int average_latency;

        if (atomic64_read(&prev_read_latency) == 0) {
                atomic64_set(&prev_read_latency, ktime_to_us(ktime_get()));
                nvfs_stat(&nvfs_read_ops_per_sec);
                nvfs_stat64_add(avg_latency, stat);
                return;
        }

        delta = ktime_to_us(ktime_get()) - atomic64_read(&prev_read_latency);

        if (delta > USEC_PER_SEC) {
                nvfs_stat64_add(avg_latency, stat);
                nvfs_stat(&nvfs_read_ops_per_sec);

                average_latency = div64_safe(atomic64_read(stat),
                                        (long)atomic_read(&nvfs_read_ops_per_sec));
                atomic_set(&nvfs_avg_read_latency, average_latency);
                nvfs_stat64_reset(stat);
                nvfs_stat_reset(&nvfs_read_ops_per_sec);

                atomic64_set(&prev_read_latency, ktime_to_us(ktime_get()));
        } else {
                nvfs_stat64_add(avg_latency, stat);
                nvfs_stat(&nvfs_read_ops_per_sec);
        }
}

void nvfs_update_batch_latency(unsigned long avg_latency,
                                atomic64_t *stat)
{
        int delta;
        int average_latency;

        if (atomic64_read(&prev_batch_submit_avg_latency) == 0) {
                atomic64_set(&prev_batch_submit_avg_latency, ktime_to_us(ktime_get()));
                nvfs_stat(&nvfs_batch_ops_per_sec);
                nvfs_stat64_add(avg_latency, stat);
                return;
        }

        delta = ktime_to_us(ktime_get()) - atomic64_read(&prev_batch_submit_avg_latency);

        if (delta > USEC_PER_SEC) {
                nvfs_stat64_add(avg_latency, stat);
                nvfs_stat(&nvfs_batch_ops_per_sec);

                average_latency = div64_safe(atomic64_read(stat),
                                        (unsigned long) atomic_read(&nvfs_batch_ops_per_sec));
                atomic_set(&nvfs_batch_submit_avg_latency, average_latency);
                nvfs_stat64_reset(stat);
                nvfs_stat_reset(&nvfs_batch_ops_per_sec);

                atomic64_set(&prev_batch_submit_avg_latency, ktime_to_us(ktime_get()));
        } else {
                nvfs_stat64_add(avg_latency, stat);
                nvfs_stat(&nvfs_batch_ops_per_sec);
        }
}


void nvfs_update_write_latency(unsigned long avg_latency,
                                atomic64_t *stat)
{
        int delta;
        int average_latency;

        if (atomic64_read(&prev_write_latency) == 0) {
                atomic64_set(&prev_write_latency, ktime_to_us(ktime_get()));
                nvfs_stat(&nvfs_write_ops_per_sec);
                nvfs_stat64_add(avg_latency, stat);
                return;
        }

        delta = ktime_to_us(ktime_get()) - atomic64_read(&prev_write_latency);

        if (delta > USEC_PER_SEC) {
                nvfs_stat64_add(avg_latency, stat);
                nvfs_stat(&nvfs_write_ops_per_sec);

                average_latency = div64_safe(atomic64_read(stat),
                                        (unsigned long) atomic_read(&nvfs_write_ops_per_sec));
                atomic_set(&nvfs_avg_write_latency, average_latency);
                nvfs_stat64_reset(stat);
                nvfs_stat_reset(&nvfs_write_ops_per_sec);

                atomic64_set(&prev_write_latency, ktime_to_us(ktime_get()));
        } else {
                nvfs_stat64_add(avg_latency, stat);
                nvfs_stat(&nvfs_write_ops_per_sec);
        }
}

void nvfs_update_write_throughput(unsigned long total_bytes,
                                atomic64_t *stat)
{
        int delta;
        int throughput;

        if (atomic_read(&prev_write_throughput) == 0) {
                atomic_set(&prev_write_throughput, ktime_to_ms(ktime_get()));
                nvfs_stat64_add(total_bytes, stat);
                return;
        }

        delta = ktime_to_ms(ktime_get()) - atomic_read(&prev_write_throughput);

        if (delta > MSEC_PER_SEC) {
                nvfs_stat64_add(total_bytes, stat);
                throughput = (BYTES_TO_MB(atomic64_read(stat)) /
                                (delta / MSEC_PER_SEC));
                atomic_set(&nvfs_write_throughput, throughput);
                nvfs_stat64_reset(stat);
                atomic_set(&prev_write_throughput, ktime_to_ms(ktime_get()));
        } else {
                nvfs_stat64_add(total_bytes, stat);
        }
}

void nvfs_stat_init() {
        spin_lock_init(&lock);
        hash_init(nvfs_gpu_stat_hash);
}

void nvfs_stat_destroy() {
	struct hlist_node *tmp;
	struct nvfs_gpu_stat *gpustat;
	int bkt = 0;

	hash_for_each_safe(nvfs_gpu_stat_hash, bkt, tmp, gpustat, hash_link) {
		hash_del(&gpustat->hash_link);
		kfree(gpustat);
	}
}

/*
 * open "/proc/fs/nvfs/stats" allowing provision of a statistical summary
 */
static int nvfs_stats_open(struct inode *inode, struct file *file)
{
        return single_open(file, nvfs_stats_show, NULL);
}

/*
 * echo <xxx> > /proc/fs/nvfs/stats clears all stats
 */
static ssize_t nvfs_stats_clear(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	nvfs_stats_reset();
	return (ssize_t) size;
}

#ifdef HAVE_STRUCT_PROC_OPS
const struct proc_ops nvfs_stats_fops = {
        .proc_open  	= nvfs_stats_open,
        .proc_read     	= seq_read,
        .proc_write    	= nvfs_stats_clear,
        .proc_lseek    	= seq_lseek,
        .proc_release	= single_release,
};
#else
const struct file_operations nvfs_stats_fops = {
        .open           = nvfs_stats_open,
        .read           = seq_read,
        .write          = nvfs_stats_clear,
        .llseek         = seq_lseek,
        .release        = single_release,
};
#endif
