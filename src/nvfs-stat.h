/* Stats for NVFS 
 *
 * Copyright (C) 2021 Nvidia, Corp. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef NVFS_STAT_H
#define NVFS_STAT_H

#include "config-host.h"

#include <linux/ktime.h>
#include <linux/version.h>
#include <linux/namei.h>

#define NVFS_STAT_VERSION		4
#define BYTES_TO_MB(b) ((b) >> 20ULL)
#define NVFS_MAX_GPU		16
#define NVFS_MAX_GPU_BITS	ilog2(NVFS_MAX_GPU)

static inline unsigned long div64_safe(unsigned long sum, unsigned long nr)
{
	return nr ? div64_ul(sum, nr) : 0;
}

static inline u64 jiffies_now(void)
{
	return get_jiffies_64();
}

static inline s64 ktime_ns_delta(const ktime_t later, const ktime_t earlier)
{
    return ktime_to_ns(ktime_sub(later, earlier));
}

#ifdef CONFIG_NVFS_STATS

struct nvfs_gpu_stat {
	uint8_t gpu_uuid[16];
	struct hlist_node hash_link;
	atomic64_t active_bar_memory_pinned;
	atomic64_t active_bounce_buffer_memory;
	atomic64_t max_bar_memory_pinned;
	unsigned int gpu_index; // gpu index for pci rank looups
};

extern atomic_t prev_read_throughput;
extern atomic_t prev_write_throughput;

extern atomic64_t prev_read_latency;
extern atomic64_t prev_write_latency;
extern atomic64_t prev_batch_avg_latency;

/*
 * Operation counters - Declaration 
 */

extern atomic64_t nvfs_n_reads;
extern atomic64_t nvfs_n_reads_ok;
extern atomic_t nvfs_n_read_err;
extern atomic_t nvfs_n_read_iostate_err;
extern atomic64_t nvfs_n_read_bytes;
extern atomic_t nvfs_read_throughput;
extern atomic64_t nvfs_read_bytes_per_sec;
extern atomic_t nvfs_read_ops_per_sec;
extern atomic64_t nvfs_read_latency_per_sec;
extern atomic_t nvfs_avg_read_latency;

extern atomic64_t nvfs_n_batches;
extern atomic64_t nvfs_n_batches_ok;
extern atomic_t nvfs_n_batch_err;

extern atomic64_t nvfs_n_reads_sparse_files;
extern atomic64_t nvfs_n_reads_sparse_io;
extern atomic64_t nvfs_n_reads_sparse_region;
extern atomic64_t nvfs_n_reads_sparse_pages;

extern atomic64_t nvfs_n_writes;
extern atomic64_t nvfs_n_writes_ok;
extern atomic_t nvfs_n_write_err;
extern atomic_t nvfs_n_write_iostate_err;
extern atomic64_t nvfs_n_write_bytes;
extern atomic_t nvfs_write_throughput;
extern atomic64_t nvfs_write_bytes_per_sec;
extern atomic_t nvfs_write_ops_per_sec;
extern atomic64_t nvfs_write_latency_per_sec;
extern atomic_t nvfs_avg_write_latency;

extern atomic_t nvfs_batch_ops_per_sec;
extern atomic64_t nvfs_batch_submit_latency_per_sec;
extern atomic_t nvfs_batch_submit_avg_latency;

extern atomic64_t nvfs_n_mmap;
extern atomic64_t nvfs_n_mmap_ok;
extern atomic_t nvfs_n_mmap_err;
extern atomic64_t nvfs_n_munmap;

extern atomic64_t nvfs_n_maps;
extern atomic64_t nvfs_n_maps_ok;
extern atomic_t nvfs_n_map_err;
extern atomic64_t nvfs_n_free;
extern atomic_t nvfs_n_callbacks;
extern atomic64_t nvfs_n_delayed_frees;

extern atomic64_t nvfs_n_active_shadow_buf_sz;
extern atomic_t nvfs_n_op_reads;
extern atomic_t nvfs_n_op_writes;
extern atomic_t nvfs_n_op_maps;
extern atomic_t nvfs_n_op_process;
extern atomic_t nvfs_n_op_batches;

extern atomic_t nvfs_n_err_mix_cpu_gpu;
extern atomic_t nvfs_n_err_sg_err;
extern atomic_t nvfs_n_err_dma_map;
extern atomic_t nvfs_n_err_dma_ref;

extern atomic_t nvfs_n_pg_cache;
extern atomic_t nvfs_n_pg_cache_fail;
extern atomic_t nvfs_n_pg_cache_eio;

#ifdef HAVE_STRUCT_PROC_OPS
extern const struct proc_ops nvfs_stats_fops;
#else
extern const struct file_operations nvfs_stats_fops;
#endif

static inline void nvfs_stat(atomic_t *stat)
{
        atomic_inc(stat);
}

static inline void nvfs_stat_d(atomic_t *stat)
{
	#ifdef CONFIG_NVFS_DEBUG_STATS
	if (unlikely(atomic_sub_return(1L, stat) < 0)) {
		pr_err("encountered -ve stat :%d\n", atomic_read(stat)); 
		WARN_ON_ONCE(1);
	}
	#else
		atomic_dec(stat);
	#endif
}

static inline void nvfs_stat64_reset(atomic64_t *stat)
{
	atomic64_set(stat, 0);
}

static inline void nvfs_stat_reset(atomic_t *stat)
{
	atomic_set(stat, 0);
}

static inline void nvfs_stat64(atomic64_t *stat)
{
        atomic64_inc(stat);
}

static inline void nvfs_stat64_d(atomic64_t *stat)
{
	#ifdef CONFIG_NVFS_DEBUG_STATS
	if (unlikely(atomic64_sub_return(1LL, stat) < 0)) {
#if LINUX_VERSION_CODE <  KERNEL_VERSION(5,0,0)
		pr_err("encountered -ve stat :%ld\n", atomic64_read(stat)); 
#else
		pr_err("encountered -ve stat :%lld\n", atomic64_read(stat)); 
#endif
		WARN_ON_ONCE(1);
	}
	#else
		atomic64_dec(stat);
	#endif
}

static inline void nvfs_stat64_add(long i, atomic64_t *stat)
{
        atomic64_add(i, stat);
}

static inline void nvfs_stat64_sub(long i, atomic64_t *stat)
{
        atomic64_sub(i, stat);
}

static inline s64 nvfs_stat64_read(atomic64_t *stat)
{
	return atomic64_read(stat);
}

static inline void nvfs_stat64_jiffies(unsigned long *now)
{
	*now = jiffies_now();
}

static inline u64 nvfs_stat64_jiffies2usec(atomic64_t *stat)
{
	return jiffies64_to_nsecs(atomic64_read(stat))/1000UL;
}

static inline void nvfs_stat64_ktime(ktime_t *now)
{
        *now = ktime_get();
}

void nvfs_update_read_throughput(unsigned long total_bytes,
				atomic64_t *stat);

void nvfs_update_read_latency(unsigned long avg_latency,
                                atomic64_t *stat);

void nvfs_update_write_latency(unsigned long avg_latency,
                                atomic64_t *stat);

void nvfs_update_batch_latency(unsigned long avg_latency,
                                atomic64_t *stat);
void nvfs_update_write_throughput(unsigned long total_bytes,
                                atomic64_t *stat);

struct nvfs_gpu_args;
void nvfs_update_free_gpustat(struct nvfs_gpu_args *gpuinfo);
void nvfs_update_alloc_gpustat(struct nvfs_gpu_args *gpuinfo);
void nvfs_stat_init(void);
void nvfs_stat_destroy(void);

#define INITIALIZE_STATS_CONFIG(value, newvalue) \
 (value) = (newvalue)

#else
#define nvfs_stat(stat) do {} while (0)
#define nvfs_stat_d(stat) do {} while (0)
#define nvfs_stat64_reset(stat) do {} while (0)
#define nvfs_stat_reset(stat) do {} while (0)
#define nvfs_stat64(stat) do {} while (0)
#define nvfs_stat64_d(stat) do {} while (0)
#define nvfs_stat64_add(x, stat) do {} while (0)
#define nvfs_stat64_sub(x, stat) do {} while (0)
#define nvfs_stat64_read(stat) 0LL
#define nvfs_stat64_jiffies(stat) do {} while (0)
#define nvfs_stat64_jiffies2usec(stat) 0
#define nvfs_stat64_ktime(stat) do {} while (0)
#define nvfs_update_write_throughput(x, stat) do {} while (0)
#define nvfs_update_write_latency(x, stat) do {} while (0)
#define nvfs_update_read_latency(x, stat) do {} while (0)
#define nvfs_update_read_throughput(x, stat) do {} while (0)
#define nvfs_update_free_gpustat(x) do {} while (0)
#define nvfs_update_alloc_gpustat(x) do {} while (0)
#define nvfs_stat_init() do {} while (0)
#define nvfs_stat_destroy() do {} while (0)
#define INITIALIZE_STATS_CONFIG(value, newvalue) do {} while (0)

#define nvfs_update_write_throughput(x, stat) do {} while (0)
#define nvfs_update_write_latency(x, stat) do {} while (0)
#define nvfs_update_read_latency(x, stat)  do {} while (0)
#define nvfs_update_read_throughput(x, stat) do {} while (0)

#endif /* CONFIG_NVFS_STATS */

#endif /* NVFS_STATS_H */
