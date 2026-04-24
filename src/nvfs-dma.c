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
#include <linux/dma-mapping.h>
#include <linux/percpu.h>
#include <linux/string.h>

#include "nvfs-core.h"
#include "nvfs-stat.h"
#include "nvfs-mmap.h"
#include "nvfs-dma.h"
#include "nvfs-kernel-interface.h"
#include "config-host.h"

/*
 * This should be inline with kernel 5.3 nvme drivers. See driver/nvme/host/pci.c
 */
#define NVME_MAX_SEGS	127

//#define CONFIG_DEBUG_NVFS_BLK

//#define TEST_RQ_MIXED

#define CHECK_AND_PUT_MGROUP(nvfs_mgroup) \
	do { \
		if ((nvfs_mgroup) != NULL)  { \
			nvfs_mgroup_put((nvfs_mgroup)); \
		} \
	} while (0);

//forward declaration
struct nvfs_dma_rw_ops nvfs_dev_dma_rw_ops;
struct nvfs_dma_rw_ops nvfs_nvme_dma_rw_ops;
struct nvfs_dma_rw_ops nvfs_sfxv_dma_rw_ops;
struct nvfs_dma_rw_ops nvfs_nvmesh_dma_rw_ops;
struct nvfs_dma_rw_ops nvfs_ibm_scale_rdma_ops;
#ifdef HAVE_BLK_RQ_DMA_MAP_ITER_START
struct nvfs_dma_rw_blk_iter_ops nvfs_nvme_dma_rw_blk_iter_ops;
#endif
// nvfs symbol table
struct module_entry modules_list[] = {
	{
		1,
		0,
		NVFS_PROC_MOD_NVME_KEY,
		0,
#ifdef HAVE_BLK_RQ_DMA_MAP_ITER_START
		"nvme_v2_register_nvfs_dma_ops",
#else
		"nvme_v1_register_nvfs_dma_ops",
#endif
		0,
#ifdef HAVE_BLK_RQ_DMA_MAP_ITER_START
		"nvme_v2_unregister_nvfs_dma_ops",
#else
		"nvme_v1_unregister_nvfs_dma_ops",
#endif
		0,
#ifdef HAVE_BLK_RQ_DMA_MAP_ITER_START
		&nvfs_nvme_dma_rw_blk_iter_ops
#else
		&nvfs_nvme_dma_rw_ops
#endif
	},

	{
		1,
		0,
		NVFS_PROC_MOD_NVME_RDMA_KEY,
		0,
		"nvme_rdma_v1_register_nvfs_dma_ops",
		0,
		"nvme_rdma_v1_unregister_nvfs_dma_ops",
		0,
		&nvfs_nvme_dma_rw_ops
	},
	
	{
		1,
		0,
		NVFS_PROC_MOD_SCALEFLUX_CSD_KEY,
		0,
		"sfxv_v1_register_nvfs_dma_ops",
		0,
		"sfxv_v1_unregister_nvfs_dma_ops",
		0,
		&nvfs_sfxv_dma_rw_ops
	},
	
	{
		1,
		0,
		NVFS_PROC_MOD_NVMESH_KEY,
		0,
		"nvmesh_v1_register_nvfs_dma_ops",
		0,
		"nvmesh_v1_unregister_nvfs_dma_ops",
		0,
		&nvfs_nvmesh_dma_rw_ops
	},


	{
		1,
		0,
		NVFS_PROC_MOD_DDN_LUSTRE_KEY,
		0,
		"lustre_v1_register_nvfs_dma_ops",
		0,
		"lustre_v1_unregister_nvfs_dma_ops",
		0,
		&nvfs_dev_dma_rw_ops
	},
	{
		1,
		0,
		NVFS_PROC_MOD_NTAP_BEEGFS_KEY,
		0,
		"beegfs_v1_register_nvfs_dma_ops",
		0,
		"beegfs_v1_unregister_nvfs_dma_ops",
		0,
		&nvfs_dev_dma_rw_ops
	},

	{
		1,
		1,
		"wekafsio",
		"1",
		NULL,
		0,
		NULL,
		0,
	        NULL
	},
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT	
	{
		1,
		0,
		NVFS_PROC_MOD_GPFS_KEY,
		0,
		"ibm_scale_v1_register_nvfs_dma_ops",
		0,
		"ibm_scale_v1_unregister_nvfs_dma_ops",
		0,
		&nvfs_ibm_scale_rdma_ops
	},
#endif

	{
		1,
		0,
		NVFS_PROC_MOD_NFS_KEY,
		0,
		"rpcrdma_register_nvfs_dma_ops",
		0,
		"rpcrdma_unregister_nvfs_dma_ops",
		0,
		&nvfs_dev_dma_rw_ops
	},
	
	{
		1,
		0,
		NVFS_PROC_MOD_SCATEFS_KEY,
		0,
		"scatefs_register_nvfs_dma_ops",
		0,
		"scatefs_unregister_nvfs_dma_ops",
		0,
		&nvfs_dev_dma_rw_ops
	},

	{
		0,
		0,
		"scsi_mod", // not a module
		"0",
		"scsi_v1_register_dma_scsi_ops",
		0,
		"scsi_v1_unregister_dma_scsi_ops",
		0,
		&nvfs_dev_dma_rw_ops
	}
};

int nr_modules(void) {
	return sizeof(modules_list)/sizeof(modules_list[0]);
}

/*
 *  debugging helper
 */
#ifdef CONFIG_DEBUG_NVFS_BLK
static void nvfs_print_sglist(struct scatterlist *sglist, int nsegs, struct request *req)
{
	int i = 0, nents = sg_nents(sglist);
        struct scatterlist *sg = NULL;

	pr_info("current sglist info :%u/%u\n", nsegs, nents);

#ifdef HAVE_BLK_RQ_PAYLOAD_BYTES
	for_each_sg(sglist, sg, nents, i)
		pr_info("sg entry :[%d]0x%llx/%u/%u\n", i, (unsigned long long)sg_page(sg),
			sg->length, blk_rq_payload_bytes(req));
#endif

}
#endif

/*
 *  reset sglist entries
 */
static void nvfs_clear_sglist_page(struct scatterlist *sglist)
{
	int i = 0, nents = sg_nents(sglist);
        struct scatterlist *sg;
	for_each_sg(sglist, sg, nents, i)
                sg_set_page(sg, 0, 0, 0); // takes care of marks
}

/*
 * fast path check if blk request can be processed by us
 */
static inline bool nvfs_blk_rq_check(struct request *req) {
	if (unlikely(!req || !req->q || !req->bio))
		return false;

	// discards or copied pages
	// We do not expect gpu request to be mingled with such requests
	#ifdef HAVE_RQF_COPY_USER
	if (unlikely((req->rq_flags & RQF_SPECIAL_PAYLOAD) || (req->rq_flags & RQF_COPY_USER)))
		return false;
	#endif

        // 1. different request types are not merged
	// 2. only interested in read-write request
        if ((req_op(req) != REQ_OP_WRITE) && (req_op(req) != REQ_OP_READ))
                return false;

	// allowing integrity req, here our request may come with it
	return true;
}

static inline bool nvfs_req_payload_supported(struct request *req)
{
#ifdef HAVE_BLK_RQ_PAYLOAD_BYTES
	if (blk_rq_payload_bytes(req) > (NVME_MAX_SEGS * GPU_PAGE_SIZE))
		return false;
#else
	return false;
#endif
	return true;
}

static inline bool nvfs_is_request_valid(bool *found_gpu_page, bool *found_cpu_page,
						bool *curr_page_gpu)
{
	if (*curr_page_gpu)
		*found_gpu_page = true;
	else
		*found_cpu_page = true;

	if (*found_cpu_page && *found_gpu_page)
		return false;

	return true;
}

static inline bool is_gpu_page_contiguous(uint64_t prev_phys_addr, uint64_t curr_phys_addr)
{
	return ((prev_phys_addr + PAGE_SIZE) == curr_phys_addr);
}


/**
 * nvfs_nvme_blk_rq_map_sg - Map a request to scatter/gather list
 * @q: request queue
 * @req: The request
 * @sglist: The array of scatter/gather entries
 * @returns number of sg entries set up for if req has GPU pages or 0 if no
 * GPU pages
 * Notes: caller must make sure sg can hold rq->nr_phys_segments entries,
 *        otherwise NVFS_IO_ERR
 */
static int nvfs_blk_rq_map_sg_internal(struct request_queue *q,
                              struct request *req,
                              struct scatterlist *iod_sglist,
			      bool nvme)
{
        int nsegs = 0;
        bool found_cpu_page = false, found_gpu_page = false;
        bool curr_page_gpu = false;
        struct req_iterator iter;
        struct scatterlist *sg = NULL;
        struct bio_vec bvec;
	uint64_t curr_phys_addr = 0, prev_phys_addr = 0;
        unsigned long gpu_page_index = 0;
        pgoff_t pgoff = 0;


#ifdef TEST_DISCONTIG_ADDR
	int key;
	int index = 0, j;

	key = nvfs_get_simulated_key_index();
	for (j = 0; j < 2; j++) {
#endif

	if (!nvfs_blk_rq_check(req))
		return 0;

	if (!iod_sglist) {
		nvfs_err("bad sglist parameter\n");
		return NVFS_IO_ERR;
	}

	rq_for_each_segment(bvec, req, iter) {
		#ifdef TEST_RQ_MIXED
		curr_page_gpu = ((page_index(bvec.bv_page) % 2) == 0);
		#else
		nvfs_mgroup_ptr_t nvfs_mgroup;

		nvfs_mgroup = nvfs_mgroup_from_page(bvec.bv_page); // ref dropped using CHECK_AND_PUT_MGROUP
		if (unlikely(IS_ERR(nvfs_mgroup))) {
			nvfs_err("%s:%d mgroup_get_page error\n", __func__, __LINE__);
			return NVFS_IO_ERR;
		}

		curr_page_gpu = (nvfs_mgroup != NULL);
		if (nvfs_mgroup != NULL) {
			if (nvfs_mgroup_metadata_set_dma_state(bvec.bv_page, nvfs_mgroup, bvec.bv_len, bvec.bv_offset) != 0) {
				nvfs_err("%s:%d mgroup_set_dma error\n", __func__, __LINE__);
				return NVFS_IO_ERR;
			}
		}
		#endif

		/*
		 * If we find a request with a mix of CPU and GPU page, we will return error.
		 */
		if (unlikely(!nvfs_is_request_valid(&found_gpu_page, &found_cpu_page, &curr_page_gpu))) {
			nvfs_clear_sglist_page(iod_sglist);
			nvfs_stat(&nvfs_n_err_mix_cpu_gpu);
			CHECK_AND_PUT_MGROUP(nvfs_mgroup);
			nvfs_err("%s:%d cannot handle mixed segments(cpu/gpu) in blkrq\n",
				__func__, __LINE__);
			return NVFS_IO_ERR;
		}

		/*
		 * If we find a CPU page, just move on. We are not responsible for creating sg entries for CPU I/O.
		 * Moreover, since we found a CPU page, we are already in the path of either returning error
		 * if the next set of pages found are GPU or we will return 0, if all pages in the request
		 * are CPU pages. Hence, in both the cases, we don't care about creating SG entries as we are serving IO's.
		 */
		if (found_cpu_page) {
			CHECK_AND_PUT_MGROUP(nvfs_mgroup);
			continue;
		}

		// First GPU page
		if (nsegs == 0) {
			if (unlikely(blk_integrity_rq(req))) {
				CHECK_AND_PUT_MGROUP(nvfs_mgroup);
				nvfs_err("%s:%d cannot handle gpu request with integrity metadata\n",
						__func__, __LINE__);
				return NVFS_IO_ERR;
			}

			/* We cannot support payload greater than 127 * 64k = 8323072 bytes. The 127 magic number
			 * comes from NVMe driver. On 5.0 kernel onwards, SG allocation
			 * in the NVMe driver can support upto 127 segments using mempool(see driver/nvme/host/pci.c). This
			 * means that we can have at most 127 sg entries. We merge segments if the two
			 * GPU physical pages are contiguous. Each GPU page size is 64K. In a worst case,
			 * we can have 127 GPU segments which are not contiguous. Hence, we can have at most
			 * 127 * 64k of payload.
			 *
			 * On 4.15 kernels, SG allocation is done based on number of phsical segments (blk_nq_nr_phys_segments).
			 * If we find that number of segments to be created is more than than blk_nq_nr_phys_segments,
			 * we will return the error. See nvfs_extend_sg_markers.
			 */
			if (unlikely(!nvfs_req_payload_supported(req))) {
				CHECK_AND_PUT_MGROUP(nvfs_mgroup);
				return NVFS_IO_ERR;
			}

#ifdef HAVE_DMA_DRAIN_IN_REQUEST_QUEUE
			if (unlikely(q->dma_drain_size && q->dma_drain_needed(req))) {
				CHECK_AND_PUT_MGROUP(nvfs_mgroup);
				nvfs_err("%s:%d cannot handle blk queue with drain segments\n",
						__func__, __LINE__);
				return NVFS_IO_ERR;
			}
#endif

		}

		/*
		 * We don't check queue max segment size for NVMe drives as devices with virt boundary fundamentally don't
		 * use segments. This is mostly for SCSI based subsystem where we may have to honor the drives segment size
		 */
		if (!nvme && (sg != NULL)) {
			// check queue segment limits
			if ((sg->length + bvec.bv_len) > queue_max_segment_size(q)) {
				curr_phys_addr = nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup,
						bvec.bv_page);
				CHECK_AND_PUT_MGROUP(nvfs_mgroup);
				nvfs_mgroup = NULL;
				goto new_segment;
			}
		}

		/*
		 * Keep coalescing the pages if the GPU Physical addresses are contiguous. If not, create a new segment
		 */

#ifdef TEST_DISCONTIG_ADDR
		if (j == 0) {
			curr_phys_addr = nvfs_get_simulated_address(key, index);
			index += 1;
		} else {
			curr_phys_addr = nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup, bvec.bv_page);
		}
#else
		curr_phys_addr = nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup, bvec.bv_page);
#endif
                nvfs_mgroup_get_gpu_index_and_off(nvfs_mgroup, bvec.bv_page, &gpu_page_index, &pgoff);
		// we no longer need nvfs_mgroup from this point onwards
		CHECK_AND_PUT_MGROUP(nvfs_mgroup);
		nvfs_mgroup = NULL;

		if (sg != NULL) {
			if (prev_phys_addr && is_gpu_page_contiguous(prev_phys_addr, curr_phys_addr)) {
                                //DONT allow merge at (4G - 64K) to handle possible discontiguous IOVA
                                // by SMMU
                                if((gpu_page_index == 0) ||
                                    (gpu_page_index % NVFS_P2P_MAX_CONTIG_GPU_PAGES != 0)) {
                                        sg->length += bvec.bv_len;
                                        prev_phys_addr = curr_phys_addr;
                                        continue;
                                }
                        }
		}

new_segment:
		nsegs++;

		if (nsegs == 1) {
			sg = iod_sglist;
		}
		else if (!sg_is_last(sg)) {
			sg = sg_next(sg);
		} else {
			// See above for the reason for extending markers.
			if ((nsegs >= NVME_MAX_SEGS) || (nvfs_extend_sg_markers(&sg))) {
				nvfs_stat(&nvfs_n_err_sg_err);
				nvfs_err("no space for entries in sglist (nsegs=%u/nr_phys=%u/found_gpu=%d)\n",
						nsegs, blk_rq_nr_phys_segments(req), found_gpu_page);
				return NVFS_IO_ERR;
			}
		}
		sg_set_page(sg, bvec.bv_page, bvec.bv_len, bvec.bv_offset);
		prev_phys_addr = curr_phys_addr;
	}
#ifdef TEST_DISCONTIG_ADDR
	if (j == 0) {
		//Reset for next iteration
		nvfs_clear_sglist_page(iod_sglist);
		nsegs = 0, found_cpu_page = false, found_gpu_page = false;
		curr_phys_addr = 0, prev_phys_addr = 0;
	}
}
#endif

	if (found_gpu_page) {
		sg_mark_end(sg); // marker for cases where alloted is more than used
                if(nsegs > blk_rq_nr_phys_segments(req)) {
                        req->nr_phys_segments = nsegs;
                }
		#ifdef CONFIG_DEBUG_NVFS_BLK
		nvfs_print_sglist(iod_sglist, nsegs, req);
		nvfs_dbg("detected gpu page\n");
		#endif
		return nsegs;
	} else {
        	// if all are host pages, we want to fall back to regular non-nvfs path
		#ifdef CONFIG_DEBUG_NVFS_BLK
		nvfs_dbg("detected cpu page\n");
		#endif
		return 0;
	}
}

static int nvfs_blk_rq_map_sg(struct request_queue *q,
                              struct request *req,
                              struct scatterlist *iod_sglist)
{
	return nvfs_blk_rq_map_sg_internal(q, req, iod_sglist, false);
}

static int nvfs_nvme_blk_rq_map_sg(struct request_queue *q,
                              struct request *req,
                              struct scatterlist *iod_sglist)
{
	return nvfs_blk_rq_map_sg_internal(q, req, iod_sglist, true);
}

// V2 ops implementations for kernels with iterator API
#ifdef HAVE_BLK_RQ_DMA_MAP_ITER_START

/*
 * nvfs_peek_next_bvec - Peek at the next bio_vec without advancing iterator
 * @req: The block request
 * @req_iter: Request iterator tracking current position
 * @bvec: Output bio_vec
 *
 * This peeks at the current bio_vec WITHOUT advancing the iterator.
 * The caller must call nvfs_advance_bvec() to actually consume it.
 *
 * Returns: true if got a bio_vec, false if no more bio_vecs
 */
static bool nvfs_peek_next_bvec(struct request *req, struct req_iterator *req_iter,
                                struct bio_vec *bvec)
{
	/* If no more data in current bio, we're done */
	if (!req_iter->iter.bi_size) {
		nvfs_dbg("%s: no more data in current bio (bi_size=0)\n", __func__);
		return false;
	}

	/* Get current bio_vec WITHOUT advancing */
	*bvec = mp_bvec_iter_bvec(req_iter->bio->bi_io_vec, req_iter->iter);
	nvfs_dbg("%s: peeked bvec page=%p len=%u offset=%u\n",
		__func__, bvec->bv_page, bvec->bv_len, bvec->bv_offset);
	return true;
}

/*
 * nvfs_advance_bvec - Advance the iterator past current bio_vec
 * @req_iter: Request iterator tracking current position
 * @bvec: The bio_vec to advance past
 *
 * This advances the iterator by the length of the given bio_vec.
 * Should be called after nvfs_peek_next_bvec() to consume the bio_vec.
 */
static void nvfs_advance_bvec(struct req_iterator *req_iter, struct bio_vec *bvec)
{
	nvfs_dbg("%s: advancing by %u bytes\n", __func__, bvec->bv_len);
	bio_advance_iter_single(req_iter->bio, &req_iter->iter, bvec->bv_len);
}

/*
 * nvfs_validate_gpu_request - Validate GPU request on first call
 * @req: The block request
 * @nvfs_mgroup: GPU memory group
 *
 * Returns: 0 on success, NVFS_IO_ERR on validation failure
 */
static int nvfs_validate_gpu_request(struct request *req, nvfs_mgroup_ptr_t nvfs_mgroup)
{
	if (unlikely(blk_integrity_rq(req))) {
		nvfs_err("%s:%d cannot handle gpu request with integrity metadata\n",
				__func__, __LINE__);
		return NVFS_IO_ERR;
	}

	if (unlikely(!nvfs_req_payload_supported(req))) {
		nvfs_err("%s:%d payload too large\n", __func__, __LINE__);
		return NVFS_IO_ERR;
	}

#ifdef HAVE_DMA_DRAIN_IN_REQUEST_QUEUE
	{
		struct request_queue *q = req->q;
		if (unlikely(q->dma_drain_size && q->dma_drain_needed(req))) {
			nvfs_err("%s:%d cannot handle blk queue with drain segments\n",
					__func__, __LINE__);
			return NVFS_IO_ERR;
		}
	}
#endif

	return 0;
}

/*
 * nvfs_check_page_coalescible - Check if a page can be coalesced with current segment
 * @prev_phys_addr: Previous GPU physical address
 * @curr_phys_addr: Current GPU physical address
 * @gpu_page_index: Current GPU page index
 * @segment_len: Current segment length
 * @bvec_len: Length of bio_vec to add (unused, kept for API consistency)
 *
 * In the 6.17+ iterator-based approach, we let the NVMe driver decide when to stop
 * calling us. We only check GPU-specific constraints: physical contiguity and 4GB boundary.
 *
 * Returns: true if page can be coalesced, false otherwise
 */
static bool nvfs_check_page_coalescible(uint64_t prev_phys_addr, uint64_t curr_phys_addr,
                                         unsigned long gpu_page_index,
                                         unsigned int segment_len, unsigned int bvec_len)
{
	/* Check physical contiguity */
	if((prev_phys_addr + segment_len) != curr_phys_addr)
		return false;
	/* Check 4GB boundary (SMMU IOVA limitation) */
	if ((gpu_page_index != 0) && (gpu_page_index % NVFS_P2P_MAX_CONTIG_GPU_PAGES == 0))
		return false;

	return true;
}

/*
 * nvfs_get_gpu_page_info - Get GPU page physical address without DMA mapping
 * @bvec: bio_vec containing the page
 * @phys_addr: Output GPU physical address
 * @gpu_page_index: Output GPU page index
 *
 * Gets the GPU physical address and page index for contiguity checking.
 * Does NOT perform DMA mapping - that's done once per segment.
 *
 * Note: When bv_offset >= PAGE_SIZE, we must calculate the actual page
 * using nvfs_mgroup->nvfs_ppages[] since shadow buffer pages are not
 * guaranteed to be contiguous struct page pointers.
 *
 * Returns: 0 on success, NVFS_BAD_REQ if CPU page, NVFS_IO_ERR on error
 */
static int nvfs_get_gpu_page_info(struct bio_vec *bvec, uint64_t *phys_addr,
                                  unsigned long *gpu_page_index)
{
	nvfs_mgroup_ptr_t nvfs_mgroup;
	pgoff_t pgoff;
	unsigned int page_skip = bvec->bv_offset / PAGE_SIZE;
	struct page *actual_page;

	nvfs_dbg("%s: getting GPU page info for page=%p bv_offset=%u\n",
		__func__, bvec->bv_page, bvec->bv_offset);

	nvfs_mgroup = nvfs_mgroup_from_page(bvec->bv_page);
	if (unlikely(IS_ERR(nvfs_mgroup))) {
		nvfs_err("%s:%d mgroup_get_page error for page=%p\n", 
			__func__, __LINE__, bvec->bv_page);
		return NVFS_IO_ERR;
	}

	if (nvfs_mgroup == NULL) {
		/* CPU page */
		nvfs_dbg("%s: CPU page detected, page=%p\n", __func__, bvec->bv_page);
		return NVFS_BAD_REQ;
	}

	/*
	 * Calculate actual page based on bv_offset.
	 * When bv_offset >= PAGE_SIZE, data starts in a different shadow buffer page.
	 */
	if (page_skip > 0) {
		unsigned long rel_page_index = NVFS_PAGE_INDEX(bvec->bv_page) % NVFS_MAX_SHADOW_PAGES;
		unsigned long target_page_index = rel_page_index + page_skip;

		/* Bounds check */
		if (target_page_index >= NVFS_MAX_SHADOW_PAGES ||
		    target_page_index >= (nvfs_mgroup->nvfs_blocks_count /
		                          (PAGE_SIZE / NVFS_BLOCK_SIZE))) {
			nvfs_err("%s:%d page index out of bounds: target=%lu\n",
				__func__, __LINE__, target_page_index);
			CHECK_AND_PUT_MGROUP(nvfs_mgroup);
			return NVFS_IO_ERR;
		}

		actual_page = nvfs_mgroup->nvfs_ppages[target_page_index];
		nvfs_dbg("%s: bv_offset=%u spans pages: rel_idx=%lu target_idx=%lu "
			  "orig_page=%p actual_page=%p\n",
			  __func__, bvec->bv_offset, rel_page_index, target_page_index,
			  bvec->bv_page, actual_page);
	} else {
		actual_page = bvec->bv_page;
	}

	/* Get GPU physical address for tracking contiguity - use actual_page */
	*phys_addr = nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup, actual_page);
	nvfs_mgroup_get_gpu_index_and_off(nvfs_mgroup, actual_page, gpu_page_index, &pgoff);
	CHECK_AND_PUT_MGROUP(nvfs_mgroup);

	nvfs_dbg("%s: GPU page phys_addr=0x%llx gpu_page_index=%lu pgoff=%lu\n",
		__func__, *phys_addr, *gpu_page_index, pgoff);

	return 0;
}

/*
 * nvfs_check_bvec_contiguity - Check physical contiguity of pages within a bvec
 * @nvfs_mgroup: The mgroup containing the shadow buffer pages
 * @bvec: bio_vec to check
 * @base_phys_addr: Physical address of the starting page
 * @contiguous_len: Output - the contiguous length from start (may be < bv_len)
 *
 * When a bvec spans multiple pages (bv_len > PAGE_SIZE - offset_in_page),
 * we must verify that all those pages are physically contiguous in GPU memory.
 * Shadow buffer pages are allocated individually and may not be contiguous.
 *
 * Returns: true if fully contiguous, false if truncated (contiguous_len < bv_len)
 */
static bool nvfs_check_bvec_contiguity(nvfs_mgroup_ptr_t nvfs_mgroup,
                                       struct bio_vec *bvec,
                                       uint64_t base_phys_addr,
                                       unsigned int *contiguous_len)
{
	unsigned int page_skip = bvec->bv_offset / PAGE_SIZE;
	unsigned int offset_in_page = bvec->bv_offset % PAGE_SIZE;
	unsigned long base_rel_index = NVFS_PAGE_INDEX(bvec->bv_page) % NVFS_MAX_SHADOW_PAGES;
	unsigned long start_page_index = base_rel_index + page_skip;
	unsigned int bytes_in_first_page = PAGE_SIZE - offset_in_page;
	unsigned int remaining_len;
	unsigned int checked_len;
	uint64_t prev_phys_addr = base_phys_addr;
	uint64_t curr_phys_addr;
	unsigned long curr_page_index;
	struct page *curr_page;

	/* If bvec fits entirely within first page, it's contiguous by definition */
	if (bvec->bv_len <= bytes_in_first_page) {
		*contiguous_len = bvec->bv_len;
		return true;
	}

	/* Start with first page */
	checked_len = bytes_in_first_page;
	remaining_len = bvec->bv_len - bytes_in_first_page;
	curr_page_index = start_page_index + 1;

	nvfs_dbg("%s: checking contiguity for bvec len=%u offset=%u, spans %lu+ pages\n",
		__func__, bvec->bv_len, bvec->bv_offset,
		(bvec->bv_len + offset_in_page + PAGE_SIZE - 1) / PAGE_SIZE);

	/* Check each subsequent page for physical contiguity */
	while (remaining_len > 0) {
		/* Bounds check */
		if (curr_page_index >= NVFS_MAX_SHADOW_PAGES ||
		    curr_page_index >= (nvfs_mgroup->nvfs_blocks_count /
		                        (PAGE_SIZE / NVFS_BLOCK_SIZE))) {
			nvfs_err("%s: page index %lu out of bounds during contiguity check\n",
				__func__, curr_page_index);
			*contiguous_len = checked_len;
			return false;
		}

		curr_page = nvfs_mgroup->nvfs_ppages[curr_page_index];
		curr_phys_addr = nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup, curr_page);

		/* Check if this page is physically contiguous with previous */
		if (curr_phys_addr != prev_phys_addr + PAGE_SIZE) {
			nvfs_dbg("%s: discontinuity at page_index=%lu: prev_phys=0x%llx "
				  "curr_phys=0x%llx (expected 0x%llx), truncating to %u bytes\n",
				  __func__, curr_page_index, prev_phys_addr, curr_phys_addr,
				  prev_phys_addr + PAGE_SIZE, checked_len);
			*contiguous_len = checked_len;
			return false;
		}

		/* This page is contiguous, add it */
		if (remaining_len >= PAGE_SIZE) {
			checked_len += PAGE_SIZE;
			remaining_len -= PAGE_SIZE;
		} else {
			checked_len += remaining_len;
			remaining_len = 0;
		}

		prev_phys_addr = curr_phys_addr;
		curr_page_index++;
	}

	*contiguous_len = bvec->bv_len;
	nvfs_dbg("%s: bvec is fully contiguous, len=%u\n", __func__, *contiguous_len);
	return true;
}

/*
 * nvfs_coalesce_gpu_pages - Try to coalesce contiguous GPU pages into segment
 * @req: The block request
 * @req_iter: Request iterator
 * @segment_len: Current segment length (updated)
 * @prev_phys_addr: Previous physical address (updated)
 * @prev_gpu_page_index: Previous GPU page index (updated)
 *
 * Tries to coalesce as many contiguous GPU pages as possible into the current segment
 * based on GPU physical address contiguity. Does NOT perform DMA mapping - that's done
 * once for the entire segment on the base page.
 */
static void nvfs_coalesce_gpu_pages(struct request *req,
                                    struct req_iterator *req_iter,
                                    unsigned int *segment_len,
                                    uint64_t *prev_phys_addr,
                                    unsigned long *prev_gpu_page_index)
{
	struct bio_vec bvec;
	uint64_t curr_phys_addr;
	unsigned long gpu_page_index;
	nvfs_mgroup_ptr_t nvfs_mgroup;
	int ret;
	int coalesced_count = 0;

	nvfs_dbg("%s: starting coalescing, initial segment_len=%u\n", __func__, *segment_len);

	/*
	 * Try to coalesce following contiguous pages into this segment.
	 * Like the kernel's blk_map_iter_next(), we handle bio chain advancement here.
	 */
	while (true) {
		/* Check if current bio is exhausted, advance to next bio if needed */
		if (!req_iter->iter.bi_size) {
			if (!req_iter->bio->bi_next) {
				nvfs_dbg("%s: no more bios in chain\n", __func__);
				break;  /* No more bios */
			}
			
			nvfs_dbg("%s: advancing to next bio in chain\n", __func__);
			req_iter->bio = req_iter->bio->bi_next;
			req_iter->iter = req_iter->bio->bi_iter;
		}
		
		/* Peek at next bio_vec WITHOUT advancing */
		if (!nvfs_peek_next_bvec(req, req_iter, &bvec)) {
			nvfs_dbg("%s: peek failed, stopping coalescing\n", __func__);
			break;  /* No more data */
		}
		
		/* Get GPU page info (physical address) for contiguity checking */
		ret = nvfs_get_gpu_page_info(&bvec, &curr_phys_addr, &gpu_page_index);
		if (ret != 0) {
			nvfs_dbg("%s: get_gpu_page_info returned %d, stopping coalescing\n",
				__func__, ret);
			break;  /* Hit CPU page or error, don't advance */
		}

		/* Check if we can coalesce this page based on physical address */
		if (!nvfs_check_page_coalescible(*prev_phys_addr, curr_phys_addr,
		                                  gpu_page_index, *segment_len, bvec.bv_len)) {
			nvfs_dbg("%s: cannot coalesce - prev=0x%llx curr=0x%llx idx=%lu, seg len=%d, bvec len=%d\n",
				__func__, *prev_phys_addr, curr_phys_addr, gpu_page_index, *segment_len, bvec.bv_len);
			break;  /* Cannot coalesce, don't advance */
		}

		/* This page can be coalesced - get mgroup and set DMA state */
		nvfs_mgroup = nvfs_mgroup_from_page(bvec.bv_page);
		if (unlikely(IS_ERR(nvfs_mgroup))) {
			nvfs_err("%s:%d mgroup_get_page error for page=%p, stopping coalescing\n",
				__func__, __LINE__, bvec.bv_page);
			break;  /* Error getting mgroup, stop coalescing */
		}

		if (nvfs_mgroup == NULL) {
			/* Should not happen - we already checked this is GPU page */
			nvfs_err("%s: unexpected CPU page in coalescing\n", __func__);
			break;
		}

		/*
		 * Check physical contiguity within this bvec.
		 * If discontinuity found, truncate to contiguous portion.
		 */
		{
			unsigned int contiguous_len;
			if (!nvfs_check_bvec_contiguity(nvfs_mgroup, &bvec, curr_phys_addr,
			                                &contiguous_len)) {
				nvfs_dbg("%s: coalesce bvec truncated from %u to %u bytes\n",
					__func__, bvec.bv_len, contiguous_len);
				bvec.bv_len = contiguous_len;
			}
		}

		/* Set DMA state for this coalesced page (using potentially truncated length) */
		nvfs_dbg("%s: setting DMA state for coalesced page=%p len=%u offset=%u\n",
			__func__, bvec.bv_page, bvec.bv_len, bvec.bv_offset);
		if (nvfs_mgroup_metadata_set_dma_state(bvec.bv_page, nvfs_mgroup,
		                                       bvec.bv_len, bvec.bv_offset) != 0) {
			nvfs_err("%s:%d mgroup_set_dma error for coalesced page=%p\n",
				__func__, __LINE__, bvec.bv_page);
			CHECK_AND_PUT_MGROUP(nvfs_mgroup);
			break;  /* Error setting DMA state, stop coalescing */
		}
		CHECK_AND_PUT_MGROUP(nvfs_mgroup);

		/* Advance the iterator by the (potentially truncated) bvec length */
		nvfs_advance_bvec(req_iter, &bvec);

		/* Coalesce this page into current segment (using truncated length if applicable) */
		*segment_len += bvec.bv_len;
		*prev_gpu_page_index = gpu_page_index;
		coalesced_count++;
		
		nvfs_dbg("%s: coalesced page %d, new segment_len=%u\n",
			__func__, coalesced_count, *segment_len);
	}

	nvfs_dbg("%s: coalescing complete, coalesced %d pages, final segment_len=%u\n",
		__func__, coalesced_count, *segment_len);
}

/*
 * nvfs_map_next_gpu_segment - Map the next GPU segment
 * @req: The block request to map
 * @dma_dev: The DMA device (NVMe PCI device)
 * @iter: Block DMA iterator to be filled
 * @is_first_call: Is this the first call for this request?
 * @cookie: output param to be filled up with nvfs_mgroup on SUCCESS
 *
 * This function returns ONE GPU segment per call and preserves iterator state.
 *
 * Returns: 1 if successfully mapped a segment (iter filled with addr/len),
 *          0 if no more GPU segments or only CPU pages found,
 *          NVFS_IO_ERR on error (iter->status set)
 */
static int nvfs_map_next_gpu_segment(struct request *req,
                                     struct device *dma_dev,
                                     struct blk_dma_iter *iter,
                                     bool is_first_call,
				     void** cookie)
{
	struct req_iterator *req_iter = &iter->iter;
	struct bio_vec bvec;
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;
	void *gpu_base_dma = NULL;
	uint64_t curr_phys_addr = 0;
	unsigned long gpu_page_index = 0;
	pgoff_t pgoff;
	int ret;
	dma_addr_t segment_start_addr;
	unsigned int segment_len;

	nvfs_dbg("%s: ENTER req=%p is_first_call=%d\n", __func__, req, is_first_call);

	/* Peek at the next bio_vec WITHOUT advancing the iterator */
	if (!nvfs_peek_next_bvec(req, req_iter, &bvec)) {
		nvfs_dbg("%s: no more bio_vecs, returning 0\n", __func__);
		return 0;  /* No more bio_vecs */
	}

	/* Check if this page is a GPU page */
	nvfs_mgroup = nvfs_mgroup_from_page(bvec.bv_page);
	if (unlikely(IS_ERR(nvfs_mgroup))) {
		nvfs_err("%s:%d mgroup_get_page error for page=%p\n", 
			__func__, __LINE__, bvec.bv_page);
		iter->status = BLK_STS_IOERR;
		return NVFS_IO_ERR;
	}

	/* If CPU page, return 0 WITHOUT advancing - let kernel handle it */
	if (nvfs_mgroup == NULL) {
		nvfs_dbg("%s: CPU page detected, returning 0 to let kernel handle it\n", __func__);
		return 0;
	}

	nvfs_dbg("%s: GPU page detected, page=%p len=%u offset=%u\n",
		__func__, bvec.bv_page, bvec.bv_len, bvec.bv_offset);


	nvfs_dbg("%s: validating req %p\n", __func__, req);
	ret = nvfs_validate_gpu_request(req, nvfs_mgroup);
	if (ret != 0) {
		CHECK_AND_PUT_MGROUP(nvfs_mgroup);
		nvfs_err("%s: validation failed\n", __func__);
		iter->status = BLK_STS_IOERR;
		return NVFS_IO_ERR;
	}

	/*
	 * Calculate the actual starting page based on bv_offset.
	 * When bv_offset >= PAGE_SIZE, the data starts in a different shadow buffer
	 * page than bvec.bv_page. We must use the correct page for:
	 * 1. Getting GPU physical address (for contiguity tracking)
	 * 2. Getting gpu_page_index (for coalescing decisions)
	 * 3. Getting DMA address (for actual I/O)
	 */
	{
		unsigned int page_skip = bvec.bv_offset / PAGE_SIZE;
		unsigned int offset_in_page = bvec.bv_offset % PAGE_SIZE;
		unsigned long rel_page_index;
		unsigned long target_page_index;
		struct page *actual_page = NULL;
		struct blk_plug *plug = NULL;

		if (page_skip > 0) {
			/* Calculate relative page index within mgroup */
			rel_page_index = NVFS_PAGE_INDEX(bvec.bv_page) % NVFS_MAX_SHADOW_PAGES;
			target_page_index = rel_page_index + page_skip;

			/* Bounds check */
			if (target_page_index >= NVFS_MAX_SHADOW_PAGES ||
			    target_page_index >= (nvfs_mgroup->nvfs_blocks_count /
			                          (PAGE_SIZE / NVFS_BLOCK_SIZE))) {
				nvfs_err("%s:%d page index out of bounds: target=%lu max=%lu\n",
					__func__, __LINE__, target_page_index,
					nvfs_mgroup->nvfs_blocks_count / (PAGE_SIZE / NVFS_BLOCK_SIZE));
				CHECK_AND_PUT_MGROUP(nvfs_mgroup);
				iter->status = BLK_STS_IOERR;
				return NVFS_IO_ERR;
			}

			actual_page = nvfs_mgroup->nvfs_ppages[target_page_index];
			nvfs_dbg("%s: bv_offset=%u spans pages: rel_idx=%lu target_idx=%lu "
				  "offset_in_page=%u orig_page=%p actual_page=%p\n",
				  __func__, bvec.bv_offset, rel_page_index, target_page_index,
				  offset_in_page, bvec.bv_page, actual_page);
		} else {
			/* No page skip needed, use original page */
			actual_page = bvec.bv_page;
			nvfs_dbg("%s: no page skip needed, bv_offset=%u < PAGE_SIZE\n",
				  __func__, bvec.bv_offset);
		}

		/* Get GPU physical address for tracking contiguity - use actual_page! */
		curr_phys_addr = nvfs_mgroup_get_gpu_physical_address(nvfs_mgroup, actual_page);
		nvfs_mgroup_get_gpu_index_and_off(nvfs_mgroup, actual_page,
		                                  &gpu_page_index, &pgoff);
		/* Adjust pgoff to include the offset within the actual page */
		pgoff = offset_in_page;

		nvfs_dbg("%s: first page phys_addr=0x%llx gpu_page_index=%lu pgoff=%lu (actual_page=%p)\n",
			__func__, curr_phys_addr, gpu_page_index, pgoff, actual_page);

		/*
		 * Check physical contiguity within this bvec.
		 * If the bvec spans multiple pages that are not physically contiguous,
		 * truncate to only the contiguous portion.
		 */
		{
			unsigned int contiguous_len;
			if (!nvfs_check_bvec_contiguity(nvfs_mgroup, &bvec, curr_phys_addr,
			                                &contiguous_len)) {
				nvfs_dbg("%s: bvec truncated from %u to %u bytes due to discontinuity\n",
					__func__, bvec.bv_len, contiguous_len);
				bvec.bv_len = contiguous_len;
			}
		}

		/* Set DMA state for this GPU page (using potentially truncated length) */
		nvfs_dbg("%s: setting DMA state for page=%p len=%u offset=%u\n",
				__func__, bvec.bv_page, bvec.bv_len, bvec.bv_offset);
		if (nvfs_mgroup_metadata_set_dma_state(bvec.bv_page, nvfs_mgroup,
					bvec.bv_len, bvec.bv_offset) != 0) {
			nvfs_err("%s:%d mgroup_set_dma error for page=%p\n", 
					__func__, __LINE__, bvec.bv_page);
			CHECK_AND_PUT_MGROUP(nvfs_mgroup);
			iter->status = BLK_STS_IOERR;
			return NVFS_IO_ERR;
		}

		/*
		 * Advance the iterator by the (potentially truncated) bvec length.
		 * nvfs_advance_bvec uses bvec.bv_len to advance, so truncation is honored.
		 */
		nvfs_advance_bvec(req_iter, &bvec);

		/* Start the segment with this page (using truncated length if applicable) */
		segment_len = bvec.bv_len;

		/* Try to coalesce following contiguous pages based on physical address */
		nvfs_coalesce_gpu_pages(req, req_iter, &segment_len,
		                        &curr_phys_addr, &gpu_page_index);

		plug = current->plug;
		current->plug = NULL;
		nvfs_dbg("%s: getting DMA mapping for req:%p, bvec.bv_page %p, actual_page %p segment_len=%u, offset %d\n",
				__func__, req, bvec.bv_page, actual_page, segment_len, bvec.bv_offset);
		ret = nvfs_get_dma(to_pci_dev(dma_dev), actual_page, &gpu_base_dma, segment_len);
		current->plug = plug;
		if (ret == NVFS_IO_ERR || ret == NVFS_BAD_REQ) {
			nvfs_err("%s:%d nvfs_get_dma failed (ret=%d) for page=%p\n",
					__func__, __LINE__, ret, actual_page);
			CHECK_AND_PUT_MGROUP(nvfs_mgroup);
			iter->status = BLK_STS_IOERR;
			return NVFS_IO_ERR;
		}
		segment_start_addr = (dma_addr_t)gpu_base_dma + offset_in_page;
	}

	/* Fill in the iterator with the segment we built */
	iter->addr = segment_start_addr;
	iter->len = segment_len;
	iter->status = BLK_STS_OK;

	/* A reference on nvfs_mgroup is held during nvfs_get_dma and hence this isn't a use after free problem */
	if(cookie != NULL)
		*cookie = (void*)nvfs_mgroup;

	CHECK_AND_PUT_MGROUP(nvfs_mgroup);
	nvfs_dbg("%s: EXIT SUCCESS - mapped segment DMA:0x%llx len:%u, mgroup %p\n",
		__func__, (unsigned long long)iter->addr, iter->len, nvfs_mgroup);

	return 1;
}

/*
 * nvfs_blk_rq_dma_map_iter_start - Start DMA mapping iteration for a request
 * @req: The block request to map
 * @dma_dev: The DMA device (NVMe PCI device)
 * @state: DMA IOVA state (managed by kernel, we don't use IOVA for GPU pages)
 * @iter: Block DMA iterator to be filled
 * @cookie: output param to be filled up with nvfs_mgroup on SUCCESS
 *
 * This function replaces nvfs_blk_rq_map_sg() in the new 6.17+ kernel approach.
 * It initializes iteration over the request's bio pages and maps the first
 * GPU page segment, returning its DMA address and length in the iterator.
 *
 * Returns: 1 if we successfully mapped a GPU segment (indicating NVFS should handle this),
 *          0 if this is a CPU-only request (let kernel handle it),
 *          NVFS_IO_ERR on error
 */
static int nvfs_blk_rq_dma_map_iter_start(struct request *req,
                                        struct device *dma_dev,
                                        struct dma_iova_state *state,
                                        struct blk_dma_iter *iter,
					void **cookie)
{
	int ret;

	nvfs_dbg("%s: ====== NVFS DMA MAP ITER START ====== req=%p\n", __func__, req);

	/* Basic request validation */
	if (!nvfs_blk_rq_check(req)) {
		nvfs_dbg("%s: nvfs_blk_rq_check failed\n", __func__);
		return 0;
	}

	/* Initialize the bio iterator to the start of the request */
	iter->iter.bio = req->bio;
	if (!iter->iter.bio) {
		nvfs_err("%s: req->bio is NULL\n", __func__);
		return 0;
	}
	iter->iter.iter = iter->iter.bio->bi_iter;
	iter->status = BLK_STS_OK;

	nvfs_dbg("%s: initialized iterator, calling nvfs_map_next_gpu_segment\n", __func__);

	/* Use common helper to map the first segment */
	ret = nvfs_map_next_gpu_segment(req, dma_dev, iter, true, cookie);
	//CPU Page detected
	if(ret == 0) 
		return ret;
	else 
		return ret > 0 ? 1 : 0;
}

/*
 * nvfs_blk_rq_dma_map_iter_next - Map the next DMA segment for a request
 * @req: The block request to map
 * @dma_dev: The DMA device (NVMe PCI device)
 * @state: DMA IOVA state (managed by kernel, we don't use IOVA for GPU pages)
 * @iter: Block DMA iterator to be filled
 *
 * This function continues DMA mapping iteration started by nvfs_blk_rq_dma_map_iter_start().
 * It maps the next GPU page segment in the request, potentially coalescing consecutive
 * pages into a single DMA segment if they are physically contiguous.
 *
 * Returns: 1 if we successfully mapped the next segment,
 *          0 if there are no more segments to map,
 *          NVFS_IO_ERR on error (status set in iter->status)
 */
static int nvfs_blk_rq_dma_map_iter_next(struct request *req,
                                        struct device *dma_dev,
                                        struct dma_iova_state *state,
                                        struct blk_dma_iter *iter)
{
	int ret;

	nvfs_dbg("%s: ====== NVFS DMA MAP ITER NEXT ====== req=%p\n", __func__, req);

	/* 
	 * The iter->iter is already positioned from either _start or previous _next call.
	 * Our nvfs_peek_next_bvec() will continue from where we left off.
	 */

	/* Use common helper to map the next segment */
	ret = nvfs_map_next_gpu_segment(req, dma_dev, iter, false, NULL);
	
	//CPU Page detected
	if(ret == 0) 
		return ret;
	else 
		return ret > 0 ? 1 : 0;
}

/*
 * nvfs_dma_unmap_page - Unmap a single DMA page
 * @device: The DMA device
 * @page: The page being unmapped
 * @addr: DMA address to unmap
 * @size: Size of the mapping
 * @dir: DMA direction
 *
 * This function is called by the NVMe driver to unmap individual GPU pages
 * after I/O completion. It replicates what nvfs_dma_unmap_sg() does but for
 * a single page in the iterator-based API.
 *
 * Returns: 0 on success (GPU page), NVFS_IO_ERR on error
 */
static int nvfs_dma_unmap_page(struct device *device,
		               void *cookie,
		               dma_addr_t addr,
		               size_t size,
		               enum dma_data_direction dir)
{
	if (unlikely(cookie == NULL)) {
		nvfs_err("%s: nvfs_mgroup passed is NULL\n",
			__func__);
		return NVFS_IO_ERR;
	}

	nvfs_dbg("%s: unmap DMA addr:0x%llx size:%zu dir:%d\n",
		__func__, (unsigned long long)addr, size, dir);
	
	nvfs_mgroup_ptr_t nvfs_mgroup = (nvfs_mgroup_ptr_t)cookie;
	nvfs_mgroup_put_dma(nvfs_mgroup);
	return 0;
}
#endif /* HAVE_BLK_RQ_DMA_MAP_ITER_START */

static int nvfs_dma_map_sg_attrs_internal(struct device *device,
	                         struct scatterlist *sglist,
				 int nents,
			         enum dma_data_direction dma_dir,
			         unsigned long attrs, bool nvme)
{
	int ret, i = 0, nr_gpu_dma = 0, nr_cpu_dma = 0;
	void *gpu_base_dma = NULL;
	struct scatterlist *sg = NULL;
	struct blk_plug *plug = NULL;
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL;

	if (unlikely(nents == 0)) {
		nvfs_err("%s:%d cannot map empty sglist\n", __func__, __LINE__);
		return NVFS_IO_ERR;
	}

	nvfs_dbg("nvfs_dma_map_sg_attrs invoked with %d entries\n", nents);

        for_each_sg(sglist, sg, nents, i) {

		if (nvme) {
			/*
			 * This is a hack.
			 * Linux Kernel 5.17 onwards, a new interface to submit a batch of requests was introduced 
			 * in the NVMe driver called nvme_queue_rqs. When this interface is present, the block layer
			 * submits the whole plug list to the NVMe driver, instead of individually poping out entries
			 * and submitting one request at a time to the NVMe driver using the nvme_queue_rq interface.
			 * Due to the introduction of this new interface, block request is popped out only 
			 * after calling the dma map request. As nvfs_nvidia_p2p_dma_map_pages() can potenitally 
			 * block and if that happens the scheduler would add this plug list to another queue, which 
			 * will be picked by a kernel thread(kblockd) in the future. Now once the 
			 * nvfs_nvidia_p2p_dma_map_pages() call gets rescheduled, there is a potential 
			 * for a race where the application thread and kblockd would be working on the 
			 * same request and potenitally cause a race. The below hack is to set 
			 * the current task's plug to NULL before calling the nvfs_nvidia_p2p_dma_map_pages(), so 
			 * that the scheduler does add this entry to another list which will be eventually picked up
			 * by kblockd. This way only one thread would be working on the request at a time.
			 */
			plug = current->plug;
			current->plug = NULL;
			ret = nvfs_get_dma(to_pci_dev(device), sg_page(sg), &gpu_base_dma, -1);
			current->plug = plug;
		} else {
			ret = nvfs_get_dma(to_pci_dev(device), sg_page(sg), &gpu_base_dma, sg->length);
			if (ret == 0) {
				nvfs_mgroup = nvfs_mgroup_from_page(sg_page(sg));
				if(nvfs_mgroup == NULL) {
					nvfs_err("%s:%d empty mgroup\n", __func__, __LINE__);
					return NVFS_IO_ERR;
				}
				// We have dma mapping set up
				if (nvfs_mgroup_metadata_set_dma_state(sg_page(sg), nvfs_mgroup, sg->length, sg->offset) < 0) {
					nvfs_err("%s:%d mgroup_set_dma error\n", __func__, __LINE__);
					ret = NVFS_IO_ERR;
				}
				nvfs_mgroup_put(nvfs_mgroup);
			}
		}

#ifdef SIMULATE_NVFS_IOERR
		ret = NVFS_IO_ERR;
#endif
		if (ret == NVFS_IO_ERR) {
			nvfs_err("%s:%d nvfs dma mapping error for sg entry!",
				__func__, __LINE__);
			goto map_err;
                }

		if (ret == NVFS_BAD_REQ) {
			// Cannot handle GPU/CPU pages
			if (unlikely(nr_gpu_dma)) {
				ret = NVFS_IO_ERR;
				nvfs_err("%s:%d nvfs detected mixed cpu/gpu pages(cpu=%d/gpu=%d)!",
					__func__, __LINE__, nr_cpu_dma, nr_gpu_dma);
				goto map_err;
			}
			// We do not handle dma mapping for CPU pages
			nr_cpu_dma++;
                } else {
			// Cannot handle GPU/CPU pages
			if (unlikely(nr_cpu_dma)) {
				ret = NVFS_IO_ERR;
				nvfs_err("%s:%d nvfs detected mixed cpu/gpu pages(cpu=%d/gpu=%d)!",
					__func__, __LINE__, nr_cpu_dma, nr_gpu_dma);
				goto map_err;
			}
			BUG_ON(!(dma_addr_t) gpu_base_dma);

			/*
			 * We are adding sg->length to the GPU DMA address. In the case of NVMe or any
			 * external client who uses blk_rq_mag_sg(), GDS driver is responsible for constructing
			 * the SG entries based on the GPU Physical address and hence sg->length is rightly set
			 * based on the contiguous address range of GPU addresses.
			 *
			 * Client who do not invoke blk_rq_map_sg(), will construct sg entries and directly invoke
			 * dma_map_sg_attrs(); If the sg->length set by client is more than 64K (GPU_PAGE_SIZE),
			 * we need to make sure that the dma addresss are indeed contiguous.
			 */
			sg_dma_address(sg) = (dma_addr_t) gpu_base_dma + sg->offset;
			sg_dma_len(sg) = sg->length;

			#ifdef CONFIG_DEBUG_NVFS_BLK
			pr_info("P2P PAGE :%lx DMA :0x%lx/0x%lx nr_gpu_dma :%d\n",
				(unsigned long) sg_page(sg),
				(unsigned long) sg_dma_address(sg),
				(unsigned long) sg_dma_len(sg),
				nr_gpu_dma);
			#endif
			nr_gpu_dma++;
		}
	}

        if (!nr_gpu_dma) {
		ret = NVFS_BAD_REQ;
		nvfs_dbg("%s: nvfs hook called for non-gpu request", __func__);
		goto map_err;
        } else
		nvfs_dbg("%s: nvfs hook called for gpu request :%u", __func__, nr_gpu_dma);

        #ifdef CONFIG_DEBUG_NVFS_BLK
        pr_info("request biovec :gpu_segs=%u/total_segs=%u\n", nr_gpu_dma, nents);
        for_each_sg(sglist, sg, nents, i)
		pr_info("sg entry :[%d]0x%llx/%u\n", i, sg_dma_address(sg), sg_dma_len(sg));
        #endif
        return nents;

map_err:
	return ret;
}

/*
 * nvfs_dma_unmap_sg, - unmap dma address for scatter/gather list entries
 * This is an external facing API for vendors.
 *
 * @device  : dma device
 * @sglist  : sglist
 * @nents   : number of sg-entries
 * @dma_dir : dma direction
 * @returns : - number of GPU pages mapped
 *            - 0 if no GPU pages
 *            - NVFS_IO_ERR if GPU dma mapping has failed
 *            - NVFS_IO_ERR if sglist has a mix of CPU & GPU pages. We update
 *              the corresponding error stat.
 * Notes:
 * 	1. This function can be invoked from IRQ context
 * 	2. Standard Linux DMA mapping API have void as return code for unmap APIs.
 * 	   But we kept return type as int to distinguish whether it is a GPU page or not,
 * 	   and also return an error for case where GPU dma mapping on page has failed.
 * 	   (Some file-systems can call unmap even if corresponding gpu dma mapping has failed)
 *
 */
static int nvfs_dma_unmap_sg(struct device *device,
                              struct scatterlist *sglist,
                              int nents,
                              enum dma_data_direction dma_dir)
{
	int i = 0, ret;
	int gpu_segs = 0, cpu_segs = 0;
	struct scatterlist *sg = NULL;
	struct page *page;

	if (unlikely(!sglist || (nents < 0)))
		BUG();

        for_each_sg(sglist, sg, nents, i) {
		if (unlikely(sg == NULL)) {
			return NVFS_IO_ERR;
		}
		page = sg_page(sg);
		if (unlikely(page == NULL))
		       continue;
		ret = nvfs_check_gpu_page_and_error(page, sg->offset, sg->length);
		if (!ret) {
			cpu_segs++;
		} else if (unlikely(ret == -1)) {
			return NVFS_IO_ERR;
		} else
			gpu_segs++;
	}

	if (unlikely(gpu_segs && cpu_segs)) {
		nvfs_stat(&nvfs_n_err_mix_cpu_gpu);
		return NVFS_IO_ERR;
	}
	return gpu_segs;
}

int nvfs_blk_register_dma_ops(void) {
	return probe_module_list();
}

void nvfs_blk_unregister_dma_ops(void) {
	cleanup_module_list();
}

static int nvfs_dma_map_sg_attrs_nvme(struct device *device,
	                         struct scatterlist *sglist,
				 int nents,
			         enum dma_data_direction dma_dir,
				 unsigned long attrs)
{
	return nvfs_dma_map_sg_attrs_internal(device, sglist, nents, dma_dir, attrs, true);
}

/*
 * nvfs_dma_map_sg_attrs, - get dma address for scatter/gather list entries
 *
 * This is an external facing API for vendors. Vendors calling this API
 * without calling nvfs_blk_rq_map_sg(), should ensure that the segment size
 * (sg->length) of each scatter gatter entries should not exceed more than
 * 64K which is the GPU_PAGE_SIZE.
 *
 * However, vendors using nvfs_blk_rq_map_sg() first and then invoking
 * nvfs_dma_map_sg_attrs() such as NVMe driver need not worry about the
 * GPU_PAGE_SIZE as nvfs_blk_rq_map_sg() takes the responsibility of
 * constructing the scatter gatter entries.
 *
 * @device  : dma device
 * @sglist  : sglist
 * @nents   : number of sg-entries
 * @dma_dir : dma direction
 * @attr    : dma attributes
 * @returns : number of mapped sg entries mapped if GPU pages
 *            or NVFS_BAD_REQ if no GPU pages
 * Notes    : works for both CPU and GPU sg entries
 */
static int nvfs_dma_map_sg_attrs(struct device *device,
	                         struct scatterlist *sglist,
				 int nents,
			         enum dma_data_direction dma_dir,
				 unsigned long attrs)
{
	return nvfs_dma_map_sg_attrs_internal(device, sglist, nents, dma_dir, attrs, false);
}
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
static int nvfs_get_gpu_sglist_rdma_info(struct scatterlist *sglist,
				int nents,
				struct nvfs_rdma_info *rdma_infop)
{
	struct scatterlist *sg = NULL;
	struct page *page;
	nvfs_mgroup_ptr_t nvfs_mgroup = NULL, prev_mgroup = NULL;
	int i = 0, nblocks = 0;
	uint64_t shadow_buf_size, total_size = 0;
	struct nvfs_io* nvfsio = NULL;
	
	if(nents <= 0) {
		
		nvfs_err("%s: Wrong or none sglist entries passed %d\n"
				, __func__, nents);
		return NVFS_BAD_REQ;
	}


	if(rdma_infop == NULL) {
		
		nvfs_err("%s: NULL pointer passed for rdma_infop\n"
				, __func__);
		return NVFS_BAD_REQ;
	}

	page = sg_page(sglist);
	if(page == NULL) {
		nvfs_err("%s: NULL page passed, page number: %d", __func__, 0);
		return NVFS_IO_ERR;
	}
	
#ifdef NVFS_TEST_GPFS_CALLBACK
	prev_mgroup = nvfs_mgroup_get((NVFS_PAGE_INDEX(page->index) >> NVFS_MAX_SHADOW_PAGES_ORDER));
#else
	prev_mgroup = nvfs_mgroup_from_page(page);
#endif

	if(unlikely(IS_ERR(prev_mgroup))) {
		nvfs_err("%s: mgroup internal error\n", __func__);
		return NVFS_IO_ERR;
	}

	if(prev_mgroup == NULL) {
		nvfs_dbg("%s: mgroup NULL for page %d for addr 0x%p", __func__, 0, page);
		return NVFS_BAD_REQ;
	} else {
                if(prev_mgroup->rdma_info.version == 0) {
		        nvfs_err("%s: rdma version not set for page %d for addr 0x%p", __func__, 0, page);
			nvfs_mgroup_put(prev_mgroup);	
		        return NVFS_IO_ERR;
                }
		shadow_buf_size = (prev_mgroup->nvfs_blocks_count) * NVFS_BLOCK_SIZE;
		nvfsio = &prev_mgroup->nvfsio;
	        memcpy(rdma_infop, &prev_mgroup->rdma_info, sizeof(*rdma_infop));
                // get to the base 64K page of the starting address
                rdma_infop->rem_vaddr -= (rdma_infop->rem_vaddr & (GPU_PAGE_SIZE -1));
                // set to the current address by calulating the number of 64K pages + offset
                rdma_infop->rem_vaddr += (nvfsio->cur_gpu_base_index << GPU_PAGE_SHIFT);
                rdma_infop->rem_vaddr += (nvfsio->gpu_page_offset);
		rdma_infop->size = (nvfsio->nvfs_active_blocks_end -
				nvfsio->nvfs_active_blocks_start + 1) * NVFS_BLOCK_SIZE;
		if ((int32_t) rdma_infop->size > (shadow_buf_size - nvfsio->rdma_seg_offset) ||
			(int32_t) rdma_infop->size < 0) {
			nvfs_err("%s: wrong rdma_infop->size %d shadow buffer size %llu addr = 0x%llx\n \
					seg_offset = %lu, rkey = %x, mgroup = %p\n",
					__func__, rdma_infop->size, shadow_buf_size, rdma_infop->rem_vaddr, \
					nvfsio->rdma_seg_offset, rdma_infop->rkey, prev_mgroup);
			nvfs_mgroup_put(prev_mgroup);	
			return NVFS_IO_ERR;
		}
		nvfs_dbg("%s: rdma_infop: vaddr = %llx size = %d, offset = %lu rkey = %x\n",
				__func__,
				rdma_infop->rem_vaddr,
				rdma_infop->size,
				nvfsio->rdma_seg_offset, rdma_infop->rkey);
        }
	
	shadow_buf_size = (prev_mgroup->nvfs_blocks_count) * NVFS_BLOCK_SIZE;
	nvfs_mgroup_put(prev_mgroup);	

	for_each_sg(sglist, sg, nents, i) {
		if (unlikely(sg == NULL)) {
			nvfs_dbg("%s: NULL sglist entry passed %d", __func__, i);
			memset(rdma_infop, 0, sizeof(*rdma_infop));
			return NVFS_BAD_REQ;
		}
		page = sg_page(sg);		
	        nblocks = DIV_ROUND_UP(sg->length, NVFS_BLOCK_SIZE);

		if(page == NULL) {
			nvfs_dbg("%s: NULL page passed, page number: %d", __func__, i);
	                memset(rdma_infop, 0, sizeof(*rdma_infop));
			return NVFS_BAD_REQ;
		}

	//	printk("%s: page %p \n", __func__, page);
#ifdef NVFS_TEST_GPFS_CALLBACK
		nvfs_mgroup = nvfs_mgroup_get((NVFS_PAGE_INDEX(page->index) >> NVFS_MAX_SHADOW_PAGES_ORDER));
#else
		nvfs_mgroup = nvfs_mgroup_from_page_range(page, nblocks, sg->offset);
#endif
		if(nvfs_mgroup == NULL) {
			nvfs_dbg("%s: mgroup NULL for page %d for addr 0x%p", __func__, i, page);
	                memset(rdma_infop, 0, sizeof(*rdma_infop));
			return NVFS_BAD_REQ;
		}
		
		if(unlikely(IS_ERR(nvfs_mgroup))) {
			nvfs_err("%s: mgroup internal error\n", __func__);
	                memset(rdma_infop, 0, sizeof(*rdma_infop));
			return NVFS_IO_ERR;
		}
	
		if(prev_mgroup != nvfs_mgroup) {
			nvfs_err("%s: Pages passed do not belong to same mgroup\n", __func__);
			nvfs_mgroup_put(nvfs_mgroup);
	                memset(rdma_infop, 0, sizeof(*rdma_infop));
			return NVFS_IO_ERR;
		}
		prev_mgroup = nvfs_mgroup;
		nvfs_mgroup_put(nvfs_mgroup);
		total_size += sg->length;
	}
	if(total_size > shadow_buf_size) {
		nvfs_err("%s: Size requested: %llu  more than shadow buf size: %llu\n",
				__func__, total_size, shadow_buf_size);
	        memset(rdma_infop, 0, sizeof(*rdma_infop));
		return NVFS_IO_ERR;
	}
	return nents;	
}
#endif

#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
#define SET_DEFAULT_OPS                                         \
	.ft_bmap                        = NVIDIA_FS_SET_FT_ALL, \
	.nvfs_blk_rq_map_sg             = nvfs_blk_rq_map_sg,   \
	.nvfs_dma_map_sg_attrs          = nvfs_dma_map_sg_attrs,        \
	.nvfs_dma_unmap_sg              = nvfs_dma_unmap_sg,    \
	.nvfs_is_gpu_page               = nvfs_is_gpu_page,     \
	.nvfs_gpu_index                 = nvfs_gpu_index,               \
	.nvfs_device_priority           = nvfs_device_priority, \
	.nvfs_get_gpu_sglist_rdma_info  = nvfs_get_gpu_sglist_rdma_info,
#else
#define SET_DEFAULT_OPS                                         \
	.ft_bmap                        = NVIDIA_FS_SET_FT_ALL, \
	.nvfs_blk_rq_map_sg             = nvfs_blk_rq_map_sg,   \
	.nvfs_dma_map_sg_attrs          = nvfs_dma_map_sg_attrs,        \
	.nvfs_dma_unmap_sg              = nvfs_dma_unmap_sg,    \
	.nvfs_is_gpu_page               = nvfs_is_gpu_page,     \
	.nvfs_gpu_index                 = nvfs_gpu_index,               \
	.nvfs_device_priority           = nvfs_device_priority,
#endif

// V2 ops default settings for kernels with iterator API
#ifdef HAVE_BLK_RQ_DMA_MAP_ITER_START
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
#define SET_DEFAULT_OPS_V2                                      \
	.ft_bmap                        = NVIDIA_FS_SET_BLK_DMA_MAP_ITER_FT_ALL, \
	.nvfs_is_gpu_page               = nvfs_is_gpu_page,     \
	.nvfs_gpu_index                 = nvfs_gpu_index,               \
	.nvfs_device_priority           = nvfs_device_priority, \
	.nvfs_get_gpu_sglist_rdma_info  = nvfs_get_gpu_sglist_rdma_info,
#else
#define SET_DEFAULT_OPS_V2                                      \
	.ft_bmap                        = NVIDIA_FS_SET_BLK_DMA_MAP_ITER_FT_ALL, \
	.nvfs_is_gpu_page               = nvfs_is_gpu_page,     \
	.nvfs_gpu_index                 = nvfs_gpu_index,               \
	.nvfs_device_priority           = nvfs_device_priority,
#endif
#endif /* HAVE_BLK_RQ_DMA_MAP_ITER_START */


struct nvfs_dma_rw_ops nvfs_dev_dma_rw_ops = {
	SET_DEFAULT_OPS
};

struct nvfs_dma_rw_ops nvfs_nvme_dma_rw_ops = {
	SET_DEFAULT_OPS
	.nvfs_blk_rq_map_sg	= nvfs_nvme_blk_rq_map_sg,
	.nvfs_dma_map_sg_attrs  = nvfs_dma_map_sg_attrs_nvme,
};

struct nvfs_dma_rw_ops nvfs_sfxv_dma_rw_ops = {
	SET_DEFAULT_OPS
	.nvfs_blk_rq_map_sg	= nvfs_nvme_blk_rq_map_sg,
	.nvfs_dma_map_sg_attrs  = nvfs_dma_map_sg_attrs_nvme,
};

struct nvfs_dma_rw_ops nvfs_nvmesh_dma_rw_ops = {
	SET_DEFAULT_OPS
	.nvfs_blk_rq_map_sg	= nvfs_nvme_blk_rq_map_sg,
	.nvfs_dma_map_sg_attrs  = nvfs_dma_map_sg_attrs_nvme,
};
#ifdef NVFS_ENABLE_KERN_RDMA_SUPPORT
struct nvfs_dma_rw_ops nvfs_ibm_scale_rdma_ops = {
	SET_DEFAULT_OPS
	.nvfs_get_gpu_sglist_rdma_info = nvfs_get_gpu_sglist_rdma_info,
};
#endif

// V2 ops for NVMe driver (for future extensibility) - only for kernels with iterator API
#ifdef HAVE_BLK_RQ_DMA_MAP_ITER_START
struct nvfs_dma_rw_blk_iter_ops nvfs_nvme_dma_rw_blk_iter_ops = {
	SET_DEFAULT_OPS_V2
	.nvfs_blk_rq_dma_map_iter_start = nvfs_blk_rq_dma_map_iter_start,
	.nvfs_blk_rq_dma_map_iter_next  = nvfs_blk_rq_dma_map_iter_next,
	.nvfs_dma_unmap_page = nvfs_dma_unmap_page,
};
#endif
