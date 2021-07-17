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

#ifndef NVFS_P2P_H
#define NVFS_P2P_H

#include "nv-p2p.h"

typedef int (*nvidia_p2p_dma_unmap_pages_fptr) (struct pci_dev*,
		struct nvidia_p2p_page_table*,
		struct nvidia_p2p_dma_mapping*);
typedef int (*nvidia_p2p_get_pages_fptr) (uint64_t, uint32_t,
		uint64_t,
		uint64_t ,
		struct nvidia_p2p_page_table **,
		void (*free_callback)(void *data),
		void *);
typedef int (*nvidia_p2p_put_pages_fptr)(uint64_t, uint32_t,
		uint64_t,
		struct nvidia_p2p_page_table *);
typedef int (*nvidia_p2p_dma_map_pages_fptr)(struct pci_dev *,
		        struct nvidia_p2p_page_table *,
			struct nvidia_p2p_dma_mapping **);
typedef int (*nvidia_p2p_free_dma_mapping_fptr)(struct nvidia_p2p_dma_mapping *);
typedef int (*nvidia_p2p_free_page_table_fptr)(struct nvidia_p2p_page_table *);


int nvfs_nvidia_p2p_dma_unmap_pages(struct pci_dev *peer,
		struct nvidia_p2p_page_table *page_table,
		struct nvidia_p2p_dma_mapping *dma_mapping);
int nvfs_nvidia_p2p_get_pages(uint64_t p2p_token, uint32_t va_space,
		uint64_t virtual_address,
		uint64_t length,
		struct nvidia_p2p_page_table **page_table,
		void (*free_callback)(void *data),
		void *data);
int nvfs_nvidia_p2p_put_pages(uint64_t p2p_token, uint32_t va_space,
		uint64_t virtual_address,
		struct nvidia_p2p_page_table *page_table);
int nvfs_nvidia_p2p_dma_map_pages(struct pci_dev *peer,
		        struct nvidia_p2p_page_table *page_table,
			        struct nvidia_p2p_dma_mapping **dma_mapping);
int nvfs_nvidia_p2p_free_dma_mapping(struct nvidia_p2p_dma_mapping *dma_mapping);
int nvfs_nvidia_p2p_free_page_table(struct nvidia_p2p_page_table *page_table);

int nvfs_nvidia_p2p_init(void);
void nvfs_nvidia_p2p_exit(void);

#endif
