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

#include <linux/module.h>
#include <linux/version.h>

#include "nvfs-p2p.h"
#include "nv-p2p.h"
#include "nvfs-core.h"

extern struct mutex module_mutex;

static nvidia_p2p_dma_unmap_pages_fptr nvidia_p2p_dma_unmap_pages_p = NULL;
static nvidia_p2p_get_pages_fptr nvidia_p2p_get_pages_p = NULL;
static nvidia_p2p_put_pages_fptr nvidia_p2p_put_pages_p = NULL;
static nvidia_p2p_dma_map_pages_fptr nvidia_p2p_dma_map_pages_p = NULL;
static nvidia_p2p_free_dma_mapping_fptr nvidia_p2p_free_dma_mapping_p = NULL;
static nvidia_p2p_free_page_table_fptr nvidia_p2p_free_page_table_p = NULL;

static inline void nvfs_nvidia_put_symbols(void) {
	if(nvidia_p2p_dma_unmap_pages_p) {
		__symbol_put("nvidia_p2p_dma_unmap_pages");
	}
	if(nvidia_p2p_get_pages_p) {
		__symbol_put("nvidia_p2p_get_pages");
	}
	if(nvidia_p2p_put_pages_p) {
		__symbol_put("nvidia_p2p_put_pages");
	}
	if(nvidia_p2p_dma_map_pages_p) {
		__symbol_put("nvidia_p2p_dma_map_pages");
	}
	if(nvidia_p2p_free_dma_mapping_p) {
		__symbol_put("nvidia_p2p_free_dma_mapping");
	}
	if(nvidia_p2p_free_page_table_p) {
		__symbol_put("nvidia_p2p_free_page_table");
	}
	nvidia_p2p_dma_unmap_pages_p = NULL;
	nvidia_p2p_get_pages_p = NULL;
	nvidia_p2p_put_pages_p = NULL;
	nvidia_p2p_dma_map_pages_p = NULL;
	nvidia_p2p_free_dma_mapping_p = NULL;
	nvidia_p2p_free_page_table_p = NULL;
}

int nvfs_nvidia_p2p_init() {
	
	mutex_lock(&module_mutex);

	if(nvidia_p2p_dma_unmap_pages_p == NULL) {
		nvidia_p2p_dma_unmap_pages_p = __symbol_get("nvidia_p2p_dma_unmap_pages");
		if(nvidia_p2p_dma_unmap_pages_p == NULL) {
			nvfs_err("Unable to find symbol: nvidia_p2p_dma_unmap_pages \n");
			goto error;
		}
	}

	if(nvidia_p2p_get_pages_p == NULL) {
		nvidia_p2p_get_pages_p = __symbol_get("nvidia_p2p_get_pages");
		if(nvidia_p2p_get_pages_p == NULL) {
			nvfs_err("Unable to find symbol: nvidia_p2p_get_pages \n");
			goto error;
		}
	}

	if(nvidia_p2p_put_pages_p == NULL) {
		nvidia_p2p_put_pages_p = __symbol_get("nvidia_p2p_put_pages");
		if(nvidia_p2p_put_pages_p == NULL) {
			nvfs_err("Unable to find symbol: nvidia_p2p_put_pages \n");
			goto error;
		}
	}
	
	if(nvidia_p2p_dma_map_pages_p == NULL) {
		nvidia_p2p_dma_map_pages_p = __symbol_get("nvidia_p2p_dma_map_pages");
		if(nvidia_p2p_dma_map_pages_p == NULL) {
			nvfs_err("Unable to find symbol: nvidia_p2p_dma_map_pages \n");
			goto error;
		}
	}

	if(nvidia_p2p_free_dma_mapping_p == NULL) {
		nvidia_p2p_free_dma_mapping_p = __symbol_get("nvidia_p2p_free_dma_mapping");
		if(nvidia_p2p_free_dma_mapping_p == NULL) {
			nvfs_err("Unable to find symbol: nvidia_p2p_free_dma_mapping \n");
			goto error;
		}
	}

	if(nvidia_p2p_free_page_table_p == NULL) {
		nvidia_p2p_free_page_table_p = __symbol_get("nvidia_p2p_free_page_table");
		if(nvidia_p2p_free_page_table_p == NULL) {
			nvfs_err("Unable to find symbol: nvidia_p2p_free_page_table \n");
			goto error;
		}
	}
	mutex_unlock(&module_mutex);
	return 0;
error:
	mutex_unlock(&module_mutex);
	nvfs_nvidia_put_symbols();
	return -1;
}

void nvfs_nvidia_p2p_exit() {
	mutex_lock(&module_mutex);
	nvfs_nvidia_put_symbols();
	mutex_unlock(&module_mutex);
}

int nvfs_nvidia_p2p_dma_unmap_pages(struct pci_dev *peer,
		struct nvidia_p2p_page_table *page_table,
		struct nvidia_p2p_dma_mapping *dma_mapping) {
	if(nvidia_p2p_dma_unmap_pages_p) {
		return nvidia_p2p_dma_unmap_pages_p(peer, page_table, dma_mapping);
	} else {
		return -ENOMEM;
	}
}
int nvfs_nvidia_p2p_get_pages(uint64_t p2p_token, uint32_t va_space,
		uint64_t virtual_address,
		uint64_t length,
		struct nvidia_p2p_page_table **page_table,
		void (*free_callback)(void *data),
		void *data) {
	if(nvidia_p2p_get_pages_p) {
		return nvidia_p2p_get_pages_p(p2p_token, va_space, virtual_address, length, page_table, free_callback, data);
	} else {
		return -ENOMEM;
	}
}
int nvfs_nvidia_p2p_put_pages(uint64_t p2p_token, uint32_t va_space,
		uint64_t virtual_address,
		struct nvidia_p2p_page_table *page_table) {
	if(nvidia_p2p_put_pages_p) {
		return nvidia_p2p_put_pages_p(p2p_token, va_space, virtual_address, page_table);
	} else {
		return -ENOMEM;
	}
}
int nvfs_nvidia_p2p_dma_map_pages(struct pci_dev *peer,
		        struct nvidia_p2p_page_table *page_table,
			        struct nvidia_p2p_dma_mapping **dma_mapping) {
	if(nvidia_p2p_dma_map_pages_p) {
		return nvidia_p2p_dma_map_pages_p(peer, page_table, dma_mapping);
	} else {
		return -ENOMEM;
	}
}
int nvfs_nvidia_p2p_free_dma_mapping(struct nvidia_p2p_dma_mapping *dma_mapping) {
	if(nvidia_p2p_free_dma_mapping_p) {
		return nvidia_p2p_free_dma_mapping_p(dma_mapping);
	} else {
		return -ENOMEM;
	}
}
int nvfs_nvidia_p2p_free_page_table(struct nvidia_p2p_page_table *page_table) {
	if(nvidia_p2p_free_page_table_p) {
		return nvidia_p2p_free_page_table_p(page_table);
	} else {
		return -ENOMEM;
	}
}
