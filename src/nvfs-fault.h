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
#ifndef NVFS_FAULT_H
#define NVFS_FAULT_H

#include <linux/fault-inject.h>

#ifdef CONFIG_FAULT_INJECTION

extern struct fault_attr nvfs_dma_error;
extern struct fault_attr nvfs_rw_verify_area_error;
extern struct fault_attr nvfs_end_fence_get_user_pages_fast_error;
extern struct fault_attr nvfs_invalid_p2p_get_page;
extern struct fault_attr nvfs_io_transit_state_fail;
extern struct fault_attr nvfs_pin_shadow_pages_error;
extern struct fault_attr nvfs_vm_insert_page_error;

static inline bool nvfs_fault_trigger(void *fault)
{
        return should_fail(fault, 1);
}

void nvfs_init_debugfs(void);
void nvfs_free_debugfs(void);

#else

#define nvfs_init_debugfs() do{} while (0)
#define nvfs_free_debugfs() do{} while (0)

#endif



#endif


