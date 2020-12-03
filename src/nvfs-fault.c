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
#include <linux/debugfs.h>

#include "nvfs-fault.h"
#include "nvfs-core.h"

#ifdef CONFIG_FAULT_INJECTION

static struct dentry *dbgfs_root;

DECLARE_FAULT_ATTR(nvfs_dma_error);
DECLARE_FAULT_ATTR(nvfs_rw_verify_area_error);
DECLARE_FAULT_ATTR(nvfs_end_fence_get_user_pages_fast_error);
DECLARE_FAULT_ATTR(nvfs_invalid_p2p_get_page);
DECLARE_FAULT_ATTR(nvfs_io_transit_state_fail);
DECLARE_FAULT_ATTR(nvfs_pin_shadow_pages_error);
DECLARE_FAULT_ATTR(nvfs_vm_insert_page_error);

void nvfs_init_debugfs(void)
{
        dbgfs_root = debugfs_create_dir("nvfs_inject_fault", NULL);

        if (!dbgfs_root || IS_ERR(dbgfs_root)) {
                dbgfs_root = NULL;
                nvfs_err("Could not initialise debugfs!\n");
                return;
        }

        fault_create_debugfs_attr("dma_error", dbgfs_root,
                                  &nvfs_dma_error);
        fault_create_debugfs_attr("rw_verify_area_error", dbgfs_root,
                                  &nvfs_rw_verify_area_error);
        fault_create_debugfs_attr("end_fence_get_user_pages_fast_error", dbgfs_root,
                                  &nvfs_end_fence_get_user_pages_fast_error);
        fault_create_debugfs_attr("invalid_p2p_get_page", dbgfs_root,
                                  &nvfs_invalid_p2p_get_page);
        fault_create_debugfs_attr("io_transit_state_fail", dbgfs_root,
                                  &nvfs_io_transit_state_fail);
        fault_create_debugfs_attr("pin_shadow_pages_error", dbgfs_root,
                                  &nvfs_pin_shadow_pages_error);
        fault_create_debugfs_attr("vm_insert_page_error", dbgfs_root,
                                  &nvfs_vm_insert_page_error);
}

void nvfs_free_debugfs(void)
{
        if (!dbgfs_root)
                return;

        debugfs_remove_recursive(dbgfs_root);
        dbgfs_root = NULL;
}

#endif
