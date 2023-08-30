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

#define nvfs_nvidia_p2p_get_pages  nvidia_p2p_get_pages
#define nvfs_nvidia_p2p_put_pages nvidia_p2p_put_pages
#define nvfs_nvidia_p2p_dma_map_pages nvidia_p2p_dma_map_pages
#define nvfs_nvidia_p2p_dma_unmap_pages nvidia_p2p_dma_unmap_pages
#define nvfs_nvidia_p2p_free_page_table nvidia_p2p_free_page_table
#define nvfs_nvidia_p2p_free_dma_mapping nvidia_p2p_free_dma_mapping

#endif
