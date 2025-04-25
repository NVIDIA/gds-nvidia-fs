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
#ifndef __NVFS_DRIVER_VERSION_H_
#define __NVFS_DRIVER_VERSION_H_

/* please update the driver version here and also the debian change log*/

#define NVFS_DRIVER_MAJOR_VERSION   2 //2-bytes

#define NVFS_DRIVER_MINOR_VERSION   25 //2-bytes

// template for build version
#define NVFS_DRIVER_PATCH_VERSION  6

static inline unsigned int nvfs_driver_version(void) {
    return (NVFS_DRIVER_MAJOR_VERSION << 16) | NVFS_DRIVER_MINOR_VERSION;
}

static inline unsigned short nvfs_major_version(unsigned int version) {
    return (version >> 16);
}

static inline unsigned short nvfs_minor_version(unsigned int version) {
    return (unsigned short) version;
}

#endif
