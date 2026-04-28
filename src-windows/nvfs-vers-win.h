/*
 * Copyright (c) 2021-2025, NVIDIA CORPORATION. All rights reserved.
 *
 * NVIDIA GDS Windows Version Definitions
 */

#ifndef NVFS_VERS_WIN_H
#define NVFS_VERS_WIN_H

// Version information
#define NVFS_DRIVER_MAJOR_VERSION 1
#define NVFS_DRIVER_MINOR_VERSION 0
#define NVFS_DRIVER_PATCH_VERSION 0
#define NVFS_DRIVER_BUILD_VERSION 1

// Version string
#define NVFS_VERSION_STRING "1.0.0.1"

// Windows file version information
#define NVFS_FILE_VERSION 1,0,0,1
#define NVFS_FILE_VERSION_STRING "1.0.0.1\0"

// Product information
#define NVFS_PRODUCT_NAME "NVIDIA GPUDirect Storage for Windows"
#define NVFS_COMPANY_NAME "NVIDIA Corporation"
#define NVFS_COPYRIGHT "Copyright (c) 2021-2025, NVIDIA Corporation. All rights reserved."

// Build information
#define NVFS_BUILD_DATE __DATE__
#define NVFS_BUILD_TIME __TIME__

#endif /* NVFS_VERS_WIN_H */