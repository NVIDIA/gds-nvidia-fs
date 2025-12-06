/*
 * Copyright (c) 2021-2025, NVIDIA CORPORATION. All rights reserved.
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
 * NVIDIA GDS (GPUDirect Storage) Windows Configuration Header
 * This file contains Windows-specific configuration settings and feature flags
 */

#ifndef __CONFIG_HOST_WIN_H__
#define __CONFIG_HOST_WIN_H__

// Windows kernel version requirements
#define NTDDI_VERSION NTDDI_WIN10_RS1
#define _WIN32_WINNT _WIN32_WINNT_WIN10

// Core Windows driver configuration
#define NVFS_WINDOWS_DRIVER                     1
#define NVFS_USE_KMDF                           1
#define NVFS_USE_WDF_VERSION                    2

// Feature flags - Core functionality
#define NVFS_ENABLE_DMA_WIN                     1
#define NVFS_ENABLE_P2P_WIN                     1
#define NVFS_ENABLE_BATCH_IO_WIN                1
#define NVFS_ENABLE_MEMORY_MAPPING_WIN          1
#define NVFS_ENABLE_PCI_WIN                     1

// Feature flags - Optional functionality
#define NVFS_ENABLE_RDMA_SUPPORT_WIN            1
#define NVFS_ENABLE_FAULT_INJECTION_WIN         1
#define NVFS_ENABLE_STATISTICS_WIN              1
#define NVFS_ENABLE_REGISTRY_CONFIG_WIN         1
#define NVFS_ENABLE_PROC_INTERFACE_WIN          1

// Feature flags - Advanced functionality
#define NVFS_ENABLE_ETW_LOGGING_WIN             1
#define NVFS_ENABLE_WMI_COUNTERS_WIN            1
#define NVFS_ENABLE_PERFORMANCE_COUNTERS_WIN    1
#define NVFS_ENABLE_GPU_STATISTICS_WIN          1

// Memory allocation tags
#define NVFS_CORE_TAG                           'cGDS'     // Core components
#define NVFS_MMAP_TAG                           'mGDS'     // Memory mapping
#define NVFS_DMA_TAG                            'dGDS'     // DMA operations
#define NVFS_PCI_TAG                            'pGDS'     // PCI management
#define NVFS_BATCH_TAG                          'bGDS'     // Batch operations
#define NVFS_STAT_TAG                           'tGDS'     // Statistics
#define NVFS_FAULT_TAG                          'fGDS'     // Fault injection
#define NVFS_RDMA_TAG                           'rGDS'     // RDMA operations
#define NVFS_REGISTRY_TAG                       'gGDS'     // Registry operations
#define NVFS_PROC_TAG                           'PGDS'     // Proc interface

// Maximum limits and sizes
#define NVFS_MAX_DEVICES_WIN                    32         // Maximum GPU devices
#define NVFS_MAX_CONCURRENT_IOS_WIN             1024       // Maximum concurrent I/O operations
#define NVFS_MAX_SCATTER_GATHER_ELEMENTS_WIN    256        // Maximum S/G elements per I/O
#define NVFS_MAX_TRANSFER_SIZE_WIN              (64 * 1024 * 1024)  // 64MB max transfer
#define NVFS_MAX_MEMORY_GROUPS_WIN              512        // Maximum memory groups
#define NVFS_MAX_PCI_DEVICES_WIN                64         // Maximum PCI devices to track
#define NVFS_MAX_RDMA_CONNECTIONS_WIN           32         // Maximum RDMA connections
#define NVFS_MAX_BATCH_SIZE_WIN                 64         // Maximum batch size

// Buffer and pool sizes
#define NVFS_DEFAULT_POOL_SIZE_WIN              (4 * 1024 * 1024)   // 4MB default pool
#define NVFS_LOOKASIDE_DEPTH_WIN                256        // Lookaside list depth
#define NVFS_HASH_TABLE_SIZE_WIN                256        // Hash table bucket count
#define NVFS_STATISTICS_BUFFER_SIZE_WIN         (64 * 1024) // Statistics buffer size

// Timing and timeout values (in milliseconds)
#define NVFS_DEFAULT_TIMEOUT_WIN                30000      // 30 seconds
#define NVFS_DMA_TIMEOUT_WIN                    5000       // 5 seconds
#define NVFS_P2P_TIMEOUT_WIN                    10000      // 10 seconds
#define NVFS_RDMA_TIMEOUT_WIN                   15000      // 15 seconds
#define NVFS_STATS_UPDATE_INTERVAL_WIN          1000       // 1 second
#define NVFS_REGISTRY_SYNC_INTERVAL_WIN         5000       // 5 seconds

// Performance and optimization settings
#define NVFS_USE_LOOKASIDE_LISTS_WIN            1
#define NVFS_ENABLE_PREFETCH_WIN                1
#define NVFS_ENABLE_WRITE_COMBINING_WIN         1
#define NVFS_ENABLE_DMA_COHERENCY_WIN           1
#define NVFS_ENABLE_INTERRUPT_COALESCING_WIN    1
#define NVFS_USE_WORK_QUEUES_WIN                1

// Debug and validation settings
#ifdef DBG
#define NVFS_ENABLE_DEBUG_WIN                   1
#define NVFS_ENABLE_VALIDATION_WIN              1
#define NVFS_ENABLE_ASSERT_WIN                  1
#define NVFS_DEFAULT_DEBUG_LEVEL_WIN            3
#else
#define NVFS_ENABLE_DEBUG_WIN                   0
#define NVFS_ENABLE_VALIDATION_WIN              0
#define NVFS_ENABLE_ASSERT_WIN                  0
#define NVFS_DEFAULT_DEBUG_LEVEL_WIN            1
#endif

// Compatibility settings
#define NVFS_SUPPORT_LEGACY_APIS_WIN            1
#define NVFS_BACKWARD_COMPATIBILITY_WIN         1
#define NVFS_MIN_WINDOWS_VERSION_WIN            _WIN32_WINNT_WIN10

// Registry configuration paths
#define NVFS_REGISTRY_ROOT_WIN                  L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs"
#define NVFS_REGISTRY_PARAMETERS_WIN            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs\\Parameters"
#define NVFS_REGISTRY_PERFORMANCE_WIN           L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs\\Performance"
#define NVFS_REGISTRY_DEBUG_WIN                 L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs\\Debug"

// Device interface and symbolic link names
#define NVFS_DEVICE_NAME_WIN                    L"\\Device\\nvfs"
#define NVFS_SYMBOLIC_LINK_NAME_WIN             L"\\DosDevices\\nvfs"
#define NVFS_NT_DEVICE_NAME_WIN                 L"\\Device\\nvfs"

// Event logging and tracing
#define NVFS_ETW_PROVIDER_NAME_WIN              L"NVIDIA-GDS-Driver"
#define NVFS_EVENT_LOG_SOURCE_WIN               L"nvfs"

// Hardware-specific settings
#define NVFS_PCI_CONFIG_SPACE_SIZE_WIN          256
#define NVFS_PCIE_CAPABILITY_SIZE_WIN           64
#define NVFS_GPU_BAR_ALIGNMENT_WIN              (4 * 1024)         // 4KB alignment
#define NVFS_DMA_ALIGNMENT_WIN                  64                 // 64-byte alignment
#define NVFS_MEMORY_PAGE_SIZE_WIN               4096               // 4KB pages

// Network and RDMA settings
#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN
#define NVFS_RDMA_PORT_WIN                      18515
#define NVFS_RDMA_QUEUE_DEPTH_WIN               256
#define NVFS_RDMA_MAX_SGE_WIN                   16
#define NVFS_RDMA_MAX_INLINE_DATA_WIN           256
#endif

// Version and build information macros
#define NVFS_CONFIG_VERSION_WIN                 1
#define NVFS_BUILD_TYPE_WIN                     "Windows Kernel Driver"

// Feature detection macros
#define NVFS_HAS_FEATURE_WIN(feature)           (NVFS_ENABLE_##feature##_WIN)
#define NVFS_FEATURE_ENABLED_WIN(feature)       (NVFS_ENABLE_##feature##_WIN == 1)

// Conditional compilation helpers
#if NVFS_ENABLE_DEBUG_WIN
#define NVFS_DEBUG_CODE_WIN(code)               do { code } while (0)
#define NVFS_DEBUG_PRINT_WIN(format, ...)      DbgPrint("NVFS: " format "\n", __VA_ARGS__)
#else
#define NVFS_DEBUG_CODE_WIN(code)               ((void)0)
#define NVFS_DEBUG_PRINT_WIN(format, ...)      ((void)0)
#endif

#if NVFS_ENABLE_VALIDATION_WIN
#define NVFS_VALIDATE_WIN(condition)            NT_ASSERT(condition)
#else
#define NVFS_VALIDATE_WIN(condition)            ((void)0)
#endif

// Memory allocation macros
#define NVFS_ALLOCATE_WIN(size, tag)            ExAllocatePoolWithTag(NonPagedPool, (size), (tag))
#define NVFS_FREE_WIN(ptr, tag)                 ExFreePoolWithTag((ptr), (tag))

// Safe allocation macros with validation
#define NVFS_SAFE_ALLOCATE_WIN(ptr, size, tag) \
    do { \
        (ptr) = NVFS_ALLOCATE_WIN((size), (tag)); \
        if ((ptr) != NULL) { \
            RtlZeroMemory((ptr), (size)); \
        } \
    } while (0)

#define NVFS_SAFE_FREE_WIN(ptr, tag) \
    do { \
        if ((ptr) != NULL) { \
            NVFS_FREE_WIN((ptr), (tag)); \
            (ptr) = NULL; \
        } \
    } while (0)

// String and path length limits
#define NVFS_MAX_DEVICE_NAME_LENGTH_WIN         64
#define NVFS_MAX_REGISTRY_KEY_LENGTH_WIN        256
#define NVFS_MAX_REGISTRY_VALUE_LENGTH_WIN      64
#define NVFS_MAX_ERROR_MESSAGE_LENGTH_WIN       512

// Configuration validation
#if !defined(NVFS_WINDOWS_DRIVER) || NVFS_WINDOWS_DRIVER != 1
#error "This configuration is only for Windows kernel drivers"
#endif

#if !defined(NVFS_USE_KMDF) || NVFS_USE_KMDF != 1
#error "Windows implementation requires KMDF framework"
#endif

// End of configuration
#endif /* __CONFIG_HOST_WIN_H__ */