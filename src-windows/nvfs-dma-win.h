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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - DMA Engine Header
 */

#ifndef __NVFS_DMA_WIN_H__
#define __NVFS_DMA_WIN_H__

#include <ntddk.h>
#include <wdf.h>
#include <storport.h>

// Windows DMA direction constants (equivalent to Linux enum dma_data_direction)
typedef enum _DMA_DATA_DIRECTION {
    DMA_BIDIRECTIONAL = 0,
    DMA_TO_DEVICE = 1,
    DMA_FROM_DEVICE = 2,
    DMA_NONE = 3
} DMA_DATA_DIRECTION;

// Windows feature bitmap definitions (equivalent to Linux)
#define NVFS_FT_PREP_SGLIST_WIN     0x1
#define NVFS_FT_MAP_SGLIST_WIN      0x2
#define NVFS_FT_RDMA_SGLIST_WIN     0x4

// Forward declarations
typedef struct _NVFS_DMA_RW_OPS_WIN NVFS_DMA_RW_OPS_WIN, *PNVFS_DMA_RW_OPS_WIN;
typedef struct _NVFS_RDMA_INFO NVFS_RDMA_INFO, *PNVFS_RDMA_INFO;

// RDMA information structure
typedef struct _NVFS_RDMA_INFO {
    ULONG Version;                  // Structure version
    ULONG Flags;                    // RDMA flags
    ULONGLONG RemVAddr;             // Remote virtual address
    ULONG Size;                     // Size of RDMA region
    ULONG RemKey;                   // Remote key
    // Additional RDMA-specific fields would be added here
} NVFS_RDMA_INFO, *PNVFS_RDMA_INFO;

// Function type definitions for DMA operations (Windows equivalents)
typedef NTSTATUS (*NVFS_MAP_SGLIST_FN_WIN)(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction,
    _In_ ULONG Attributes
);

typedef NTSTATUS (*NVFS_UNMAP_SGLIST_FN_WIN)(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction
);

typedef BOOLEAN (*NVFS_IS_GPU_PAGE_FN_WIN)(
    _In_ PMDL Mdl
);

typedef ULONG (*NVFS_GPU_INDEX_FN_WIN)(
    _In_ PMDL Mdl
);

typedef ULONG (*NVFS_DEVICE_PRIORITY_FN_WIN)(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG GpuIndex
);

typedef NTSTATUS (*NVFS_GET_GPU_SGLIST_RDMA_INFO_FN_WIN)(
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _Out_ PNVFS_RDMA_INFO RdmaInfo
);

// DMA operations structure (Windows equivalent of nvfs_dma_rw_ops)
typedef struct _NVFS_DMA_RW_OPS_WIN {
    ULONG FeatureBitmap;                                    // Supported features
    NVFS_MAP_SGLIST_FN_WIN MapScatterGatherList;          // Map scatter-gather list
    NVFS_UNMAP_SGLIST_FN_WIN UnmapScatterGatherList;      // Unmap scatter-gather list
    NVFS_IS_GPU_PAGE_FN_WIN IsGpuPage;                     // Check if page is GPU memory
    NVFS_GPU_INDEX_FN_WIN GpuIndex;                        // Get GPU index
    NVFS_DEVICE_PRIORITY_FN_WIN DevicePriority;           // Get device priority
    NVFS_GET_GPU_SGLIST_RDMA_INFO_FN_WIN GetGpuSglistRdmaInfo; // Get RDMA info
} NVFS_DMA_RW_OPS_WIN, *PNVFS_DMA_RW_OPS_WIN;

// Function type definitions for module registration
typedef NTSTATUS (*NVFS_REGISTER_DMA_OPS_FN_WIN)(
    _In_ PNVFS_DMA_RW_OPS_WIN DmaOps
);

typedef VOID (*NVFS_UNREGISTER_DMA_OPS_FN_WIN)(VOID);

// Public function declarations

// DMA operation functions
LONG
NvfsCheckGpuSegsWin(
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction
);

NTSTATUS
NvfsMapScatterGatherListWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction,
    _In_ ULONG Attributes
);

NTSTATUS
NvfsUnmapScatterGatherListWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction
);

BOOLEAN
NvfsIsGpuPageWin(
    _In_ PMDL Mdl
);

ULONG
NvfsGpuIndexWin(
    _In_ PMDL Mdl
);

ULONG
NvfsDevicePriorityWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG GpuIndex
);

NTSTATUS
NvfsGetGpuSglistRdmaInfoWin(
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _Out_ PNVFS_RDMA_INFO RdmaInfo
);

// Module management functions
ULONG
NrModulesWin(VOID);

NTSTATUS
ProbeModuleListWin(VOID);

VOID
CleanupModuleListWin(VOID);

// DMA registration functions
NTSTATUS
NvfsBlkRegisterDmaOps(VOID);

VOID
NvfsBlkUnregisterDmaOps(VOID);

// Helper functions
BOOLEAN
NvfsCheckGpuMemoryWin(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ ULONG Length
);

ULONG
NvfsGetGpuIndexFromPhysicalAddressWin(
    _In_ PHYSICAL_ADDRESS PhysicalAddress
);

ULONG
NvfsCalculatePciAffinityWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG GpuIndex
);

PVOID
NvfsGetModuleSymbolWin(
    _In_ PUNICODE_STRING ModuleName,
    _In_ PCWSTR SymbolName
);

// Windows-specific constants and macros
#define NVFS_MAX_GPU_COUNT_WIN          8
#define NVFS_MAX_SEGMENTS_WIN           127
#define NVFS_DMA_ALIGNMENT_WIN          512

// Windows DMA attributes (equivalent to Linux GFP_ flags)
#define NVFS_DMA_ATTR_NORMAL_WIN        0x00000000
#define NVFS_DMA_ATTR_COHERENT_WIN      0x00000001
#define NVFS_DMA_ATTR_STREAMING_WIN     0x00000002

// Error codes specific to DMA operations
#define NVFS_DMA_ERROR_INVALID_SGLIST   ((NTSTATUS)0xE0000001L)
#define NVFS_DMA_ERROR_GPU_MAPPING      ((NTSTATUS)0xE0000002L)
#define NVFS_DMA_ERROR_MIXED_MEMORY     ((NTSTATUS)0xE0000003L)
#define NVFS_DMA_ERROR_NO_ADAPTER       ((NTSTATUS)0xE0000004L)

// Inline helper functions

static __inline BOOLEAN
NvfsIsDmaDirectionValidWin(
    _In_ DMA_DATA_DIRECTION Direction
)
{
    return (Direction >= DMA_BIDIRECTIONAL && Direction <= DMA_NONE);
}

static __inline ULONG
NvfsGetScatterGatherElementCountWin(
    _In_ PSCATTER_GATHER_LIST ScatterGatherList
)
{
    return (ScatterGatherList != NULL) ? ScatterGatherList->NumberOfElements : 0;
}

static __inline ULONG
NvfsGetScatterGatherTotalLengthWin(
    _In_ PSCATTER_GATHER_LIST ScatterGatherList
)
{
    ULONG totalLength = 0;
    ULONG i;
    
    if (ScatterGatherList != NULL) {
        for (i = 0; i < ScatterGatherList->NumberOfElements; i++) {
            totalLength += ScatterGatherList->Elements[i].Length;
        }
    }
    
    return totalLength;
}

#endif // __NVFS_DMA_WIN_H__