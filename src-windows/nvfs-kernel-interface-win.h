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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Kernel Interface Header
 */

#ifndef __NVFS_KERNEL_INTERFACE_WIN_H__
#define __NVFS_KERNEL_INTERFACE_WIN_H__

#include <ntddk.h>
#include <wdf.h>
#include <ntddstor.h>
#include <storport.h>

// Access type enumeration for memory validation
typedef enum _NVFS_ACCESS_TYPE_WIN {
    NvfsAccessRead = 0,
    NvfsAccessWrite,
    NvfsAccessReadWrite
} NVFS_ACCESS_TYPE_WIN;

// MDL page information structure
typedef struct _NVFS_MDL_PAGE_INFO_WIN {
    ULONG TotalPages;                   // Total number of pages in MDL
    ULONG FragmentCount;                // Number of non-contiguous fragments
    BOOLEAN IsContiguous;               // Whether all pages are physically contiguous
    PHYSICAL_ADDRESS FirstPhysicalAddress;  // Physical address of first page
    PHYSICAL_ADDRESS LastPhysicalAddress;   // Physical address of last page
    SIZE_T TotalSize;                   // Total size in bytes
} NVFS_MDL_PAGE_INFO_WIN, *PNVFS_MDL_PAGE_INFO_WIN;

// Windows version compatibility constants
#define NVFS_WIN_VERSION_VISTA_MAJOR        6
#define NVFS_WIN_VERSION_VISTA_MINOR        0
#define NVFS_WIN_VERSION_WIN7_MAJOR         6
#define NVFS_WIN_VERSION_WIN7_MINOR         1
#define NVFS_WIN_VERSION_WIN8_MAJOR         6
#define NVFS_WIN_VERSION_WIN8_MINOR         2
#define NVFS_WIN_VERSION_WIN10_MAJOR        10
#define NVFS_WIN_VERSION_WIN10_MINOR        0

// Memory alignment constants
#define NVFS_MEMORY_ALIGNMENT_4K            4096
#define NVFS_MEMORY_ALIGNMENT_64K           65536
#define NVFS_MEMORY_ALIGNMENT_2M            (2 * 1024 * 1024)

// Function prototypes

// Initialization and cleanup
NTSTATUS
NvfsInitializeKernelInterfaceWin(VOID);

VOID
NvfsCleanupKernelInterfaceWin(VOID);

// Memory access validation (Windows equivalent of Linux access_ok)
BOOLEAN
NvfsCheckAccessWin(
    _In_ NVFS_ACCESS_TYPE_WIN AccessType,
    _In_ PVOID UserBuffer,
    _In_ SIZE_T BufferSize
);

// Scatter-gather list manipulation
NTSTATUS
NvfsExtendScatterGatherListWin(
    _Inout_ PSCATTER_GATHER_LIST* ScatterGatherList,
    _In_ ULONG AdditionalElements
);

// Physical memory contiguity checking
BOOLEAN
NvfsCheckPhysicalContiguityWin(
    _In_ PHYSICAL_ADDRESS PrevPhysAddr,
    _In_ ULONG PrevLength,
    _In_ PHYSICAL_ADDRESS CurrPhysAddr
);

// MDL analysis and manipulation
NTSTATUS
NvfsAnalyzeMdlPagesWin(
    _In_ PMDL Mdl,
    _Out_ PNVFS_MDL_PAGE_INFO_WIN PageInfo
);

// User buffer locking and unlocking
NTSTATUS
NvfsLockUserBufferWin(
    _In_ PVOID UserBuffer,
    _In_ SIZE_T BufferSize,
    _In_ NVFS_ACCESS_TYPE_WIN AccessType,
    _Outptr_ PMDL* Mdl
);

VOID
NvfsUnlockUserBufferWin(
    _In_ PMDL Mdl
);

// DMA adapter interface
NTSTATUS
NvfsGetDmaAdapterWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG MaximumLength,
    _Outptr_ PDMA_ADAPTER* DmaAdapter
);

// Storage stack integration
NTSTATUS
NvfsGetStorageDeviceNumberWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PSTORAGE_DEVICE_NUMBER DeviceNumber
);

// Version compatibility
BOOLEAN
NvfsIsWindowsVersionCompatibleWin(
    _In_ ULONG MajorVersion,
    _In_ ULONG MinorVersion
);

// Error handling and logging
VOID
NvfsLogKernelErrorWin(
    _In_ NTSTATUS ErrorCode,
    _In_ PCSTR Function,
    _In_ ULONG Line
);

// Memory alignment utilities
BOOLEAN
NvfsIsMemoryAlignedWin(
    _In_ PVOID Address,
    _In_ SIZE_T Alignment
);

SIZE_T
NvfsAlignSizeWin(
    _In_ SIZE_T Size,
    _In_ SIZE_T Alignment
);

PVOID
NvfsAlignAddressWin(
    _In_ PVOID Address,
    _In_ SIZE_T Alignment
);

// Inline helper functions

// Windows equivalent of Linux page_index calculation
static __inline ULONG_PTR
NvfsGetPageIndexWin(
    _In_ PVOID Address
)
{
    return (ULONG_PTR)Address >> PAGE_SHIFT;
}

// Physical page mergeability check (Windows equivalent of GPU_BIOVEC_PHYS_MERGEABLE)
static __inline BOOLEAN
NvfsArePhysicalPagesMergeableWin(
    _In_ PHYSICAL_ADDRESS PrevPageAddr,
    _In_ PHYSICAL_ADDRESS CurrPageAddr
)
{
    ULONG_PTR prevPageIndex = (ULONG_PTR)(PrevPageAddr.QuadPart >> PAGE_SHIFT);
    ULONG_PTR currPageIndex = (ULONG_PTR)(CurrPageAddr.QuadPart >> PAGE_SHIFT);
    
    return (prevPageIndex == (currPageIndex - 1));
}

// Convert physical frame number to physical address
static __inline PHYSICAL_ADDRESS
NvfsPfnToPhysicalAddressWin(
    _In_ PFN_NUMBER Pfn
)
{
    PHYSICAL_ADDRESS physAddr;
    physAddr.QuadPart = (ULONGLONG)Pfn << PAGE_SHIFT;
    return physAddr;
}

// Convert physical address to physical frame number
static __inline PFN_NUMBER
NvfsPhysicalAddressToPfnWin(
    _In_ PHYSICAL_ADDRESS PhysAddr
)
{
    return (PFN_NUMBER)(PhysAddr.QuadPart >> PAGE_SHIFT);
}

// Round up to page boundary
static __inline SIZE_T
NvfsRoundUpToPageWin(
    _In_ SIZE_T Size
)
{
    return (Size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

// Round down to page boundary
static __inline SIZE_T
NvfsRoundDownToPageWin(
    _In_ SIZE_T Size
)
{
    return Size & ~(PAGE_SIZE - 1);
}

// Check if address is page-aligned
static __inline BOOLEAN
NvfsIsPageAlignedWin(
    _In_ PVOID Address
)
{
    return ((ULONG_PTR)Address & (PAGE_SIZE - 1)) == 0;
}

// Get number of pages spanned by a buffer
static __inline ULONG
NvfsGetPageSpanWin(
    _In_ PVOID StartAddress,
    _In_ SIZE_T Size
)
{
    return ADDRESS_AND_SIZE_TO_SPAN_PAGES(StartAddress, Size);
}

// Convenience macros

// Error logging with function and line information
#define NVFS_LOG_ERROR_WIN(status) \
    NvfsLogKernelErrorWin((status), __FUNCTION__, __LINE__)

// Safe MDL cleanup
#define NVFS_SAFE_UNLOCK_MDL_WIN(mdl) \
    do { \
        if ((mdl) != NULL) { \
            NvfsUnlockUserBufferWin(mdl); \
            (mdl) = NULL; \
        } \
    } while (0)

// Safe DMA adapter cleanup
#define NVFS_SAFE_PUT_DMA_ADAPTER_WIN(adapter) \
    do { \
        if ((adapter) != NULL) { \
            (adapter)->DmaOperations->PutDmaAdapter(adapter); \
            (adapter) = NULL; \
        } \
    } while (0)

// Access validation with automatic error logging
#define NVFS_VALIDATE_ACCESS_WIN(accessType, buffer, size) \
    (NvfsCheckAccessWin((accessType), (buffer), (size)) ? TRUE : \
     (NVFS_LOG_ERROR_WIN(STATUS_ACCESS_VIOLATION), FALSE))

// Memory alignment validation
#define NVFS_REQUIRE_ALIGNMENT_WIN(addr, alignment) \
    do { \
        if (!NvfsIsMemoryAlignedWin((addr), (alignment))) { \
            NVFS_LOG_ERROR_WIN(STATUS_DATATYPE_MISALIGNMENT); \
            return STATUS_DATATYPE_MISALIGNMENT; \
        } \
    } while (0)

// Version compatibility checking
#define NVFS_REQUIRE_MIN_WINDOWS_VERSION_WIN(major, minor) \
    do { \
        if (!NvfsIsWindowsVersionCompatibleWin((major), (minor))) { \
            NVFS_LOG_ERROR_WIN(STATUS_NOT_SUPPORTED); \
            return STATUS_NOT_SUPPORTED; \
        } \
    } while (0)

// Windows fault type for VM fault handling
typedef NTSTATUS NVFS_VMA_FAULT_T_WIN;

// Success and error codes for fault handling
#define NVFS_VM_FAULT_NOPAGE_WIN        STATUS_UNSUCCESSFUL
#define NVFS_VM_FAULT_SIGBUS_WIN        STATUS_ACCESS_VIOLATION
#define NVFS_VM_FAULT_OOM_WIN           STATUS_INSUFFICIENT_RESOURCES
#define NVFS_VM_FAULT_HWPOISON_WIN      STATUS_DEVICE_HARDWARE_ERROR

// I/O operation types
typedef enum _NVFS_IO_OPERATION_TYPE_WIN {
    NvfsIoOperationRead = 0,
    NvfsIoOperationWrite,
    NvfsIoOperationBatch
} NVFS_IO_OPERATION_TYPE_WIN;

// I/O status tracking structure
typedef struct _NVFS_IO_STATUS_WIN {
    NTSTATUS Status;
    ULONG_PTR Information;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    NVFS_IO_OPERATION_TYPE_WIN OperationType;
} NVFS_IO_STATUS_WIN, *PNVFS_IO_STATUS_WIN;

// Initialize I/O status structure
static __inline VOID
NvfsInitializeIoStatusWin(
    _Out_ PNVFS_IO_STATUS_WIN IoStatus,
    _In_ NVFS_IO_OPERATION_TYPE_WIN OperationType
)
{
    RtlZeroMemory(IoStatus, sizeof(NVFS_IO_STATUS_WIN));
    IoStatus->OperationType = OperationType;
    KeQueryPerformanceCounter(&IoStatus->StartTime);
}

// Complete I/O status structure
static __inline VOID
NvfsCompleteIoStatusWin(
    _Inout_ PNVFS_IO_STATUS_WIN IoStatus,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
)
{
    IoStatus->Status = Status;
    IoStatus->Information = Information;
    KeQueryPerformanceCounter(&IoStatus->EndTime);
}

#endif // __NVFS_KERNEL_INTERFACE_WIN_H__