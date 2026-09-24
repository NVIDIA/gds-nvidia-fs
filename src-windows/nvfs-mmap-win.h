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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Memory Management Definitions
 */

#ifndef NVFS_MMAP_WIN_H
#define NVFS_MMAP_WIN_H

// Windows kernel includes
#include <ntddk.h>
#include <wdf.h>

// Memory allocation constants
#define NVFS_MAX_SHADOW_PAGES_ORDER 20
#define NVFS_MAX_SHADOW_PAGES (1 << NVFS_MAX_SHADOW_PAGES_ORDER)
#define NVFS_MAX_SHADOW_ALLOCS_ORDER 14
#define NVFS_MAX_SHADOW_ALLOCS (1 << NVFS_MAX_SHADOW_ALLOCS_ORDER)

#define MAX_PCI_BUCKETS 32
#define MAX_PCI_BUCKETS_BITS 5  // log2(32)
#define MAX_RDMA_REGS_SUPPORTED 16

// Forward declarations
typedef struct _NVFS_GPU_ARGS NVFS_GPU_ARGS, *PNVFS_GPU_ARGS;

// Windows equivalent of Linux nvfs_block_state enum
typedef enum _NVFS_BLOCK_STATE {
    NVFS_IO_FREE = 0,       // Set on initialization
    NVFS_IO_ALLOC,          // Allocated
    NVFS_IO_INIT,           // Initialized
    NVFS_IO_QUEUED,         // Queued for processing
    NVFS_IO_DMA_START,      // DMA started
    NVFS_IO_DONE,           // I/O completed
    NVFS_IO_DMA_ERROR,      // DMA error occurred
    NVFS_IO_LAST_STATE = NVFS_IO_DMA_ERROR,
} NVFS_BLOCK_STATE;

// Windows equivalent of Linux IO state enumeration
typedef enum _NVFS_IO_STATE {
    IO_READY = 0,
    IO_IN_PROGRESS,
    IO_TERMINATE_REQ,
    IO_TERMINATED,
    IO_CALLBACK_REQ,
    IO_CALLBACK_END
} NVFS_IO_STATE;

// Windows equivalent of Linux sparse data enumeration
typedef enum _NVFS_METASTATE_ENUM {
    NVFS_METASTATE_NORMAL = 0,
    NVFS_METASTATE_SPARSE,
    NVFS_METASTATE_ERROR
} NVFS_METASTATE_ENUM;

// Windows equivalent of Linux RDMA information structure
typedef struct _NVFS_RDMA_INFO {
    UCHAR Version;           // Structure version for future compatibility
    UCHAR Flags;             // Flags (bit 0: GID field valid)
    USHORT Lid;              // Subnet local identifier
    ULONG QpNum;             // Queue pair number
    
    // Client shadow buffer (GPU buffer) info for RDMA setup
    ULONGLONG RemVAddr;      // Remote virtual address
    ULONG Size;              // Buffer size
    ULONG RKey;              // Remote key
    
    // Client information for RDMA setup
    ULONGLONG Gid[2];        // 16-byte global identifier
    ULONG DcKey;             // Datagram connection key
} NVFS_RDMA_INFO, *PNVFS_RDMA_INFO;

// Windows equivalent of Linux PCI device mapping structure
typedef struct _PCI_DEV_MAPPING {
    PVOID DmaMapping;           // Windows DMA mapping (equivalent to p2p_dma_mapping)
    PDEVICE_OBJECT PciDevice;   // PCI device object
    ULONG DmaChunkCount;        // Number of DMA chunks
    LIST_ENTRY ListEntry;       // List entry for hash table
} PCI_DEV_MAPPING, *PPCI_DEV_MAPPING;

// Windows equivalent of Linux NVIDIA P2P page table
typedef struct _NVIDIA_P2P_PAGE_TABLE_WIN {
    ULONG PageCount;            // Number of pages
    ULONGLONG* PhysicalAddresses; // Array of physical addresses
    PVOID VirtualAddress;       // Virtual address
    ULONG PageSize;             // Page size
    PVOID P2PToken;             // P2P token from NVIDIA driver
} NVIDIA_P2P_PAGE_TABLE_WIN, *PNVIDIA_P2P_PAGE_TABLE_WIN;

// Windows equivalent of Linux nvfs_gpu_args structure
typedef struct _NVFS_GPU_ARGS {
    PNVIDIA_P2P_PAGE_TABLE_WIN PageTable;  // P2P page table
    ULONGLONG GpuVAddr;                     // GPU buffer virtual address
    ULONGLONG GpuBufLen;                    // GPU buffer length
    PMDL EndFenceMdl;                       // End fence MDL
    ULONG OffsetInPage;                     // End fence byte offset in page
    LONG IoState;                           // I/O state (using InterlockedXxx functions)
    LONG DmaMappingInProgress;              // DMA mapping in progress flag
    LONG CallbackInvoked;                   // Callback invoked flag
    KEVENT CallbackEvent;                   // Event for I/O completion
    BOOLEAN IsBounceBuffer;                 // Bounce buffer flag
    BOOLEAN UseLegacyP2pAllocation;         // Use legacy P2P allocation
    ULONG PhysicalChunkCount;               // Number of contiguous physical ranges
    ULONGLONG PciDevInfo;                   // PCI domain/bus/device/function info
    ULONG GpuHashIndex;                     // GPU hash index for PCI lookups
    LIST_ENTRY PciBuckets[MAX_PCI_BUCKETS]; // PCI device buckets
} NVFS_GPU_ARGS, *PNVFS_GPU_ARGS;

// Windows equivalent of Linux nvfs_io structure
typedef struct _NVFS_IO {
    SSIZE_T ReturnValue;                    // Return value from I/O
    LONGLONG FileOffset;                    // File offset
    LONGLONG GpuPageOffset;                 // GPU page offset
    ULONGLONG EndFenceValue;                // End fence value
    HANDLE FileHandle;                      // File handle
    ULONG Operation;                        // Operation type
    BOOLEAN Synchronous;                    // Synchronous flag
    BOOLEAN HighPriority;                   // High priority flag
    BOOLEAN CheckSparse;                    // Check for sparse files
    BOOLEAN RwStatsEnabled;                 // R/W statistics enabled
    ULONG_PTR CurrentGpuBaseIndex;          // Current GPU base index
    ULONG_PTR ActiveBlocksStart;            // Active blocks start
    ULONG_PTR ActiveBlocksEnd;              // Active blocks end
    NVFS_METASTATE_ENUM State;              // Sparse data state
    ULONG RetryCount;                       // Retry count for errors
    KEVENT RwEvent;                         // Event for serializing DMA requests
    LARGE_INTEGER StartIo;                  // Start time for latency calculation
    SSIZE_T RdmaSegmentOffset;              // RDMA segment offset
    BOOLEAN UseRKeys;                       // Use RDMA keys for I/O
} NVFS_IO, *PNVFS_IO;

// Windows equivalent of Linux nvfs_io_metadata structure
typedef struct _NVFS_IO_METADATA {
    ULONGLONG NvfsStartMagic;               // Start magic value
    NVFS_BLOCK_STATE NvfsState;             // Block state
    PMDL PageMdl;                           // MDL for the page
} NVFS_IO_METADATA, *PNVFS_IO_METADATA;

// Windows equivalent of Linux nvfs_io_mgroup structure
typedef struct _NVFS_IO_MGROUP {
    LONG RefCount;                          // Reference count (atomic)
    LONG DmaRefCount;                       // DMA reference count (atomic)
    LIST_ENTRY HashLink;                    // Hash table link
    ULONGLONG CpuBaseVAddr;                 // CPU base virtual address
    ULONG_PTR BaseIndex;                    // Base index for hash table
    ULONG_PTR NvfsBlocksCount;              // Number of NVFS blocks
    PMDL* PageMdls;                         // Array of page MDLs
    PNVFS_IO_METADATA NvfsMetadata;         // Metadata array
    NVFS_GPU_ARGS GpuInfo;                  // GPU information
    NVFS_IO NvfsIo;                         // I/O structure
    PMDL ShadowMdl;                         // Shadow buffer MDL
    PMDL GpuMdl;                            // GPU buffer MDL
#ifdef NVFS_ENABLE_WIN_RDMA_SUPPORT
    NVFS_RDMA_INFO RdmaInfo;                // RDMA information
#endif
    LONG NextSegment;                       // Next segment counter
#ifdef CONFIG_FAULT_INJECTION
    BOOLEAN FaultInjected;                  // Fault injection flag
#endif
} NVFS_IO_MGROUP, *PNVFS_IO_MGROUP;

// Function prototypes

// Initialization and cleanup
NTSTATUS NvfsMgroupInit(VOID);
VOID NvfsMgroupCleanup(VOID);

// Memory group management
PNVFS_IO_MGROUP NvfsMgroupGet(_In_ ULONG_PTR BaseIndex);
VOID NvfsMgroupPut(_In_ PNVFS_IO_MGROUP MGroup);
VOID NvfsMgroupGetRef(_In_ PNVFS_IO_MGROUP MGroup);
BOOLEAN NvfsMgroupPutRef(_In_ PNVFS_IO_MGROUP MGroup);

// Memory mapping
NTSTATUS NvfsMgroupMmap(
    _In_ WDFFILEOBJECT FileObject,
    _In_ WDFREQUEST Request,
    _In_ PVOID InputBuffer,
    _In_ SIZE_T InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ SIZE_T OutputBufferLength,
    _Out_ PSIZE_T BytesReturned
);

// Memory group lookup functions
PNVFS_IO_MGROUP NvfsMgroupFromPage(_In_ PMDL Mdl);
PNVFS_IO_MGROUP NvfsMgroupFromPageRange(
    _In_ PMDL Mdl,
    _In_ ULONG BlockCount,
    _In_ ULONG StartOffset
);
PNVFS_IO_MGROUP NvfsGetMgroupFromVaddr(_In_ ULONG_PTR VirtualAddress);

// State management
VOID NvfsMgroupCheckAndSet(
    _In_ PNVFS_IO_MGROUP MGroup,
    _In_ NVFS_BLOCK_STATE State,
    _In_ BOOLEAN Validate,
    _In_ BOOLEAN UpdateNvfsIo
);

// Utility functions
static FORCEINLINE BOOLEAN
NvfsCheckGpuPage(
    _In_ PMDL Mdl,
    _In_ ULONG Offset,
    _In_ ULONG Length
)
{
    // Windows implementation would check if the MDL represents GPU memory
    // This requires integration with NVIDIA's Windows P2P SDK
    UNREFERENCED_PARAMETER(Mdl);
    UNREFERENCED_PARAMETER(Offset);
    UNREFERENCED_PARAMETER(Length);
    
    // Placeholder implementation
    return FALSE;
}

static FORCEINLINE BOOLEAN
NvfsCheckGpuPageAndError(
    _In_ PMDL Mdl,
    _In_ ULONG Offset,
    _In_ ULONG Length
)
{
    // Windows implementation for GPU page validation with error checking
    if (Mdl == NULL || Length == 0) {
        return FALSE;
    }
    
    return NvfsCheckGpuPage(Mdl, Offset, Length);
}

// MDL manipulation functions
static FORCEINLINE ULONG
NvfsGetMdlPageCount(
    _In_ PMDL Mdl
)
{
    if (Mdl == NULL) {
        return 0;
    }
    
    return ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(Mdl), MmGetMdlByteCount(Mdl));
}

static FORCEINLINE PHYSICAL_ADDRESS
NvfsGetMdlPhysicalAddress(
    _In_ PMDL Mdl,
    _In_ ULONG PageIndex
)
{
    PHYSICAL_ADDRESS physAddr = {0};
    PPFN_NUMBER pageArray;
    
    if (Mdl == NULL || PageIndex >= NvfsGetMdlPageCount(Mdl)) {
        return physAddr;
    }
    
    pageArray = MmGetMdlPfnArray(Mdl);
    physAddr.QuadPart = (LONGLONG)pageArray[PageIndex] << PAGE_SHIFT;
    
    return physAddr;
}

// DMA reference counting
static FORCEINLINE VOID
NvfsMgroupGetDmaRef(
    _In_ PNVFS_IO_MGROUP MGroup
)
{
    InterlockedIncrement(&MGroup->DmaRefCount);
}

static FORCEINLINE BOOLEAN
NvfsMgroupPutDmaRef(
    _In_ PNVFS_IO_MGROUP MGroup
)
{
    return (InterlockedDecrement(&MGroup->DmaRefCount) == 0);
}

// I/O state management
static FORCEINLINE BOOLEAN
NvfsTransitState(
    _In_ PNVFS_GPU_ARGS GpuInfo,
    _In_ BOOLEAN Sync,
    _In_ NVFS_IO_STATE FromState,
    _In_ NVFS_IO_STATE ToState
)
{
    LONG expectedState = (LONG)FromState;
    LONG newState = (LONG)ToState;
    
    // Atomically compare and exchange the state
    return (InterlockedCompareExchange(&GpuInfo->IoState, newState, expectedState) == expectedState);
}

// Windows equivalent of Linux I/O state status strings
static FORCEINLINE PCSTR
NvfsIoStateStatus(
    _In_ NVFS_IO_STATE State
)
{
    switch (State) {
        case IO_READY: return "IO_READY";
        case IO_IN_PROGRESS: return "IO_IN_PROGRESS";
        case IO_TERMINATE_REQ: return "IO_TERMINATE_REQ";
        case IO_TERMINATED: return "IO_TERMINATED";
        case IO_CALLBACK_REQ: return "IO_CALLBACK_REQ";
        case IO_CALLBACK_END: return "IO_CALLBACK_END";
        default: return "UNKNOWN";
    }
}

#endif /* NVFS_MMAP_WIN_H */