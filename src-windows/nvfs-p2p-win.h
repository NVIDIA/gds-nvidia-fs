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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - P2P Interface Header
 */

#ifndef __NVFS_P2P_WIN_H__
#define __NVFS_P2P_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Forward declarations
typedef struct _NVFS_P2P_PAGE_TABLE_WIN NVFS_P2P_PAGE_TABLE_WIN, *PNVFS_P2P_PAGE_TABLE_WIN;
typedef struct _NVFS_P2P_DMA_MAPPING_WIN NVFS_P2P_DMA_MAPPING_WIN, *PNVFS_P2P_DMA_MAPPING_WIN;

// P2P page types
typedef enum _NVFS_P2P_PAGE_TYPE_WIN {
    NvfsP2pPageTypeGpuMemory = 0,
    NvfsP2pPageTypeSystemMemory,
    NvfsP2pPageTypeUnknown
} NVFS_P2P_PAGE_TYPE_WIN;

// P2P access flags
typedef enum _NVFS_P2P_ACCESS_FLAGS_WIN {
    NvfsP2pAccessRead       = 0x01,
    NvfsP2pAccessWrite      = 0x02,
    NvfsP2pAccessReadWrite  = 0x03
} NVFS_P2P_ACCESS_FLAGS_WIN;

// P2P page information structure
typedef struct _NVFS_P2P_PAGE_WIN {
    PHYSICAL_ADDRESS PhysicalAddress;   // Physical address of the page
    ULONG Size;                         // Size of the page
    NVFS_P2P_PAGE_TYPE_WIN PageType;    // Type of memory page
    PVOID VirtualAddress;               // Virtual address (if mapped)
    ULONG Flags;                        // Page-specific flags
} NVFS_P2P_PAGE_WIN, *PNVFS_P2P_PAGE_WIN;

// P2P page table structure
typedef struct _NVFS_P2P_PAGE_TABLE_WIN {
    ULONG Version;                      // Structure version
    ULONG PageCount;                    // Number of pages
    ULONG TotalSize;                    // Total size in bytes
    GUID GpuUuid;                       // GPU UUID for this memory
    NVFS_P2P_ACCESS_FLAGS_WIN AccessFlags; // Access permissions
    PNVFS_P2P_PAGE_WIN Pages;           // Array of page information
    PVOID Reserved[4];                  // Reserved for future use
} NVFS_P2P_PAGE_TABLE_WIN, *PNVFS_P2P_PAGE_TABLE_WIN;

// P2P DMA mapping structure
typedef struct _NVFS_P2P_DMA_MAPPING_WIN {
    ULONG Version;                      // Structure version
    PDEVICE_OBJECT PeerDevice;          // Peer device for DMA
    PSCATTER_GATHER_LIST ScatterGatherList; // DMA scatter-gather list
    ULONG MappingCount;                 // Number of mappings
    PVOID MappingContext;               // Driver-specific context
    PVOID Reserved[4];                  // Reserved for future use
} NVFS_P2P_DMA_MAPPING_WIN, *PNVFS_P2P_DMA_MAPPING_WIN;

// P2P callback function types
typedef VOID (*NVFS_P2P_FREE_CALLBACK_WIN)(
    _In_ PVOID Context
);

typedef NTSTATUS (*NVFS_P2P_GET_PAGES_CALLBACK_WIN)(
    _In_ PVOID Context,
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG Size,
    _Out_ PNVFS_P2P_PAGE_TABLE_WIN* PageTable,
    _In_opt_ NVFS_P2P_FREE_CALLBACK_WIN FreeCallback,
    _In_opt_ PVOID CallbackContext
);

// P2P function prototypes

// Initialize P2P subsystem
NTSTATUS
NvfsInitializeP2PWin(VOID);

VOID
NvfsCleanupP2PWin(VOID);

// P2P page management functions (Windows equivalents of Linux nvidia_p2p_* functions)
NTSTATUS
NvfsP2pGetPagesWin(
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG Size,
    _Out_ PNVFS_P2P_PAGE_TABLE_WIN* PageTable,
    _In_opt_ NVFS_P2P_FREE_CALLBACK_WIN FreeCallback,
    _In_opt_ PVOID CallbackContext
);

NTSTATUS
NvfsP2pGetPagesPersistentWin(
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG Size,
    _Out_ PNVFS_P2P_PAGE_TABLE_WIN* PageTable,
    _In_opt_ NVFS_P2P_FREE_CALLBACK_WIN FreeCallback,
    _In_opt_ PVOID CallbackContext
);

VOID
NvfsP2pPutPagesWin(
    _In_ PNVFS_P2P_PAGE_TABLE_WIN PageTable
);

VOID
NvfsP2pPutPagesPersistentWin(
    _In_ PNVFS_P2P_PAGE_TABLE_WIN PageTable
);

NTSTATUS
NvfsP2pDmaMapPagesWin(
    _In_ PDEVICE_OBJECT PeerDevice,
    _In_ PNVFS_P2P_PAGE_TABLE_WIN PageTable,
    _Out_ PNVFS_P2P_DMA_MAPPING_WIN* DmaMapping
);

VOID
NvfsP2pDmaUnmapPagesWin(
    _In_ PNVFS_P2P_DMA_MAPPING_WIN DmaMapping
);

VOID
NvfsP2pFreePageTableWin(
    _In_ PNVFS_P2P_PAGE_TABLE_WIN PageTable
);

VOID
NvfsP2pFreeDmaMappingWin(
    _In_ PNVFS_P2P_DMA_MAPPING_WIN DmaMapping
);

// P2P capability checking
BOOLEAN
NvfsP2pIsDeviceCompatibleWin(
    _In_ PDEVICE_OBJECT Device1,
    _In_ PDEVICE_OBJECT Device2
);

NTSTATUS
NvfsP2pGetDeviceInfoWin(
    _In_ PDEVICE_OBJECT Device,
    _Out_ PGUID DeviceUuid,
    _Out_opt_ PULONG BusNumber,
    _Out_opt_ PULONG DeviceNumber,
    _Out_opt_ PULONG FunctionNumber
);

// P2P memory validation
BOOLEAN
NvfsP2pIsGpuMemoryWin(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ ULONG Size
);

NTSTATUS
NvfsP2pValidateAddressRangeWin(
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG Size,
    _In_ NVFS_P2P_ACCESS_FLAGS_WIN RequiredAccess
);

// P2P statistics and monitoring
typedef struct _NVFS_P2P_STATISTICS_WIN {
    ULONG GetPagesCount;                // Number of get_pages calls
    ULONG PutPagesCount;                // Number of put_pages calls
    ULONG DmaMapCount;                  // Number of DMA map operations
    ULONG DmaUnmapCount;                // Number of DMA unmap operations
    ULONG ActivePageTables;             // Currently active page tables
    ULONG ActiveDmaMappings;            // Currently active DMA mappings
    ULONGLONG TotalBytesMappped;        // Total bytes mapped
    ULONG ErrorCount;                   // Total errors encountered
} NVFS_P2P_STATISTICS_WIN, *PNVFS_P2P_STATISTICS_WIN;

NTSTATUS
NvfsP2pGetStatisticsWin(
    _Out_ PNVFS_P2P_STATISTICS_WIN Statistics
);

VOID
NvfsP2pResetStatisticsWin(VOID);

// P2P configuration
typedef struct _NVFS_P2P_CONFIGURATION_WIN {
    BOOLEAN EnableP2P;                  // Enable/disable P2P transfers
    ULONG MaxConcurrentMappings;        // Maximum concurrent P2P mappings
    ULONG MaxMappingSize;               // Maximum size per mapping
    ULONG TimeoutMs;                    // Timeout for P2P operations
    BOOLEAN PersistentMappings;         // Enable persistent mappings
} NVFS_P2P_CONFIGURATION_WIN, *PNVFS_P2P_CONFIGURATION_WIN;

NTSTATUS
NvfsP2pSetConfigurationWin(
    _In_ PNVFS_P2P_CONFIGURATION_WIN Configuration
);

NTSTATUS
NvfsP2pGetConfigurationWin(
    _Out_ PNVFS_P2P_CONFIGURATION_WIN Configuration
);

// Compatibility macros for Linux function names
#define nvfs_nvidia_p2p_get_pages_persistent_win       NvfsP2pGetPagesPersistentWin
#define nvfs_nvidia_p2p_put_pages_persistent_win        NvfsP2pPutPagesPersistentWin
#define nvfs_nvidia_p2p_get_pages_win                   NvfsP2pGetPagesWin
#define nvfs_nvidia_p2p_put_pages_win                   NvfsP2pPutPagesWin
#define nvfs_nvidia_p2p_dma_map_pages_win              NvfsP2pDmaMapPagesWin
#define nvfs_nvidia_p2p_dma_unmap_pages_win            NvfsP2pDmaUnmapPagesWin
#define nvfs_nvidia_p2p_free_page_table_win            NvfsP2pFreePageTableWin
#define nvfs_nvidia_p2p_free_dma_mapping_win           NvfsP2pFreeDmaMappingWin

// Inline helper functions

static __inline BOOLEAN
NvfsP2pIsPageTableValidWin(
    _In_opt_ PNVFS_P2P_PAGE_TABLE_WIN PageTable
)
{
    return (PageTable != NULL && 
            PageTable->Version > 0 && 
            PageTable->PageCount > 0 && 
            PageTable->Pages != NULL);
}

static __inline BOOLEAN
NvfsP2pIsDmaMappingValidWin(
    _In_opt_ PNVFS_P2P_DMA_MAPPING_WIN DmaMapping
)
{
    return (DmaMapping != NULL && 
            DmaMapping->Version > 0 && 
            DmaMapping->PeerDevice != NULL && 
            DmaMapping->ScatterGatherList != NULL);
}

static __inline ULONG
NvfsP2pGetPageTableSizeWin(
    _In_ PNVFS_P2P_PAGE_TABLE_WIN PageTable
)
{
    if (!NvfsP2pIsPageTableValidWin(PageTable)) {
        return 0;
    }
    
    return PageTable->TotalSize;
}

static __inline ULONG
NvfsP2pGetPageCountWin(
    _In_ PNVFS_P2P_PAGE_TABLE_WIN PageTable
)
{
    if (!NvfsP2pIsPageTableValidWin(PageTable)) {
        return 0;
    }
    
    return PageTable->PageCount;
}

// P2P IOCTL codes
#define NVFS_IOCTL_P2P_GET_PAGES_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_P2P_PUT_PAGES_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define NVFS_IOCTL_P2P_DMA_MAP_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_P2P_DMA_UNMAP_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define NVFS_IOCTL_P2P_GET_STATISTICS_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_P2P_SET_CONFIG_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// P2P IOCTL structures
typedef struct _NVFS_P2P_GET_PAGES_INPUT_WIN {
    ULONG_PTR VirtualAddress;           // Virtual address to map
    ULONG Size;                         // Size to map
    NVFS_P2P_ACCESS_FLAGS_WIN AccessFlags; // Required access
} NVFS_P2P_GET_PAGES_INPUT_WIN, *PNVFS_P2P_GET_PAGES_INPUT_WIN;

typedef struct _NVFS_P2P_PUT_PAGES_INPUT_WIN {
    HANDLE PageTableHandle;             // Handle to page table
} NVFS_P2P_PUT_PAGES_INPUT_WIN, *PNVFS_P2P_PUT_PAGES_INPUT_WIN;

typedef struct _NVFS_P2P_DMA_MAP_INPUT_WIN {
    HANDLE PageTableHandle;             // Handle to page table
    HANDLE PeerDeviceHandle;            // Handle to peer device
} NVFS_P2P_DMA_MAP_INPUT_WIN, *PNVFS_P2P_DMA_MAP_INPUT_WIN;

typedef struct _NVFS_P2P_DMA_UNMAP_INPUT_WIN {
    HANDLE DmaMappingHandle;            // Handle to DMA mapping
} NVFS_P2P_DMA_UNMAP_INPUT_WIN, *PNVFS_P2P_DMA_UNMAP_INPUT_WIN;

#endif // __NVFS_P2P_WIN_H__