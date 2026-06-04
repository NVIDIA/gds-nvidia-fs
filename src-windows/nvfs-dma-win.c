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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - DMA Engine
 */

// Windows kernel headers
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <storport.h>

// Windows-specific includes
#include "nvfs-core-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-mmap-win.h"
#include "nvfs-dma-win.h"
#include "nvfs-kernel-interface-win.h"
#include "config-host-win.h"

// Windows equivalent of Linux constants
#define NVME_MAX_SEGS_WIN 127
#define NVFS_IO_ERR_WIN -1
#define NVFS_BAD_REQ_WIN -2

// Windows sector definitions
#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

// Windows storage driver key definitions (equivalent to Linux module keys)
#define NVFS_PROC_MOD_NVME_KEY_WIN          L"nvme"
#define NVFS_PROC_MOD_NVME_RDMA_KEY_WIN     L"nvme_rdma"
#define NVFS_PROC_MOD_SCSI_KEY_WIN          L"scsi_port"
#define NVFS_PROC_MOD_SCALEFLUX_CSD_KEY_WIN L"sfxvdriver"
#define NVFS_PROC_MOD_NVMESH_KEY_WIN        L"nvmeib_common"
#define NVFS_PROC_MOD_DDN_LUSTRE_KEY_WIN    L"lustre"
#define NVFS_PROC_MOD_NTAP_BEEGFS_KEY_WIN   L"beegfs"
#define NVFS_PROC_MOD_GPFS_KEY_WIN          L"mmfslinux"
#define NVFS_PROC_MOD_NFS_KEY_WIN           L"nfsrdma"
#define NVFS_PROC_MOD_WEKAFS_KEY_WIN        L"wekafsio"
#define NVFS_PROC_MOD_SCATEFS_KEY_WIN       L"scatefs"

// Forward declarations for Windows DMA operation structures
static NVFS_DMA_RW_OPS_WIN g_NvfsDevDmaRwOps;
static NVFS_DMA_RW_OPS_WIN g_NvfsNvmeDmaRwOps;
static NVFS_DMA_RW_OPS_WIN g_NvfsSfxvDmaRwOps;
static NVFS_DMA_RW_OPS_WIN g_NvfsNvmeshDmaRwOps;
static NVFS_DMA_RW_OPS_WIN g_NvfsIbmScaleRdmaOps;

// Windows module entry structure (equivalent to Linux module_entry)
typedef struct _NVFS_MODULE_ENTRY_WIN {
    BOOLEAN IsModule;               // Is this a loadable module
    BOOLEAN Found;                  // Module found and registered
    PCWSTR ModuleName;              // Module name
    PCWSTR ModuleVersion;           // Module version
    PCWSTR RegisterSymbol;          // Registration function name
    NVFS_REGISTER_DMA_OPS_FN_WIN RegisterFunc; // Registration function pointer
    PCWSTR UnregisterSymbol;        // Unregistration function name
    NVFS_UNREGISTER_DMA_OPS_FN_WIN UnregisterFunc; // Unregistration function pointer
    PNVFS_DMA_RW_OPS_WIN Operations; // DMA operations structure
} NVFS_MODULE_ENTRY_WIN, *PNVFS_MODULE_ENTRY_WIN;

// Windows module list (equivalent to Linux modules_list)
static NVFS_MODULE_ENTRY_WIN g_ModulesList[] = {
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_NVME_KEY_WIN,
        L"1.0",
        L"nvme_v1_register_nvfs_dma_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"nvme_v1_unregister_nvfs_dma_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsNvmeDmaRwOps
    },
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_NVME_RDMA_KEY_WIN,
        L"1.0",
        L"nvme_rdma_v1_register_nvfs_dma_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"nvme_rdma_v1_unregister_nvfs_dma_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsNvmeDmaRwOps
    },
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_SCALEFLUX_CSD_KEY_WIN,
        L"1.0",
        L"sfxv_v1_register_nvfs_dma_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"sfxv_v1_unregister_nvfs_dma_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsSfxvDmaRwOps
    },
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_NVMESH_KEY_WIN,
        L"1.0",
        L"nvmesh_v1_register_nvfs_dma_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"nvmesh_v1_unregister_nvfs_dma_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsNvmeshDmaRwOps
    },
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_DDN_LUSTRE_KEY_WIN,
        L"1.0",
        L"lustre_v1_register_nvfs_dma_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"lustre_v1_unregister_nvfs_dma_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsDevDmaRwOps
    },
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_NTAP_BEEGFS_KEY_WIN,
        L"1.0",
        L"beegfs_v1_register_nvfs_dma_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"beegfs_v1_unregister_nvfs_dma_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsDevDmaRwOps
    },
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_WEKAFS_KEY_WIN,
        L"1.0",
        NULL,  // No registration function for this module
        NULL,
        NULL,
        NULL,
        NULL
    },
#ifdef NVFS_ENABLE_WIN_RDMA_SUPPORT
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_GPFS_KEY_WIN,
        L"1.0",
        L"ibm_scale_v1_register_nvfs_dma_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"ibm_scale_v1_unregister_nvfs_dma_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsIbmScaleRdmaOps
    },
#endif
    {
        TRUE,  // IsModule
        FALSE, // Found
        NVFS_PROC_MOD_SCSI_KEY_WIN,
        L"1.0",
        L"scsi_v1_register_dma_scsi_ops_win",
        NULL,  // RegisterFunc (filled at runtime)
        L"scsi_v1_unregister_dma_scsi_ops_win",
        NULL,  // UnregisterFunc (filled at runtime)
        &g_NvfsDevDmaRwOps
    }
};

// Global variables
static BOOLEAN g_DmaOpsRegistered = FALSE;
static FAST_MUTEX g_DmaOpsMutex;

// Function to get number of modules
ULONG
NrModulesWin(VOID)
{
    return ARRAYSIZE(g_ModulesList);
}

// Windows equivalent of checking GPU page in scatter-gather list
LONG
NvfsCheckGpuSegsWin(
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction
)
{
    ULONG i;
    LONG gpuSegs = 0, cpuSegs = 0;
    PSCATTER_GATHER_ELEMENT element;
    PHYSICAL_ADDRESS physAddr;
    
    if (ScatterGatherList == NULL || NumEntries == 0) {
        nvfs_err("Invalid scatter-gather list parameters\n");
        return NVFS_IO_ERR_WIN;
    }
    
    element = ScatterGatherList->Elements;
    
    for (i = 0; i < NumEntries; i++) {
        physAddr = element[i].Address;
        
        // Check if this is GPU memory (would require NVIDIA P2P API integration)
        if (NvfsCheckGpuMemoryWin(physAddr, element[i].Length)) {
            gpuSegs++;
        } else {
            cpuSegs++;
        }
    }
    
    // Mixed CPU and GPU segments are not allowed
    if (gpuSegs > 0 && cpuSegs > 0) {
        NvfsStatIncrement(&g_NvfsStats.ErrorMixCpuGpu);
        return NVFS_IO_ERR_WIN;
    }
    
    return gpuSegs;
}

// Windows equivalent of mapping scatter-gather list for DMA
NTSTATUS
NvfsMapScatterGatherListWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction,
    _In_ ULONG Attributes
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDMA_ADAPTER dmaAdapter;
    DEVICE_DESCRIPTION deviceDescription;
    ULONG mapRegistersRequired;
    
    if (DeviceObject == NULL || ScatterGatherList == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Get DMA adapter for the device
    RtlZeroMemory(&deviceDescription, sizeof(deviceDescription));
    deviceDescription.Version = DEVICE_DESCRIPTION_VERSION;
    deviceDescription.Master = TRUE;
    deviceDescription.ScatterGather = TRUE;
    deviceDescription.Dma32BitAddresses = FALSE;
    deviceDescription.Dma64BitAddresses = TRUE;
    deviceDescription.InterfaceType = PCIBus;
    deviceDescription.MaximumLength = MAXULONG;
    
    dmaAdapter = IoGetDmaAdapter(DeviceObject, &deviceDescription, &mapRegistersRequired);
    if (dmaAdapter == NULL) {
        nvfs_err("Failed to get DMA adapter for device\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Map the scatter-gather list
    // This is a simplified implementation - actual implementation would
    // handle the specific mapping requirements for GPU memory
    
    // Release DMA adapter reference
    dmaAdapter->DmaOperations->PutDmaAdapter(dmaAdapter);
    
    return status;
}

// Windows equivalent of unmapping scatter-gather list
NTSTATUS
NvfsUnmapScatterGatherListWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _In_ DMA_DATA_DIRECTION Direction
)
{
    // Implementation for unmapping DMA
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(ScatterGatherList);
    UNREFERENCED_PARAMETER(NumEntries);
    UNREFERENCED_PARAMETER(Direction);
    
    // Windows DMA unmapping would be handled here
    return STATUS_SUCCESS;
}

// Windows equivalent of checking if page is GPU memory
BOOLEAN
NvfsIsGpuPageWin(
    _In_ PMDL Mdl
)
{
    PHYSICAL_ADDRESS physAddr;
    
    if (Mdl == NULL) {
        return FALSE;
    }
    
    // Get physical address from MDL
    physAddr = MmGetPhysicalAddress(MmGetMdlVirtualAddress(Mdl));
    
    // Check if this physical address belongs to GPU memory
    // This would require integration with NVIDIA's Windows P2P SDK
    return NvfsCheckGpuMemoryWin(physAddr, MmGetMdlByteCount(Mdl));
}

// Windows equivalent of getting GPU index
ULONG
NvfsGpuIndexWin(
    _In_ PMDL Mdl
)
{
    PHYSICAL_ADDRESS physAddr;
    
    if (Mdl == NULL) {
        return 0;
    }
    
    physAddr = MmGetPhysicalAddress(MmGetMdlVirtualAddress(Mdl));
    
    // Determine GPU index from physical address
    // This would require NVIDIA P2P API integration
    return NvfsGetGpuIndexFromPhysicalAddressWin(physAddr);
}

// Windows equivalent of device priority calculation
ULONG
NvfsDevicePriorityWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG GpuIndex
)
{
    ULONG priority = 0;
    
    if (DeviceObject == NULL) {
        return 0;
    }
    
    // Calculate device priority based on PCI topology and GPU affinity
    // This would involve analyzing the PCI bus hierarchy to determine
    // the optimal path between GPU and storage device
    
    priority = NvfsCalculatePciAffinityWin(DeviceObject, GpuIndex);
    
    return priority;
}

// Windows equivalent of getting RDMA info from scatter-gather list
NTSTATUS
NvfsGetGpuSglistRdmaInfoWin(
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ ULONG NumEntries,
    _Out_ PNVFS_RDMA_INFO RdmaInfo
)
{
#ifdef NVFS_ENABLE_WIN_RDMA_SUPPORT
    ULONG i;
    PSCATTER_GATHER_ELEMENT element;
    
    if (ScatterGatherList == NULL || RdmaInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlZeroMemory(RdmaInfo, sizeof(NVFS_RDMA_INFO));
    
    element = ScatterGatherList->Elements;
    
    // Extract RDMA information from scatter-gather list
    for (i = 0; i < NumEntries && i < 1; i++) { // Only process first element for simplicity
        RdmaInfo->RemVAddr = element[i].Address.QuadPart;
        RdmaInfo->Size = element[i].Length;
        // Additional RDMA-specific information would be filled here
    }
    
    RdmaInfo->Version = 1;
    RdmaInfo->Flags = 0;
    
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(ScatterGatherList);
    UNREFERENCED_PARAMETER(NumEntries);
    UNREFERENCED_PARAMETER(RdmaInfo);
    return STATUS_NOT_SUPPORTED;
#endif
}

// Initialize DMA operations structure
static VOID
InitializeDmaOpsWin(
    _Out_ PNVFS_DMA_RW_OPS_WIN DmaOps
)
{
    RtlZeroMemory(DmaOps, sizeof(NVFS_DMA_RW_OPS_WIN));
    
    // Set feature bitmap
    DmaOps->FeatureBitmap = NVFS_FT_PREP_SGLIST_WIN | NVFS_FT_MAP_SGLIST_WIN;
    
    // Set function pointers
    DmaOps->MapScatterGatherList = NvfsMapScatterGatherListWin;
    DmaOps->UnmapScatterGatherList = NvfsUnmapScatterGatherListWin;
    DmaOps->IsGpuPage = NvfsIsGpuPageWin;
    DmaOps->GpuIndex = NvfsGpuIndexWin;
    DmaOps->DevicePriority = NvfsDevicePriorityWin;
    DmaOps->GetGpuSglistRdmaInfo = NvfsGetGpuSglistRdmaInfoWin;
}

// Windows equivalent of probing module list
NTSTATUS
ProbeModuleListWin(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    PNVFS_MODULE_ENTRY_WIN moduleEntry;
    UNICODE_STRING moduleName;
    
    ExAcquireFastMutex(&g_DmaOpsMutex);
    
    for (i = 0; i < NrModulesWin(); i++) {
        moduleEntry = &g_ModulesList[i];
        
        // Skip pseudo module dependencies
        if (moduleEntry->RegisterSymbol == NULL || moduleEntry->UnregisterSymbol == NULL) {
            continue;
        }
        
        if (moduleEntry->Found) {
            continue;
        }
        
        RtlInitUnicodeString(&moduleName, moduleEntry->ModuleName);
        
        // Try to resolve symbols from loaded modules
        // In Windows, this would involve looking up exported functions
        // from loaded drivers/modules
        moduleEntry->RegisterFunc = NvfsGetModuleSymbolWin(&moduleName, moduleEntry->RegisterSymbol);
        if (moduleEntry->RegisterFunc == NULL) {
            continue;
        }
        
        moduleEntry->UnregisterFunc = NvfsGetModuleSymbolWin(&moduleName, moduleEntry->UnregisterSymbol);
        if (moduleEntry->UnregisterFunc == NULL) {
            moduleEntry->RegisterFunc = NULL;
            nvfs_err("Unregister function not found: %ws\n", moduleEntry->UnregisterSymbol);
            continue;
        }
        
        // Register the module
        status = moduleEntry->RegisterFunc(moduleEntry->Operations);
        if (!NT_SUCCESS(status)) {
            nvfs_err("NVFS registration failed for module %ws: 0x%08lx\n",
                    moduleEntry->ModuleName, status);
            moduleEntry->RegisterFunc = NULL;
            moduleEntry->UnregisterFunc = NULL;
            continue;
        }
        
        moduleEntry->Found = TRUE;
        nvfs_info("NVFS registered with module: %ws\n", moduleEntry->ModuleName);
    }
    
    ExReleaseFastMutex(&g_DmaOpsMutex);
    
    return status;
}

// Windows equivalent of cleaning up module list
VOID
CleanupModuleListWin(VOID)
{
    ULONG i;
    PNVFS_MODULE_ENTRY_WIN moduleEntry;
    
    ExAcquireFastMutex(&g_DmaOpsMutex);
    
    for (i = 0; i < NrModulesWin(); i++) {
        moduleEntry = &g_ModulesList[i];
        
        if (moduleEntry->Found && moduleEntry->UnregisterFunc != NULL) {
            nvfs_dbg("Unregistering module: %ws\n", moduleEntry->ModuleName);
            
            moduleEntry->Found = FALSE;
            moduleEntry->UnregisterFunc();
            moduleEntry->RegisterFunc = NULL;
            moduleEntry->UnregisterFunc = NULL;
        }
    }
    
    ExReleaseFastMutex(&g_DmaOpsMutex);
}

// Windows equivalent of registering DMA operations
NTSTATUS
NvfsBlkRegisterDmaOps(VOID)
{
    NTSTATUS status;
    
    if (g_DmaOpsRegistered) {
        return STATUS_SUCCESS;
    }
    
    // Initialize DMA operations structures
    InitializeDmaOpsWin(&g_NvfsDevDmaRwOps);
    InitializeDmaOpsWin(&g_NvfsNvmeDmaRwOps);
    InitializeDmaOpsWin(&g_NvfsSfxvDmaRwOps);
    InitializeDmaOpsWin(&g_NvfsNvmeshDmaRwOps);
    InitializeDmaOpsWin(&g_NvfsIbmScaleRdmaOps);
    
    // Initialize mutex
    ExInitializeFastMutex(&g_DmaOpsMutex);
    
    // Probe and register with available storage modules
    status = ProbeModuleListWin();
    if (NT_SUCCESS(status)) {
        g_DmaOpsRegistered = TRUE;
        nvfs_info("NVFS DMA operations registered successfully\n");
    } else {
        nvfs_err("Failed to register NVFS DMA operations: 0x%08lx\n", status);
    }
    
    return status;
}

// Windows equivalent of unregistering DMA operations
VOID
NvfsBlkUnregisterDmaOps(VOID)
{
    if (!g_DmaOpsRegistered) {
        return;
    }
    
    CleanupModuleListWin();
    g_DmaOpsRegistered = FALSE;
    
    nvfs_info("NVFS DMA operations unregistered\n");
}

// Helper function to check if physical address is GPU memory
BOOLEAN
NvfsCheckGpuMemoryWin(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ ULONG Length
)
{
    // This would require integration with NVIDIA's Windows P2P SDK
    // to determine if the physical address range belongs to GPU memory
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Length);
    
    // Placeholder implementation
    return FALSE;
}

// Helper function to get GPU index from physical address
ULONG
NvfsGetGpuIndexFromPhysicalAddressWin(
    _In_ PHYSICAL_ADDRESS PhysicalAddress
)
{
    // This would require NVIDIA P2P API to map physical address to GPU index
    UNREFERENCED_PARAMETER(PhysicalAddress);
    
    // Placeholder implementation
    return 0;
}

// Helper function to calculate PCI affinity
ULONG
NvfsCalculatePciAffinityWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG GpuIndex
)
{
    // This would analyze PCI topology to determine optimal GPU-storage pairing
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(GpuIndex);
    
    // Placeholder implementation
    return 1;
}

// Helper function to get module symbol (equivalent to __symbol_get)
PVOID
NvfsGetModuleSymbolWin(
    _In_ PUNICODE_STRING ModuleName,
    _In_ PCWSTR SymbolName
)
{
    // This would involve looking up exported functions from loaded drivers
    // Windows equivalent would use ZwQuerySystemInformation or other APIs
    UNREFERENCED_PARAMETER(ModuleName);
    UNREFERENCED_PARAMETER(SymbolName);
    
    // Placeholder implementation
    return NULL;
}