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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Memory Management
 */

// Windows kernel headers
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <ntifs.h>

// Windows-specific includes
#include "nvfs-pci-win.h"
#include "nvfs-mmap-win.h"
#include "nvfs-core-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-fault-win.h"
#include "nvfs-kernel-interface-win.h"
#include "config-host-win.h"

// Windows hash table implementation (equivalent to Linux HASHTABLE)
typedef struct _NVFS_HASH_ENTRY {
    LIST_ENTRY ListEntry;
    PNVFS_IO_MGROUP MGroup;
    ULONG_PTR BaseIndex;
} NVFS_HASH_ENTRY, *PNVFS_HASH_ENTRY;

// Global hash table for memory groups
static LIST_ENTRY g_NvfsIoMgroupHash[NVFS_MAX_SHADOW_ALLOCS];
static KSPIN_LOCK g_NvfsHashLock;
static BOOLEAN g_NvfsHashInitialized = FALSE;

// Windows equivalent of Linux process context check
static FORCEINLINE BOOLEAN
NvfsCheckProcessContext(VOID)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    
    // Check if we're at appropriate IRQL for memory operations
    if (currentIrql > APC_LEVEL) {
        nvfs_dbg("Invalid IRQL for memory operations: %d\n", currentIrql);
        return FALSE;
    }
    
    // Check if we're in DPC context
    if (KeGetCurrentThread() == NULL) {
        nvfs_dbg("No current thread context\n");
        return FALSE;
    }
    
    return TRUE;
}

// Windows equivalent of atomic reference counting
VOID
NvfsMgroupGetRef(
    _In_ PNVFS_IO_MGROUP MGroup
)
{
    InterlockedIncrement(&MGroup->RefCount);
}

BOOLEAN
NvfsMgroupPutRef(
    _In_ PNVFS_IO_MGROUP MGroup
)
{
    return (InterlockedDecrement(&MGroup->RefCount) == 0);
}

// Hash function for memory group lookup
static FORCEINLINE ULONG
NvfsHashIndex(
    _In_ ULONG_PTR BaseIndex
)
{
    return (ULONG)(BaseIndex % NVFS_MAX_SHADOW_ALLOCS);
}

// Initialize hash table
NTSTATUS
NvfsMgroupInit(VOID)
{
    ULONG i;
    
    if (g_NvfsHashInitialized) {
        return STATUS_SUCCESS;
    }
    
    // Initialize spin lock
    KeInitializeSpinLock(&g_NvfsHashLock);
    
    // Initialize hash table buckets
    for (i = 0; i < NVFS_MAX_SHADOW_ALLOCS; i++) {
        InitializeListHead(&g_NvfsIoMgroupHash[i]);
    }
    
    g_NvfsHashInitialized = TRUE;
    
    nvfs_dbg("NVFS memory group hash table initialized\n");
    return STATUS_SUCCESS;
}

// Cleanup hash table
VOID
NvfsMgroupCleanup(VOID)
{
    KIRQL oldIrql;
    ULONG i;
    PLIST_ENTRY listEntry;
    PNVFS_HASH_ENTRY hashEntry;
    
    if (!g_NvfsHashInitialized) {
        return;
    }
    
    KeAcquireSpinLock(&g_NvfsHashLock, &oldIrql);
    
    // Clean up all hash table entries
    for (i = 0; i < NVFS_MAX_SHADOW_ALLOCS; i++) {
        while (!IsListEmpty(&g_NvfsIoMgroupHash[i])) {
            listEntry = RemoveHeadList(&g_NvfsIoMgroupHash[i]);
            hashEntry = CONTAINING_RECORD(listEntry, NVFS_HASH_ENTRY, ListEntry);
            
            // Clean up the memory group
            if (hashEntry->MGroup != NULL) {
                ExFreePool(hashEntry->MGroup);
            }
            ExFreePool(hashEntry);
        }
    }
    
    g_NvfsHashInitialized = FALSE;
    
    KeReleaseSpinLock(&g_NvfsHashLock, oldIrql);
    
    nvfs_dbg("NVFS memory group hash table cleaned up\n");
}

// Get memory group by base index (Windows equivalent of nvfs_mgroup_get_unlocked)
static PNVFS_IO_MGROUP
NvfsMgroupGetUnlocked(
    _In_ ULONG_PTR BaseIndex
)
{
    ULONG hashIndex;
    PLIST_ENTRY listEntry;
    PNVFS_HASH_ENTRY hashEntry;
    PNVFS_IO_MGROUP mgroup = NULL;
    PNVFS_GPU_ARGS gpuInfo;
    
    hashIndex = NvfsHashIndex(BaseIndex);
    
    // Search for the memory group in the hash table
    listEntry = g_NvfsIoMgroupHash[hashIndex].Flink;
    while (listEntry != &g_NvfsIoMgroupHash[hashIndex]) {
        hashEntry = CONTAINING_RECORD(listEntry, NVFS_HASH_ENTRY, ListEntry);
        
        if (hashEntry->BaseIndex == BaseIndex) {
            mgroup = hashEntry->MGroup;
            
            // Check if the backing buffer is still valid
            gpuInfo = &mgroup->GpuInfo;
            if (InterlockedCompareExchange(&gpuInfo->IoState, 0, 0) > IO_IN_PROGRESS) {
                nvfs_info("Memory group found but IO is in invalid state: %ld\n",
                         gpuInfo->IoState);
                mgroup = NULL;
                break;
            }
            
            // Increment reference count
            NvfsMgroupGetRef(mgroup);
            break;
        }
        
        listEntry = listEntry->Flink;
    }
    
    return mgroup;
}

// Public function to get memory group with locking
PNVFS_IO_MGROUP
NvfsMgroupGet(
    _In_ ULONG_PTR BaseIndex
)
{
    KIRQL oldIrql;
    PNVFS_IO_MGROUP mgroup;
    
    if (!g_NvfsHashInitialized) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_NvfsHashLock, &oldIrql);
    mgroup = NvfsMgroupGetUnlocked(BaseIndex);
    KeReleaseSpinLock(&g_NvfsHashLock, oldIrql);
    
    return mgroup;
}

// Release memory group reference
VOID
NvfsMgroupPut(
    _In_ PNVFS_IO_MGROUP MGroup
)
{
    if (MGroup == NULL) {
        return;
    }
    
    if (NvfsMgroupPutRef(MGroup)) {
        // Reference count reached zero, clean up
        nvfs_dbg("Memory group reference count reached zero, cleaning up\n");
        
        // Clean up GPU resources
        if (MGroup->GpuInfo.PageTable != NULL) {
            // Free NVIDIA P2P page table
            // This would call NVIDIA's Windows P2P API
            // Implementation depends on NVIDIA Windows P2P SDK
        }
        
        // Clean up MDLs
        if (MGroup->ShadowMdl != NULL) {
            IoFreeMdl(MGroup->ShadowMdl);
        }
        
        if (MGroup->GpuMdl != NULL) {
            IoFreeMdl(MGroup->GpuMdl);
        }
        
        // Free the memory group structure
        ExFreePool(MGroup);
    }
}

// Windows equivalent of memory mapping for memory groups
NTSTATUS
NvfsMgroupMmap(
    _In_ WDFFILEOBJECT FileObject,
    _In_ WDFREQUEST Request,
    _In_ PVOID InputBuffer,
    _In_ SIZE_T InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ SIZE_T OutputBufferLength,
    _Out_ PSIZE_T BytesReturned
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNVFS_IOCTL_MAP_S mapParams;
    PNVFS_IO_MGROUP mgroup = NULL;
    PNVFS_HASH_ENTRY hashEntry = NULL;
    KIRQL oldIrql;
    ULONG hashIndex;
    ULONG_PTR baseIndex;
    
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    
    *BytesReturned = 0;
    
    // Validate input parameters
    if (InputBuffer == NULL || InputBufferLength < sizeof(NVFS_IOCTL_MAP_S)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!NvfsCheckProcessContext()) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    mapParams = (PNVFS_IOCTL_MAP_S)InputBuffer;
    
    // Validate GPU and CPU addresses
    if (mapParams->GpuVAddr == 0 || mapParams->CpuVAddr == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Calculate base index for hash table
    baseIndex = (ULONG_PTR)(mapParams->CpuVAddr >> PAGE_SHIFT);
    hashIndex = NvfsHashIndex(baseIndex);
    
    // Allocate memory group structure
    mgroup = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NVFS_IO_MGROUP), 'gfvN');
    if (mgroup == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(mgroup, sizeof(NVFS_IO_MGROUP));
    
    // Initialize memory group
    mgroup->RefCount = 1;
    mgroup->DmaRefCount = 0;
    mgroup->CpuBaseVAddr = mapParams->CpuVAddr;
    mgroup->BaseIndex = baseIndex;
    mgroup->NvfsBlocksCount = (ULONG)(mapParams->Size / PAGE_SIZE);
    
    // Initialize GPU info
    mgroup->GpuInfo.GpuVAddr = mapParams->GpuVAddr;
    mgroup->GpuInfo.GpuBufLen = mapParams->Size;
    mgroup->GpuInfo.PciDevInfo = mapParams->PciDevInfo;
    mgroup->GpuInfo.IsBounceBuffer = (mapParams->IsBounceBuffer != 0);
    mgroup->GpuInfo.IoState = IO_READY;
    
    // Initialize wait objects
    KeInitializeEvent(&mgroup->GpuInfo.CallbackEvent, NotificationEvent, FALSE);
    
    // Create MDL for shadow buffer (CPU virtual address)
    __try {
        mgroup->ShadowMdl = IoAllocateMdl((PVOID)mapParams->CpuVAddr,
                                         (ULONG)mapParams->Size,
                                         FALSE,
                                         FALSE,
                                         NULL);
        if (mgroup->ShadowMdl == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        
        // Probe and lock the shadow buffer pages
        MmProbeAndLockPages(mgroup->ShadowMdl, UserMode, IoReadAccess);
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        nvfs_err("Exception occurred while creating shadow buffer MDL: 0x%08lx\n", status);
        __leave;
    }
    
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    
    // Pin GPU memory using NVIDIA P2P API
    // This would require integration with NVIDIA's Windows P2P SDK
    // For now, we'll create a placeholder MDL
    mgroup->GpuMdl = IoAllocateMdl((PVOID)mapParams->GpuVAddr,
                                  (ULONG)mapParams->Size,
                                  FALSE,
                                  FALSE,
                                  NULL);
    if (mgroup->GpuMdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    // Allocate hash table entry
    hashEntry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NVFS_HASH_ENTRY), 'hfvN');
    if (hashEntry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    hashEntry->MGroup = mgroup;
    hashEntry->BaseIndex = baseIndex;
    
    // Add to hash table
    KeAcquireSpinLock(&g_NvfsHashLock, &oldIrql);
    InsertTailList(&g_NvfsIoMgroupHash[hashIndex], &hashEntry->ListEntry);
    KeReleaseSpinLock(&g_NvfsHashLock, oldIrql);
    
    nvfs_dbg("Memory group mapped successfully. GPU: 0x%llx, CPU: 0x%llx, Size: %lld\n",
             mapParams->GpuVAddr, mapParams->CpuVAddr, mapParams->Size);
    
    return STATUS_SUCCESS;

cleanup:
    if (hashEntry != NULL) {
        ExFreePool(hashEntry);
    }
    
    if (mgroup != NULL) {
        if (mgroup->ShadowMdl != NULL) {
            if (mgroup->ShadowMdl->MdlFlags & MDL_PAGES_LOCKED) {
                MmUnlockPages(mgroup->ShadowMdl);
            }
            IoFreeMdl(mgroup->ShadowMdl);
        }
        
        if (mgroup->GpuMdl != NULL) {
            IoFreeMdl(mgroup->GpuMdl);
        }
        
        ExFreePool(mgroup);
    }
    
    return status;
}

// Windows equivalent of finding memory group from page
PNVFS_IO_MGROUP
NvfsMgroupFromPage(
    _In_ PMDL Mdl
)
{
    ULONG_PTR baseIndex;
    PHYSICAL_ADDRESS physicalAddress;
    
    if (Mdl == NULL || Mdl->ByteCount == 0) {
        return NULL;
    }
    
    // Get physical address from MDL
    physicalAddress = MmGetPhysicalAddress(MmGetMdlVirtualAddress(Mdl));
    baseIndex = (ULONG_PTR)(physicalAddress.QuadPart >> PAGE_SHIFT);
    
    return NvfsMgroupGet(baseIndex);
}

// Windows equivalent of finding memory group from page range
PNVFS_IO_MGROUP
NvfsMgroupFromPageRange(
    _In_ PMDL Mdl,
    _In_ ULONG BlockCount,
    _In_ ULONG StartOffset
)
{
    ULONG_PTR baseIndex;
    PHYSICAL_ADDRESS physicalAddress;
    PVOID virtualAddress;
    
    if (Mdl == NULL || BlockCount == 0) {
        return NULL;
    }
    
    // Calculate virtual address with offset
    virtualAddress = (PUCHAR)MmGetMdlVirtualAddress(Mdl) + StartOffset;
    physicalAddress = MmGetPhysicalAddress(virtualAddress);
    baseIndex = (ULONG_PTR)(physicalAddress.QuadPart >> PAGE_SHIFT);
    
    return NvfsMgroupGet(baseIndex);
}

// Windows equivalent of checking and setting memory group state
VOID
NvfsMgroupCheckAndSet(
    _In_ PNVFS_IO_MGROUP MGroup,
    _In_ NVFS_BLOCK_STATE State,
    _In_ BOOLEAN Validate,
    _In_ BOOLEAN UpdateNvfsIo
)
{
    if (MGroup == NULL) {
        return;
    }
    
    if (Validate) {
        // Validate current state before setting new state
        LONG currentState = InterlockedCompareExchange(&MGroup->GpuInfo.IoState, 0, 0);
        if (currentState >= NVFS_IO_LAST_STATE) {
            nvfs_warn("Invalid current state %ld for memory group\n", currentState);
            return;
        }
    }
    
    // Set new state
    InterlockedExchange(&MGroup->GpuInfo.IoState, State);
    
    if (UpdateNvfsIo) {
        // Update NVFS I/O structure if requested
        // Implementation would update the NvfsIo structure
        KeQuerySystemTime(&MGroup->NvfsIo.StartIo);
    }
    
    nvfs_dbg("Memory group state changed to %d\n", State);
}

// Windows equivalent of getting memory group from virtual address
PNVFS_IO_MGROUP
NvfsGetMgroupFromVaddr(
    _In_ ULONG_PTR VirtualAddress
)
{
    ULONG_PTR baseIndex;
    
    if (VirtualAddress == 0) {
        return NULL;
    }
    
    baseIndex = VirtualAddress >> PAGE_SHIFT;
    return NvfsMgroupGet(baseIndex);
}