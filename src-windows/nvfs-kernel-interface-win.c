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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Kernel Interface Layer
 */

#include <ntddk.h>
#include <wdf.h>
#include "nvfs-kernel-interface-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-fault-win.h"

// Global variables
static BOOLEAN g_KernelInterfaceInitialized = FALSE;

NTSTATUS
NvfsInitializeKernelInterfaceWin(VOID)
{
    if (g_KernelInterfaceInitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }
    
    g_KernelInterfaceInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
NvfsCleanupKernelInterfaceWin(VOID)
{
    g_KernelInterfaceInitialized = FALSE;
}

// Memory access validation (Windows equivalent of Linux access_ok)
BOOLEAN
NvfsCheckAccessWin(
    _In_ NVFS_ACCESS_TYPE_WIN AccessType,
    _In_ PVOID UserBuffer,
    _In_ SIZE_T BufferSize
)
{
    BOOLEAN result = FALSE;
    
    if (UserBuffer == NULL || BufferSize == 0) {
        return FALSE;
    }
    
    // Inject fault for testing
    NVFS_FAULT_INJECT_WIN(NVFS_FAULT_RW_VERIFY_AREA_ERROR_WIN, FALSE);
    
    __try {
        switch (AccessType) {
            case NvfsAccessRead:
                // Check if we can read from user buffer
                ProbeForRead(UserBuffer, BufferSize, sizeof(UCHAR));
                result = TRUE;
                break;
                
            case NvfsAccessWrite:
                // Check if we can write to user buffer
                ProbeForWrite(UserBuffer, BufferSize, sizeof(UCHAR));
                result = TRUE;
                break;
                
            case NvfsAccessReadWrite:
                // Check both read and write access
                ProbeForWrite(UserBuffer, BufferSize, sizeof(UCHAR));
                result = TRUE;
                break;
                
            default:
                result = FALSE;
                break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
        NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorMixCpuGpu);
    }
    
    return result;
}

// MDL scatter-gather list extension (Windows equivalent of Linux sg extension)
NTSTATUS
NvfsExtendScatterGatherListWin(
    _Inout_ PSCATTER_GATHER_LIST* ScatterGatherList,
    _In_ ULONG AdditionalElements
)
{
    PSCATTER_GATHER_LIST newSgList;
    ULONG newElementCount;
    ULONG totalSize;
    ULONG i;
    
    if (ScatterGatherList == NULL || *ScatterGatherList == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Inject fault for testing
    NVFS_FAULT_INJECT_STATUS_WIN(NVFS_FAULT_MDL_ALLOCATION_ERROR_WIN, STATUS_INSUFFICIENT_RESOURCES);
    
    newElementCount = (*ScatterGatherList)->NumberOfElements + AdditionalElements;
    totalSize = sizeof(SCATTER_GATHER_LIST) + 
                (sizeof(SCATTER_GATHER_ELEMENT) * (newElementCount - 1));
    
    newSgList = ExAllocatePoolWithTag(
        NonPagedPool,
        totalSize,
        'lGDS'
    );
    
    if (newSgList == NULL) {
        NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorScatterGather);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Copy existing elements
    RtlCopyMemory(
        newSgList,
        *ScatterGatherList,
        sizeof(SCATTER_GATHER_LIST) + 
        (sizeof(SCATTER_GATHER_ELEMENT) * ((*ScatterGatherList)->NumberOfElements - 1))
    );
    
    // Initialize new elements
    for (i = (*ScatterGatherList)->NumberOfElements; i < newElementCount; i++) {
        newSgList->Elements[i].Address.QuadPart = 0;
        newSgList->Elements[i].Length = 0;
    }
    
    newSgList->NumberOfElements = newElementCount;
    
    // Free old list and update pointer
    ExFreePoolWithTag(*ScatterGatherList, 'lGDS');
    *ScatterGatherList = newSgList;
    
    return STATUS_SUCCESS;
}

// Physical page contiguity checking (Windows equivalent of Linux page mergeability)
BOOLEAN
NvfsCheckPhysicalContiguityWin(
    _In_ PHYSICAL_ADDRESS PrevPhysAddr,
    _In_ ULONG PrevLength,
    _In_ PHYSICAL_ADDRESS CurrPhysAddr
)
{
    PHYSICAL_ADDRESS expectedNextAddr;
    
    expectedNextAddr.QuadPart = PrevPhysAddr.QuadPart + PrevLength;
    
    return (expectedNextAddr.QuadPart == CurrPhysAddr.QuadPart);
}

// MDL physical page analysis
NTSTATUS
NvfsAnalyzeMdlPagesWin(
    _In_ PMDL Mdl,
    _Out_ PNVFS_MDL_PAGE_INFO_WIN PageInfo
)
{
    PPFN_NUMBER mdlPages;
    ULONG pageCount;
    ULONG i;
    PHYSICAL_ADDRESS physAddr, prevPhysAddr;
    BOOLEAN isContiguous = TRUE;
    
    if (Mdl == NULL || PageInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlZeroMemory(PageInfo, sizeof(NVFS_MDL_PAGE_INFO_WIN));
    
    pageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        MmGetMdlVirtualAddress(Mdl),
        MmGetMdlByteCount(Mdl)
    );
    
    if (pageCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    mdlPages = MmGetMdlPfnArray(Mdl);
    PageInfo->TotalPages = pageCount;
    
    // Analyze page layout
    for (i = 0; i < pageCount; i++) {
        physAddr.QuadPart = (ULONGLONG)mdlPages[i] << PAGE_SHIFT;
        
        if (i == 0) {
            PageInfo->FirstPhysicalAddress = physAddr;
        } else {
            // Check contiguity with previous page
            if (physAddr.QuadPart != (prevPhysAddr.QuadPart + PAGE_SIZE)) {
                isContiguous = FALSE;
                PageInfo->FragmentCount++;
            }
        }
        
        prevPhysAddr = physAddr;
        PageInfo->LastPhysicalAddress = physAddr;
    }
    
    PageInfo->IsContiguous = isContiguous;
    
    // If not contiguous, we have at least one fragment
    if (!isContiguous && PageInfo->FragmentCount == 0) {
        PageInfo->FragmentCount = 1;
    }
    
    PageInfo->TotalSize = MmGetMdlByteCount(Mdl);
    
    return STATUS_SUCCESS;
}

// User buffer validation and locking
NTSTATUS
NvfsLockUserBufferWin(
    _In_ PVOID UserBuffer,
    _In_ SIZE_T BufferSize,
    _In_ NVFS_ACCESS_TYPE_WIN AccessType,
    _Outptr_ PMDL* Mdl
)
{
    LOCK_OPERATION lockOperation;
    PMDL mdl = NULL;
    
    if (UserBuffer == NULL || BufferSize == 0 || Mdl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *Mdl = NULL;
    
    // Validate access first
    if (!NvfsCheckAccessWin(AccessType, UserBuffer, BufferSize)) {
        return STATUS_ACCESS_VIOLATION;
    }
    
    // Determine lock operation
    switch (AccessType) {
        case NvfsAccessRead:
            lockOperation = IoWriteAccess;
            break;
            
        case NvfsAccessWrite:
            lockOperation = IoReadAccess;
            break;
            
        case NvfsAccessReadWrite:
            lockOperation = IoModifyAccess;
            break;
            
        default:
            return STATUS_INVALID_PARAMETER;
    }
    
    // Inject fault for testing
    NVFS_FAULT_INJECT_STATUS_WIN(NVFS_FAULT_GET_USER_PAGES_ERROR_WIN, STATUS_INSUFFICIENT_RESOURCES);
    
    __try {
        // Create MDL for user buffer
        mdl = IoAllocateMdl(
            UserBuffer,
            (ULONG)BufferSize,
            FALSE,
            FALSE,
            NULL
        );
        
        if (mdl == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // Lock pages in memory
        MmProbeAndLockPages(mdl, UserMode, lockOperation);
        
        *Mdl = mdl;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mdl != NULL) {
            IoFreeMdl(mdl);
        }
        
        NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorMixCpuGpu);
        return GetExceptionCode();
    }
}

// User buffer unlocking
VOID
NvfsUnlockUserBufferWin(
    _In_ PMDL Mdl
)
{
    if (Mdl != NULL) {
        __try {
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Log error but continue cleanup
            NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorMixCpuGpu);
        }
    }
}

// DMA adapter interface helpers
NTSTATUS
NvfsGetDmaAdapterWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG MaximumLength,
    _Outptr_ PDMA_ADAPTER* DmaAdapter
)
{
    DEVICE_DESCRIPTION deviceDescription;
    PDMA_ADAPTER adapter;
    
    if (DeviceObject == NULL || DmaAdapter == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *DmaAdapter = NULL;
    
    RtlZeroMemory(&deviceDescription, sizeof(deviceDescription));
    deviceDescription.Version = DEVICE_DESCRIPTION_VERSION3;
    deviceDescription.BusNumber = 0;
    deviceDescription.InterfaceType = PCIBus;
    deviceDescription.MaximumLength = MaximumLength;
    deviceDescription.Dma64BitAddresses = TRUE;
    deviceDescription.Dma32BitAddresses = TRUE;
    deviceDescription.ScatterGather = TRUE;
    
    adapter = IoGetDmaAdapter(
        DeviceObject,
        &deviceDescription,
        NULL
    );
    
    if (adapter == NULL) {
        NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorDmaMap);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    *DmaAdapter = adapter;
    return STATUS_SUCCESS;
}

// Storage stack integration helpers
NTSTATUS
NvfsGetStorageDeviceNumberWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PSTORAGE_DEVICE_NUMBER DeviceNumber
)
{
    KEVENT event;
    PIRP irp;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;
    
    if (DeviceObject == NULL || DeviceNumber == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        DeviceObject,
        NULL,
        0,
        DeviceNumber,
        sizeof(STORAGE_DEVICE_NUMBER),
        FALSE,
        &event,
        &ioStatusBlock
    );
    
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    status = IoCallDriver(DeviceObject, irp);
    
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }
    
    return status;
}

// Version compatibility helpers
BOOLEAN
NvfsIsWindowsVersionCompatibleWin(
    _In_ ULONG MajorVersion,
    _In_ ULONG MinorVersion
)
{
    RTL_OSVERSIONINFOW versionInfo;
    NTSTATUS status;
    
    RtlZeroMemory(&versionInfo, sizeof(versionInfo));
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    if (versionInfo.dwMajorVersion > MajorVersion) {
        return TRUE;
    }
    
    if (versionInfo.dwMajorVersion == MajorVersion && 
        versionInfo.dwMinorVersion >= MinorVersion) {
        return TRUE;
    }
    
    return FALSE;
}

// Error handling and logging
VOID
NvfsLogKernelErrorWin(
    _In_ NTSTATUS ErrorCode,
    _In_ PCSTR Function,
    _In_ ULONG Line
)
{
    KdPrint((
        "NVFS: Kernel interface error in %s:%u - Status: 0x%08X\n",
        Function,
        Line,
        ErrorCode
    ));
    
    // Update error statistics based on error type
    if (ErrorCode == STATUS_ACCESS_VIOLATION) {
        NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorMixCpuGpu);
    } else if (ErrorCode == STATUS_INSUFFICIENT_RESOURCES) {
        NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorDmaMap);
    }
}

// Utility functions for memory alignment
BOOLEAN
NvfsIsMemoryAlignedWin(
    _In_ PVOID Address,
    _In_ SIZE_T Alignment
)
{
    return ((ULONG_PTR)Address & (Alignment - 1)) == 0;
}

SIZE_T
NvfsAlignSizeWin(
    _In_ SIZE_T Size,
    _In_ SIZE_T Alignment
)
{
    return (Size + Alignment - 1) & ~(Alignment - 1);
}

PVOID
NvfsAlignAddressWin(
    _In_ PVOID Address,
    _In_ SIZE_T Alignment
)
{
    ULONG_PTR alignedAddr = ((ULONG_PTR)Address + Alignment - 1) & ~(Alignment - 1);
    return (PVOID)alignedAddr;
}