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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - RDMA Support
 */

#include <ntddk.h>
#include <wdf.h>
#include <ndkpi.h>
#include "nvfs-rdma-win.h"
#include "nvfs-core-win.h"
#include "nvfs-mmap-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-fault-win.h"

#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN

// Global RDMA state
static BOOLEAN g_RdmaInitialized = FALSE;
static KGUARDED_MUTEX g_RdmaLock;

// NDK provider list
static LIST_ENTRY g_NdkProviderList;
static KSPIN_LOCK g_NdkProviderLock;

// RDMA statistics
static NVFS_RDMA_STATISTICS_WIN g_RdmaStats;

// NDK provider entry structure
typedef struct _NVFS_NDK_PROVIDER_ENTRY_WIN {
    LIST_ENTRY ListEntry;
    NDK_PROVIDER NdkProvider;
    WCHAR ProviderName[256];
    BOOLEAN Available;
} NVFS_NDK_PROVIDER_ENTRY_WIN, *PNVFS_NDK_PROVIDER_ENTRY_WIN;

// Function prototypes
static NTSTATUS NvfsEnumerateNdkProvidersWin(VOID);
static VOID NvfsCleanupNdkProvidersWin(VOID);
static PNVFS_NDK_PROVIDER_ENTRY_WIN NvfsFindBestNdkProviderWin(VOID);

NTSTATUS
NvfsInitializeRdmaWin(VOID)
{
    NTSTATUS status;
    
    if (g_RdmaInitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }
    
    // Initialize synchronization
    KeInitializeGuardedMutex(&g_RdmaLock);
    KeInitializeSpinLock(&g_NdkProviderLock);
    InitializeListHead(&g_NdkProviderList);
    
    // Initialize statistics
    RtlZeroMemory(&g_RdmaStats, sizeof(g_RdmaStats));
    
    // Enumerate available NDK providers
    status = NvfsEnumerateNdkProvidersWin();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    g_RdmaInitialized = TRUE;
    
    return STATUS_SUCCESS;
}

VOID
NvfsCleanupRdmaWin(VOID)
{
    if (!g_RdmaInitialized) {
        return;
    }
    
    NvfsCleanupNdkProvidersWin();
    g_RdmaInitialized = FALSE;
}

NTSTATUS
NvfsSetRdmaRegInfoToMgroupWin(
    _In_ PNVFS_IOCTL_SET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs
)
{
    PNVFS_MGROUP_WIN mgroup = NULL;
    PNVFS_RDMA_INFO_WIN rdmaInfo;
    ULONG shadowBufSize;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!g_RdmaInitialized || RdmaRegInfoArgs == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Fault injection
    NVFS_FAULT_INJECT_STATUS_WIN(NVFS_FAULT_INVALID_P2P_GET_PAGE_WIN, STATUS_UNSUCCESSFUL);
    
    // Get memory group from virtual address
    mgroup = NvfsGetMgroupFromVaddrWin(RdmaRegInfoArgs->CpuVaddr);
    if (mgroup == NULL) {
        NVFS_STATS_INCREMENT_ERROR_WIN(NvfsErrorMixCpuGpu);
        return STATUS_INVALID_ADDRESS;
    }
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    
    __try {
        // Validate number of keys
        if (RdmaRegInfoArgs->NumKeys <= 0 || RdmaRegInfoArgs->NumKeys > NVFS_MAX_RDMA_KEYS_WIN) {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }
        
        // Validate version
        if (RdmaRegInfoArgs->Version < NVFS_RDMA_MIN_SUPPORTED_VERSION_WIN) {
            status = STATUS_VERSION_PARSE_ERROR;
            __leave;
        }
        
        shadowBufSize = mgroup->BlocksCount * NVFS_BLOCK_SIZE_WIN;
        rdmaInfo = &mgroup->RdmaInfo;
        
        // Copy RDMA registration information
        rdmaInfo->Version = RdmaRegInfoArgs->Version;
        rdmaInfo->Flags = RdmaRegInfoArgs->Flags;
        rdmaInfo->Lid = RdmaRegInfoArgs->Lid;
        rdmaInfo->QpNum = RdmaRegInfoArgs->QpNum;
        rdmaInfo->Gid[0] = RdmaRegInfoArgs->Gid[0];
        rdmaInfo->Gid[1] = RdmaRegInfoArgs->Gid[1];
        rdmaInfo->DcKey = RdmaRegInfoArgs->DcKey;
        
        // Set up remote key and virtual address information
        rdmaInfo->RKey = RdmaRegInfoArgs->RKey[0];
        rdmaInfo->RemVaddr = mgroup->GpuInfo.GpuVaddr;
        rdmaInfo->Size = mgroup->GpuInfo.GpuBufLen;
        
        // Update statistics
        InterlockedIncrement(&g_RdmaStats.RegistrationCount);
        
    }
    __finally {
        KeReleaseGuardedMutex(&g_RdmaLock);
        
        if (NT_SUCCESS(status)) {
            NvfsMgroupPutWin(mgroup);
        } else {
            // Clear RDMA info on error
            RtlZeroMemory(&mgroup->RdmaInfo, sizeof(NVFS_RDMA_INFO_WIN));
            NvfsMgroupPutWin(mgroup);
            InterlockedIncrement(&g_RdmaStats.ErrorCount);
        }
    }
    
    return status;
}

NTSTATUS
NvfsGetRdmaRegInfoFromMgroupWin(
    _Inout_ PNVFS_IOCTL_GET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs
)
{
    PNVFS_MGROUP_WIN mgroup = NULL;
    PNVFS_RDMA_INFO_WIN rdmaInfo;
    ULONG shadowBufSize;
    
    if (!g_RdmaInitialized || RdmaRegInfoArgs == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    mgroup = NvfsGetMgroupFromVaddrWin(RdmaRegInfoArgs->CpuVaddr);
    if (mgroup == NULL) {
        return STATUS_INVALID_ADDRESS;
    }
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    
    shadowBufSize = mgroup->BlocksCount * NVFS_BLOCK_SIZE_WIN;
    rdmaInfo = &mgroup->RdmaInfo;
    
    // Copy RDMA information to output structure
    RdmaRegInfoArgs->RdmaInfo = *rdmaInfo;
    
    KeReleaseGuardedMutex(&g_RdmaLock);
    
    NvfsMgroupPutWin(mgroup);
    
    // Update statistics
    InterlockedIncrement(&g_RdmaStats.QueryCount);
    
    return STATUS_SUCCESS;
}

NTSTATUS
NvfsClearRdmaRegInfoInMgroupWin(
    _In_ PNVFS_IOCTL_CLEAR_RDMA_REG_INFO_ARGS_WIN RdmaClearInfoArgs
)
{
    PNVFS_MGROUP_WIN mgroup = NULL;
    
    if (!g_RdmaInitialized || RdmaClearInfoArgs == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    mgroup = NvfsGetMgroupFromVaddrWin(RdmaClearInfoArgs->CpuVaddr);
    if (mgroup == NULL) {
        return STATUS_INVALID_ADDRESS;
    }
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    
    // Clear RDMA information
    RtlZeroMemory(&mgroup->RdmaInfo, sizeof(NVFS_RDMA_INFO_WIN));
    
    KeReleaseGuardedMutex(&g_RdmaLock);
    
    NvfsMgroupPutWin(mgroup);
    
    // Update statistics
    InterlockedIncrement(&g_RdmaStats.ClearCount);
    
    return STATUS_SUCCESS;
}

VOID
NvfsSetCurrentRdmaSegmentToMgroupWin(
    _In_ PNVFS_MGROUP_WIN Mgroup,
    _In_ ULONG RdmaSegment
)
{
    if (!g_RdmaInitialized || Mgroup == NULL) {
        return;
    }
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    Mgroup->RdmaInfo.CurrentSegment = RdmaSegment;
    KeReleaseGuardedMutex(&g_RdmaLock);
}

NTSTATUS
NvfsGetRdmaStatisticsWin(
    _Out_ PNVFS_RDMA_STATISTICS_WIN Statistics
)
{
    if (!g_RdmaInitialized || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    *Statistics = g_RdmaStats;
    KeReleaseGuardedMutex(&g_RdmaLock);
    
    return STATUS_SUCCESS;
}

VOID
NvfsResetRdmaStatisticsWin(VOID)
{
    if (!g_RdmaInitialized) {
        return;
    }
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    RtlZeroMemory(&g_RdmaStats, sizeof(g_RdmaStats));
    KeReleaseGuardedMutex(&g_RdmaLock);
}

NTSTATUS
NvfsCreateRdmaConnectionWin(
    _In_ PNVFS_RDMA_CONNECTION_INFO_WIN ConnectionInfo,
    _Outptr_ PNVFS_RDMA_CONNECTION_WIN* Connection
)
{
    PNVFS_RDMA_CONNECTION_WIN connection = NULL;
    PNVFS_NDK_PROVIDER_ENTRY_WIN provider;
    NTSTATUS status;
    
    if (!g_RdmaInitialized || ConnectionInfo == NULL || Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *Connection = NULL;
    
    // Find best NDK provider
    provider = NvfsFindBestNdkProviderWin();
    if (provider == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    
    // Allocate connection structure
    connection = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(NVFS_RDMA_CONNECTION_WIN),
        'cRDS'
    );
    
    if (connection == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(connection, sizeof(NVFS_RDMA_CONNECTION_WIN));
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    
    __try {
        // Initialize connection
        connection->Provider = provider;
        connection->ConnectionInfo = *ConnectionInfo;
        connection->State = NvfsRdmaConnectionStateInitialized;
        
        // TODO: Create NDK connector, QP, and other RDMA resources
        // This would involve complex NDK API calls for establishing RDMA connections
        
        *Connection = connection;
        status = STATUS_SUCCESS;
        
        InterlockedIncrement(&g_RdmaStats.ConnectionCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (connection != NULL) {
            ExFreePoolWithTag(connection, 'cRDS');
        }
        InterlockedIncrement(&g_RdmaStats.ErrorCount);
    }
    
    KeReleaseGuardedMutex(&g_RdmaLock);
    
    return status;
}

VOID
NvfsDestroyRdmaConnectionWin(
    _In_ PNVFS_RDMA_CONNECTION_WIN Connection
)
{
    if (!g_RdmaInitialized || Connection == NULL) {
        return;
    }
    
    KeAcquireGuardedMutex(&g_RdmaLock);
    
    // TODO: Cleanup NDK resources (connector, QP, etc.)
    
    Connection->State = NvfsRdmaConnectionStateDisconnected;
    ExFreePoolWithTag(Connection, 'cRDS');
    
    InterlockedDecrement(&g_RdmaStats.ConnectionCount);
    
    KeReleaseGuardedMutex(&g_RdmaLock);
}

BOOLEAN
NvfsIsRdmaEnabledWin(VOID)
{
    return g_RdmaInitialized;
}

// Helper functions

static NTSTATUS
NvfsEnumerateNdkProvidersWin(VOID)
{
    // TODO: Implement NDK provider enumeration
    // This would involve querying the system for available NDK providers
    // and populating the g_NdkProviderList
    
    // For now, return success as if providers were found
    return STATUS_SUCCESS;
}

static VOID
NvfsCleanupNdkProvidersWin(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PNVFS_NDK_PROVIDER_ENTRY_WIN providerEntry;
    
    KeAcquireSpinLock(&g_NdkProviderLock, &oldIrql);
    
    while (!IsListEmpty(&g_NdkProviderList)) {
        entry = RemoveHeadList(&g_NdkProviderList);
        providerEntry = CONTAINING_RECORD(
            entry,
            NVFS_NDK_PROVIDER_ENTRY_WIN,
            ListEntry
        );
        
        ExFreePoolWithTag(providerEntry, 'pRDS');
    }
    
    KeReleaseSpinLock(&g_NdkProviderLock, oldIrql);
}

static PNVFS_NDK_PROVIDER_ENTRY_WIN
NvfsFindBestNdkProviderWin(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PNVFS_NDK_PROVIDER_ENTRY_WIN providerEntry;
    PNVFS_NDK_PROVIDER_ENTRY_WIN bestProvider = NULL;
    
    KeAcquireSpinLock(&g_NdkProviderLock, &oldIrql);
    
    entry = g_NdkProviderList.Flink;
    while (entry != &g_NdkProviderList) {
        providerEntry = CONTAINING_RECORD(
            entry,
            NVFS_NDK_PROVIDER_ENTRY_WIN,
            ListEntry
        );
        
        if (providerEntry->Available) {
            bestProvider = providerEntry;
            break; // Use first available provider for now
        }
        
        entry = entry->Flink;
    }
    
    KeReleaseSpinLock(&g_NdkProviderLock, oldIrql);
    
    return bestProvider;
}

#else // !NVFS_ENABLE_RDMA_SUPPORT_WIN

// Stub implementations when RDMA support is disabled

NTSTATUS NvfsInitializeRdmaWin(VOID) { return STATUS_NOT_SUPPORTED; }
VOID NvfsCleanupRdmaWin(VOID) { }
NTSTATUS NvfsSetRdmaRegInfoToMgroupWin(_In_ PNVFS_IOCTL_SET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs) { UNREFERENCED_PARAMETER(RdmaRegInfoArgs); return STATUS_NOT_SUPPORTED; }
NTSTATUS NvfsGetRdmaRegInfoFromMgroupWin(_Inout_ PNVFS_IOCTL_GET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs) { UNREFERENCED_PARAMETER(RdmaRegInfoArgs); return STATUS_NOT_SUPPORTED; }
NTSTATUS NvfsClearRdmaRegInfoInMgroupWin(_In_ PNVFS_IOCTL_CLEAR_RDMA_REG_INFO_ARGS_WIN RdmaClearInfoArgs) { UNREFERENCED_PARAMETER(RdmaClearInfoArgs); return STATUS_NOT_SUPPORTED; }
VOID NvfsSetCurrentRdmaSegmentToMgroupWin(_In_ PNVFS_MGROUP_WIN Mgroup, _In_ ULONG RdmaSegment) { UNREFERENCED_PARAMETER(Mgroup); UNREFERENCED_PARAMETER(RdmaSegment); }
BOOLEAN NvfsIsRdmaEnabledWin(VOID) { return FALSE; }

#endif // NVFS_ENABLE_RDMA_SUPPORT_WIN