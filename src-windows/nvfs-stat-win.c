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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Statistics Collection
 */

#include <ntddk.h>
#include <wdf.h>
#include "nvfs-stat-win.h"
#include "nvfs-core-win.h"
#include "nvfs-registry-win.h"

// Global statistics structures
static NVFS_STATISTICS_WIN g_NvfsStats;
static KGUARDED_MUTEX g_StatsLock;
static BOOLEAN g_StatsInitialized = FALSE;
static BOOLEAN g_StatsEnabled = TRUE;

// GPU statistics hash table
#define NVFS_GPU_HASH_SIZE 16
typedef struct _NVFS_GPU_STAT_ENTRY_WIN {
    LIST_ENTRY ListEntry;
    NVFS_GPU_STATISTICS_WIN GpuStats;
} NVFS_GPU_STAT_ENTRY_WIN, *PNVFS_GPU_STAT_ENTRY_WIN;

static LIST_ENTRY g_GpuStatsList[NVFS_GPU_HASH_SIZE];
static KSPIN_LOCK g_GpuStatsLock;

// Performance tracking
static LARGE_INTEGER g_PerformanceFrequency;
static LARGE_INTEGER g_StatsStartTime;

// Function prototypes
static ULONG NvfsComputeGpuHash(CONST GUID* GpuUuid);
static PNVFS_GPU_STAT_ENTRY_WIN NvfsFindGpuStatEntry(CONST GUID* GpuUuid);
static NTSTATUS NvfsCreateGpuStatEntry(CONST GUID* GpuUuid, ULONG GpuIndex);
static VOID NvfsUpdateBandwidthStats(VOID);
static VOID NvfsUpdateLatencyStats(VOID);

NTSTATUS
NvfsInitializeStatisticsWin(VOID)
{
    ULONG i;
    
    if (g_StatsInitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }
    
    // Initialize global statistics
    RtlZeroMemory(&g_NvfsStats, sizeof(g_NvfsStats));
    
    // Initialize GPU statistics lists
    KeInitializeSpinLock(&g_GpuStatsLock);
    for (i = 0; i < NVFS_GPU_HASH_SIZE; i++) {
        InitializeListHead(&g_GpuStatsList[i]);
    }
    
    // Initialize mutex for statistics access
    KeInitializeGuardedMutex(&g_StatsLock);
    
    // Get performance frequency for timing calculations
    g_PerformanceFrequency = KeQueryPerformanceCounter(NULL);
    KeQueryPerformanceCounter(&g_StatsStartTime);
    
    // Load configuration from registry
    NTSTATUS status = NvfsGetRegistryValueWin(
        L"StatsEnabled",
        REG_DWORD,
        &g_StatsEnabled,
        sizeof(g_StatsEnabled)
    );
    
    if (!NT_SUCCESS(status)) {
        g_StatsEnabled = TRUE; // Default to enabled
    }
    
    g_StatsInitialized = TRUE;
    
    return STATUS_SUCCESS;
}

VOID
NvfsCleanupStatisticsWin(VOID)
{
    KIRQL oldIrql;
    ULONG i;
    
    if (!g_StatsInitialized) {
        return;
    }
    
    // Free all GPU statistics entries
    KeAcquireSpinLock(&g_GpuStatsLock, &oldIrql);
    
    for (i = 0; i < NVFS_GPU_HASH_SIZE; i++) {
        while (!IsListEmpty(&g_GpuStatsList[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&g_GpuStatsList[i]);
            PNVFS_GPU_STAT_ENTRY_WIN gpuEntry = CONTAINING_RECORD(
                entry,
                NVFS_GPU_STAT_ENTRY_WIN,
                ListEntry
            );
            ExFreePoolWithTag(gpuEntry, 'tGDS');
        }
    }
    
    KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
    
    g_StatsInitialized = FALSE;
}

NTSTATUS
NvfsGetGlobalStatisticsWin(
    _Out_ PNVFS_STATISTICS_WIN Statistics
)
{
    if (!g_StatsInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireGuardedMutex(&g_StatsLock);
    
    // Update derived statistics before returning
    NvfsUpdateBandwidthStats();
    NvfsUpdateLatencyStats();
    
    *Statistics = g_NvfsStats;
    
    KeReleaseGuardedMutex(&g_StatsLock);
    
    return STATUS_SUCCESS;
}

NTSTATUS
NvfsGetGpuStatisticsWin(
    _In_ CONST GUID* GpuUuid,
    _Out_ PNVFS_GPU_STATISTICS_WIN GpuStatistics
)
{
    KIRQL oldIrql;
    PNVFS_GPU_STAT_ENTRY_WIN entry;
    
    if (!g_StatsInitialized || GpuUuid == NULL || GpuStatistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_GpuStatsLock, &oldIrql);
    
    entry = NvfsFindGpuStatEntry(GpuUuid);
    if (entry != NULL) {
        *GpuStatistics = entry->GpuStats;
        KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
    return STATUS_NOT_FOUND;
}

VOID
NvfsResetStatisticsWin(VOID)
{
    KIRQL oldIrql;
    ULONG i;
    PLIST_ENTRY entry;
    PNVFS_GPU_STAT_ENTRY_WIN gpuEntry;
    
    if (!g_StatsInitialized) {
        return;
    }
    
    KeAcquireGuardedMutex(&g_StatsLock);
    
    // Reset global statistics
    RtlZeroMemory(&g_NvfsStats, sizeof(g_NvfsStats));
    
    KeReleaseGuardedMutex(&g_StatsLock);
    
    // Reset GPU statistics
    KeAcquireSpinLock(&g_GpuStatsLock, &oldIrql);
    
    for (i = 0; i < NVFS_GPU_HASH_SIZE; i++) {
        entry = g_GpuStatsList[i].Flink;
        while (entry != &g_GpuStatsList[i]) {
            gpuEntry = CONTAINING_RECORD(entry, NVFS_GPU_STAT_ENTRY_WIN, ListEntry);
            
            // Reset counters but keep GPU UUID and index
            RtlZeroMemory(
                &gpuEntry->GpuStats.ActiveBarMemoryPinned,
                sizeof(NVFS_GPU_STATISTICS_WIN) - 
                FIELD_OFFSET(NVFS_GPU_STATISTICS_WIN, ActiveBarMemoryPinned)
            );
            
            entry = entry->Flink;
        }
    }
    
    KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
    
    // Reset start time
    KeQueryPerformanceCounter(&g_StatsStartTime);
}

NTSTATUS
NvfsRegisterGpuStatisticsWin(
    _In_ CONST GUID* GpuUuid,
    _In_ ULONG GpuIndex
)
{
    KIRQL oldIrql;
    PNVFS_GPU_STAT_ENTRY_WIN existingEntry;
    
    if (!g_StatsInitialized || GpuUuid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_GpuStatsLock, &oldIrql);
    
    // Check if GPU is already registered
    existingEntry = NvfsFindGpuStatEntry(GpuUuid);
    if (existingEntry != NULL) {
        KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
        return STATUS_ALREADY_REGISTERED;
    }
    
    KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
    
    // Create new GPU statistics entry
    return NvfsCreateGpuStatEntry(GpuUuid, GpuIndex);
}

VOID
NvfsUnregisterGpuStatisticsWin(
    _In_ CONST GUID* GpuUuid
)
{
    KIRQL oldIrql;
    PNVFS_GPU_STAT_ENTRY_WIN entry;
    
    if (!g_StatsInitialized || GpuUuid == NULL) {
        return;
    }
    
    KeAcquireSpinLock(&g_GpuStatsLock, &oldIrql);
    
    entry = NvfsFindGpuStatEntry(GpuUuid);
    if (entry != NULL) {
        RemoveEntryList(&entry->ListEntry);
        ExFreePoolWithTag(entry, 'tGDS');
    }
    
    KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
}

// Statistics update functions
VOID
NvfsUpdateReadStatisticsWin(
    _In_ ULONG BytesRead,
    _In_ LARGE_INTEGER StartTime,
    _In_ BOOLEAN Success
)
{
    LARGE_INTEGER endTime, latency;
    ULONG latencyUs;
    
    if (!g_StatsInitialized || !g_StatsEnabled) {
        return;
    }
    
    KeQueryPerformanceCounter(&endTime);
    latency.QuadPart = endTime.QuadPart - StartTime.QuadPart;
    latencyUs = (ULONG)((latency.QuadPart * 1000000) / g_PerformanceFrequency.QuadPart);
    
    KeAcquireGuardedMutex(&g_StatsLock);
    
    InterlockedIncrement64(&g_NvfsStats.ReadOperations.Count);
    
    if (Success) {
        InterlockedIncrement64(&g_NvfsStats.ReadOperations.SuccessCount);
        InterlockedAdd64(&g_NvfsStats.ReadOperations.BytesTransferred, BytesRead);
        InterlockedAdd64(&g_NvfsStats.ReadOperations.TotalLatencyUs, latencyUs);
    } else {
        InterlockedIncrement(&g_NvfsStats.ReadOperations.ErrorCount);
    }
    
    KeReleaseGuardedMutex(&g_StatsLock);
}

VOID
NvfsUpdateWriteStatisticsWin(
    _In_ ULONG BytesWritten,
    _In_ LARGE_INTEGER StartTime,
    _In_ BOOLEAN Success
)
{
    LARGE_INTEGER endTime, latency;
    ULONG latencyUs;
    
    if (!g_StatsInitialized || !g_StatsEnabled) {
        return;
    }
    
    KeQueryPerformanceCounter(&endTime);
    latency.QuadPart = endTime.QuadPart - StartTime.QuadPart;
    latencyUs = (ULONG)((latency.QuadPart * 1000000) / g_PerformanceFrequency.QuadPart);
    
    KeAcquireGuardedMutex(&g_StatsLock);
    
    InterlockedIncrement64(&g_NvfsStats.WriteOperations.Count);
    
    if (Success) {
        InterlockedIncrement64(&g_NvfsStats.WriteOperations.SuccessCount);
        InterlockedAdd64(&g_NvfsStats.WriteOperations.BytesTransferred, BytesWritten);
        InterlockedAdd64(&g_NvfsStats.WriteOperations.TotalLatencyUs, latencyUs);
    } else {
        InterlockedIncrement(&g_NvfsStats.WriteOperations.ErrorCount);
    }
    
    KeReleaseGuardedMutex(&g_StatsLock);
}

VOID
NvfsUpdateBatchStatisticsWin(
    _In_ ULONG BatchSize,
    _In_ LARGE_INTEGER SubmitTime,
    _In_ BOOLEAN Success
)
{
    LARGE_INTEGER endTime, latency;
    ULONG latencyUs;
    
    if (!g_StatsInitialized || !g_StatsEnabled) {
        return;
    }
    
    KeQueryPerformanceCounter(&endTime);
    latency.QuadPart = endTime.QuadPart - SubmitTime.QuadPart;
    latencyUs = (ULONG)((latency.QuadPart * 1000000) / g_PerformanceFrequency.QuadPart);
    
    KeAcquireGuardedMutex(&g_StatsLock);
    
    InterlockedIncrement64(&g_NvfsStats.BatchOperations.Count);
    InterlockedAdd64(&g_NvfsStats.BatchOperations.TotalBatchSize, BatchSize);
    InterlockedAdd64(&g_NvfsStats.BatchOperations.TotalLatencyUs, latencyUs);
    
    if (Success) {
        InterlockedIncrement64(&g_NvfsStats.BatchOperations.SuccessCount);
    } else {
        InterlockedIncrement(&g_NvfsStats.BatchOperations.ErrorCount);
    }
    
    KeReleaseGuardedMutex(&g_StatsLock);
}

VOID
NvfsUpdateMemoryStatisticsWin(
    _In_ CONST GUID* GpuUuid,
    _In_ LONGLONG MemoryDelta,
    _In_ NVFS_MEMORY_TYPE_WIN MemoryType
)
{
    KIRQL oldIrql;
    PNVFS_GPU_STAT_ENTRY_WIN entry;
    PLONGLONG targetCounter;
    PLONGLONG maxCounter;
    LONGLONG newValue;
    
    if (!g_StatsInitialized || !g_StatsEnabled || GpuUuid == NULL) {
        return;
    }
    
    KeAcquireSpinLock(&g_GpuStatsLock, &oldIrql);
    
    entry = NvfsFindGpuStatEntry(GpuUuid);
    if (entry == NULL) {
        KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
        return;
    }
    
    switch (MemoryType) {
        case NvfsMemoryTypeBar:
            targetCounter = &entry->GpuStats.ActiveBarMemoryPinned;
            maxCounter = &entry->GpuStats.MaxBarMemoryPinned;
            break;
            
        case NvfsMemoryTypeBounceBuffer:
            targetCounter = &entry->GpuStats.ActiveBounceBufferMemory;
            maxCounter = NULL; // No max tracking for bounce buffers
            break;
            
        default:
            KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
            return;
    }
    
    newValue = InterlockedAdd64(targetCounter, MemoryDelta);
    
    // Update maximum if this is a new high watermark
    if (maxCounter != NULL && newValue > *maxCounter) {
        InterlockedExchange64(maxCounter, newValue);
    }
    
    KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
}

VOID
NvfsIncrementErrorStatisticsWin(
    _In_ NVFS_ERROR_TYPE_WIN ErrorType
)
{
    if (!g_StatsInitialized || !g_StatsEnabled) {
        return;
    }
    
    switch (ErrorType) {
        case NvfsErrorMixCpuGpu:
            InterlockedIncrement(&g_NvfsStats.ErrorCounters.MixCpuGpuErrors);
            break;
            
        case NvfsErrorScatterGather:
            InterlockedIncrement(&g_NvfsStats.ErrorCounters.ScatterGatherErrors);
            break;
            
        case NvfsErrorDmaMap:
            InterlockedIncrement(&g_NvfsStats.ErrorCounters.DmaMapErrors);
            break;
            
        case NvfsErrorDmaRef:
            InterlockedIncrement(&g_NvfsStats.ErrorCounters.DmaRefErrors);
            break;
            
        case NvfsErrorPageCache:
            InterlockedIncrement(&g_NvfsStats.ErrorCounters.PageCacheErrors);
            break;
            
        case NvfsErrorPageCacheFail:
            InterlockedIncrement(&g_NvfsStats.ErrorCounters.PageCacheFailErrors);
            break;
            
        case NvfsErrorPageCacheEio:
            InterlockedIncrement(&g_NvfsStats.ErrorCounters.PageCacheEioErrors);
            break;
    }
}

BOOLEAN
NvfsIsStatisticsEnabledWin(VOID)
{
    return g_StatsInitialized && g_StatsEnabled;
}

VOID
NvfsSetStatisticsEnabledWin(
    _In_ BOOLEAN Enabled
)
{
    if (g_StatsInitialized) {
        g_StatsEnabled = Enabled;
        
        // Save to registry
        NvfsSetRegistryValueWin(
            L"StatsEnabled",
            REG_DWORD,
            &g_StatsEnabled,
            sizeof(g_StatsEnabled)
        );
    }
}

// Helper functions
static ULONG
NvfsComputeGpuHash(
    _In_ CONST GUID* GpuUuid
)
{
    PULONG hashData = (PULONG)GpuUuid;
    ULONG hash = 0;
    
    // Simple hash of the first DWORD of the GUID
    hash = hashData[0] % NVFS_GPU_HASH_SIZE;
    
    return hash;
}

static PNVFS_GPU_STAT_ENTRY_WIN
NvfsFindGpuStatEntry(
    _In_ CONST GUID* GpuUuid
)
{
    ULONG hash = NvfsComputeGpuHash(GpuUuid);
    PLIST_ENTRY entry = g_GpuStatsList[hash].Flink;
    
    while (entry != &g_GpuStatsList[hash]) {
        PNVFS_GPU_STAT_ENTRY_WIN gpuEntry = CONTAINING_RECORD(
            entry,
            NVFS_GPU_STAT_ENTRY_WIN,
            ListEntry
        );
        
        if (IsEqualGUID(&gpuEntry->GpuStats.GpuUuid, GpuUuid)) {
            return gpuEntry;
        }
        
        entry = entry->Flink;
    }
    
    return NULL;
}

static NTSTATUS
NvfsCreateGpuStatEntry(
    _In_ CONST GUID* GpuUuid,
    _In_ ULONG GpuIndex
)
{
    PNVFS_GPU_STAT_ENTRY_WIN newEntry;
    ULONG hash;
    KIRQL oldIrql;
    
    newEntry = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(NVFS_GPU_STAT_ENTRY_WIN),
        'tGDS'
    );
    
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(newEntry, sizeof(NVFS_GPU_STAT_ENTRY_WIN));
    newEntry->GpuStats.GpuUuid = *GpuUuid;
    newEntry->GpuStats.GpuIndex = GpuIndex;
    
    hash = NvfsComputeGpuHash(GpuUuid);
    
    KeAcquireSpinLock(&g_GpuStatsLock, &oldIrql);
    InsertTailList(&g_GpuStatsList[hash], &newEntry->ListEntry);
    KeReleaseSpinLock(&g_GpuStatsLock, oldIrql);
    
    return STATUS_SUCCESS;
}

static VOID
NvfsUpdateBandwidthStats(VOID)
{
    LARGE_INTEGER currentTime, elapsedTime;
    ULONGLONG elapsedSeconds;
    
    KeQueryPerformanceCounter(&currentTime);
    elapsedTime.QuadPart = currentTime.QuadPart - g_StatsStartTime.QuadPart;
    elapsedSeconds = (elapsedTime.QuadPart) / g_PerformanceFrequency.QuadPart;
    
    if (elapsedSeconds > 0) {
        g_NvfsStats.ReadOperations.BandwidthMBps = 
            (ULONG)((g_NvfsStats.ReadOperations.BytesTransferred / (1024 * 1024)) / elapsedSeconds);
        
        g_NvfsStats.WriteOperations.BandwidthMBps = 
            (ULONG)((g_NvfsStats.WriteOperations.BytesTransferred / (1024 * 1024)) / elapsedSeconds);
    }
}

static VOID
NvfsUpdateLatencyStats(VOID)
{
    if (g_NvfsStats.ReadOperations.SuccessCount > 0) {
        g_NvfsStats.ReadOperations.AverageLatencyUs = 
            (ULONG)(g_NvfsStats.ReadOperations.TotalLatencyUs / g_NvfsStats.ReadOperations.SuccessCount);
    }
    
    if (g_NvfsStats.WriteOperations.SuccessCount > 0) {
        g_NvfsStats.WriteOperations.AverageLatencyUs = 
            (ULONG)(g_NvfsStats.WriteOperations.TotalLatencyUs / g_NvfsStats.WriteOperations.SuccessCount);
    }
    
    if (g_NvfsStats.BatchOperations.SuccessCount > 0) {
        g_NvfsStats.BatchOperations.AverageLatencyUs = 
            (ULONG)(g_NvfsStats.BatchOperations.TotalLatencyUs / g_NvfsStats.BatchOperations.SuccessCount);
        
        g_NvfsStats.BatchOperations.AverageBatchSize = 
            (ULONG)(g_NvfsStats.BatchOperations.TotalBatchSize / g_NvfsStats.BatchOperations.SuccessCount);
    }
}