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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Batch I/O Operations
 */

// Windows kernel headers
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Windows-specific includes
#include "nvfs-core-win.h"
#include "nvfs-batch-win.h"
#include "nvfs-mmap-win.h"
#include "nvfs-dma-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-kernel-interface-win.h"
#include "config-host-win.h"

#ifdef NVFS_BATCH_SUPPORT_WIN

// Global variables for batch processing
static NPAGED_LOOKASIDE_LIST g_BatchLookasideList;
static FAST_MUTEX g_BatchMutex;
static BOOLEAN g_BatchSubsystemInitialized = FALSE;
static ULONG g_BatchOperationId = 0;

// Performance tracking
static LARGE_INTEGER g_BatchLatencySum;
static ULONG g_BatchOperationCount;

// Windows equivalent of ktime_get() for performance measurement
static __inline LARGE_INTEGER
NvfsGetCurrentTimeWin(VOID)
{
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    return currentTime;
}

// Windows equivalent of ktime_us_delta() for microsecond timing
static __inline ULONGLONG
NvfsGetTimeDeltaMicrosecondsWin(
    _In_ LARGE_INTEGER StartTime,
    _In_ LARGE_INTEGER EndTime
)
{
    LARGE_INTEGER delta;
    delta.QuadPart = EndTime.QuadPart - StartTime.QuadPart;
    // Convert 100ns units to microseconds
    return (ULONGLONG)(delta.QuadPart / 10);
}

// Initialize batch I/O subsystem
NTSTATUS
NvfsInitializeBatchSubsystemWin(VOID)
{
    if (g_BatchSubsystemInitialized) {
        return STATUS_SUCCESS;
    }
    
    // Initialize lookaside list for batch structures
    ExInitializeNPagedLookasideList(
        &g_BatchLookasideList,
        NULL,                               // Allocate function
        NULL,                               // Free function
        0,                                  // Flags
        sizeof(NVFS_BATCH_IO_WIN),          // Size
        'TBCN',                             // Tag
        0                                   // Depth
    );
    
    // Initialize mutex for batch operations
    ExInitializeFastMutex(&g_BatchMutex);
    
    // Initialize performance counters
    g_BatchLatencySum.QuadPart = 0;
    g_BatchOperationCount = 0;
    g_BatchOperationId = 0;
    
    g_BatchSubsystemInitialized = TRUE;
    
    nvfs_info("Batch I/O subsystem initialized\n");
    return STATUS_SUCCESS;
}

// Cleanup batch I/O subsystem
VOID
NvfsCleanupBatchSubsystemWin(VOID)
{
    if (!g_BatchSubsystemInitialized) {
        return;
    }
    
    ExDeleteNPagedLookasideList(&g_BatchLookasideList);
    g_BatchSubsystemInitialized = FALSE;
    
    nvfs_info("Batch I/O subsystem cleaned up\n");
}

// Windows equivalent of copy_from_user for batch entry validation
static NTSTATUS
NvfsCopyBatchEntryFromUserWin(
    _Out_ PNVFS_IOCTL_IOARGS_WIN IoEntry,
    _In_ PNVFS_IOCTL_IOARGS_WIN UserEntry
)
{
    NTSTATUS status;
    
    if (IoEntry == NULL || UserEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    __try {
        // Probe and copy user-mode data
        ProbeForRead(UserEntry, sizeof(NVFS_IOCTL_IOARGS_WIN), sizeof(UCHAR));
        RtlCopyMemory(IoEntry, UserEntry, sizeof(NVFS_IOCTL_IOARGS_WIN));
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        nvfs_err("Failed to copy batch entry from user mode: 0x%08lx\n", GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
    }
    
    return status;
}

// Windows equivalent of nvfs_io_batch_init
PNVFS_BATCH_IO_WIN
NvfsIoBatchInitWin(
    _In_ PNVFS_IOCTL_PARAM_UNION_WIN InputParam
)
{
    PNVFS_IOCTL_BATCH_IOARGS_WIN batchArgs;
    PNVFS_BATCH_IO_WIN nvfsBatch = NULL;
    NTSTATUS status;
    ULONG i;
    BOOLEAN rwStatsEnabled = FALSE;
    
    if (InputParam == NULL) {
        nvfs_err("Invalid input parameter for batch initialization\n");
        return NULL;
    }
    
    batchArgs = &(InputParam->BatchIoArgs);
    
    // Check if read/write statistics are enabled
    if (g_NvfsRwStatsEnabled > 0) {
        rwStatsEnabled = TRUE;
    }
    
    // Validate batch entry count
    if (batchArgs->NumEntries <= 0 || batchArgs->NumEntries > NVFS_MAX_BATCH_ENTRIES_WIN) {
        nvfs_err("Number of batch entries (%lld) exceeds maximum supported (%d)\n",
                batchArgs->NumEntries, NVFS_MAX_BATCH_ENTRIES_WIN);
        return NULL;
    }
    
    // Allocate batch structure from lookaside list
    nvfsBatch = (PNVFS_BATCH_IO_WIN)ExAllocateFromNPagedLookasideList(&g_BatchLookasideList);
    if (nvfsBatch == NULL) {
        nvfs_err("Failed to allocate memory for batch structure\n");
        return NULL;
    }
    
    RtlZeroMemory(nvfsBatch, sizeof(NVFS_BATCH_IO_WIN));
    
    // Initialize batch structure
    nvfsBatch->ContextId = batchArgs->ContextId;
    nvfsBatch->StartTime = NvfsGetCurrentTimeWin();
    nvfsBatch->NumEntries = batchArgs->NumEntries;
    nvfsBatch->BatchId = InterlockedIncrement(&g_BatchOperationId);
    
    nvfs_dbg("Batch submit - ContextId: %lld, NumEntries: %lld, BatchId: %ld\n",
             batchArgs->ContextId, batchArgs->NumEntries, nvfsBatch->BatchId);
    
    // Process each batch entry
    for (i = 0; i < batchArgs->NumEntries; i++) {
        NVFS_IOCTL_IOARGS_WIN ioEntry;
        PNVFS_IOCTL_IOARGS_WIN userEntryPtr;
        
        userEntryPtr = &(batchArgs->IoEntries[i]);
        
        // Copy entry from user mode
        status = NvfsCopyBatchEntryFromUserWin(&ioEntry, userEntryPtr);
        if (!NT_SUCCESS(status)) {
            nvfs_err("Failed to copy batch entry %d from user mode: 0x%08lx\n", i, status);
            goto cleanup;
        }
        
        nvfs_dbg("Entry %d: OpType=%d, CpuVAddr=0x%llx, Offset=0x%llx, Size=0x%llx\n"
                 "         Sync=%d, HiPri=%d, AllowReads=%d, UseRKeys=%d\n"
                 "         Fd=%d, Inum=%ld, Generation=%d, MajDev=0x%x, MinDev=0x%x\n",
                 i, ioEntry.OpType, ioEntry.CpuVAddr, ioEntry.Offset, ioEntry.Size,
                 ioEntry.Sync, ioEntry.HiPri, ioEntry.AllowReads, ioEntry.UseRKeys,
                 ioEntry.Fd, ioEntry.FileArgs.Inum, ioEntry.FileArgs.Generation,
                 ioEntry.FileArgs.MajDev, ioEntry.FileArgs.MinDev);
        
        // Initialize individual I/O operation
        nvfsBatch->NvfsIo[i] = NvfsIoInitWin(ioEntry.OpType, &ioEntry);
        if (nvfsBatch->NvfsIo[i] == NULL) {
            nvfs_err("Failed to initialize I/O operation for batch entry %d\n", i);
            goto cleanup;
        }
        
        // Update statistics based on operation type
        if (ioEntry.OpType == NVFS_OP_READ_WIN) {
            if (rwStatsEnabled) {
                NvfsStatIncrement64(&g_NvfsStats.ReadCount);
                NvfsStatIncrement(&g_NvfsStats.OpReads);
            }
        } else if (ioEntry.OpType == NVFS_OP_WRITE_WIN) {
            if (rwStatsEnabled) {
                NvfsStatIncrement64(&g_NvfsStats.WriteCount);
                NvfsStatIncrement(&g_NvfsStats.OpWrites);
            }
        }
        
        nvfsBatch->NvfsIo[i]->RwStatsEnabled = rwStatsEnabled;
    }
    
    return nvfsBatch;
    
cleanup:
    if (nvfsBatch != NULL) {
        for (i = 0; i < nvfsBatch->NumEntries; i++) {
            if (nvfsBatch->NvfsIo[i] != NULL) {
                NvfsIoFreeWin(nvfsBatch->NvfsIo[i], STATUS_UNSUCCESSFUL);
            }
        }
        ExFreeToNPagedLookasideList(&g_BatchLookasideList, nvfsBatch);
    }
    return NULL;
}

// Windows equivalent of nvfs_io_batch_submit
NTSTATUS
NvfsIoBatchSubmitWin(
    _In_ PNVFS_BATCH_IO_WIN NvfsBatch
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    LARGE_INTEGER endTime;
    ULONGLONG latencyMicroseconds;
    
    if (NvfsBatch == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    nvfs_dbg("Submitting batch %ld with %lld entries\n", 
             NvfsBatch->BatchId, NvfsBatch->NumEntries);
    
    // Submit each I/O operation in the batch
    for (i = 0; i < NvfsBatch->NumEntries; i++) {
        if (NvfsBatch->NvfsIo[i] == NULL) {
            continue;
        }
        
        status = NvfsIoStartOpWin(NvfsBatch->NvfsIo[i]);
        if (!NT_SUCCESS(status)) {
            nvfs_err("Failed to start batch I/O entry %d: 0x%08lx\n", i, status);
            NvfsBatch->NvfsIo[i] = NULL;
            goto cleanup;
        }
    }
    
    // Calculate and update batch submission latency
    endTime = NvfsGetCurrentTimeWin();
    latencyMicroseconds = NvfsGetTimeDeltaMicrosecondsWin(NvfsBatch->StartTime, endTime);
    
    ExAcquireFastMutex(&g_BatchMutex);
    g_BatchLatencySum.QuadPart += latencyMicroseconds;
    g_BatchOperationCount++;
    ExReleaseFastMutex(&g_BatchMutex);
    
    nvfs_dbg("Batch %ld submitted successfully, latency: %lld μs\n",
             NvfsBatch->BatchId, latencyMicroseconds);
    
    // Update batch submission statistics
    NvfsUpdateBatchLatencyWin(latencyMicroseconds, &g_NvfsBatchSubmitLatencyPerSec);
    
    // Free batch structure
    ExFreeToNPagedLookasideList(&g_BatchLookasideList, NvfsBatch);
    
    return status;
    
cleanup:
    // Clean up any remaining I/O operations
    for (i = 0; i < NvfsBatch->NumEntries; i++) {
        if (NvfsBatch->NvfsIo[i] != NULL) {
            NvfsIoFreeWin(NvfsBatch->NvfsIo[i], STATUS_UNSUCCESSFUL);
        }
    }
    
    // Note: In a real implementation, we should wait for ongoing operations
    // or implement proper cancellation mechanism
    
    ExFreeToNPagedLookasideList(&g_BatchLookasideList, NvfsBatch);
    return status;
}

// Get batch performance statistics
NTSTATUS
NvfsGetBatchStatisticsWin(
    _Out_ PNVFS_BATCH_STATISTICS_WIN Statistics
)
{
    if (Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlZeroMemory(Statistics, sizeof(NVFS_BATCH_STATISTICS_WIN));
    
    ExAcquireFastMutex(&g_BatchMutex);
    
    Statistics->TotalBatchOperations = g_BatchOperationCount;
    if (g_BatchOperationCount > 0) {
        Statistics->AverageLatencyMicroseconds = 
            (ULONG)(g_BatchLatencySum.QuadPart / g_BatchOperationCount);
    }
    Statistics->TotalLatencyMicroseconds = g_BatchLatencySum.QuadPart;
    
    ExReleaseFastMutex(&g_BatchMutex);
    
    return STATUS_SUCCESS;
}

// Reset batch performance counters
VOID
NvfsResetBatchStatisticsWin(VOID)
{
    ExAcquireFastMutex(&g_BatchMutex);
    
    g_BatchLatencySum.QuadPart = 0;
    g_BatchOperationCount = 0;
    
    ExReleaseFastMutex(&g_BatchMutex);
    
    nvfs_info("Batch statistics reset\n");
}

// Update batch latency statistics (Windows equivalent of nvfs_update_batch_latency)
VOID
NvfsUpdateBatchLatencyWin(
    _In_ ULONGLONG LatencyMicroseconds,
    _Inout_ PNVFS_BATCH_LATENCY_STATS_WIN LatencyStats
)
{
    if (LatencyStats == NULL) {
        return;
    }
    
    // Update per-second statistics (simplified implementation)
    InterlockedIncrement64(&LatencyStats->TotalOperations);
    InterlockedAdd64(&LatencyStats->TotalLatencyMicroseconds, LatencyMicroseconds);
    
    // Update min/max latency
    ULONGLONG currentMin = LatencyStats->MinLatencyMicroseconds;
    while (currentMin == 0 || LatencyMicroseconds < currentMin) {
        ULONGLONG originalMin = InterlockedCompareExchange64(
            &LatencyStats->MinLatencyMicroseconds,
            LatencyMicroseconds,
            currentMin
        );
        if (originalMin == currentMin) {
            break;
        }
        currentMin = originalMin;
    }
    
    ULONGLONG currentMax = LatencyStats->MaxLatencyMicroseconds;
    while (LatencyMicroseconds > currentMax) {
        ULONGLONG originalMax = InterlockedCompareExchange64(
            &LatencyStats->MaxLatencyMicroseconds,
            LatencyMicroseconds,
            currentMax
        );
        if (originalMax == currentMax) {
            break;
        }
        currentMax = originalMax;
    }
}

// Validate batch operation parameters
BOOLEAN
NvfsValidateBatchParametersWin(
    _In_ PNVFS_IOCTL_BATCH_IOARGS_WIN BatchArgs
)
{
    if (BatchArgs == NULL) {
        return FALSE;
    }
    
    // Validate number of entries
    if (BatchArgs->NumEntries == 0 || BatchArgs->NumEntries > NVFS_MAX_BATCH_ENTRIES_WIN) {
        nvfs_err("Invalid batch entry count: %lld (max: %d)\n",
                BatchArgs->NumEntries, NVFS_MAX_BATCH_ENTRIES_WIN);
        return FALSE;
    }
    
    // Validate context ID
    if (BatchArgs->ContextId == 0) {
        nvfs_warn("Batch context ID is zero\n");
    }
    
    // Validate I/O entries pointer
    if (BatchArgs->IoEntries == NULL) {
        nvfs_err("Batch I/O entries pointer is NULL\n");
        return FALSE;
    }
    
    return TRUE;
}

// Get current batch operation count
ULONG
NvfsGetCurrentBatchCountWin(VOID)
{
    return g_BatchOperationCount;
}

// Check if batch subsystem is initialized
BOOLEAN
NvfsIsBatchSubsystemInitializedWin(VOID)
{
    return g_BatchSubsystemInitialized;
}

#endif // NVFS_BATCH_SUPPORT_WIN