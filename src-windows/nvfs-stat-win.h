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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Statistics Header
 */

#ifndef __NVFS_STAT_WIN_H__
#define __NVFS_STAT_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Statistics version for compatibility
#define NVFS_STAT_VERSION_WIN           4
#define BYTES_TO_MB(b)                  ((b) >> 20ULL)

// Memory type enumeration for GPU statistics
typedef enum _NVFS_MEMORY_TYPE_WIN {
    NvfsMemoryTypeBar = 0,
    NvfsMemoryTypeBounceBuffer,
    NvfsMemoryTypeMax
} NVFS_MEMORY_TYPE_WIN;

// Error type enumeration for error statistics
typedef enum _NVFS_ERROR_TYPE_WIN {
    NvfsErrorMixCpuGpu = 0,
    NvfsErrorScatterGather,
    NvfsErrorDmaMap,
    NvfsErrorDmaRef,
    NvfsErrorPageCache,
    NvfsErrorPageCacheFail,
    NvfsErrorPageCacheEio,
    NvfsErrorMax
} NVFS_ERROR_TYPE_WIN;

// Operation statistics structure
typedef struct _NVFS_OPERATION_STATISTICS_WIN {
    LONGLONG Count;                     // Total number of operations
    LONGLONG SuccessCount;              // Number of successful operations
    ULONG ErrorCount;                   // Number of failed operations
    LONGLONG BytesTransferred;          // Total bytes transferred
    LONGLONG TotalLatencyUs;            // Total latency in microseconds
    ULONG AverageLatencyUs;             // Average latency in microseconds
    ULONG BandwidthMBps;               // Bandwidth in MB/s
    ULONG IoStateErrors;               // I/O state errors
} NVFS_OPERATION_STATISTICS_WIN, *PNVFS_OPERATION_STATISTICS_WIN;

// Batch operation statistics structure
typedef struct _NVFS_BATCH_STATISTICS_WIN {
    LONGLONG Count;                     // Total number of batch operations
    LONGLONG SuccessCount;              // Number of successful batch operations
    ULONG ErrorCount;                   // Number of failed batch operations
    LONGLONG TotalBatchSize;            // Total size of all batches
    ULONG AverageBatchSize;             // Average batch size
    LONGLONG TotalLatencyUs;            // Total submission latency
    ULONG AverageLatencyUs;             // Average submission latency
} NVFS_BATCH_STATISTICS_WIN, *PNVFS_BATCH_STATISTICS_WIN;

// Memory mapping statistics structure
typedef struct _NVFS_MMAP_STATISTICS_WIN {
    LONGLONG MmapCount;                 // Total mmap operations
    LONGLONG MmapSuccessCount;          // Successful mmap operations
    ULONG MmapErrorCount;               // Failed mmap operations
    LONGLONG MunmapCount;               // Total munmap operations
    LONGLONG MapsCount;                 // Total memory maps
    LONGLONG MapsSuccessCount;          // Successful memory maps
    ULONG MapsErrorCount;               // Failed memory maps
    LONGLONG FreeCount;                 // Total memory frees
    ULONG CallbackCount;                // Callback count
    ULONG ActiveMaps;                   // Currently active maps
    LONGLONG DelayedFrees;              // Delayed free operations
} NVFS_MMAP_STATISTICS_WIN, *PNVFS_MMAP_STATISTICS_WIN;

// Sparse file statistics structure
typedef struct _NVFS_SPARSE_STATISTICS_WIN {
    LONGLONG SparseFileReads;           // Reads from sparse files
    LONGLONG SparseIoOperations;        // Sparse I/O operations
    LONGLONG SparseRegions;             // Sparse regions encountered
    LONGLONG SparsePages;               // Sparse pages processed
} NVFS_SPARSE_STATISTICS_WIN, *PNVFS_SPARSE_STATISTICS_WIN;

// Error counters structure
typedef struct _NVFS_ERROR_COUNTERS_WIN {
    ULONG MixCpuGpuErrors;              // Mixed CPU-GPU page errors
    ULONG ScatterGatherErrors;          // Scatter-gather errors
    ULONG DmaMapErrors;                 // DMA mapping errors
    ULONG DmaRefErrors;                 // DMA reference errors
    ULONG PageCacheErrors;              // Page cache errors
    ULONG PageCacheFailErrors;          // Page cache failure errors
    ULONG PageCacheEioErrors;           // Page cache EIO errors
} NVFS_ERROR_COUNTERS_WIN, *PNVFS_ERROR_COUNTERS_WIN;

// Global statistics structure
typedef struct _NVFS_STATISTICS_WIN {
    NVFS_OPERATION_STATISTICS_WIN ReadOperations;
    NVFS_OPERATION_STATISTICS_WIN WriteOperations;
    NVFS_BATCH_STATISTICS_WIN BatchOperations;
    NVFS_MMAP_STATISTICS_WIN MmapOperations;
    NVFS_SPARSE_STATISTICS_WIN SparseOperations;
    NVFS_ERROR_COUNTERS_WIN ErrorCounters;
    
    // Active resource counters
    LONGLONG ActiveShadowBufferSize;    // Active shadow buffer size in bytes
    ULONG ActiveProcesses;              // Number of active processes
    
    // Driver information
    ULONG DriverMajorVersion;
    ULONG DriverMinorVersion;
    ULONG DriverPatchVersion;
    BOOLEAN PeerDirectSupported;
    BOOLEAN IoStatsEnabled;
    BOOLEAN PeerIoStatsEnabled;
    
} NVFS_STATISTICS_WIN, *PNVFS_STATISTICS_WIN;

// GPU-specific statistics structure
typedef struct _NVFS_GPU_STATISTICS_WIN {
    GUID GpuUuid;                       // GPU unique identifier
    ULONG GpuIndex;                     // GPU index for PCI lookups
    
    // Memory statistics
    LONGLONG ActiveBarMemoryPinned;     // Currently pinned BAR memory
    LONGLONG ActiveBounceBufferMemory;  // Currently allocated bounce buffer memory
    LONGLONG MaxBarMemoryPinned;        // Maximum BAR memory pinned (high watermark)
    
    // Cross-root port traffic statistics
    ULONG CrossRootPortUsagePercent;    // Cross root port usage percentage
    
} NVFS_GPU_STATISTICS_WIN, *PNVFS_GPU_STATISTICS_WIN;

// Function prototypes

// Initialization and cleanup
NTSTATUS
NvfsInitializeStatisticsWin(VOID);

VOID
NvfsCleanupStatisticsWin(VOID);

// Statistics retrieval
NTSTATUS
NvfsGetGlobalStatisticsWin(
    _Out_ PNVFS_STATISTICS_WIN Statistics
);

NTSTATUS
NvfsGetGpuStatisticsWin(
    _In_ CONST GUID* GpuUuid,
    _Out_ PNVFS_GPU_STATISTICS_WIN GpuStatistics
);

// Statistics management
VOID
NvfsResetStatisticsWin(VOID);

NTSTATUS
NvfsRegisterGpuStatisticsWin(
    _In_ CONST GUID* GpuUuid,
    _In_ ULONG GpuIndex
);

VOID
NvfsUnregisterGpuStatisticsWin(
    _In_ CONST GUID* GpuUuid
);

// Statistics update functions
VOID
NvfsUpdateReadStatisticsWin(
    _In_ ULONG BytesRead,
    _In_ LARGE_INTEGER StartTime,
    _In_ BOOLEAN Success
);

VOID
NvfsUpdateWriteStatisticsWin(
    _In_ ULONG BytesWritten,
    _In_ LARGE_INTEGER StartTime,
    _In_ BOOLEAN Success
);

VOID
NvfsUpdateBatchStatisticsWin(
    _In_ ULONG BatchSize,
    _In_ LARGE_INTEGER SubmitTime,
    _In_ BOOLEAN Success
);

VOID
NvfsUpdateMemoryStatisticsWin(
    _In_ CONST GUID* GpuUuid,
    _In_ LONGLONG MemoryDelta,
    _In_ NVFS_MEMORY_TYPE_WIN MemoryType
);

VOID
NvfsIncrementErrorStatisticsWin(
    _In_ NVFS_ERROR_TYPE_WIN ErrorType
);

// Configuration
BOOLEAN
NvfsIsStatisticsEnabledWin(VOID);

VOID
NvfsSetStatisticsEnabledWin(
    _In_ BOOLEAN Enabled
);

// Inline helper functions for atomic operations and timing

static __inline LONGLONG
NvfsGetCurrentTimeMs(VOID)
{
    LARGE_INTEGER currentTime;
    LARGE_INTEGER frequency;
    
    currentTime = KeQueryPerformanceCounter(&frequency);
    return (currentTime.QuadPart * 1000) / frequency.QuadPart;
}

static __inline ULONG
NvfsCalculateLatencyUs(
    _In_ LARGE_INTEGER StartTime,
    _In_ LARGE_INTEGER EndTime,
    _In_ LARGE_INTEGER Frequency
)
{
    LARGE_INTEGER elapsed;
    
    elapsed.QuadPart = EndTime.QuadPart - StartTime.QuadPart;
    return (ULONG)((elapsed.QuadPart * 1000000) / Frequency.QuadPart);
}

static __inline ULONG
NvfsCalculateBandwidthMBps(
    _In_ ULONGLONG BytesTransferred,
    _In_ ULONGLONG ElapsedTimeMs
)
{
    if (ElapsedTimeMs == 0) {
        return 0;
    }
    
    // Convert to MB/s: (bytes / (1024*1024)) / (ms / 1000)
    return (ULONG)((BytesTransferred * 1000) / (ElapsedTimeMs * 1024 * 1024));
}

// Convenience macros for statistics updates

#define NVFS_STATS_UPDATE_READ_WIN(bytes, startTime, success) \
    NvfsUpdateReadStatisticsWin((bytes), (startTime), (success))

#define NVFS_STATS_UPDATE_WRITE_WIN(bytes, startTime, success) \
    NvfsUpdateWriteStatisticsWin((bytes), (startTime), (success))

#define NVFS_STATS_UPDATE_BATCH_WIN(batchSize, submitTime, success) \
    NvfsUpdateBatchStatisticsWin((batchSize), (submitTime), (success))

#define NVFS_STATS_UPDATE_MEMORY_WIN(gpuUuid, delta, type) \
    NvfsUpdateMemoryStatisticsWin((gpuUuid), (delta), (type))

#define NVFS_STATS_INCREMENT_ERROR_WIN(errorType) \
    NvfsIncrementErrorStatisticsWin(errorType)

// IOCTL codes for statistics access
#define NVFS_IOCTL_GET_GLOBAL_STATISTICS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_READ_ACCESS)
#define NVFS_IOCTL_GET_GPU_STATISTICS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_READ_ACCESS)
#define NVFS_IOCTL_RESET_STATISTICS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define NVFS_IOCTL_SET_STATS_ENABLED        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// IOCTL input/output structures
typedef struct _NVFS_GET_GPU_STATS_INPUT_WIN {
    GUID GpuUuid;                       // GPU UUID to query
} NVFS_GET_GPU_STATS_INPUT_WIN, *PNVFS_GET_GPU_STATS_INPUT_WIN;

typedef struct _NVFS_SET_STATS_ENABLED_INPUT_WIN {
    BOOLEAN Enabled;                    // Enable/disable statistics collection
} NVFS_SET_STATS_ENABLED_INPUT_WIN, *PNVFS_SET_STATS_ENABLED_INPUT_WIN;

// Statistics formatting helpers
static __inline VOID
NvfsFormatGpuUuidString(
    _In_ CONST GUID* GpuUuid,
    _Out_writes_(40) PWCHAR UuidString
)
{
    RtlStringCchPrintfW(
        UuidString,
        40,
        L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        GpuUuid->Data1,
        GpuUuid->Data2,
        GpuUuid->Data3,
        GpuUuid->Data4[0],
        GpuUuid->Data4[1],
        GpuUuid->Data4[2],
        GpuUuid->Data4[3],
        GpuUuid->Data4[4],
        GpuUuid->Data4[5],
        GpuUuid->Data4[6],
        GpuUuid->Data4[7]
    );
}

// Debug and diagnostics macros
#ifdef DBG
#define NVFS_STATS_DEBUG_PRINT(format, ...) \
    DbgPrint("NVFS_STATS: " format "\n", __VA_ARGS__)
#else
#define NVFS_STATS_DEBUG_PRINT(format, ...) ((void)0)
#endif

#endif // __NVFS_STAT_WIN_H__