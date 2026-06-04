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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Batch I/O Operations Header
 */

#ifndef __NVFS_BATCH_WIN_H__
#define __NVFS_BATCH_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Enable batch support by default
#ifndef NVFS_BATCH_SUPPORT_WIN
#define NVFS_BATCH_SUPPORT_WIN
#endif

#ifdef NVFS_BATCH_SUPPORT_WIN

// Forward declarations
typedef struct _NVFS_IO_WIN NVFS_IO_WIN, *PNVFS_IO_WIN;
typedef union _NVFS_IOCTL_PARAM_UNION_WIN NVFS_IOCTL_PARAM_UNION_WIN, *PNVFS_IOCTL_PARAM_UNION_WIN;

// Constants
#define NVFS_MAX_BATCH_ENTRIES_WIN      256

// Operation types (Windows equivalents)
typedef enum _NVFS_OPERATION_TYPE_WIN {
    NVFS_OP_READ_WIN = 0,
    NVFS_OP_WRITE_WIN = 1,
    NVFS_OP_MAX_WIN
} NVFS_OPERATION_TYPE_WIN;

// File arguments structure (Windows equivalent)
typedef struct _NVFS_FILE_ARGS_WIN {
    ULONGLONG Inum;             // Inode number
    ULONG Generation;           // File generation
    ULONG MajDev;               // Major device number
    ULONG MinDev;               // Minor device number
    ULONGLONG DevPtrOff;        // Device pointer offset
} NVFS_FILE_ARGS_WIN, *PNVFS_FILE_ARGS_WIN;

// I/O arguments structure (Windows equivalent of nvfs_ioctl_ioargs_t)
typedef struct _NVFS_IOCTL_IOARGS_WIN {
    ULONG OpType;               // Operation type (READ/WRITE)
    ULONGLONG CpuVAddr;         // CPU virtual address
    ULONGLONG Offset;           // File offset
    ULONGLONG Size;             // Transfer size
    BOOLEAN Sync;               // Synchronous operation
    BOOLEAN HiPri;              // High priority
    BOOLEAN AllowReads;         // Allow read operations
    BOOLEAN UseRKeys;           // Use RDMA keys
    HANDLE Fd;                  // File descriptor (Windows handle)
    NVFS_FILE_ARGS_WIN FileArgs; // File-specific arguments
} NVFS_IOCTL_IOARGS_WIN, *PNVFS_IOCTL_IOARGS_WIN;

// Batch I/O arguments structure (Windows equivalent of nvfs_ioctl_batch_ioargs_t)
typedef struct _NVFS_IOCTL_BATCH_IOARGS_WIN {
    ULONGLONG ContextId;        // Context identifier
    ULONGLONG NumEntries;       // Number of I/O entries
    PNVFS_IOCTL_IOARGS_WIN IoEntries; // Array of I/O entries
} NVFS_IOCTL_BATCH_IOARGS_WIN, *PNVFS_IOCTL_BATCH_IOARGS_WIN;

// Batch I/O structure (Windows equivalent of nvfs_batch_io_t)
typedef struct _NVFS_BATCH_IO_WIN {
    ULONGLONG ContextId;        // Context identifier
    LARGE_INTEGER StartTime;    // Start time for latency calculation
    ULONGLONG NumEntries;       // Number of entries
    ULONG BatchId;              // Unique batch identifier
    PNVFS_IO_WIN NvfsIo[NVFS_MAX_BATCH_ENTRIES_WIN]; // Array of I/O operations
} NVFS_BATCH_IO_WIN, *PNVFS_BATCH_IO_WIN;

// Batch latency statistics structure
typedef struct _NVFS_BATCH_LATENCY_STATS_WIN {
    volatile LONGLONG TotalOperations;          // Total number of operations
    volatile LONGLONG TotalLatencyMicroseconds; // Total latency in microseconds
    volatile LONGLONG MinLatencyMicroseconds;   // Minimum latency
    volatile LONGLONG MaxLatencyMicroseconds;   // Maximum latency
} NVFS_BATCH_LATENCY_STATS_WIN, *PNVFS_BATCH_LATENCY_STATS_WIN;

// Batch performance statistics
typedef struct _NVFS_BATCH_STATISTICS_WIN {
    ULONG TotalBatchOperations;         // Total batch operations submitted
    ULONG AverageLatencyMicroseconds;   // Average submission latency
    ULONGLONG TotalLatencyMicroseconds; // Total accumulated latency
    ULONG CurrentBatchCount;            // Current number of active batches
} NVFS_BATCH_STATISTICS_WIN, *PNVFS_BATCH_STATISTICS_WIN;

// Global batch latency statistics
extern NVFS_BATCH_LATENCY_STATS_WIN g_NvfsBatchSubmitLatencyPerSec;

// Function prototypes

// Batch subsystem management
NTSTATUS
NvfsInitializeBatchSubsystemWin(VOID);

VOID
NvfsCleanupBatchSubsystemWin(VOID);

// Batch I/O operations
PNVFS_BATCH_IO_WIN
NvfsIoBatchInitWin(
    _In_ PNVFS_IOCTL_PARAM_UNION_WIN InputParam
);

NTSTATUS
NvfsIoBatchSubmitWin(
    _In_ PNVFS_BATCH_IO_WIN NvfsBatch
);

// Statistics and monitoring
NTSTATUS
NvfsGetBatchStatisticsWin(
    _Out_ PNVFS_BATCH_STATISTICS_WIN Statistics
);

VOID
NvfsResetBatchStatisticsWin(VOID);

VOID
NvfsUpdateBatchLatencyWin(
    _In_ ULONGLONG LatencyMicroseconds,
    _Inout_ PNVFS_BATCH_LATENCY_STATS_WIN LatencyStats
);

// Validation and utility functions
BOOLEAN
NvfsValidateBatchParametersWin(
    _In_ PNVFS_IOCTL_BATCH_IOARGS_WIN BatchArgs
);

ULONG
NvfsGetCurrentBatchCountWin(VOID);

BOOLEAN
NvfsIsBatchSubsystemInitializedWin(VOID);

// Forward declarations for functions that need to be implemented elsewhere
PNVFS_IO_WIN
NvfsIoInitWin(
    _In_ ULONG OpType,
    _In_ PNVFS_IOCTL_IOARGS_WIN IoArgs
);

VOID
NvfsIoFreeWin(
    _In_ PNVFS_IO_WIN NvfsIo,
    _In_ NTSTATUS Status
);

NTSTATUS
NvfsIoStartOpWin(
    _In_ PNVFS_IO_WIN NvfsIo
);

// Inline helper functions

static __inline ULONGLONG
NvfsGetBatchEntryCount(
    _In_ PNVFS_BATCH_IO_WIN Batch
)
{
    return (Batch != NULL) ? Batch->NumEntries : 0;
}

static __inline BOOLEAN
NvfsIsBatchValid(
    _In_ PNVFS_BATCH_IO_WIN Batch
)
{
    return (Batch != NULL && 
            Batch->NumEntries > 0 && 
            Batch->NumEntries <= NVFS_MAX_BATCH_ENTRIES_WIN);
}

static __inline BOOLEAN
NvfsIsBatchContextValid(
    _In_ ULONGLONG ContextId
)
{
    return (ContextId != 0);
}

static __inline ULONG
NvfsCalculateBatchMemorySize(
    _In_ ULONG NumEntries
)
{
    if (NumEntries > NVFS_MAX_BATCH_ENTRIES_WIN) {
        return 0;
    }
    return sizeof(NVFS_BATCH_IO_WIN) + (NumEntries * sizeof(PNVFS_IO_WIN));
}

// Batch operation priority levels
typedef enum _NVFS_BATCH_PRIORITY_WIN {
    NVFS_BATCH_PRIORITY_LOW_WIN = 0,
    NVFS_BATCH_PRIORITY_NORMAL_WIN = 1,
    NVFS_BATCH_PRIORITY_HIGH_WIN = 2,
    NVFS_BATCH_PRIORITY_CRITICAL_WIN = 3
} NVFS_BATCH_PRIORITY_WIN;

// Batch operation flags
#define NVFS_BATCH_FLAG_ASYNC_WIN           0x00000001
#define NVFS_BATCH_FLAG_HIGH_PRIORITY_WIN   0x00000002
#define NVFS_BATCH_FLAG_COHERENT_WIN        0x00000004
#define NVFS_BATCH_FLAG_NO_CACHE_WIN        0x00000008

// Error codes specific to batch operations
#define NVFS_BATCH_ERROR_TOO_MANY_ENTRIES   ((NTSTATUS)0xE0000010L)
#define NVFS_BATCH_ERROR_INVALID_CONTEXT    ((NTSTATUS)0xE0000011L)
#define NVFS_BATCH_ERROR_OPERATION_FAILED   ((NTSTATUS)0xE0000012L)
#define NVFS_BATCH_ERROR_TIMEOUT            ((NTSTATUS)0xE0000013L)

#endif // NVFS_BATCH_SUPPORT_WIN

#endif // __NVFS_BATCH_WIN_H__