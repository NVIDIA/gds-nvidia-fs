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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - RDMA Header
 */

#ifndef __NVFS_RDMA_WIN_H__
#define __NVFS_RDMA_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Enable RDMA support for Windows (comment out to disable)
#define NVFS_ENABLE_RDMA_SUPPORT_WIN

// Forward declarations
typedef struct _NVFS_MGROUP_WIN NVFS_MGROUP_WIN, *PNVFS_MGROUP_WIN;

// RDMA constants
#define NVFS_RDMA_MIN_SUPPORTED_VERSION_WIN     1
#define NVFS_MAX_RDMA_KEYS_WIN                  4
#define NVFS_BLOCK_SIZE_WIN                     4096

// RDMA information structure (Windows equivalent of nvfs_rdma_info)
typedef struct _NVFS_RDMA_INFO_WIN {
    ULONG Version;                      // RDMA registration version
    ULONG Flags;                        // RDMA flags
    ULONG Lid;                          // Local identifier
    ULONG QpNum;                        // Queue pair number
    ULONGLONG Gid[2];                   // Global identifier (128-bit)
    ULONG DcKey;                        // Dynamically connected key
    ULONG RKey;                         // Remote key
    ULONGLONG RemVaddr;                 // Remote virtual address
    ULONG Size;                         // Size of remote memory region
    ULONG CurrentSegment;               // Current RDMA segment
} NVFS_RDMA_INFO_WIN, *PNVFS_RDMA_INFO_WIN;

// RDMA IOCTL argument structures
typedef struct _NVFS_IOCTL_SET_RDMA_REG_INFO_ARGS_WIN {
    ULONGLONG CpuVaddr;                 // CPU virtual address
    ULONG Version;                      // RDMA version
    ULONG Flags;                        // RDMA flags
    ULONG Lid;                          // Local identifier
    ULONG QpNum;                        // Queue pair number
    ULONGLONG Gid[2];                   // Global identifier
    ULONG DcKey;                        // Dynamically connected key
    ULONG NumKeys;                      // Number of remote keys
    ULONG RKey[NVFS_MAX_RDMA_KEYS_WIN]; // Remote keys array
} NVFS_IOCTL_SET_RDMA_REG_INFO_ARGS_WIN, *PNVFS_IOCTL_SET_RDMA_REG_INFO_ARGS_WIN;

typedef struct _NVFS_IOCTL_GET_RDMA_REG_INFO_ARGS_WIN {
    ULONGLONG CpuVaddr;                 // CPU virtual address
    NVFS_RDMA_INFO_WIN RdmaInfo;        // Retrieved RDMA information
} NVFS_IOCTL_GET_RDMA_REG_INFO_ARGS_WIN, *PNVFS_IOCTL_GET_RDMA_REG_INFO_ARGS_WIN;

typedef struct _NVFS_IOCTL_CLEAR_RDMA_REG_INFO_ARGS_WIN {
    ULONGLONG CpuVaddr;                 // CPU virtual address
} NVFS_IOCTL_CLEAR_RDMA_REG_INFO_ARGS_WIN, *PNVFS_IOCTL_CLEAR_RDMA_REG_INFO_ARGS_WIN;

// RDMA connection state enumeration
typedef enum _NVFS_RDMA_CONNECTION_STATE_WIN {
    NvfsRdmaConnectionStateUninitialized = 0,
    NvfsRdmaConnectionStateInitialized,
    NvfsRdmaConnectionStateConnecting,
    NvfsRdmaConnectionStateConnected,
    NvfsRdmaConnectionStateDisconnecting,
    NvfsRdmaConnectionStateDisconnected,
    NvfsRdmaConnectionStateError
} NVFS_RDMA_CONNECTION_STATE_WIN;

// RDMA connection information
typedef struct _NVFS_RDMA_CONNECTION_INFO_WIN {
    ULONGLONG RemoteAddress;            // Remote IP address
    USHORT RemotePort;                  // Remote port
    ULONGLONG LocalAddress;             // Local IP address
    USHORT LocalPort;                   // Local port
    ULONG MaxSendSge;                   // Maximum send scatter-gather elements
    ULONG MaxRecvSge;                   // Maximum receive scatter-gather elements
    ULONG MaxInlineData;                // Maximum inline data size
} NVFS_RDMA_CONNECTION_INFO_WIN, *PNVFS_RDMA_CONNECTION_INFO_WIN;

// RDMA connection structure
typedef struct _NVFS_RDMA_CONNECTION_WIN {
    NVFS_RDMA_CONNECTION_STATE_WIN State;   // Connection state
    NVFS_RDMA_CONNECTION_INFO_WIN ConnectionInfo; // Connection parameters
    PVOID Provider;                     // NDK provider reference
    PVOID Connector;                    // NDK connector
    PVOID QueuePair;                    // NDK queue pair
    PVOID CompletionQueue;              // NDK completion queue
    PVOID MemoryRegion;                 // NDK memory region
    KGUARDED_MUTEX ConnectionLock;      // Connection synchronization
} NVFS_RDMA_CONNECTION_WIN, *PNVFS_RDMA_CONNECTION_WIN;

// RDMA statistics structure
typedef struct _NVFS_RDMA_STATISTICS_WIN {
    ULONG RegistrationCount;            // Number of RDMA registrations
    ULONG QueryCount;                   // Number of RDMA queries
    ULONG ClearCount;                   // Number of RDMA clears
    ULONG ConnectionCount;              // Number of active connections
    ULONG TransferCount;                // Number of RDMA transfers
    ULONGLONG BytesTransferred;         // Total bytes transferred via RDMA
    ULONG ErrorCount;                   // Number of RDMA errors
    ULONG TimeoutCount;                 // Number of RDMA timeouts
} NVFS_RDMA_STATISTICS_WIN, *PNVFS_RDMA_STATISTICS_WIN;

// Function prototypes

#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN

// Initialization and cleanup
NTSTATUS
NvfsInitializeRdmaWin(VOID);

VOID
NvfsCleanupRdmaWin(VOID);

// RDMA registration management
NTSTATUS
NvfsSetRdmaRegInfoToMgroupWin(
    _In_ PNVFS_IOCTL_SET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs
);

NTSTATUS
NvfsGetRdmaRegInfoFromMgroupWin(
    _Inout_ PNVFS_IOCTL_GET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs
);

NTSTATUS
NvfsClearRdmaRegInfoInMgroupWin(
    _In_ PNVFS_IOCTL_CLEAR_RDMA_REG_INFO_ARGS_WIN RdmaClearInfoArgs
);

// RDMA segment management
VOID
NvfsSetCurrentRdmaSegmentToMgroupWin(
    _In_ PNVFS_MGROUP_WIN Mgroup,
    _In_ ULONG RdmaSegment
);

// RDMA connection management
NTSTATUS
NvfsCreateRdmaConnectionWin(
    _In_ PNVFS_RDMA_CONNECTION_INFO_WIN ConnectionInfo,
    _Outptr_ PNVFS_RDMA_CONNECTION_WIN* Connection
);

VOID
NvfsDestroyRdmaConnectionWin(
    _In_ PNVFS_RDMA_CONNECTION_WIN Connection
);

// RDMA statistics and monitoring
NTSTATUS
NvfsGetRdmaStatisticsWin(
    _Out_ PNVFS_RDMA_STATISTICS_WIN Statistics
);

VOID
NvfsResetRdmaStatisticsWin(VOID);

// RDMA capability checking
BOOLEAN
NvfsIsRdmaEnabledWin(VOID);

#else // !NVFS_ENABLE_RDMA_SUPPORT_WIN

// Stub implementations when RDMA support is disabled
static __inline NTSTATUS NvfsInitializeRdmaWin(VOID) { return STATUS_NOT_SUPPORTED; }
static __inline VOID NvfsCleanupRdmaWin(VOID) { }
static __inline NTSTATUS NvfsSetRdmaRegInfoToMgroupWin(_In_ PNVFS_IOCTL_SET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs) { UNREFERENCED_PARAMETER(RdmaRegInfoArgs); return STATUS_NOT_SUPPORTED; }
static __inline NTSTATUS NvfsGetRdmaRegInfoFromMgroupWin(_Inout_ PNVFS_IOCTL_GET_RDMA_REG_INFO_ARGS_WIN RdmaRegInfoArgs) { UNREFERENCED_PARAMETER(RdmaRegInfoArgs); return STATUS_NOT_SUPPORTED; }
static __inline NTSTATUS NvfsClearRdmaRegInfoInMgroupWin(_In_ PNVFS_IOCTL_CLEAR_RDMA_REG_INFO_ARGS_WIN RdmaClearInfoArgs) { UNREFERENCED_PARAMETER(RdmaClearInfoArgs); return STATUS_NOT_SUPPORTED; }
static __inline VOID NvfsSetCurrentRdmaSegmentToMgroupWin(_In_ PNVFS_MGROUP_WIN Mgroup, _In_ ULONG RdmaSegment) { UNREFERENCED_PARAMETER(Mgroup); UNREFERENCED_PARAMETER(RdmaSegment); }
static __inline BOOLEAN NvfsIsRdmaEnabledWin(VOID) { return FALSE; }

#endif // NVFS_ENABLE_RDMA_SUPPORT_WIN

// IOCTL codes for RDMA operations
#define NVFS_IOCTL_SET_RDMA_REG_INFO_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x930, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define NVFS_IOCTL_GET_RDMA_REG_INFO_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x931, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_CLEAR_RDMA_REG_INFO_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x932, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define NVFS_IOCTL_GET_RDMA_STATISTICS_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x933, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_RESET_RDMA_STATISTICS_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x934, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Inline helper functions

static __inline BOOLEAN
NvfsIsRdmaInfoValidWin(
    _In_opt_ PNVFS_RDMA_INFO_WIN RdmaInfo
)
{
    return (RdmaInfo != NULL && 
            RdmaInfo->Version >= NVFS_RDMA_MIN_SUPPORTED_VERSION_WIN &&
            RdmaInfo->Size > 0);
}

static __inline VOID
NvfsClearRdmaInfoWin(
    _Out_ PNVFS_RDMA_INFO_WIN RdmaInfo
)
{
    if (RdmaInfo != NULL) {
        RtlZeroMemory(RdmaInfo, sizeof(NVFS_RDMA_INFO_WIN));
    }
}

static __inline BOOLEAN
NvfsIsRdmaConnectionValidWin(
    _In_opt_ PNVFS_RDMA_CONNECTION_WIN Connection
)
{
    return (Connection != NULL && 
            Connection->State == NvfsRdmaConnectionStateConnected);
}

// Debugging and logging macros
#ifdef DBG
#define NVFS_RDMA_DEBUG_PRINT(format, ...) \
    DbgPrint("NVFS_RDMA: " format "\n", __VA_ARGS__)
#else
#define NVFS_RDMA_DEBUG_PRINT(format, ...) ((void)0)
#endif

// RDMA error logging
#define NVFS_RDMA_LOG_ERROR(status, message) \
    do { \
        KdPrint(("NVFS_RDMA_ERROR: %s - Status: 0x%08X\n", (message), (status))); \
    } while (0)

// RDMA information logging
#define NVFS_RDMA_LOG_INFO(rdmaInfo) \
    do { \
        if (NvfsIsRdmaInfoValidWin(rdmaInfo)) { \
            NVFS_RDMA_DEBUG_PRINT( \
                "RDMA Info: ver=%u, flags=0x%x, lid=0x%x, qp=%u, rkey=0x%x, size=%u", \
                (rdmaInfo)->Version, (rdmaInfo)->Flags, (rdmaInfo)->Lid, \
                (rdmaInfo)->QpNum, (rdmaInfo)->RKey, (rdmaInfo)->Size \
            ); \
        } \
    } while (0)

#endif // __NVFS_RDMA_WIN_H__