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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Core Definitions
 */

#ifndef NVFS_CORE_WIN_H
#define NVFS_CORE_WIN_H

// Windows kernel includes
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <ntifs.h>
#include <ntstrsafe.h>

// Include Windows-specific headers
#include "nvfs-mmap-win.h"
#include "config-host-win.h"

// Device and class names
#define DEVICE_NAME L"nvidia-fs"
#define CLASS_NAME L"nvidia-fs-class"

// Windows equivalent of Linux macros
#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#define STR_HELPER(x) L#x
#define STR(x) STR_HELPER(x)

// Windows PCI device ID calculation
#define NVFS_GET_PCI_DEVID(PciDev) \
    (((ULONG)(PciDev)->BusNumber << 16) | ((PciDev)->SlotNumber.u.AsULONG))

// Windows logging macros (equivalent to Linux printk variants)
extern ULONG g_NvfsDbgEnabled;
extern ULONG g_NvfsInfoEnabled;

#define nvfs_msg(Level, Format, ...) \
    DbgPrintEx(DPFLTR_DEFAULT_ID, Level, "nvidia-fs: " Format, __VA_ARGS__)

#define nvfs_dbg(Format, ...) \
    do { \
        if (g_NvfsDbgEnabled) { \
            nvfs_msg(DPFLTR_TRACE_LEVEL, Format, __VA_ARGS__); \
        } \
    } while(0)

#define nvfs_info(Format, ...) \
    do { \
        if (g_NvfsInfoEnabled) { \
            nvfs_msg(DPFLTR_INFO_LEVEL, Format, __VA_ARGS__); \
        } \
    } while(0)

#define nvfs_warn(Format, ...) \
    nvfs_msg(DPFLTR_WARNING_LEVEL, Format, __VA_ARGS__)

#define nvfs_err(Format, ...) \
    nvfs_msg(DPFLTR_ERROR_LEVEL, Format, __VA_ARGS__)

// Statistics control variables
extern ULONG g_NvfsRwStatsEnabled;
extern ULONG g_NvfsPeerStatsEnabled;

// Windows equivalent of Linux u64
typedef ULONGLONG u64;

// IOCTL codes for Windows (equivalent to Linux ioctl commands)
#define NVFS_DEVICE_TYPE 0x8000

#define IOCTL_NVFS_MAP \
    CTL_CODE(NVFS_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NVFS_READ \
    CTL_CODE(NVFS_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NVFS_WRITE \
    CTL_CODE(NVFS_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NVFS_REMOVE \
    CTL_CODE(NVFS_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NVFS_SET_RDMA_REG_INFO \
    CTL_CODE(NVFS_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NVFS_BATCH_SUBMIT \
    CTL_CODE(NVFS_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NVFS_BATCH_GET_STATUS \
    CTL_CODE(NVFS_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Windows IOCTL structures (equivalent to Linux structures)
#pragma pack(push, 8)

typedef struct _NVFS_IOCTL_MAP_S {
    LONGLONG Size;              // GPU Buffer size
    u64 PciDevInfo;             // PCI domain/bus/device/func info
    u64 CpuVAddr;               // Shadow buffer address
    u64 GpuVAddr;               // GPU Buffer address
    u64 EndFenceAddr;           // End fence address
    ULONG SBufBlock;            // Number of 4k blocks
    USHORT IsBounceBuffer;      // Bounce buffer flag
    UCHAR Padding[2];           // Padding for alignment
} NVFS_IOCTL_MAP_S, *PNVFS_IOCTL_MAP_S;

typedef struct _NVFS_FILE_ARGS {
    ULONGLONG Inum;             // Inode number equivalent (file ID)
    ULONG Generation;           // File generation for cache validation
    ULONG MajDev;               // Device major number
    ULONG MinDev;               // Device minor number
    u64 DevPtrOff;              // Device buffer offset
} NVFS_FILE_ARGS, *PNVFS_FILE_ARGS;

typedef struct _NVFS_IOCTL_IOARGS {
    u64 CpuVAddr;               // Shadow buffer VA
    LONGLONG Offset;            // File offset
    u64 Size;                   // Read/Write length
    u64 EndFenceValue;          // End fence value for DMA completion
    LONGLONG IoctlReturn;       // IOCTL return value
    NVFS_FILE_ARGS FileArgs;    // File arguments
    HANDLE FileHandle;          // File handle (Windows equivalent of fd)
    UCHAR Sync : 1;             // Perform sync IO
    UCHAR HiPri : 1;            // Set high priority flag
    UCHAR AllowReads : 1;       // Allow reads for write-only files
    UCHAR UseRKeys : 1;         // Use RDMA rkey for IO
    UCHAR Reserved : 4;         // Reserved bits
    UCHAR Padding[7];           // Padding for alignment
} NVFS_IOCTL_IOARGS, *PNVFS_IOCTL_IOARGS;

#pragma pack(pop)

// Windows equivalent of Linux union for IOCTL parameters
typedef union _NVFS_IOCTL_PARAM_UNION {
    NVFS_IOCTL_MAP_S MapParams;
    NVFS_IOCTL_IOARGS IoArgs;
    // Add other parameter structures as needed
} NVFS_IOCTL_PARAM_UNION, *PNVFS_IOCTL_PARAM_UNION;

// Magic constants
#define NVFS_START_MAGIC    0xabc0cba1abc2cba3ULL
#define NVFS_END_MAGIC      0x3abc2cba1abc0cbaULL

// Version information
#define NVFS_DRIVER_MAJOR_VERSION 1
#define NVFS_DRIVER_MINOR_VERSION 0
#define NVFS_DRIVER_PATCH_VERSION 0

// Windows equivalent of Linux version macros
static FORCEINLINE ULONG
nvfs_driver_version(VOID)
{
    return (NVFS_DRIVER_MAJOR_VERSION << 16) | NVFS_DRIVER_MINOR_VERSION;
}

static FORCEINLINE ULONG
nvfs_major_version(ULONG Version)
{
    return (Version >> 16) & 0xFFFF;
}

static FORCEINLINE ULONG
nvfs_minor_version(ULONG Version)
{
    return Version & 0xFFFF;
}

// Forward declarations for Windows-specific structures
typedef struct _NVFS_GPU_ARGS NVFS_GPU_ARGS, *PNVFS_GPU_ARGS;
typedef struct _NVFS_IO NVFS_IO, *PNVFS_IO;
typedef struct _NVFS_IO_MGROUP NVFS_IO_MGROUP, *PNVFS_IO_MGROUP;

// Windows equivalent of Linux sparse data types
typedef enum _NVFS_METASTATE_ENUM {
    NVFS_METASTATE_NORMAL = 0,
    NVFS_METASTATE_SPARSE,
    NVFS_METASTATE_ERROR
} NVFS_METASTATE_ENUM;

typedef PVOID nvfs_io_sparse_dptr_t;

// Function prototypes (Windows equivalents of Linux functions)

// Core functions
NTSTATUS NvfsBlkRegisterDmaOps(VOID);
VOID NvfsBlkUnregisterDmaOps(VOID);

// Memory management functions
NTSTATUS NvfsGetDma(PVOID Buffer, PMDL Mdl, PVOID* DmaBuffer, ULONG Flags);

// GPU management functions
BOOLEAN NvfsFreeGpuInfo(PNVFS_GPU_ARGS GpuInfo, BOOLEAN FromDma);
BOOLEAN NvfsIoTerminateRequested(PNVFS_GPU_ARGS GpuInfo, BOOLEAN Check);
VOID NvfsIoProcessExiting(PNVFS_IO_MGROUP NvfsMgroup);

// Sparse data functions
VOID NvfsIoUnmapSparseData(nvfs_io_sparse_dptr_t Ptr, NVFS_METASTATE_ENUM State);

// Device count functions
ULONG NvfsGetDeviceCount(VOID);

// Subsystem initialization functions
NTSTATUS NvfsProcInit(VOID);
VOID NvfsProcCleanup(VOID);

NTSTATUS NvfsStatInit(VOID);
VOID NvfsStatCleanup(VOID);

NTSTATUS NvfsFaultInit(VOID);
VOID NvfsFaultCleanup(VOID);

// Statistics functions
typedef struct _NVFS_STATS {
    LONG OpProcess;
    LONG ErrorCount;
    LONG IoCount;
    // Add more statistics as needed
} NVFS_STATS, *PNVFS_STATS;

extern NVFS_STATS g_NvfsStats;

static FORCEINLINE VOID
NvfsStatIncrement(PLONG Counter)
{
    InterlockedIncrement(Counter);
}

static FORCEINLINE VOID
NvfsStatDecrement(PLONG Counter)
{
    InterlockedDecrement(Counter);
}

// Windows-specific utility functions
NTSTATUS NvfsCreateControlDevice(WDFDRIVER Driver);
VOID NvfsDeleteControlDevice(VOID);

// File operation callbacks
EVT_WDF_DEVICE_FILE_CREATE NvfsFileCreate;
EVT_WDF_FILE_CLOSE NvfsFileClose;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL NvfsIoDeviceControl;

#endif /* NVFS_CORE_WIN_H */