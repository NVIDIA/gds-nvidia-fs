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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Proc Interface Header
 */

#ifndef __NVFS_PROC_WIN_H__
#define __NVFS_PROC_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Function prototypes

// Initialization and cleanup
NTSTATUS
NvfsInitializeProcWin(VOID);

VOID
NvfsCleanupProcWin(VOID);

// Update proc information
NTSTATUS
NvfsUpdateProcInfoWin(VOID);

// Proc information retrieval functions (Windows equivalents of Linux /proc reads)
NTSTATUS
NvfsGetProcVersionInfoWin(
    _Out_writes_(BufferSize) PWCHAR VersionBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
);

NTSTATUS
NvfsGetProcModuleInfoWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWCHAR ModuleBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
);

NTSTATUS
NvfsGetProcBridgeInfoWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWCHAR BridgeBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
);

NTSTATUS
NvfsGetProcStatisticsInfoWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWCHAR StatisticsBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
);

// IOCTL codes for proc information access
#define NVFS_IOCTL_GET_PROC_VERSION_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x950, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_GET_PROC_MODULES_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x951, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_GET_PROC_BRIDGES_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x952, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_GET_PROC_STATISTICS_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x953, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_UPDATE_PROC_INFO_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x954, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Proc information structures
typedef struct _NVFS_PROC_VERSION_OUTPUT_WIN {
    ULONG Size;                         // Size of this structure
    WCHAR VersionString[64];            // Driver version string
} NVFS_PROC_VERSION_OUTPUT_WIN, *PNVFS_PROC_VERSION_OUTPUT_WIN;

typedef struct _NVFS_PROC_MODULES_OUTPUT_WIN {
    ULONG Size;                         // Size of this structure
    ULONG ModuleCount;                  // Number of modules
    WCHAR ModulesString[1024];          // Formatted modules string
} NVFS_PROC_MODULES_OUTPUT_WIN, *PNVFS_PROC_MODULES_OUTPUT_WIN;

typedef struct _NVFS_PROC_BRIDGES_OUTPUT_WIN {
    ULONG Size;                         // Size of this structure
    ULONG BridgeCount;                  // Number of bridges
    WCHAR BridgesString[2048];          // Formatted bridges string
} NVFS_PROC_BRIDGES_OUTPUT_WIN, *PNVFS_PROC_BRIDGES_OUTPUT_WIN;

typedef struct _NVFS_PROC_STATISTICS_OUTPUT_WIN {
    ULONG Size;                         // Size of this structure
    WCHAR StatisticsString[4096];       // Formatted statistics string
} NVFS_PROC_STATISTICS_OUTPUT_WIN, *PNVFS_PROC_STATISTICS_OUTPUT_WIN;

// Inline helper functions

static __inline VOID
NvfsInitializeProcVersionOutputWin(
    _Out_ PNVFS_PROC_VERSION_OUTPUT_WIN Output
)
{
    RtlZeroMemory(Output, sizeof(NVFS_PROC_VERSION_OUTPUT_WIN));
    Output->Size = sizeof(NVFS_PROC_VERSION_OUTPUT_WIN);
}

static __inline VOID
NvfsInitializeProcModulesOutputWin(
    _Out_ PNVFS_PROC_MODULES_OUTPUT_WIN Output
)
{
    RtlZeroMemory(Output, sizeof(NVFS_PROC_MODULES_OUTPUT_WIN));
    Output->Size = sizeof(NVFS_PROC_MODULES_OUTPUT_WIN);
}

static __inline VOID
NvfsInitializeProcBridgesOutputWin(
    _Out_ PNVFS_PROC_BRIDGES_OUTPUT_WIN Output
)
{
    RtlZeroMemory(Output, sizeof(NVFS_PROC_BRIDGES_OUTPUT_WIN));
    Output->Size = sizeof(NVFS_PROC_BRIDGES_OUTPUT_WIN);
}

static __inline VOID
NvfsInitializeProcStatisticsOutputWin(
    _Out_ PNVFS_PROC_STATISTICS_OUTPUT_WIN Output
)
{
    RtlZeroMemory(Output, sizeof(NVFS_PROC_STATISTICS_OUTPUT_WIN));
    Output->Size = sizeof(NVFS_PROC_STATISTICS_OUTPUT_WIN);
}

// Registry access functions for proc information
NTSTATUS
NvfsCreateRegistryKeyWin(
    _In_ PCWSTR KeyPath
);

VOID
NvfsDeleteRegistryKeyWin(
    _In_ PCWSTR KeyPath
);

// Debug and logging macros
#ifdef DBG
#define NVFS_PROC_DEBUG_PRINT(format, ...) \
    DbgPrint("NVFS_PROC: " format "\n", __VA_ARGS__)
#else
#define NVFS_PROC_DEBUG_PRINT(format, ...) ((void)0)
#endif

#define NVFS_PROC_LOG_ERROR(status, message) \
    do { \
        KdPrint(("NVFS_PROC_ERROR: %s - Status: 0x%08X\n", (message), (status))); \
    } while (0)

#define NVFS_PROC_LOG_INFO(message, ...) \
    do { \
        NVFS_PROC_DEBUG_PRINT(message, __VA_ARGS__); \
    } while (0)

// Convenience macros for proc information formatting

#define NVFS_FORMAT_VERSION_STRING_WIN(buffer, bufferSize) \
    RtlStringCchPrintfW( \
        (buffer), \
        (bufferSize), \
        L"version: %u.%u", \
        NVFS_DRIVER_MAJOR_VERSION_WIN, \
        NVFS_DRIVER_MINOR_VERSION_WIN \
    )

#define NVFS_FORMAT_MODULE_STRING_WIN(buffer, bufferSize, moduleName, moduleDesc) \
    RtlStringCchPrintfW( \
        (buffer), \
        (bufferSize), \
        L"%s: %s\r\n", \
        (moduleName), \
        (moduleDesc) \
    )

#define NVFS_FORMAT_BRIDGE_STRING_WIN(buffer, bufferSize, domain, bus, device, function) \
    RtlStringCchPrintfW( \
        (buffer), \
        (bufferSize), \
        L"%04x:%02x:%02x.%x\r\n", \
        (domain), \
        (bus), \
        (device), \
        (function) \
    )

// Constants for proc information
#define NVFS_PROC_MAX_VERSION_LENGTH_WIN        64
#define NVFS_PROC_MAX_MODULES_LENGTH_WIN        1024
#define NVFS_PROC_MAX_BRIDGES_LENGTH_WIN        2048
#define NVFS_PROC_MAX_STATISTICS_LENGTH_WIN     4096

// Proc information update intervals
#define NVFS_PROC_UPDATE_INTERVAL_MS_WIN        5000    // Update every 5 seconds
#define NVFS_PROC_STATS_UPDATE_INTERVAL_MS_WIN  1000    // Update stats every 1 second

// Additional proc interface functions for compatibility

// Get formatted driver information (equivalent to /proc/driver/nvidia-fs/version)
static __inline NTSTATUS
NvfsGetDriverVersionStringWin(
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
)
{
    return NvfsGetProcVersionInfoWin(Buffer, BufferSize, NULL);
}

// Get formatted module information (equivalent to /proc/driver/nvidia-fs/modules)
static __inline NTSTATUS
NvfsGetModuleInfoStringWin(
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
)
{
    ULONG requiredSize;
    return NvfsGetProcModuleInfoWin(Buffer, BufferSize, &requiredSize);
}

// Get formatted bridge information (equivalent to /proc/driver/nvidia-fs/bridges)
static __inline NTSTATUS
NvfsGetBridgeInfoStringWin(
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
)
{
    ULONG requiredSize;
    return NvfsGetProcBridgeInfoWin(Buffer, BufferSize, &requiredSize);
}

// Get formatted statistics information (equivalent to /proc/fs/nvfs/stats)
static __inline NTSTATUS
NvfsGetStatisticsInfoStringWin(
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
)
{
    ULONG requiredSize;
    return NvfsGetProcStatisticsInfoWin(Buffer, BufferSize, &requiredSize);
}

#endif // __NVFS_PROC_WIN_H__