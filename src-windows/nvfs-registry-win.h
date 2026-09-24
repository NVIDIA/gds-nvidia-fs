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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Registry Interface Header
 */

#ifndef __NVFS_REGISTRY_WIN_H__
#define __NVFS_REGISTRY_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Configuration structure
typedef struct _NVFS_CONFIG_WIN {
    ULONG DebugLevel;           // Debug output level
    BOOLEAN EnableP2P;          // Enable GPU P2P operations
    BOOLEAN EnableRdma;         // Enable RDMA support
    ULONG MaxConcurrentIOs;     // Maximum concurrent I/O operations
    ULONG MaxMemoryGroups;      // Maximum memory groups
    ULONG IoTimeoutMs;          // I/O timeout in milliseconds
    BOOLEAN EnableStatistics;   // Enable statistics collection
    BOOLEAN EnablePciAffinity;  // Enable PCI affinity optimization
} NVFS_CONFIG_WIN, *PNVFS_CONFIG_WIN;

// Debug levels
#define NVFS_DEBUG_LEVEL_NONE       0
#define NVFS_DEBUG_LEVEL_ERROR      1
#define NVFS_DEBUG_LEVEL_WARNING    2
#define NVFS_DEBUG_LEVEL_INFO       3
#define NVFS_DEBUG_LEVEL_DEBUG      4
#define NVFS_DEBUG_LEVEL_VERBOSE    5

// Registry access functions
NTSTATUS
NvfsOpenRegistryKeyWin(
    _In_ PCWSTR RegistryPath,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE KeyHandle
);

NTSTATUS
NvfsSetRegistryValueWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_reads_bytes_(ValueLength) PVOID ValueData,
    _In_ ULONG ValueLength
);

NTSTATUS
NvfsGetRegistryValueWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _Out_writes_bytes_opt_(ValueLength) PVOID ValueData,
    _In_ ULONG ValueLength,
    _Out_opt_ PULONG ActualLength
);

// Statistics and module management
NTSTATUS
NvfsUpdateStatisticsRegistryWin(VOID);

NTSTATUS
NvfsUpdateModuleInfoRegistryWin(
    _In_ PCWSTR ModuleName,
    _In_ PCWSTR ModuleVersion,
    _In_ BOOLEAN IsLoaded
);

// Configuration management
NTSTATUS
NvfsLoadConfigurationFromRegistryWin(
    _Out_ PNVFS_CONFIG_WIN Configuration
);

NTSTATUS
NvfsSaveConfigurationToRegistryWin(
    _In_ PNVFS_CONFIG_WIN Configuration
);

// Interface initialization/cleanup
NTSTATUS
NvfsInitializeRegistryInterfaceWin(VOID);

VOID
NvfsCleanupRegistryInterfaceWin(VOID);

// Registry paths and constants
#define NVFS_VERSION_STRING_WIN     L"1.0.0.0"

// Inline helper functions

static __inline BOOLEAN
NvfsIsDebugLevelEnabledWin(
    _In_ ULONG DebugLevel,
    _In_ ULONG CurrentLevel
)
{
    return (DebugLevel <= CurrentLevel);
}

static __inline NTSTATUS
NvfsSetRegistryDwordWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ ULONG Value
)
{
    return NvfsSetRegistryValueWin(
        KeyHandle,
        ValueName,
        REG_DWORD,
        &Value,
        sizeof(Value)
    );
}

static __inline NTSTATUS
NvfsSetRegistryQwordWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ ULONGLONG Value
)
{
    return NvfsSetRegistryValueWin(
        KeyHandle,
        ValueName,
        REG_QWORD,
        &Value,
        sizeof(Value)
    );
}

static __inline NTSTATUS
NvfsSetRegistryStringWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ PCWSTR StringValue
)
{
    return NvfsSetRegistryValueWin(
        KeyHandle,
        ValueName,
        REG_SZ,
        (PVOID)StringValue,
        (ULONG)(wcslen(StringValue) + 1) * sizeof(WCHAR)
    );
}

static __inline NTSTATUS
NvfsGetRegistryDwordWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Out_ PULONG Value
)
{
    return NvfsGetRegistryValueWin(
        KeyHandle,
        ValueName,
        REG_DWORD,
        Value,
        sizeof(*Value),
        NULL
    );
}

static __inline NTSTATUS
NvfsGetRegistryQwordWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Out_ PULONGLONG Value
)
{
    return NvfsGetRegistryValueWin(
        KeyHandle,
        ValueName,
        REG_QWORD,
        Value,
        sizeof(*Value),
        NULL
    );
}

#endif // __NVFS_REGISTRY_WIN_H__