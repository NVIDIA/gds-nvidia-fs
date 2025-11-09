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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Proc Interface Replacement
 * This module provides Windows Registry-based exposure of driver information
 * that was previously exposed through Linux /proc filesystem
 */

#include <ntddk.h>
#include <wdf.h>
#include "nvfs-proc-win.h"
#include "nvfs-core-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-pci-win.h"
#include "nvfs-mod-win.h"
#include "nvfs-registry-win.h"
#include "nvfs-vers-win.h"

// Global state
static BOOLEAN g_ProcInitialized = FALSE;
static KGUARDED_MUTEX g_ProcLock;

// Registry paths for exposing driver information
#define NVFS_PROC_REGISTRY_PATH_WIN         L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs\\Info"
#define NVFS_PROC_MODULES_PATH_WIN          L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs\\Info\\Modules"
#define NVFS_PROC_BRIDGES_PATH_WIN          L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs\\Info\\Bridges"
#define NVFS_PROC_STATISTICS_PATH_WIN       L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvfs\\Info\\Statistics"

// Function prototypes
static NTSTATUS NvfsCreateProcRegistryKeysWin(VOID);
static NTSTATUS NvfsUpdateDriverVersionInfoWin(VOID);
static NTSTATUS NvfsUpdateModuleInfoWin(VOID);
static NTSTATUS NvfsUpdateBridgeInfoWin(VOID);
static NTSTATUS NvfsUpdateStatisticsInfoWin(VOID);
static VOID NvfsDeleteProcRegistryKeysWin(VOID);

NTSTATUS
NvfsInitializeProcWin(VOID)
{
    NTSTATUS status;
    
    if (g_ProcInitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }
    
    KeInitializeGuardedMutex(&g_ProcLock);
    
    KeAcquireGuardedMutex(&g_ProcLock);
    
    __try {
        // Create registry keys for proc information
        status = NvfsCreateProcRegistryKeysWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        // Update all proc information
        status = NvfsUpdateDriverVersionInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsUpdateModuleInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsUpdateBridgeInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsUpdateStatisticsInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        g_ProcInitialized = TRUE;
        status = STATUS_SUCCESS;
    }
    __finally {
        KeReleaseGuardedMutex(&g_ProcLock);
    }
    
    return status;
}

VOID
NvfsCleanupProcWin(VOID)
{
    if (!g_ProcInitialized) {
        return;
    }
    
    KeAcquireGuardedMutex(&g_ProcLock);
    
    NvfsDeleteProcRegistryKeysWin();
    g_ProcInitialized = FALSE;
    
    KeReleaseGuardedMutex(&g_ProcLock);
}

NTSTATUS
NvfsUpdateProcInfoWin(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!g_ProcInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    KeAcquireGuardedMutex(&g_ProcLock);
    
    __try {
        // Update all proc information
        status = NvfsUpdateDriverVersionInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsUpdateModuleInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsUpdateBridgeInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsUpdateStatisticsInfoWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
    }
    __finally {
        KeReleaseGuardedMutex(&g_ProcLock);
    }
    
    return status;
}

NTSTATUS
NvfsGetProcVersionInfoWin(
    _Out_writes_(BufferSize) PWCHAR VersionBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
)
{
    WCHAR versionString[64];
    ULONG versionStringLength;
    
    if (VersionBuffer == NULL || RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Format version string
    RtlStringCchPrintfW(
        versionString,
        ARRAYSIZE(versionString),
        L"version: %u.%u",
        NVFS_DRIVER_MAJOR_VERSION_WIN,
        NVFS_DRIVER_MINOR_VERSION_WIN
    );
    
    versionStringLength = (ULONG)(wcslen(versionString) + 1) * sizeof(WCHAR);
    *RequiredSize = versionStringLength;
    
    if (BufferSize < versionStringLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlCopyMemory(VersionBuffer, versionString, versionStringLength);
    
    return STATUS_SUCCESS;
}

NTSTATUS
NvfsGetProcModuleInfoWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWCHAR ModuleBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
)
{
    WCHAR moduleString[1024];
    ULONG moduleStringLength;
    PNVFS_MODULE_INFO_WIN moduleList = NULL;
    ULONG moduleListSize;
    ULONG moduleCount;
    ULONG i;
    NTSTATUS status;
    
    if (ModuleBuffer == NULL || RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    moduleString[0] = L'\0';
    
    // Get module list
    status = NvfsGetModuleListWin(NULL, 0, &moduleListSize);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        return status;
    }
    
    moduleList = ExAllocatePoolWithTag(
        NonPagedPool,
        moduleListSize,
        'mPFS'
    );
    
    if (moduleList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    status = NvfsGetModuleListWin(moduleList, moduleListSize, &moduleListSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleList, 'mPFS');
        return status;
    }
    
    moduleCount = moduleListSize / sizeof(NVFS_MODULE_INFO_WIN);
    
    // Format module information
    for (i = 0; i < moduleCount; i++) {
        if (moduleList[i].Loaded) {
            WCHAR tempString[128];
            
            RtlStringCchPrintfW(
                tempString,
                ARRAYSIZE(tempString),
                L"%s: %s\r\n",
                moduleList[i].ModuleName,
                moduleList[i].Description
            );
            
            RtlStringCchCatW(
                moduleString,
                ARRAYSIZE(moduleString),
                tempString
            );
        }
    }
    
    ExFreePoolWithTag(moduleList, 'mPFS');
    
    moduleStringLength = (ULONG)(wcslen(moduleString) + 1) * sizeof(WCHAR);
    *RequiredSize = moduleStringLength;
    
    if (BufferSize < moduleStringLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlCopyMemory(ModuleBuffer, moduleString, moduleStringLength);
    
    return STATUS_SUCCESS;
}

NTSTATUS
NvfsGetProcBridgeInfoWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWCHAR BridgeBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
)
{
    WCHAR bridgeString[2048];
    ULONG bridgeStringLength;
    PNVFS_PCI_DEVICE_INFO_WIN bridgeList = NULL;
    ULONG bridgeListSize;
    ULONG bridgeCount;
    ULONG i;
    NTSTATUS status;
    
    if (BridgeBuffer == NULL || RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    bridgeString[0] = L'\0';
    
    // Get PCI bridge information
    status = NvfsGetPciBridgeListWin(NULL, 0, &bridgeListSize);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        return status;
    }
    
    bridgeList = ExAllocatePoolWithTag(
        NonPagedPool,
        bridgeListSize,
        'bPFS'
    );
    
    if (bridgeList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    status = NvfsGetPciBridgeListWin(bridgeList, bridgeListSize, &bridgeListSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bridgeList, 'bPFS');
        return status;
    }
    
    bridgeCount = bridgeListSize / sizeof(NVFS_PCI_DEVICE_INFO_WIN);
    
    // Format bridge information (Windows equivalent of Linux PCI notation)
    for (i = 0; i < bridgeCount; i++) {
        WCHAR tempString[64];
        
        RtlStringCchPrintfW(
            tempString,
            ARRAYSIZE(tempString),
            L"%04x:%02x:%02x.%x\r\n",
            bridgeList[i].Domain,
            bridgeList[i].Bus,
            bridgeList[i].Device,
            bridgeList[i].Function
        );
        
        RtlStringCchCatW(
            bridgeString,
            ARRAYSIZE(bridgeString),
            tempString
        );
    }
    
    ExFreePoolWithTag(bridgeList, 'bPFS');
    
    bridgeStringLength = (ULONG)(wcslen(bridgeString) + 1) * sizeof(WCHAR);
    *RequiredSize = bridgeStringLength;
    
    if (BufferSize < bridgeStringLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlCopyMemory(BridgeBuffer, bridgeString, bridgeStringLength);
    
    return STATUS_SUCCESS;
}

NTSTATUS
NvfsGetProcStatisticsInfoWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWCHAR StatisticsBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
)
{
    WCHAR statString[4096];
    ULONG statStringLength;
    NVFS_STATISTICS_WIN statistics;
    NTSTATUS status;
    
    if (StatisticsBuffer == NULL || RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Get current statistics
    status = NvfsGetGlobalStatisticsWin(&statistics);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Format statistics information (Windows equivalent of Linux /proc/fs/nvfs/stats)
    RtlStringCchPrintfW(
        statString,
        ARRAYSIZE(statString),
        L"NVFS Driver v%u.%u.%u\r\n"
        L"NVFS statistics (ver: %d.0)\r\n"
        L"IO stats: %s, peer IO stats: %s\r\n\r\n"
        L"Active Shadow-Buffer (MiB): %llu\r\n"
        L"Active Process: %u\r\n\r\n"
        L"Reads: n=%llu ok=%llu err=%u readMiB=%llu\r\n"
        L"Reads: Bandwidth(MiB/s)=%u Avg-Latency(usec)=%u\r\n\r\n"
        L"Writes: n=%llu ok=%llu err=%u writeMiB=%llu\r\n"
        L"Writes: Bandwidth(MiB/s)=%u Avg-Latency(usec)=%u\r\n\r\n"
        L"Batches: n=%llu ok=%llu err=%u Avg-Submit-Latency(usec)=%u\r\n\r\n"
        L"Mmap: n=%llu ok=%llu err=%u munmap=%llu\r\n"
        L"Error: cpu-gpu-pages=%u sg-ext=%u dma-map=%u dma-ref=%u\r\n",
        NVFS_DRIVER_MAJOR_VERSION_WIN,
        NVFS_DRIVER_MINOR_VERSION_WIN,
        NVFS_DRIVER_PATCH_VERSION_WIN,
        NVFS_STAT_VERSION_WIN,
        statistics.IoStatsEnabled ? L"Enabled" : L"Disabled",
        statistics.PeerIoStatsEnabled ? L"Enabled" : L"Disabled",
        BYTES_TO_MB(statistics.ActiveShadowBufferSize),
        statistics.ActiveProcesses,
        statistics.ReadOperations.Count,
        statistics.ReadOperations.SuccessCount,
        statistics.ReadOperations.ErrorCount,
        BYTES_TO_MB(statistics.ReadOperations.BytesTransferred),
        statistics.ReadOperations.BandwidthMBps,
        statistics.ReadOperations.AverageLatencyUs,
        statistics.WriteOperations.Count,
        statistics.WriteOperations.SuccessCount,
        statistics.WriteOperations.ErrorCount,
        BYTES_TO_MB(statistics.WriteOperations.BytesTransferred),
        statistics.WriteOperations.BandwidthMBps,
        statistics.WriteOperations.AverageLatencyUs,
        statistics.BatchOperations.Count,
        statistics.BatchOperations.SuccessCount,
        statistics.BatchOperations.ErrorCount,
        statistics.BatchOperations.AverageLatencyUs,
        statistics.MmapOperations.MmapCount,
        statistics.MmapOperations.MmapSuccessCount,
        statistics.MmapOperations.MmapErrorCount,
        statistics.MmapOperations.MunmapCount,
        statistics.ErrorCounters.MixCpuGpuErrors,
        statistics.ErrorCounters.ScatterGatherErrors,
        statistics.ErrorCounters.DmaMapErrors,
        statistics.ErrorCounters.DmaRefErrors
    );
    
    statStringLength = (ULONG)(wcslen(statString) + 1) * sizeof(WCHAR);
    *RequiredSize = statStringLength;
    
    if (BufferSize < statStringLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlCopyMemory(StatisticsBuffer, statString, statStringLength);
    
    return STATUS_SUCCESS;
}

// Helper functions

static NTSTATUS
NvfsCreateProcRegistryKeysWin(VOID)
{
    NTSTATUS status;
    
    // Create main info key
    status = NvfsCreateRegistryKeyWin(NVFS_PROC_REGISTRY_PATH_WIN);
    if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) {
        return status;
    }
    
    // Create modules key
    status = NvfsCreateRegistryKeyWin(NVFS_PROC_MODULES_PATH_WIN);
    if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) {
        return status;
    }
    
    // Create bridges key
    status = NvfsCreateRegistryKeyWin(NVFS_PROC_BRIDGES_PATH_WIN);
    if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) {
        return status;
    }
    
    // Create statistics key
    status = NvfsCreateRegistryKeyWin(NVFS_PROC_STATISTICS_PATH_WIN);
    if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) {
        return status;
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS
NvfsUpdateDriverVersionInfoWin(VOID)
{
    WCHAR versionString[64];
    ULONG versionValue;
    NTSTATUS status;
    
    // Update version string
    RtlStringCchPrintfW(
        versionString,
        ARRAYSIZE(versionString),
        L"%u.%u.%u",
        NVFS_DRIVER_MAJOR_VERSION_WIN,
        NVFS_DRIVER_MINOR_VERSION_WIN,
        NVFS_DRIVER_PATCH_VERSION_WIN
    );
    
    status = NvfsSetRegistryValueWin(
        L"DriverVersion",
        REG_SZ,
        versionString,
        (ULONG)(wcslen(versionString) + 1) * sizeof(WCHAR)
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Update version as DWORD
    versionValue = NvfsGetDriverVersionWin();
    status = NvfsSetRegistryValueWin(
        L"DriverVersionDWORD",
        REG_DWORD,
        &versionValue,
        sizeof(versionValue)
    );
    
    return status;
}

static NTSTATUS
NvfsUpdateModuleInfoWin(VOID)
{
    // Module information is updated through the module management system
    // This function can trigger updates to module-specific registry entries
    return STATUS_SUCCESS;
}

static NTSTATUS
NvfsUpdateBridgeInfoWin(VOID)
{
    // Bridge information is updated through the PCI management system
    // This function can trigger updates to bridge-specific registry entries
    return STATUS_SUCCESS;
}

static NTSTATUS
NvfsUpdateStatisticsInfoWin(VOID)
{
    NVFS_STATISTICS_WIN statistics;
    NTSTATUS status;
    
    // Get current statistics
    status = NvfsGetGlobalStatisticsWin(&statistics);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Update key statistics in registry
    status = NvfsSetRegistryValueWin(
        L"ReadOperations",
        REG_QWORD,
        &statistics.ReadOperations.Count,
        sizeof(statistics.ReadOperations.Count)
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = NvfsSetRegistryValueWin(
        L"WriteOperations",
        REG_QWORD,
        &statistics.WriteOperations.Count,
        sizeof(statistics.WriteOperations.Count)
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = NvfsSetRegistryValueWin(
        L"ErrorCount",
        REG_DWORD,
        &statistics.ErrorCounters.MixCpuGpuErrors,
        sizeof(statistics.ErrorCounters.MixCpuGpuErrors)
    );
    
    return status;
}

static VOID
NvfsDeleteProcRegistryKeysWin(VOID)
{
    // Delete registry keys (Windows will handle cleanup on driver unload)
    NvfsDeleteRegistryKeyWin(NVFS_PROC_STATISTICS_PATH_WIN);
    NvfsDeleteRegistryKeyWin(NVFS_PROC_BRIDGES_PATH_WIN);
    NvfsDeleteRegistryKeyWin(NVFS_PROC_MODULES_PATH_WIN);
    NvfsDeleteRegistryKeyWin(NVFS_PROC_REGISTRY_PATH_WIN);
}