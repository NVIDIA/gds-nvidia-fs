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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Registry Statistics Interface
 */

// Windows kernel headers
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Windows-specific includes
#include "nvfs-core-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-registry-win.h"
#include "config-host-win.h"

// Registry paths and keys
#define NVFS_REGISTRY_ROOT_PATH     L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nvidia-fs"
#define NVFS_REGISTRY_STATS_PATH    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nvidia-fs\\Statistics"
#define NVFS_REGISTRY_MODULES_PATH  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nvidia-fs\\Modules"
#define NVFS_REGISTRY_CONFIG_PATH   L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nvidia-fs\\Configuration"

// Registry value names for statistics
#define NVFS_REG_VAL_NVFS_VERSION       L"Version"
#define NVFS_REG_VAL_GPU_COUNT          L"GpuCount"
#define NVFS_REG_VAL_MGROUP_COUNT       L"MgroupCount"
#define NVFS_REG_VAL_MGROUP_PAGES       L"MgroupPages"
#define NVFS_REG_VAL_MGROUP_ERRORS      L"MgroupErrors"
#define NVFS_REG_VAL_READ_COUNT         L"ReadCount"
#define NVFS_REG_VAL_WRITE_COUNT        L"WriteCount"
#define NVFS_REG_VAL_READ_BYTES         L"ReadBytes"
#define NVFS_REG_VAL_WRITE_BYTES        L"WriteBytes"
#define NVFS_REG_VAL_READ_ERRORS        L"ReadErrors"
#define NVFS_REG_VAL_WRITE_ERRORS       L"WriteErrors"
#define NVFS_REG_VAL_DMA_MAPPINGS       L"DmaMappings"
#define NVFS_REG_VAL_DMA_UNMAPPINGS     L"DmaUnmappings"
#define NVFS_REG_VAL_DMA_ERRORS         L"DmaErrors"
#define NVFS_REG_VAL_CPU_GPU_MIX_ERR    L"CpuGpuMixErrors"

// Registry value names for configuration
#define NVFS_REG_VAL_DEBUG_LEVEL        L"DebugLevel"
#define NVFS_REG_VAL_ENABLE_P2P         L"EnableP2P"
#define NVFS_REG_VAL_ENABLE_RDMA        L"EnableRdma"
#define NVFS_REG_VAL_MAX_CONCURRENT_IOS L"MaxConcurrentIOs"

// Global registry handles
static HANDLE g_RegistryRootHandle = NULL;
static HANDLE g_RegistryStatsHandle = NULL;
static HANDLE g_RegistryModulesHandle = NULL;
static HANDLE g_RegistryConfigHandle = NULL;

// Helper function to open registry key
NTSTATUS
NvfsOpenRegistryKeyWin(
    _In_ PCWSTR RegistryPath,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE KeyHandle
)
{
    NTSTATUS status;
    UNICODE_STRING registryPath;
    OBJECT_ATTRIBUTES objectAttributes;
    
    if (RegistryPath == NULL || KeyHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&registryPath, RegistryPath);
    
    InitializeObjectAttributes(
        &objectAttributes,
        &registryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );
    
    status = ZwCreateKey(
        KeyHandle,
        DesiredAccess,
        &objectAttributes,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        NULL
    );
    
    return status;
}

// Helper function to set registry value
NTSTATUS
NvfsSetRegistryValueWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_reads_bytes_(ValueLength) PVOID ValueData,
    _In_ ULONG ValueLength
)
{
    UNICODE_STRING valueName;
    
    if (KeyHandle == NULL || ValueName == NULL || ValueData == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&valueName, ValueName);
    
    return ZwSetValueKey(
        KeyHandle,
        &valueName,
        0,
        ValueType,
        ValueData,
        ValueLength
    );
}

// Helper function to get registry value
NTSTATUS
NvfsGetRegistryValueWin(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _Out_writes_bytes_opt_(ValueLength) PVOID ValueData,
    _In_ ULONG ValueLength,
    _Out_opt_ PULONG ActualLength
)
{
    NTSTATUS status;
    UNICODE_STRING valueName;
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo;
    ULONG requiredLength;
    
    if (KeyHandle == NULL || ValueName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&valueName, ValueName);
    
    // Query required buffer size
    status = ZwQueryValueKey(
        KeyHandle,
        &valueName,
        KeyValuePartialInformation,
        NULL,
        0,
        &requiredLength
    );
    
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }
    
    // Allocate buffer for value information
    valueInfo = ExAllocatePoolWithTag(PagedPool, requiredLength, 'FREG');
    if (valueInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Query the actual value
    status = ZwQueryValueKey(
        KeyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueInfo,
        requiredLength,
        &requiredLength
    );
    
    if (NT_SUCCESS(status)) {
        if (ActualLength != NULL) {
            *ActualLength = valueInfo->DataLength;
        }
        
        if (ValueData != NULL && ValueLength >= valueInfo->DataLength) {
            RtlCopyMemory(ValueData, valueInfo->Data, valueInfo->DataLength);
        } else if (ValueData != NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    
    ExFreePoolWithTag(valueInfo, 'FREG');
    return status;
}

// Update statistics in registry
NTSTATUS
NvfsUpdateStatisticsRegistryWin(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG value;
    ULONGLONG value64;
    
    if (g_RegistryStatsHandle == NULL) {
        return STATUS_INVALID_HANDLE;
    }
    
    // Update version information
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_NVFS_VERSION,
        REG_SZ,
        (PVOID)NVFS_VERSION_STRING_WIN,
        (ULONG)(wcslen(NVFS_VERSION_STRING_WIN) + 1) * sizeof(WCHAR)
    );
    
    // Update GPU count
    value = g_NvfsStats.GpuCount;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_GPU_COUNT,
        REG_DWORD,
        &value,
        sizeof(value)
    );
    
    // Update memory group statistics
    value = g_NvfsStats.MgroupCount;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_MGROUP_COUNT,
        REG_DWORD,
        &value,
        sizeof(value)
    );
    
    value64 = g_NvfsStats.MgroupPages;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_MGROUP_PAGES,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.MgroupErrors;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_MGROUP_ERRORS,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    // Update I/O statistics
    value64 = g_NvfsStats.ReadCount;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_READ_COUNT,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.WriteCount;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_WRITE_COUNT,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.ReadBytes;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_READ_BYTES,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.WriteBytes;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_WRITE_BYTES,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    // Update error statistics
    value64 = g_NvfsStats.ReadErrors;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_READ_ERRORS,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.WriteErrors;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_WRITE_ERRORS,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    // Update DMA statistics
    value64 = g_NvfsStats.DmaMappings;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_DMA_MAPPINGS,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.DmaUnmappings;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_DMA_UNMAPPINGS,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.DmaErrors;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_DMA_ERRORS,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    value64 = g_NvfsStats.ErrorMixCpuGpu;
    status = NvfsSetRegistryValueWin(
        g_RegistryStatsHandle,
        NVFS_REG_VAL_CPU_GPU_MIX_ERR,
        REG_QWORD,
        &value64,
        sizeof(value64)
    );
    
    return status;
}

// Update module information in registry
NTSTATUS
NvfsUpdateModuleInfoRegistryWin(
    _In_ PCWSTR ModuleName,
    _In_ PCWSTR ModuleVersion,
    _In_ BOOLEAN IsLoaded
)
{
    NTSTATUS status;
    HANDLE moduleKeyHandle = NULL;
    UNICODE_STRING moduleKeyPath;
    OBJECT_ATTRIBUTES objectAttributes;
    WCHAR moduleKeyPathBuffer[256];
    ULONG loadedValue;
    
    if (ModuleName == NULL || ModuleVersion == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (g_RegistryModulesHandle == NULL) {
        return STATUS_INVALID_HANDLE;
    }
    
    // Create module-specific subkey path
    status = RtlStringCchPrintfW(
        moduleKeyPathBuffer,
        ARRAYSIZE(moduleKeyPathBuffer),
        L"%s\\%s",
        NVFS_REGISTRY_MODULES_PATH,
        ModuleName
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    RtlInitUnicodeString(&moduleKeyPath, moduleKeyPathBuffer);
    
    InitializeObjectAttributes(
        &objectAttributes,
        &moduleKeyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );
    
    // Create or open module subkey
    status = ZwCreateKey(
        &moduleKeyHandle,
        KEY_ALL_ACCESS,
        &objectAttributes,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Set module version
    status = NvfsSetRegistryValueWin(
        moduleKeyHandle,
        L"Version",
        REG_SZ,
        (PVOID)ModuleVersion,
        (ULONG)(wcslen(ModuleVersion) + 1) * sizeof(WCHAR)
    );
    
    // Set module loaded status
    loadedValue = IsLoaded ? 1 : 0;
    status = NvfsSetRegistryValueWin(
        moduleKeyHandle,
        L"Loaded",
        REG_DWORD,
        &loadedValue,
        sizeof(loadedValue)
    );
    
    ZwClose(moduleKeyHandle);
    return status;
}

// Load configuration from registry
NTSTATUS
NvfsLoadConfigurationFromRegistryWin(
    _Out_ PNVFS_CONFIG_WIN Configuration
)
{
    NTSTATUS status;
    ULONG value;
    ULONG actualLength;
    
    if (Configuration == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (g_RegistryConfigHandle == NULL) {
        return STATUS_INVALID_HANDLE;
    }
    
    // Initialize with defaults
    RtlZeroMemory(Configuration, sizeof(NVFS_CONFIG_WIN));
    Configuration->DebugLevel = NVFS_DEBUG_LEVEL_INFO;
    Configuration->EnableP2P = TRUE;
    Configuration->EnableRdma = FALSE;
    Configuration->MaxConcurrentIOs = 256;
    
    // Load debug level
    status = NvfsGetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_DEBUG_LEVEL,
        REG_DWORD,
        &value,
        sizeof(value),
        &actualLength
    );
    
    if (NT_SUCCESS(status) && actualLength == sizeof(value)) {
        Configuration->DebugLevel = value;
    }
    
    // Load P2P enable flag
    status = NvfsGetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_ENABLE_P2P,
        REG_DWORD,
        &value,
        sizeof(value),
        &actualLength
    );
    
    if (NT_SUCCESS(status) && actualLength == sizeof(value)) {
        Configuration->EnableP2P = (value != 0);
    }
    
    // Load RDMA enable flag
    status = NvfsGetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_ENABLE_RDMA,
        REG_DWORD,
        &value,
        sizeof(value),
        &actualLength
    );
    
    if (NT_SUCCESS(status) && actualLength == sizeof(value)) {
        Configuration->EnableRdma = (value != 0);
    }
    
    // Load max concurrent I/Os
    status = NvfsGetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_MAX_CONCURRENT_IOS,
        REG_DWORD,
        &value,
        sizeof(value),
        &actualLength
    );
    
    if (NT_SUCCESS(status) && actualLength == sizeof(value)) {
        Configuration->MaxConcurrentIOs = value;
    }
    
    return STATUS_SUCCESS;
}

// Save configuration to registry
NTSTATUS
NvfsSaveConfigurationToRegistryWin(
    _In_ PNVFS_CONFIG_WIN Configuration
)
{
    NTSTATUS status;
    ULONG value;
    
    if (Configuration == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (g_RegistryConfigHandle == NULL) {
        return STATUS_INVALID_HANDLE;
    }
    
    // Save debug level
    value = Configuration->DebugLevel;
    status = NvfsSetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_DEBUG_LEVEL,
        REG_DWORD,
        &value,
        sizeof(value)
    );
    
    // Save P2P enable flag
    value = Configuration->EnableP2P ? 1 : 0;
    status = NvfsSetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_ENABLE_P2P,
        REG_DWORD,
        &value,
        sizeof(value)
    );
    
    // Save RDMA enable flag
    value = Configuration->EnableRdma ? 1 : 0;
    status = NvfsSetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_ENABLE_RDMA,
        REG_DWORD,
        &value,
        sizeof(value)
    );
    
    // Save max concurrent I/Os
    value = Configuration->MaxConcurrentIOs;
    status = NvfsSetRegistryValueWin(
        g_RegistryConfigHandle,
        NVFS_REG_VAL_MAX_CONCURRENT_IOS,
        REG_DWORD,
        &value,
        sizeof(value)
    );
    
    return status;
}

// Initialize registry interface
NTSTATUS
NvfsInitializeRegistryInterfaceWin(VOID)
{
    NTSTATUS status;
    
    // Open or create root registry key
    status = NvfsOpenRegistryKeyWin(
        NVFS_REGISTRY_ROOT_PATH,
        KEY_ALL_ACCESS,
        &g_RegistryRootHandle
    );
    
    if (!NT_SUCCESS(status)) {
        nvfs_err("Failed to open registry root key: 0x%08lx\n", status);
        return status;
    }
    
    // Open or create statistics registry key
    status = NvfsOpenRegistryKeyWin(
        NVFS_REGISTRY_STATS_PATH,
        KEY_ALL_ACCESS,
        &g_RegistryStatsHandle
    );
    
    if (!NT_SUCCESS(status)) {
        nvfs_err("Failed to open registry statistics key: 0x%08lx\n", status);
        goto cleanup_root;
    }
    
    // Open or create modules registry key
    status = NvfsOpenRegistryKeyWin(
        NVFS_REGISTRY_MODULES_PATH,
        KEY_ALL_ACCESS,
        &g_RegistryModulesHandle
    );
    
    if (!NT_SUCCESS(status)) {
        nvfs_err("Failed to open registry modules key: 0x%08lx\n", status);
        goto cleanup_stats;
    }
    
    // Open or create configuration registry key
    status = NvfsOpenRegistryKeyWin(
        NVFS_REGISTRY_CONFIG_PATH,
        KEY_ALL_ACCESS,
        &g_RegistryConfigHandle
    );
    
    if (!NT_SUCCESS(status)) {
        nvfs_err("Failed to open registry configuration key: 0x%08lx\n", status);
        goto cleanup_modules;
    }
    
    nvfs_info("Registry interface initialized successfully\n");
    return STATUS_SUCCESS;
    
cleanup_modules:
    if (g_RegistryModulesHandle != NULL) {
        ZwClose(g_RegistryModulesHandle);
        g_RegistryModulesHandle = NULL;
    }
    
cleanup_stats:
    if (g_RegistryStatsHandle != NULL) {
        ZwClose(g_RegistryStatsHandle);
        g_RegistryStatsHandle = NULL;
    }
    
cleanup_root:
    if (g_RegistryRootHandle != NULL) {
        ZwClose(g_RegistryRootHandle);
        g_RegistryRootHandle = NULL;
    }
    
    return status;
}

// Cleanup registry interface
VOID
NvfsCleanupRegistryInterfaceWin(VOID)
{
    if (g_RegistryConfigHandle != NULL) {
        ZwClose(g_RegistryConfigHandle);
        g_RegistryConfigHandle = NULL;
    }
    
    if (g_RegistryModulesHandle != NULL) {
        ZwClose(g_RegistryModulesHandle);
        g_RegistryModulesHandle = NULL;
    }
    
    if (g_RegistryStatsHandle != NULL) {
        ZwClose(g_RegistryStatsHandle);
        g_RegistryStatsHandle = NULL;
    }
    
    if (g_RegistryRootHandle != NULL) {
        ZwClose(g_RegistryRootHandle);
        g_RegistryRootHandle = NULL;
    }
    
    nvfs_info("Registry interface cleaned up\n");
}