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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Fault Injection System
 */

// Windows kernel headers
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Windows-specific includes
#include "nvfs-fault-win.h"
#include "nvfs-core-win.h"
#include "nvfs-registry-win.h"
#include "config-host-win.h"

#ifdef NVFS_FAULT_INJECTION_WIN

// Global fault injection state
static BOOLEAN g_FaultInjectionEnabled = FALSE;
static FAST_MUTEX g_FaultInjectionMutex;

// Fault injection attributes structure (Windows equivalent of fault_attr)
typedef struct _NVFS_FAULT_ATTR_WIN {
    PCWSTR Name;                    // Fault point name
    volatile LONG Probability;      // Failure probability (0-100)
    volatile LONG CallCount;        // Number of times called
    volatile LONG FailureCount;     // Number of failures injected
    volatile LONG Enabled;          // Enable/disable flag
    ULONG RandomSeed;               // Random seed for this fault point
} NVFS_FAULT_ATTR_WIN, *PNVFS_FAULT_ATTR_WIN;

// Fault injection points (Windows equivalents)
static NVFS_FAULT_ATTR_WIN g_FaultInjectionPoints[] = {
    { L"DmaError", 0, 0, 0, 0, 0x12345678 },
    { L"RwVerifyAreaError", 0, 0, 0, 0, 0x23456789 },
    { L"EndFenceGetUserPagesFastError", 0, 0, 0, 0, 0x3456789A },
    { L"InvalidP2pGetPage", 0, 0, 0, 0, 0x456789AB },
    { L"IoTransitStateFail", 0, 0, 0, 0, 0x56789ABC },
    { L"PinShadowPagesError", 0, 0, 0, 0, 0x6789ABCD },
    { L"VmInsertPageError", 0, 0, 0, 0, 0x789ABCDE },
    { L"MemoryAllocationError", 0, 0, 0, 0, 0x89ABCDEF },
    { L"MdlAllocationError", 0, 0, 0, 0, 0x9ABCDEF0 },
    { L"PciConfigReadError", 0, 0, 0, 0, 0xABCDEF01 },
    { L"RegistryAccessError", 0, 0, 0, 0, 0xBCDEF012 },
    { L"BatchSubmissionError", 0, 0, 0, 0, 0xCDEF0123 }
};

#define NVFS_FAULT_POINT_COUNT_WIN (sizeof(g_FaultInjectionPoints) / sizeof(g_FaultInjectionPoints[0]))

// Registry path for fault injection configuration
#define NVFS_FAULT_INJECTION_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nvidia-fs\\FaultInjection"

// Simple pseudo-random number generator (LCG)
static ULONG
NvfsSimpleRandomWin(
    _Inout_ PULONG Seed
)
{
    *Seed = (*Seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return *Seed;
}

// Get fault injection point by name
static PNVFS_FAULT_ATTR_WIN
NvfsGetFaultPointWin(
    _In_ PCWSTR FaultPointName
)
{
    ULONG i;
    
    if (FaultPointName == NULL) {
        return NULL;
    }
    
    for (i = 0; i < NVFS_FAULT_POINT_COUNT_WIN; i++) {
        if (wcscmp(g_FaultInjectionPoints[i].Name, FaultPointName) == 0) {
            return &g_FaultInjectionPoints[i];
        }
    }
    
    return NULL;
}

// Initialize fault injection subsystem
NTSTATUS
NvfsInitializeFaultInjectionWin(VOID)
{
    NTSTATUS status;
    HANDLE registryHandle = NULL;
    ULONG i;
    
    if (g_FaultInjectionEnabled) {
        return STATUS_SUCCESS;
    }
    
    // Initialize mutex
    ExInitializeFastMutex(&g_FaultInjectionMutex);
    
    // Try to open fault injection registry key
    status = NvfsOpenRegistryKeyWin(
        NVFS_FAULT_INJECTION_REG_PATH,
        KEY_READ,
        &registryHandle
    );
    
    if (NT_SUCCESS(status)) {
        // Load fault injection configuration from registry
        for (i = 0; i < NVFS_FAULT_POINT_COUNT_WIN; i++) {
            PNVFS_FAULT_ATTR_WIN faultPoint = &g_FaultInjectionPoints[i];
            ULONG value;
            
            // Load probability setting
            status = NvfsGetRegistryValueWin(
                registryHandle,
                faultPoint->Name,
                REG_DWORD,
                &value,
                sizeof(value),
                NULL
            );
            
            if (NT_SUCCESS(status)) {
                InterlockedExchange(&faultPoint->Probability, (LONG)value);
                InterlockedExchange(&faultPoint->Enabled, (value > 0) ? 1 : 0);
                nvfs_dbg("Fault injection point '%ws' configured with probability %ld%%\n",
                        faultPoint->Name, value);
            }
        }
        
        ZwClose(registryHandle);
        g_FaultInjectionEnabled = TRUE;
        
        nvfs_info("Fault injection subsystem initialized with registry configuration\n");
    } else {
        // Initialize with default disabled state
        for (i = 0; i < NVFS_FAULT_POINT_COUNT_WIN; i++) {
            PNVFS_FAULT_ATTR_WIN faultPoint = &g_FaultInjectionPoints[i];
            InterlockedExchange(&faultPoint->Probability, 0);
            InterlockedExchange(&faultPoint->Enabled, 0);
            InterlockedExchange(&faultPoint->CallCount, 0);
            InterlockedExchange(&faultPoint->FailureCount, 0);
        }
        
        nvfs_info("Fault injection subsystem initialized with default disabled state\n");
    }
    
    return STATUS_SUCCESS;
}

// Cleanup fault injection subsystem
VOID
NvfsCleanupFaultInjectionWin(VOID)
{
    if (g_FaultInjectionEnabled) {
        g_FaultInjectionEnabled = FALSE;
        nvfs_info("Fault injection subsystem cleaned up\n");
    }
}

// Windows equivalent of should_fail() - determine if fault should be injected
BOOLEAN
NvfsShouldFailWin(
    _In_ PCWSTR FaultPointName
)
{
    PNVFS_FAULT_ATTR_WIN faultPoint;
    ULONG randomValue;
    BOOLEAN shouldFail = FALSE;
    
    if (!g_FaultInjectionEnabled || FaultPointName == NULL) {
        return FALSE;
    }
    
    faultPoint = NvfsGetFaultPointWin(FaultPointName);
    if (faultPoint == NULL) {
        return FALSE;
    }
    
    // Increment call count
    InterlockedIncrement(&faultPoint->CallCount);
    
    // Check if fault injection is enabled for this point
    if (InterlockedCompareExchange(&faultPoint->Enabled, 0, 0) == 0) {
        return FALSE;
    }
    
    // Check probability
    LONG probability = InterlockedCompareExchange(&faultPoint->Probability, 0, 0);
    if (probability <= 0) {
        return FALSE;
    }
    
    // Generate random number and compare with probability
    randomValue = NvfsSimpleRandomWin(&faultPoint->RandomSeed);
    shouldFail = ((randomValue % 100) < (ULONG)probability);
    
    if (shouldFail) {
        InterlockedIncrement(&faultPoint->FailureCount);
        nvfs_dbg("Fault injected at '%ws' (call %ld, failure %ld)\n",
                faultPoint->Name, faultPoint->CallCount, faultPoint->FailureCount);
    }
    
    return shouldFail;
}

// Configure fault injection point
NTSTATUS
NvfsConfigureFaultPointWin(
    _In_ PCWSTR FaultPointName,
    _In_ ULONG Probability
)
{
    PNVFS_FAULT_ATTR_WIN faultPoint;
    
    if (FaultPointName == NULL || Probability > 100) {
        return STATUS_INVALID_PARAMETER;
    }
    
    faultPoint = NvfsGetFaultPointWin(FaultPointName);
    if (faultPoint == NULL) {
        return STATUS_NOT_FOUND;
    }
    
    ExAcquireFastMutex(&g_FaultInjectionMutex);
    
    InterlockedExchange(&faultPoint->Probability, (LONG)Probability);
    InterlockedExchange(&faultPoint->Enabled, (Probability > 0) ? 1 : 0);
    
    ExReleaseFastMutex(&g_FaultInjectionMutex);
    
    nvfs_info("Fault injection point '%ws' configured: %s (probability: %ld%%)\n",
             FaultPointName, (Probability > 0) ? "enabled" : "disabled", Probability);
    
    return STATUS_SUCCESS;
}

// Get fault injection statistics
NTSTATUS
NvfsGetFaultStatisticsWin(
    _In_ PCWSTR FaultPointName,
    _Out_ PNVFS_FAULT_STATISTICS_WIN Statistics
)
{
    PNVFS_FAULT_ATTR_WIN faultPoint;
    
    if (FaultPointName == NULL || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    faultPoint = NvfsGetFaultPointWin(FaultPointName);
    if (faultPoint == NULL) {
        return STATUS_NOT_FOUND;
    }
    
    RtlZeroMemory(Statistics, sizeof(NVFS_FAULT_STATISTICS_WIN));
    
    Statistics->CallCount = InterlockedCompareExchange(&faultPoint->CallCount, 0, 0);
    Statistics->FailureCount = InterlockedCompareExchange(&faultPoint->FailureCount, 0, 0);
    Statistics->Probability = InterlockedCompareExchange(&faultPoint->Probability, 0, 0);
    Statistics->Enabled = (InterlockedCompareExchange(&faultPoint->Enabled, 0, 0) != 0);
    
    if (Statistics->CallCount > 0) {
        Statistics->FailureRate = (ULONG)((Statistics->FailureCount * 100) / Statistics->CallCount);
    }
    
    return STATUS_SUCCESS;
}

// Reset fault injection statistics
VOID
NvfsResetFaultStatisticsWin(
    _In_opt_ PCWSTR FaultPointName
)
{
    ULONG i;
    
    ExAcquireFastMutex(&g_FaultInjectionMutex);
    
    if (FaultPointName != NULL) {
        // Reset specific fault point
        PNVFS_FAULT_ATTR_WIN faultPoint = NvfsGetFaultPointWin(FaultPointName);
        if (faultPoint != NULL) {
            InterlockedExchange(&faultPoint->CallCount, 0);
            InterlockedExchange(&faultPoint->FailureCount, 0);
        }
    } else {
        // Reset all fault points
        for (i = 0; i < NVFS_FAULT_POINT_COUNT_WIN; i++) {
            InterlockedExchange(&g_FaultInjectionPoints[i].CallCount, 0);
            InterlockedExchange(&g_FaultInjectionPoints[i].FailureCount, 0);
        }
    }
    
    ExReleaseFastMutex(&g_FaultInjectionMutex);
    
    nvfs_info("Fault injection statistics reset for '%ws'\n",
             FaultPointName ? FaultPointName : L"all points");
}

// Get list of all fault injection points
NTSTATUS
NvfsGetFaultPointListWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWSTR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
)
{
    ULONG i;
    ULONG totalLength = 0;
    ULONG currentOffset = 0;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Calculate required buffer size
    for (i = 0; i < NVFS_FAULT_POINT_COUNT_WIN; i++) {
        totalLength += (ULONG)(wcslen(g_FaultInjectionPoints[i].Name) + 1) * sizeof(WCHAR);
    }
    totalLength += sizeof(WCHAR); // For final null terminator
    
    *RequiredSize = totalLength;
    
    if (Buffer == NULL || BufferSize < totalLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    // Copy fault point names to buffer
    for (i = 0; i < NVFS_FAULT_POINT_COUNT_WIN; i++) {
        ULONG nameLength = (ULONG)(wcslen(g_FaultInjectionPoints[i].Name) + 1) * sizeof(WCHAR);
        
        if (currentOffset + nameLength > BufferSize) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        
        RtlCopyMemory(&Buffer[currentOffset / sizeof(WCHAR)], 
                     g_FaultInjectionPoints[i].Name, 
                     nameLength);
        currentOffset += nameLength;
    }
    
    // Add final null terminator
    if (currentOffset < BufferSize) {
        Buffer[currentOffset / sizeof(WCHAR)] = L'\0';
    }
    
    return status;
}

// Save fault injection configuration to registry
NTSTATUS
NvfsSaveFaultConfigurationWin(VOID)
{
    NTSTATUS status;
    HANDLE registryHandle = NULL;
    ULONG i;
    
    // Create or open fault injection registry key
    status = NvfsOpenRegistryKeyWin(
        NVFS_FAULT_INJECTION_REG_PATH,
        KEY_ALL_ACCESS,
        &registryHandle
    );
    
    if (!NT_SUCCESS(status)) {
        nvfs_err("Failed to open fault injection registry key: 0x%08lx\n", status);
        return status;
    }
    
    // Save configuration for each fault point
    for (i = 0; i < NVFS_FAULT_POINT_COUNT_WIN; i++) {
        PNVFS_FAULT_ATTR_WIN faultPoint = &g_FaultInjectionPoints[i];
        ULONG probability = (ULONG)InterlockedCompareExchange(&faultPoint->Probability, 0, 0);
        
        status = NvfsSetRegistryValueWin(
            registryHandle,
            faultPoint->Name,
            REG_DWORD,
            &probability,
            sizeof(probability)
        );
        
        if (!NT_SUCCESS(status)) {
            nvfs_warn("Failed to save fault injection setting for '%ws': 0x%08lx\n",
                     faultPoint->Name, status);
        }
    }
    
    ZwClose(registryHandle);
    
    nvfs_info("Fault injection configuration saved to registry\n");
    return STATUS_SUCCESS;
}

// Check if fault injection is enabled
BOOLEAN
NvfsIsFaultInjectionEnabledWin(VOID)
{
    return g_FaultInjectionEnabled;
}

// Enable or disable entire fault injection subsystem
VOID
NvfsSetFaultInjectionEnabledWin(
    _In_ BOOLEAN Enabled
)
{
    g_FaultInjectionEnabled = Enabled;
    
    nvfs_info("Fault injection subsystem %s\n", Enabled ? "enabled" : "disabled");
}

#else // !NVFS_FAULT_INJECTION_WIN

// Stub implementations when fault injection is disabled

NTSTATUS
NvfsInitializeFaultInjectionWin(VOID)
{
    return STATUS_SUCCESS;
}

VOID
NvfsCleanupFaultInjectionWin(VOID)
{
    // No operation
}

BOOLEAN
NvfsShouldFailWin(
    _In_ PCWSTR FaultPointName
)
{
    UNREFERENCED_PARAMETER(FaultPointName);
    return FALSE;
}

NTSTATUS
NvfsConfigureFaultPointWin(
    _In_ PCWSTR FaultPointName,
    _In_ ULONG Probability
)
{
    UNREFERENCED_PARAMETER(FaultPointName);
    UNREFERENCED_PARAMETER(Probability);
    return STATUS_NOT_SUPPORTED;
}

BOOLEAN
NvfsIsFaultInjectionEnabledWin(VOID)
{
    return FALSE;
}

VOID
NvfsSetFaultInjectionEnabledWin(
    _In_ BOOLEAN Enabled
)
{
    UNREFERENCED_PARAMETER(Enabled);
}

#endif // NVFS_FAULT_INJECTION_WIN