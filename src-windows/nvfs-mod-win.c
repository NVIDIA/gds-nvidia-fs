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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Module Initialization
 */

#include <ntddk.h>
#include <wdf.h>
#include "nvfs-mod-win.h"
#include "nvfs-core-win.h"
#include "nvfs-dma-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-fault-win.h"
#include "nvfs-registry-win.h"

#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN
#include "nvfs-rdma-win.h"
#endif

// Global module state
static BOOLEAN g_ModuleInitialized = FALSE;
static KGUARDED_MUTEX g_ModuleLock;
static LIST_ENTRY g_ModuleList;
static KSPIN_LOCK g_ModuleListLock;

// Module entries for Windows (equivalent of Linux modules_list)
static NVFS_MODULE_ENTRY_WIN g_NvfsModules[] = {
    {
        L"nvidia_fs_core",
        L"NVIDIA GDS Core Module",
        NvfsModuleTypeCore,
        FALSE,
        NULL,
        NULL,
        NULL
    },
    {
        L"nvidia_fs_dma",
        L"NVIDIA GDS DMA Module", 
        NvfsModuleTypeDma,
        FALSE,
        NULL,
        NULL,
        NULL
    },
    {
        L"nvidia_fs_p2p",
        L"NVIDIA GDS P2P Module",
        NvfsModuleTypeP2P,
        FALSE,
        NULL,
        NULL,
        NULL
    },
#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN
    {
        L"nvidia_fs_rdma",
        L"NVIDIA GDS RDMA Module",
        NvfsModuleTypeRdma,
        FALSE,
        NULL,
        NULL,
        NULL
    },
#endif
    // Terminator entry
    {
        NULL,
        NULL,
        NvfsModuleTypeUnknown,
        FALSE,
        NULL,
        NULL,
        NULL
    }
};

// Function prototypes
static NTSTATUS NvfsProbeModuleListWin(VOID);
static VOID NvfsCleanupModuleListWin(VOID);
static NTSTATUS NvfsRegisterModuleWin(PNVFS_MODULE_ENTRY_WIN ModuleEntry);
static VOID NvfsUnregisterModuleWin(PNVFS_MODULE_ENTRY_WIN ModuleEntry);
static PNVFS_MODULE_ENTRY_WIN NvfsFindModuleByNameWin(PCWSTR ModuleName);

NTSTATUS
NvfsInitializeModulesWin(VOID)
{
    NTSTATUS status;
    
    if (g_ModuleInitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }
    
    // Initialize synchronization objects
    KeInitializeGuardedMutex(&g_ModuleLock);
    KeInitializeSpinLock(&g_ModuleListLock);
    InitializeListHead(&g_ModuleList);
    
    KeAcquireGuardedMutex(&g_ModuleLock);
    
    __try {
        // Initialize all core subsystems
        status = NvfsInitializeStatisticsWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsInitializeFaultInjectionWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsInitializeRegistryWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        status = NvfsInitializeDmaWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN
        status = NvfsInitializeRdmaWin();
        if (!NT_SUCCESS(status)) {
            // RDMA is optional, don't fail if not available
            status = STATUS_SUCCESS;
        }
#endif
        
        // Probe and register available modules
        status = NvfsProbeModuleListWin();
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        
        g_ModuleInitialized = TRUE;
        status = STATUS_SUCCESS;
    }
    __finally {
        if (!NT_SUCCESS(status)) {
            // Cleanup on failure
            NvfsCleanupModuleListWin();
        }
        
        KeReleaseGuardedMutex(&g_ModuleLock);
    }
    
    return status;
}

VOID
NvfsCleanupModulesWin(VOID)
{
    if (!g_ModuleInitialized) {
        return;
    }
    
    KeAcquireGuardedMutex(&g_ModuleLock);
    
    // Cleanup all modules
    NvfsCleanupModuleListWin();
    
    // Cleanup core subsystems in reverse order
#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN
    NvfsCleanupRdmaWin();
#endif
    
    NvfsCleanupDmaWin();
    NvfsCleanupRegistryWin();
    NvfsCleanupFaultInjectionWin();
    NvfsCleanupStatisticsWin();
    
    g_ModuleInitialized = FALSE;
    
    KeReleaseGuardedMutex(&g_ModuleLock);
}

NTSTATUS
NvfsRegisterExternalModuleWin(
    _In_ PNVFS_MODULE_REGISTRATION_WIN Registration
)
{
    PNVFS_MODULE_ENTRY_WIN moduleEntry;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!g_ModuleInitialized || Registration == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (Registration->Size < sizeof(NVFS_MODULE_REGISTRATION_WIN)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Allocate new module entry
    moduleEntry = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(NVFS_MODULE_ENTRY_WIN),
        'mGDS'
    );
    
    if (moduleEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(moduleEntry, sizeof(NVFS_MODULE_ENTRY_WIN));
    
    // Copy registration information
    RtlStringCchCopyW(
        moduleEntry->ModuleName,
        ARRAYSIZE(moduleEntry->ModuleName),
        Registration->ModuleName
    );
    
    RtlStringCchCopyW(
        moduleEntry->Description,
        ARRAYSIZE(moduleEntry->Description),
        Registration->Description
    );
    
    moduleEntry->ModuleType = Registration->ModuleType;
    moduleEntry->RegisterFunction = Registration->RegisterFunction;
    moduleEntry->UnregisterFunction = Registration->UnregisterFunction;
    moduleEntry->Context = Registration->Context;
    
    KeAcquireSpinLock(&g_ModuleListLock, &oldIrql);
    
    // Check if module already exists
    if (NvfsFindModuleByNameWin(Registration->ModuleName) != NULL) {
        status = STATUS_DUPLICATE_NAME;
    } else {
        // Register the module
        status = NvfsRegisterModuleWin(moduleEntry);
        if (NT_SUCCESS(status)) {
            InsertTailList(&g_ModuleList, &moduleEntry->ListEntry);
            moduleEntry->Found = TRUE;
        }
    }
    
    KeReleaseSpinLock(&g_ModuleListLock, oldIrql);
    
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleEntry, 'mGDS');
    }
    
    return status;
}

VOID
NvfsUnregisterExternalModuleWin(
    _In_ PCWSTR ModuleName
)
{
    PNVFS_MODULE_ENTRY_WIN moduleEntry;
    KIRQL oldIrql;
    
    if (!g_ModuleInitialized || ModuleName == NULL) {
        return;
    }
    
    KeAcquireSpinLock(&g_ModuleListLock, &oldIrql);
    
    moduleEntry = NvfsFindModuleByNameWin(ModuleName);
    if (moduleEntry != NULL && moduleEntry->Found) {
        RemoveEntryList(&moduleEntry->ListEntry);
        NvfsUnregisterModuleWin(moduleEntry);
        moduleEntry->Found = FALSE;
    }
    
    KeReleaseSpinLock(&g_ModuleListLock, oldIrql);
    
    if (moduleEntry != NULL) {
        ExFreePoolWithTag(moduleEntry, 'mGDS');
    }
}

NTSTATUS
NvfsGetModuleListWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PNVFS_MODULE_INFO_WIN ModuleList,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PNVFS_MODULE_ENTRY_WIN moduleEntry;
    ULONG moduleCount = 0;
    ULONG requiredSize;
    ULONG i;
    
    if (!g_ModuleInitialized || RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Count internal modules
    for (i = 0; g_NvfsModules[i].ModuleName != NULL; i++) {
        moduleCount++;
    }
    
    // Count external modules
    KeAcquireSpinLock(&g_ModuleListLock, &oldIrql);
    
    entry = g_ModuleList.Flink;
    while (entry != &g_ModuleList) {
        moduleCount++;
        entry = entry->Flink;
    }
    
    KeReleaseSpinLock(&g_ModuleListLock, oldIrql);
    
    requiredSize = moduleCount * sizeof(NVFS_MODULE_INFO_WIN);
    *RequiredSize = requiredSize;
    
    if (BufferSize < requiredSize || ModuleList == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlZeroMemory(ModuleList, BufferSize);
    
    // Copy internal module information
    for (i = 0; i < moduleCount && g_NvfsModules[i].ModuleName != NULL; i++) {
        RtlStringCchCopyW(
            ModuleList[i].ModuleName,
            ARRAYSIZE(ModuleList[i].ModuleName),
            g_NvfsModules[i].ModuleName
        );
        
        RtlStringCchCopyW(
            ModuleList[i].Description,
            ARRAYSIZE(ModuleList[i].Description),
            g_NvfsModules[i].Description
        );
        
        ModuleList[i].ModuleType = g_NvfsModules[i].ModuleType;
        ModuleList[i].Loaded = g_NvfsModules[i].Found;
    }
    
    // Copy external module information
    KeAcquireSpinLock(&g_ModuleListLock, &oldIrql);
    
    entry = g_ModuleList.Flink;
    while (entry != &g_ModuleList && i < moduleCount) {
        moduleEntry = CONTAINING_RECORD(entry, NVFS_MODULE_ENTRY_WIN, ListEntry);
        
        RtlStringCchCopyW(
            ModuleList[i].ModuleName,
            ARRAYSIZE(ModuleList[i].ModuleName),
            moduleEntry->ModuleName
        );
        
        RtlStringCchCopyW(
            ModuleList[i].Description,
            ARRAYSIZE(ModuleList[i].Description),
            moduleEntry->Description
        );
        
        ModuleList[i].ModuleType = moduleEntry->ModuleType;
        ModuleList[i].Loaded = moduleEntry->Found;
        
        i++;
        entry = entry->Flink;
    }
    
    KeReleaseSpinLock(&g_ModuleListLock, oldIrql);
    
    return STATUS_SUCCESS;
}

BOOLEAN
NvfsIsModuleInitializedWin(VOID)
{
    return g_ModuleInitialized;
}

// Helper functions

static NTSTATUS
NvfsProbeModuleListWin(VOID)
{
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;
    
    // Initialize internal modules
    for (i = 0; g_NvfsModules[i].ModuleName != NULL; i++) {
        PNVFS_MODULE_ENTRY_WIN moduleEntry = &g_NvfsModules[i];
        
        // Mark core modules as found/loaded
        switch (moduleEntry->ModuleType) {
            case NvfsModuleTypeCore:
            case NvfsModuleTypeDma:
            case NvfsModuleTypeP2P:
                moduleEntry->Found = TRUE;
                break;
                
#ifdef NVFS_ENABLE_RDMA_SUPPORT_WIN
            case NvfsModuleTypeRdma:
                moduleEntry->Found = NvfsIsRdmaEnabledWin();
                break;
#endif
                
            default:
                moduleEntry->Found = FALSE;
                break;
        }
    }
    
    return status;
}

static VOID
NvfsCleanupModuleListWin(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PNVFS_MODULE_ENTRY_WIN moduleEntry;
    
    // Cleanup external modules
    KeAcquireSpinLock(&g_ModuleListLock, &oldIrql);
    
    while (!IsListEmpty(&g_ModuleList)) {
        entry = RemoveHeadList(&g_ModuleList);
        moduleEntry = CONTAINING_RECORD(entry, NVFS_MODULE_ENTRY_WIN, ListEntry);
        
        if (moduleEntry->Found) {
            NvfsUnregisterModuleWin(moduleEntry);
        }
        
        ExFreePoolWithTag(moduleEntry, 'mGDS');
    }
    
    KeReleaseSpinLock(&g_ModuleListLock, oldIrql);
    
    // Mark internal modules as not found
    for (ULONG i = 0; g_NvfsModules[i].ModuleName != NULL; i++) {
        g_NvfsModules[i].Found = FALSE;
    }
}

static NTSTATUS
NvfsRegisterModuleWin(
    _In_ PNVFS_MODULE_ENTRY_WIN ModuleEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (ModuleEntry->RegisterFunction != NULL) {
        __try {
            status = ModuleEntry->RegisterFunction(ModuleEntry->Context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }
    
    return status;
}

static VOID
NvfsUnregisterModuleWin(
    _In_ PNVFS_MODULE_ENTRY_WIN ModuleEntry
)
{
    if (ModuleEntry->UnregisterFunction != NULL) {
        __try {
            ModuleEntry->UnregisterFunction(ModuleEntry->Context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Log error but continue cleanup
        }
    }
}

static PNVFS_MODULE_ENTRY_WIN
NvfsFindModuleByNameWin(
    _In_ PCWSTR ModuleName
)
{
    PLIST_ENTRY entry;
    PNVFS_MODULE_ENTRY_WIN moduleEntry;
    
    // Search external modules
    entry = g_ModuleList.Flink;
    while (entry != &g_ModuleList) {
        moduleEntry = CONTAINING_RECORD(entry, NVFS_MODULE_ENTRY_WIN, ListEntry);
        
        if (wcscmp(moduleEntry->ModuleName, ModuleName) == 0) {
            return moduleEntry;
        }
        
        entry = entry->Flink;
    }
    
    // Search internal modules
    for (ULONG i = 0; g_NvfsModules[i].ModuleName != NULL; i++) {
        if (wcscmp(g_NvfsModules[i].ModuleName, ModuleName) == 0) {
            return &g_NvfsModules[i];
        }
    }
    
    return NULL;
}