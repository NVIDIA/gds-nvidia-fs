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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Module Management Header
 */

#ifndef __NVFS_MOD_WIN_H__
#define __NVFS_MOD_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Module type enumeration
typedef enum _NVFS_MODULE_TYPE_WIN {
    NvfsModuleTypeUnknown = 0,
    NvfsModuleTypeCore,
    NvfsModuleTypeDma,
    NvfsModuleTypeP2P,
    NvfsModuleTypeRdma,
    NvfsModuleTypeStorage,
    NvfsModuleTypeExternal
} NVFS_MODULE_TYPE_WIN;

// Module function prototypes
typedef NTSTATUS (*NVFS_MODULE_REGISTER_FUNCTION_WIN)(
    _In_opt_ PVOID Context
);

typedef VOID (*NVFS_MODULE_UNREGISTER_FUNCTION_WIN)(
    _In_opt_ PVOID Context
);

// Module entry structure (Windows equivalent of Linux module_entry)
typedef struct _NVFS_MODULE_ENTRY_WIN {
    LIST_ENTRY ListEntry;                               // For linking in module list
    WCHAR ModuleName[64];                               // Module name
    WCHAR Description[128];                             // Module description
    NVFS_MODULE_TYPE_WIN ModuleType;                    // Module type
    BOOLEAN Found;                                      // Whether module is loaded
    NVFS_MODULE_REGISTER_FUNCTION_WIN RegisterFunction; // Registration function
    NVFS_MODULE_UNREGISTER_FUNCTION_WIN UnregisterFunction; // Unregistration function
    PVOID Context;                                      // Module-specific context
} NVFS_MODULE_ENTRY_WIN, *PNVFS_MODULE_ENTRY_WIN;

// Module registration structure for external modules
typedef struct _NVFS_MODULE_REGISTRATION_WIN {
    ULONG Size;                                         // Size of this structure
    WCHAR ModuleName[64];                               // Module name
    WCHAR Description[128];                             // Module description
    NVFS_MODULE_TYPE_WIN ModuleType;                    // Module type
    NVFS_MODULE_REGISTER_FUNCTION_WIN RegisterFunction; // Registration function
    NVFS_MODULE_UNREGISTER_FUNCTION_WIN UnregisterFunction; // Unregistration function
    PVOID Context;                                      // Module-specific context
} NVFS_MODULE_REGISTRATION_WIN, *PNVFS_MODULE_REGISTRATION_WIN;

// Module information structure for queries
typedef struct _NVFS_MODULE_INFO_WIN {
    WCHAR ModuleName[64];                               // Module name
    WCHAR Description[128];                             // Module description
    NVFS_MODULE_TYPE_WIN ModuleType;                    // Module type
    BOOLEAN Loaded;                                     // Whether module is currently loaded
} NVFS_MODULE_INFO_WIN, *PNVFS_MODULE_INFO_WIN;

// Function prototypes

// Module system initialization and cleanup
NTSTATUS
NvfsInitializeModulesWin(VOID);

VOID
NvfsCleanupModulesWin(VOID);

// External module registration
NTSTATUS
NvfsRegisterExternalModuleWin(
    _In_ PNVFS_MODULE_REGISTRATION_WIN Registration
);

VOID
NvfsUnregisterExternalModuleWin(
    _In_ PCWSTR ModuleName
);

// Module enumeration and information
NTSTATUS
NvfsGetModuleListWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PNVFS_MODULE_INFO_WIN ModuleList,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
);

// Module status checking
BOOLEAN
NvfsIsModuleInitializedWin(VOID);

// Inline helper functions

static __inline BOOLEAN
NvfsIsModuleTypeValidWin(
    _In_ NVFS_MODULE_TYPE_WIN ModuleType
)
{
    return (ModuleType > NvfsModuleTypeUnknown && ModuleType <= NvfsModuleTypeExternal);
}

static __inline PCWSTR
NvfsGetModuleTypeStringWin(
    _In_ NVFS_MODULE_TYPE_WIN ModuleType
)
{
    switch (ModuleType) {
        case NvfsModuleTypeCore:
            return L"Core";
        case NvfsModuleTypeDma:
            return L"DMA";
        case NvfsModuleTypeP2P:
            return L"P2P";
        case NvfsModuleTypeRdma:
            return L"RDMA";
        case NvfsModuleTypeStorage:
            return L"Storage";
        case NvfsModuleTypeExternal:
            return L"External";
        default:
            return L"Unknown";
    }
}

static __inline VOID
NvfsInitializeModuleRegistrationWin(
    _Out_ PNVFS_MODULE_REGISTRATION_WIN Registration,
    _In_ PCWSTR ModuleName,
    _In_ PCWSTR Description,
    _In_ NVFS_MODULE_TYPE_WIN ModuleType,
    _In_opt_ NVFS_MODULE_REGISTER_FUNCTION_WIN RegisterFunction,
    _In_opt_ NVFS_MODULE_UNREGISTER_FUNCTION_WIN UnregisterFunction,
    _In_opt_ PVOID Context
)
{
    RtlZeroMemory(Registration, sizeof(NVFS_MODULE_REGISTRATION_WIN));
    Registration->Size = sizeof(NVFS_MODULE_REGISTRATION_WIN);
    
    RtlStringCchCopyW(
        Registration->ModuleName,
        ARRAYSIZE(Registration->ModuleName),
        ModuleName
    );
    
    RtlStringCchCopyW(
        Registration->Description,
        ARRAYSIZE(Registration->Description),
        Description
    );
    
    Registration->ModuleType = ModuleType;
    Registration->RegisterFunction = RegisterFunction;
    Registration->UnregisterFunction = UnregisterFunction;
    Registration->Context = Context;
}

// IOCTL codes for module management
#define NVFS_IOCTL_GET_MODULE_LIST_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x940, METHOD_BUFFERED, FILE_READ_ACCESS)

#define NVFS_IOCTL_REGISTER_MODULE_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x941, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define NVFS_IOCTL_UNREGISTER_MODULE_WIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x942, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// IOCTL input/output structures
typedef struct _NVFS_GET_MODULE_LIST_OUTPUT_WIN {
    ULONG ModuleCount;                  // Number of modules returned
    NVFS_MODULE_INFO_WIN Modules[1];    // Variable-length array of modules
} NVFS_GET_MODULE_LIST_OUTPUT_WIN, *PNVFS_GET_MODULE_LIST_OUTPUT_WIN;

typedef struct _NVFS_UNREGISTER_MODULE_INPUT_WIN {
    WCHAR ModuleName[64];               // Name of module to unregister
} NVFS_UNREGISTER_MODULE_INPUT_WIN, *PNVFS_UNREGISTER_MODULE_INPUT_WIN;

// Convenience macros

// Module registration helper
#define NVFS_REGISTER_MODULE_WIN(name, desc, type, regFunc, unregFunc, ctx) \
    do { \
        NVFS_MODULE_REGISTRATION_WIN reg; \
        NvfsInitializeModuleRegistrationWin(&reg, (name), (desc), (type), (regFunc), (unregFunc), (ctx)); \
        NvfsRegisterExternalModuleWin(&reg); \
    } while (0)

// Module unregistration helper
#define NVFS_UNREGISTER_MODULE_WIN(name) \
    NvfsUnregisterExternalModuleWin(name)

// Module existence check
#define NVFS_IS_MODULE_LOADED_WIN(name) \
    (NvfsFindModuleByNameWin(name) != NULL && NvfsFindModuleByNameWin(name)->Found)

// Debug and logging macros
#ifdef DBG
#define NVFS_MODULE_DEBUG_PRINT(format, ...) \
    DbgPrint("NVFS_MODULE: " format "\n", __VA_ARGS__)
#else
#define NVFS_MODULE_DEBUG_PRINT(format, ...) ((void)0)
#endif

#define NVFS_MODULE_LOG_ERROR(status, message) \
    do { \
        KdPrint(("NVFS_MODULE_ERROR: %s - Status: 0x%08X\n", (message), (status))); \
    } while (0)

#define NVFS_MODULE_LOG_INFO(message, ...) \
    do { \
        NVFS_MODULE_DEBUG_PRINT(message, __VA_ARGS__); \
    } while (0)

// Module capability flags
typedef enum _NVFS_MODULE_CAPABILITIES_WIN {
    NvfsModuleCapabilityNone            = 0x00000000,
    NvfsModuleCapabilityDMA             = 0x00000001,
    NvfsModuleCapabilityP2P             = 0x00000002,
    NvfsModuleCapabilityRDMA            = 0x00000004,
    NvfsModuleCapabilityBatch           = 0x00000008,
    NvfsModuleCapabilityMemoryMapping   = 0x00000010,
    NvfsModuleCapabilityFaultInjection  = 0x00000020,
    NvfsModuleCapabilityStatistics      = 0x00000040,
    NvfsModuleCapabilityAll             = 0x0000007F
} NVFS_MODULE_CAPABILITIES_WIN;

// Extended module information with capabilities
typedef struct _NVFS_MODULE_INFO_EX_WIN {
    NVFS_MODULE_INFO_WIN BaseInfo;              // Base module information
    NVFS_MODULE_CAPABILITIES_WIN Capabilities;  // Module capabilities
    ULONG Version;                              // Module version
    LARGE_INTEGER LoadTime;                     // When module was loaded
    ULONG_PTR BaseAddress;                      // Module base address (if applicable)
    ULONG Size;                                 // Module size (if applicable)
} NVFS_MODULE_INFO_EX_WIN, *PNVFS_MODULE_INFO_EX_WIN;

// Extended module query function
NTSTATUS
NvfsGetModuleListExWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PNVFS_MODULE_INFO_EX_WIN ModuleList,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
);

// Module dependency management
typedef struct _NVFS_MODULE_DEPENDENCY_WIN {
    WCHAR ModuleName[64];               // Name of dependent module
    NVFS_MODULE_TYPE_WIN ModuleType;    // Type of dependent module
    BOOLEAN Required;                   // Whether dependency is required
} NVFS_MODULE_DEPENDENCY_WIN, *PNVFS_MODULE_DEPENDENCY_WIN;

NTSTATUS
NvfsCheckModuleDependenciesWin(
    _In_reads_(DependencyCount) PNVFS_MODULE_DEPENDENCY_WIN Dependencies,
    _In_ ULONG DependencyCount,
    _Out_ PBOOLEAN AllSatisfied
);

#endif // __NVFS_MOD_WIN_H__