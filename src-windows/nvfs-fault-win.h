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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Fault Injection Header
 */

#ifndef __NVFS_FAULT_WIN_H__
#define __NVFS_FAULT_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Enable fault injection for debug builds by default
#ifdef DBG
#ifndef NVFS_FAULT_INJECTION_WIN
#define NVFS_FAULT_INJECTION_WIN
#endif
#endif

// Fault injection statistics structure
typedef struct _NVFS_FAULT_STATISTICS_WIN {
    ULONG CallCount;        // Number of times fault point was called
    ULONG FailureCount;     // Number of times fault was injected
    ULONG Probability;      // Current failure probability (0-100)
    ULONG FailureRate;      // Actual failure rate percentage
    BOOLEAN Enabled;        // Whether fault injection is enabled
} NVFS_FAULT_STATISTICS_WIN, *PNVFS_FAULT_STATISTICS_WIN;

// Function prototypes
#ifdef NVFS_FAULT_INJECTION_WIN

// Initialization and cleanup
NTSTATUS
NvfsInitializeFaultInjectionWin(VOID);

VOID
NvfsCleanupFaultInjectionWin(VOID);

// Core fault injection functionality
BOOLEAN
NvfsShouldFailWin(
    _In_ PCWSTR FaultPointName
);

// Configuration management
NTSTATUS
NvfsConfigureFaultPointWin(
    _In_ PCWSTR FaultPointName,
    _In_ ULONG Probability
);

// Statistics and monitoring
NTSTATUS
NvfsGetFaultStatisticsWin(
    _In_ PCWSTR FaultPointName,
    _Out_ PNVFS_FAULT_STATISTICS_WIN Statistics
);

VOID
NvfsResetFaultStatisticsWin(
    _In_opt_ PCWSTR FaultPointName
);

NTSTATUS
NvfsGetFaultPointListWin(
    _Out_writes_to_(BufferSize, *RequiredSize) PWSTR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
);

// Configuration persistence
NTSTATUS
NvfsSaveFaultConfigurationWin(VOID);

// Global enable/disable
BOOLEAN
NvfsIsFaultInjectionEnabledWin(VOID);

VOID
NvfsSetFaultInjectionEnabledWin(
    _In_ BOOLEAN Enabled
);

// Fault point name constants (Windows equivalents of Linux fault points)
#define NVFS_FAULT_DMA_ERROR_WIN                    L"DmaError"
#define NVFS_FAULT_RW_VERIFY_AREA_ERROR_WIN         L"RwVerifyAreaError"
#define NVFS_FAULT_GET_USER_PAGES_ERROR_WIN         L"EndFenceGetUserPagesFastError"
#define NVFS_FAULT_INVALID_P2P_GET_PAGE_WIN         L"InvalidP2pGetPage"
#define NVFS_FAULT_IO_TRANSIT_STATE_FAIL_WIN        L"IoTransitStateFail"
#define NVFS_FAULT_PIN_SHADOW_PAGES_ERROR_WIN       L"PinShadowPagesError"
#define NVFS_FAULT_VM_INSERT_PAGE_ERROR_WIN         L"VmInsertPageError"
#define NVFS_FAULT_MEMORY_ALLOCATION_ERROR_WIN      L"MemoryAllocationError"
#define NVFS_FAULT_MDL_ALLOCATION_ERROR_WIN         L"MdlAllocationError"
#define NVFS_FAULT_PCI_CONFIG_READ_ERROR_WIN        L"PciConfigReadError"
#define NVFS_FAULT_REGISTRY_ACCESS_ERROR_WIN        L"RegistryAccessError"
#define NVFS_FAULT_BATCH_SUBMISSION_ERROR_WIN       L"BatchSubmissionError"

// Convenience macros for fault injection
#define NVFS_FAULT_TRIGGER_WIN(faultPoint) \
    NvfsShouldFailWin(faultPoint)

#define NVFS_FAULT_INJECT_WIN(faultPoint, failureCode) \
    do { \
        if (NvfsShouldFailWin(faultPoint)) { \
            return (failureCode); \
        } \
    } while (0)

#define NVFS_FAULT_INJECT_STATUS_WIN(faultPoint, failureStatus) \
    do { \
        if (NvfsShouldFailWin(faultPoint)) { \
            return (failureStatus); \
        } \
    } while (0)

#define NVFS_FAULT_INJECT_NULL_WIN(faultPoint) \
    do { \
        if (NvfsShouldFailWin(faultPoint)) { \
            return NULL; \
        } \
    } while (0)

#define NVFS_FAULT_INJECT_VOID_WIN(faultPoint) \
    do { \
        if (NvfsShouldFailWin(faultPoint)) { \
            return; \
        } \
    } while (0)

// Conditional fault injection (only inject if condition is true)
#define NVFS_FAULT_INJECT_CONDITIONAL_WIN(faultPoint, condition, failureCode) \
    do { \
        if ((condition) && NvfsShouldFailWin(faultPoint)) { \
            return (failureCode); \
        } \
    } while (0)

#else // !NVFS_FAULT_INJECTION_WIN

// Stub implementations when fault injection is disabled
static __inline NTSTATUS NvfsInitializeFaultInjectionWin(VOID) { return STATUS_SUCCESS; }
static __inline VOID NvfsCleanupFaultInjectionWin(VOID) { }
static __inline BOOLEAN NvfsShouldFailWin(_In_ PCWSTR FaultPointName) { UNREFERENCED_PARAMETER(FaultPointName); return FALSE; }
static __inline NTSTATUS NvfsConfigureFaultPointWin(_In_ PCWSTR FaultPointName, _In_ ULONG Probability) { UNREFERENCED_PARAMETER(FaultPointName); UNREFERENCED_PARAMETER(Probability); return STATUS_NOT_SUPPORTED; }
static __inline BOOLEAN NvfsIsFaultInjectionEnabledWin(VOID) { return FALSE; }
static __inline VOID NvfsSetFaultInjectionEnabledWin(_In_ BOOLEAN Enabled) { UNREFERENCED_PARAMETER(Enabled); }

// Empty macros when fault injection is disabled
#define NVFS_FAULT_TRIGGER_WIN(faultPoint) FALSE
#define NVFS_FAULT_INJECT_WIN(faultPoint, failureCode) do { } while (0)
#define NVFS_FAULT_INJECT_STATUS_WIN(faultPoint, failureStatus) do { } while (0)
#define NVFS_FAULT_INJECT_NULL_WIN(faultPoint) do { } while (0)
#define NVFS_FAULT_INJECT_VOID_WIN(faultPoint) do { } while (0)
#define NVFS_FAULT_INJECT_CONDITIONAL_WIN(faultPoint, condition, failureCode) do { } while (0)

#endif // NVFS_FAULT_INJECTION_WIN

// Inline helper functions

static __inline BOOLEAN
NvfsIsFaultPointNameValid(
    _In_opt_ PCWSTR FaultPointName
)
{
    return (FaultPointName != NULL && wcslen(FaultPointName) > 0);
}

static __inline BOOLEAN
NvfsIsProbabilityValid(
    _In_ ULONG Probability
)
{
    return (Probability <= 100);
}

// Fault injection IOCTL codes (for user-mode configuration)
#define NVFS_IOCTL_CONFIGURE_FAULT_POINT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVFS_IOCTL_GET_FAULT_STATISTICS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVFS_IOCTL_RESET_FAULT_STATISTICS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVFS_IOCTL_GET_FAULT_POINT_LIST     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVFS_IOCTL_ENABLE_FAULT_INJECTION   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTL input/output structures
typedef struct _NVFS_FAULT_CONFIG_INPUT_WIN {
    WCHAR FaultPointName[64];   // Fault point name
    ULONG Probability;          // Failure probability (0-100)
} NVFS_FAULT_CONFIG_INPUT_WIN, *PNVFS_FAULT_CONFIG_INPUT_WIN;

typedef struct _NVFS_FAULT_STATISTICS_INPUT_WIN {
    WCHAR FaultPointName[64];   // Fault point name
} NVFS_FAULT_STATISTICS_INPUT_WIN, *PNVFS_FAULT_STATISTICS_INPUT_WIN;

typedef struct _NVFS_FAULT_ENABLE_INPUT_WIN {
    BOOLEAN Enabled;            // Enable/disable fault injection
} NVFS_FAULT_ENABLE_INPUT_WIN, *PNVFS_FAULT_ENABLE_INPUT_WIN;

#endif // __NVFS_FAULT_WIN_H__