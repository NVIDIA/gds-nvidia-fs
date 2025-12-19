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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - Core Module
 */

// Windows kernel headers
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <ntifs.h>
#include <ntstrsafe.h>

// Windows-specific includes
#include "nvfs-core-win.h"
#include "nvfs-batch-win.h"
#include "nvfs-dma-win.h"
#include "nvfs-pci-win.h"
#include "nvfs-stat-win.h"
#include "nvfs-fault-win.h"
#include "nvfs-kernel-interface-win.h"
#include "nvfs-p2p-win.h"
#ifdef NVFS_ENABLE_WIN_RDMA_SUPPORT
#include "nvfs-rdma-win.h"
#endif
#include "nvfs-vers-win.h"

// Windows driver constants
#define NVFS_HOLD_TIME_MS 200
#define MAX_NVFS_DEVICES 16U

// Windows equivalent of Linux constants
#define NVIDIA_DRIVER_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nvlddmkm"
#define NVIDIA_DRIVER_VERSION_VALUE L"Version"
#define NVIDIA_MIN_DRIVER_FOR_VGPU 555

// Global driver state
typedef struct _NVFS_DRIVER_CONTEXT {
    WDFDRIVER WdfDriver;
    WDFDEVICE ControlDevice;
    UNICODE_STRING ControlDeviceName;
    UNICODE_STRING ControlDeviceSymLink;
    FAST_MUTEX ModuleMutex;
    LONG OperationCount;
    KEVENT ShutdownEvent;
    ULONG DeviceCount;
    BOOLEAN ShutdownRequested;
} NVFS_DRIVER_CONTEXT, *PNVFS_DRIVER_CONTEXT;

// Module parameters (equivalent to Linux module parameters)
typedef struct _NVFS_MODULE_PARAMS {
    ULONG DbgEnabled;
    ULONG InfoEnabled;
    ULONG RwStatsEnabled;
    ULONG PeerStatsEnabled;
    ULONG MaxDevices;
    ULONG UseLegacyP2pAllocation;
} NVFS_MODULE_PARAMS, *PNVFS_MODULE_PARAMS;

// Global variables
static NVFS_DRIVER_CONTEXT g_DriverContext = {0};
static NVFS_MODULE_PARAMS g_ModuleParams = {
    .DbgEnabled = 0,
    .InfoEnabled = 1,
    .RwStatsEnabled = 0,
    .PeerStatsEnabled = 0,
    .MaxDevices = MAX_NVFS_DEVICES,
    .UseLegacyP2pAllocation = 1
};

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD NvfsDriverUnload;
EVT_WDF_DEVICE_FILE_CREATE NvfsFileCreate;
EVT_WDF_FILE_CLOSE NvfsFileClose;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL NvfsIoDeviceControl;

NTSTATUS
NvfsCreateControlDevice(
    _In_ WDFDRIVER Driver
);

VOID
NvfsDeleteControlDevice(
    VOID
);

// Utility functions (Windows equivalents of Linux functions)
static FORCEINLINE LONG
NvfsCountOps(VOID)
{
    return InterlockedCompareExchange(&g_DriverContext.OperationCount, 0, 0);
}

static FORCEINLINE VOID
NvfsGetOps(VOID)
{
    InterlockedIncrement(&g_DriverContext.OperationCount);
}

static FORCEINLINE VOID
NvfsPutOps(VOID)
{
    InterlockedDecrement(&g_DriverContext.OperationCount);
}

static FORCEINLINE VOID
NvfsSetDeviceCount(
    _In_ ULONG MaxDevicesParam
)
{
    g_DriverContext.DeviceCount = min(MaxDevicesParam, MAX_NVFS_DEVICES);
    if (g_DriverContext.DeviceCount == 0) {
        g_DriverContext.DeviceCount = MAX_NVFS_DEVICES;
    }
    
    if (g_ModuleParams.DbgEnabled) {
        KdPrint(("NVFS: Device count: %lu\n", g_DriverContext.DeviceCount));
    }
}

ULONG
NvfsGetDeviceCount(VOID)
{
    return g_DriverContext.DeviceCount;
}

// Windows equivalent of nvfs_transit_state function
static BOOLEAN
NvfsTransitState(
    _In_ PNVFS_GPU_ARGS GpuInfo,
    _In_ BOOLEAN Sync,
    _In_ INT From,
    _In_ INT To
)
{
    BOOLEAN IoTransit = TRUE;
    PNVFS_IO_MGROUP NvfsMgroup;
    PNVFS_IO NvfsIo;
    
    // Container_of equivalent for Windows
    NvfsMgroup = CONTAINING_RECORD(GpuInfo, NVFS_IO_MGROUP, GpuInfo);
    NvfsIo = &NvfsMgroup->NvfsIo;
    
    if (g_ModuleParams.DbgEnabled) {
        KdPrint(("NVFS: IO Transit requested from %d->%d NvfsIo: %p\n",
                From, To, NvfsIo));
    }
    
    // Implementation would continue here with Windows-specific state management
    // This is a simplified version - full implementation would include
    // proper synchronization using Windows kernel objects
    
    return IoTransit;
}

// Windows equivalent of get_nvidia_driver_version
static NTSTATUS
GetNvidiaDriverVersion(
    _Out_ PULONG DriverVersion
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING registryPath;
    UNICODE_STRING valueName;
    HANDLE keyHandle = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo = NULL;
    ULONG valueInfoSize;
    ULONG resultLength;
    
    *DriverVersion = 0;
    
    RtlInitUnicodeString(&registryPath, NVIDIA_DRIVER_REG_PATH);
    RtlInitUnicodeString(&valueName, NVIDIA_DRIVER_VERSION_VALUE);
    
    InitializeObjectAttributes(&objectAttributes,
                              &registryPath,
                              OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                              NULL,
                              NULL);
    
    status = ZwOpenKey(&keyHandle, KEY_READ, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    
    // Query value size
    status = ZwQueryValueKey(keyHandle,
                            &valueName,
                            KeyValuePartialInformation,
                            NULL,
                            0,
                            &resultLength);
    
    if (status != STATUS_BUFFER_TOO_SMALL) {
        goto cleanup;
    }
    
    valueInfoSize = resultLength;
    valueInfo = ExAllocatePool2(POOL_FLAG_PAGED, valueInfoSize, 'sfvN');
    if (valueInfo == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    status = ZwQueryValueKey(keyHandle,
                            &valueName,
                            KeyValuePartialInformation,
                            valueInfo,
                            valueInfoSize,
                            &resultLength);
    
    if (NT_SUCCESS(status)) {
        // Parse version information from registry data
        // This is simplified - actual implementation would parse the version string
        *DriverVersion = *(PULONG)valueInfo->Data;
    }

cleanup:
    if (valueInfo != NULL) {
        ExFreePool(valueInfo);
    }
    if (keyHandle != NULL) {
        ZwClose(keyHandle);
    }
    
    return status;
}

// Windows device I/O control handler (equivalent to Linux ioctl)
VOID
NvfsIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_SUCCESS;
    size_t bytesReturned = 0;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    
    UNREFERENCED_PARAMETER(Queue);
    
    // Get input and output buffers
    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            goto complete;
        }
    }
    
    if (OutputBufferLength > 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            goto complete;
        }
    }
    
    // Process I/O control codes (Windows equivalent of Linux ioctl commands)
    switch (IoControlCode) {
        case IOCTL_NVFS_MAP:
            // Handle memory mapping requests
            if (g_ModuleParams.DbgEnabled) {
                KdPrint(("NVFS: IOCTL_NVFS_MAP received\n"));
            }
            // Implementation would call Windows-specific memory mapping functions
            status = STATUS_NOT_IMPLEMENTED;
            break;
            
        case IOCTL_NVFS_READ:
            // Handle read requests
            if (g_ModuleParams.DbgEnabled) {
                KdPrint(("NVFS: IOCTL_NVFS_READ received\n"));
            }
            // Implementation would call Windows storage stack
            status = STATUS_NOT_IMPLEMENTED;
            break;
            
        case IOCTL_NVFS_WRITE:
            // Handle write requests
            if (g_ModuleParams.DbgEnabled) {
                KdPrint(("NVFS: IOCTL_NVFS_WRITE received\n"));
            }
            // Implementation would call Windows storage stack
            status = STATUS_NOT_IMPLEMENTED;
            break;
            
        case IOCTL_NVFS_REMOVE:
            // Handle resource cleanup
            if (g_ModuleParams.DbgEnabled) {
                KdPrint(("NVFS: IOCTL_NVFS_REMOVE received\n"));
            }
            // Implementation would clean up Windows resources
            status = STATUS_NOT_IMPLEMENTED;
            break;
            
        case IOCTL_NVFS_SET_RDMA_REG_INFO:
            // Handle RDMA registration info
            if (g_ModuleParams.DbgEnabled) {
                KdPrint(("NVFS: IOCTL_NVFS_SET_RDMA_REG_INFO received\n"));
            }
            // Implementation would configure Windows RDMA
            status = STATUS_NOT_IMPLEMENTED;
            break;
            
        default:
            if (g_ModuleParams.DbgEnabled) {
                KdPrint(("NVFS: Invalid IOCTL code: 0x%08lx\n", IoControlCode));
            }
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

complete:
    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

// File create handler (equivalent to Linux open)
VOID
NvfsFileCreate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);
    
    ExAcquireFastMutex(&g_DriverContext.ModuleMutex);
    
    NvfsGetOps();
    
    // Register with storage drivers (Windows equivalent)
    status = NvfsBlkRegisterDmaOps();
    if (!NT_SUCCESS(status)) {
        KdPrint(("NVFS: NVFS modules probe failed with status: 0x%08lx\n", status));
        NvfsPutOps();
        goto cleanup;
    }

cleanup:
    ExReleaseFastMutex(&g_DriverContext.ModuleMutex);
    
    // Update statistics
    NvfsStatIncrement(&g_NvfsStats.OpProcess);
    
    if (g_ModuleParams.DbgEnabled) {
        KdPrint(("NVFS: File create status: 0x%08lx\n", status));
    }
    
    WdfRequestComplete(Request, status);
}

// File close handler (equivalent to Linux close)
VOID
NvfsFileClose(
    _In_ WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(FileObject);
    
    ExAcquireFastMutex(&g_DriverContext.ModuleMutex);
    
    NvfsPutOps();
    
    if (NvfsCountOps() == 0) {
        NvfsBlkUnregisterDmaOps();
        if (g_ModuleParams.DbgEnabled) {
            KdPrint(("NVFS: Unregistering DMA ops and NVIDIA P2P ops\n"));
        }
    }
    
    ExReleaseFastMutex(&g_DriverContext.ModuleMutex);
    
    // Update statistics
    NvfsStatDecrement(&g_NvfsStats.OpProcess);
    
    if (g_ModuleParams.DbgEnabled) {
        KdPrint(("NVFS: File close\n"));
    }
}

// Create control device (Windows equivalent of character device)
NTSTATUS
NvfsCreateControlDevice(
    _In_ WDFDRIVER Driver
)
{
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    WDF_FILEOBJECT_CONFIG fileConfig;
    
    // Initialize device name and symbolic link
    RtlInitUnicodeString(&g_DriverContext.ControlDeviceName, L"\\Device\\nvidia-fs");
    RtlInitUnicodeString(&g_DriverContext.ControlDeviceSymLink, L"\\DosDevices\\nvidia-fs");
    
    // Allocate device init structure
    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R);
    if (deviceInit == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    // Set device name
    status = WdfDeviceInitAssignName(deviceInit, &g_DriverContext.ControlDeviceName);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    
    // Configure file object
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, NvfsFileCreate, NvfsFileClose, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);
    
    // Set device attributes
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    deviceAttributes.SynchronizationScope = WdfSynchronizationScopeDevice;
    
    // Create the device
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &g_DriverContext.ControlDevice);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    
    // Create symbolic link
    status = WdfDeviceCreateSymbolicLink(g_DriverContext.ControlDevice, &g_DriverContext.ControlDeviceSymLink);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    
    // Configure I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = NvfsIoDeviceControl;
    
    status = WdfIoQueueCreate(g_DriverContext.ControlDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    
    // Finish initializing the device
    WdfControlFinishInitializing(g_DriverContext.ControlDevice);
    
    KdPrint(("NVFS: Control device created successfully\n"));
    
cleanup:
    if (deviceInit != NULL) {
        WdfDeviceInitFree(deviceInit);
    }
    
    return status;
}

// Delete control device
VOID
NvfsDeleteControlDevice(VOID)
{
    if (g_DriverContext.ControlDevice != NULL) {
        WdfObjectDelete(g_DriverContext.ControlDevice);
        g_DriverContext.ControlDevice = NULL;
    }
}

// Driver unload routine
VOID
NvfsDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);
    
    KdPrint(("NVFS: Driver unloading...\n"));
    
    // Signal shutdown
    g_DriverContext.ShutdownRequested = TRUE;
    KeSetEvent(&g_DriverContext.ShutdownEvent, IO_NO_INCREMENT, FALSE);
    
    // Wait for operations to complete
    while (NvfsCountOps() > 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000 * NVFS_HOLD_TIME_MS; // Convert to 100ns units
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    
    // Cleanup resources
    NvfsDeleteControlDevice();
    NvfsProcCleanup();
    NvfsStatCleanup();
    NvfsFaultCleanup();
    
    KdPrint(("NVFS: Driver unloaded successfully\n"));
}

// Driver entry point (equivalent to Linux module_init)
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driverConfig;
    WDF_OBJECT_ATTRIBUTES driverAttributes;
    ULONG nvidiaDriverVersion;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    KdPrint(("NVFS: Initializing Windows NVIDIA GDS driver\n"));
    
    // Initialize driver context
    RtlZeroMemory(&g_DriverContext, sizeof(g_DriverContext));
    ExInitializeFastMutex(&g_DriverContext.ModuleMutex);
    KeInitializeEvent(&g_DriverContext.ShutdownEvent, NotificationEvent, FALSE);
    
    // Check NVIDIA driver version
    status = GetNvidiaDriverVersion(&nvidiaDriverVersion);
    if (NT_SUCCESS(status)) {
        if (nvidiaDriverVersion >= NVIDIA_MIN_DRIVER_FOR_VGPU) {
            g_ModuleParams.UseLegacyP2pAllocation = 0;
        }
        KdPrint(("NVFS: NVIDIA driver version: %lu\n", nvidiaDriverVersion));
    }
    
    // Configure WDF driver
    WDF_DRIVER_CONFIG_INIT(&driverConfig, WDF_NO_EVENT_CALLBACK);
    driverConfig.EvtDriverUnload = NvfsDriverUnload;
    driverConfig.DriverInitFlags = WdfDriverInitNonPnpDriver;
    
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttributes);
    
    // Create WDF driver object
    status = WdfDriverCreate(DriverObject, RegistryPath, &driverAttributes, &driverConfig, &g_DriverContext.WdfDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("NVFS: WdfDriverCreate failed: 0x%08lx\n", status));
        goto cleanup;
    }
    
    // Set device count
    NvfsSetDeviceCount(g_ModuleParams.MaxDevices);
    
    // Initialize subsystems
    status = NvfsProcInit();
    if (!NT_SUCCESS(status)) {
        KdPrint(("NVFS: NvfsProcInit failed: 0x%08lx\n", status));
        goto cleanup;
    }
    
    status = NvfsStatInit();
    if (!NT_SUCCESS(status)) {
        KdPrint(("NVFS: NvfsStatInit failed: 0x%08lx\n", status));
        goto cleanup;
    }
    
    status = NvfsFaultInit();
    if (!NT_SUCCESS(status)) {
        KdPrint(("NVFS: NvfsFaultInit failed: 0x%08lx\n", status));
        goto cleanup;
    }
    
    // Create control device
    status = NvfsCreateControlDevice(g_DriverContext.WdfDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("NVFS: NvfsCreateControlDevice failed: 0x%08lx\n", status));
        goto cleanup;
    }
    
    KdPrint(("NVFS: Driver initialized successfully\n"));
    return STATUS_SUCCESS;

cleanup:
    // Cleanup on failure
    NvfsFaultCleanup();
    NvfsStatCleanup();
    NvfsProcCleanup();
    
    if (g_DriverContext.WdfDriver != NULL) {
        WdfObjectDelete(g_DriverContext.WdfDriver);
    }
    
    KdPrint(("NVFS: Driver initialization failed: 0x%08lx\n", status));
    return status;
}