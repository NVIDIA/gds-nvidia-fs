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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - PCI Management
 */

// Windows kernel headers
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

// Windows-specific includes
#include "nvfs-core-win.h"
#include "nvfs-pci-win.h"
#include "nvfs-stat-win.h"
#include "config-host-win.h"

// PCI configuration space constants
#define PCI_CAPABILITY_ID_MSIX          0x11
#define PCI_CAPABILITY_ID_PCIE          0x10
#define PCI_CAPABILITY_ID_PM            0x01

// PCIe capability register offsets
#define PCIE_DEVICE_CAPABILITIES_REG    0x04
#define PCIE_DEVICE_CONTROL_REG         0x08
#define PCIE_DEVICE_STATUS_REG          0x0A
#define PCIE_LINK_CAPABILITIES_REG      0x0C
#define PCIE_LINK_CONTROL_REG           0x10
#define PCIE_LINK_STATUS_REG            0x12

// PCIe link speed constants
#define PCIE_LINK_SPEED_25GT            0x01    // 2.5 GT/s
#define PCIE_LINK_SPEED_50GT            0x02    // 5.0 GT/s
#define PCIE_LINK_SPEED_80GT            0x03    // 8.0 GT/s
#define PCIE_LINK_SPEED_160GT           0x04    // 16.0 GT/s
#define PCIE_LINK_SPEED_320GT           0x05    // 32.0 GT/s

// PCIe link width constants
#define PCIE_LINK_WIDTH_1X              0x01
#define PCIE_LINK_WIDTH_2X              0x02
#define PCIE_LINK_WIDTH_4X              0x04
#define PCIE_LINK_WIDTH_8X              0x08
#define PCIE_LINK_WIDTH_16X             0x10
#define PCIE_LINK_WIDTH_32X             0x20

// Windows PCI device information structure
typedef struct _NVFS_PCI_DEV_INFO_WIN {
    PDEVICE_OBJECT DeviceObject;        // Device object
    PDEVICE_OBJECT PhysicalDeviceObject; // PDO
    ULONG BusNumber;                     // PCI bus number
    ULONG DeviceNumber;                  // PCI device number
    ULONG FunctionNumber;                // PCI function number
    USHORT VendorId;                     // PCI vendor ID
    USHORT DeviceId;                     // PCI device ID
    UCHAR RevisionId;                    // PCI revision ID
    UCHAR ClassCode[3];                  // PCI class code
    ULONG SubsystemVendorId;             // Subsystem vendor ID
    ULONG SubsystemDeviceId;             // Subsystem device ID
    BOOLEAN PcieCapable;                 // PCIe capability present
    UCHAR PcieCapabilityOffset;          // PCIe capability offset
    UCHAR MaxPayloadSize;                // Max payload size (128, 256, 512, etc.)
    UCHAR MaxReadRequestSize;            // Max read request size
    UCHAR LinkSpeed;                     // Current link speed
    UCHAR LinkWidth;                     // Current link width
    BOOLEAN MsixSupported;               // MSI-X support
    UCHAR MsixCapabilityOffset;          // MSI-X capability offset
    LIST_ENTRY ListEntry;                // List entry for device tracking
} NVFS_PCI_DEV_INFO_WIN, *PNVFS_PCI_DEV_INFO_WIN;

// Global variables
static LIST_ENTRY g_PciDeviceList;
static FAST_MUTEX g_PciDeviceListMutex;
static BOOLEAN g_PciSubsystemInitialized = FALSE;

// Windows equivalent of reading PCI configuration space
NTSTATUS
NvfsReadPciConfigWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG Offset,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
)
{
    NTSTATUS status;
    KEVENT event;
    IO_STATUS_BLOCK ioStatusBlock;
    PIRP irp;
    PIO_STACK_LOCATION irpStack;
    
    if (DeviceObject == NULL || Buffer == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    irp = IoBuildSynchronousFsdRequest(
        IRP_MJ_PNP,
        DeviceObject,
        NULL,
        0,
        NULL,
        &event,
        &ioStatusBlock
    );
    
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    irpStack = IoGetNextIrpStackLocation(irp);
    irpStack->MinorFunction = IRP_MN_READ_CONFIG;
    irpStack->Parameters.ReadWriteConfig.WhichSpace = PCI_WHICHSPACE_CONFIG;
    irpStack->Parameters.ReadWriteConfig.Buffer = Buffer;
    irpStack->Parameters.ReadWriteConfig.Offset = Offset;
    irpStack->Parameters.ReadWriteConfig.Length = Length;
    
    status = IoCallDriver(DeviceObject, irp);
    
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }
    
    return status;
}

// Windows equivalent of writing PCI configuration space
NTSTATUS
NvfsWritePciConfigWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG Offset,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
)
{
    NTSTATUS status;
    KEVENT event;
    IO_STATUS_BLOCK ioStatusBlock;
    PIRP irp;
    PIO_STACK_LOCATION irpStack;
    
    if (DeviceObject == NULL || Buffer == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    irp = IoBuildSynchronousFsdRequest(
        IRP_MJ_PNP,
        DeviceObject,
        NULL,
        0,
        NULL,
        &event,
        &ioStatusBlock
    );
    
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    irpStack = IoGetNextIrpStackLocation(irp);
    irpStack->MinorFunction = IRP_MN_WRITE_CONFIG;
    irpStack->Parameters.ReadWriteConfig.WhichSpace = PCI_WHICHSPACE_CONFIG;
    irpStack->Parameters.ReadWriteConfig.Buffer = Buffer;
    irpStack->Parameters.ReadWriteConfig.Offset = Offset;
    irpStack->Parameters.ReadWriteConfig.Length = Length;
    
    status = IoCallDriver(DeviceObject, irp);
    
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }
    
    return status;
}

// Find PCI capability offset
UCHAR
NvfsFindPciCapabilityWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR CapabilityId
)
{
    NTSTATUS status;
    UCHAR capabilityPtr;
    UCHAR currentCapability;
    UCHAR offset = 0;
    USHORT statusReg;
    
    // Check if capabilities list is present
    status = NvfsReadPciConfigWin(DeviceObject, FIELD_OFFSET(PCI_COMMON_CONFIG, Status),
                                  &statusReg, sizeof(statusReg));
    if (!NT_SUCCESS(status)) {
        return 0;
    }
    
    if (!(statusReg & PCI_STATUS_CAPABILITIES_LIST)) {
        return 0;
    }
    
    // Get capabilities pointer
    status = NvfsReadPciConfigWin(DeviceObject, FIELD_OFFSET(PCI_COMMON_CONFIG, u.type0.CapabilitiesPtr),
                                  &capabilityPtr, sizeof(capabilityPtr));
    if (!NT_SUCCESS(status)) {
        return 0;
    }
    
    // Walk the capabilities list
    while (capabilityPtr != 0) {
        offset = capabilityPtr;
        
        status = NvfsReadPciConfigWin(DeviceObject, capabilityPtr, &currentCapability, sizeof(currentCapability));
        if (!NT_SUCCESS(status)) {
            break;
        }
        
        if (currentCapability == CapabilityId) {
            return offset;
        }
        
        // Get next capability pointer
        status = NvfsReadPciConfigWin(DeviceObject, capabilityPtr + 1, &capabilityPtr, sizeof(capabilityPtr));
        if (!NT_SUCCESS(status)) {
            break;
        }
    }
    
    return 0;
}

// Get PCIe link information
NTSTATUS
NvfsGetPcieLinkInfoWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PUCHAR LinkSpeed,
    _Out_ PUCHAR LinkWidth
)
{
    NTSTATUS status;
    UCHAR pcieCapOffset;
    USHORT linkStatus;
    
    if (DeviceObject == NULL || LinkSpeed == NULL || LinkWidth == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *LinkSpeed = 0;
    *LinkWidth = 0;
    
    // Find PCIe capability
    pcieCapOffset = NvfsFindPciCapabilityWin(DeviceObject, PCI_CAPABILITY_ID_PCIE);
    if (pcieCapOffset == 0) {
        return STATUS_NOT_FOUND;
    }
    
    // Read link status register
    status = NvfsReadPciConfigWin(DeviceObject,
                                  pcieCapOffset + PCIE_LINK_STATUS_REG,
                                  &linkStatus,
                                  sizeof(linkStatus));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Extract link speed and width
    *LinkSpeed = (UCHAR)(linkStatus & 0x0F);
    *LinkWidth = (UCHAR)((linkStatus >> 4) & 0x3F);
    
    return STATUS_SUCCESS;
}

// Get PCIe maximum payload size
NTSTATUS
NvfsGetPcieMaxPayloadSizeWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PUCHAR MaxPayloadSize
)
{
    NTSTATUS status;
    UCHAR pcieCapOffset;
    USHORT deviceControl;
    
    if (DeviceObject == NULL || MaxPayloadSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *MaxPayloadSize = 0;
    
    // Find PCIe capability
    pcieCapOffset = NvfsFindPciCapabilityWin(DeviceObject, PCI_CAPABILITY_ID_PCIE);
    if (pcieCapOffset == 0) {
        return STATUS_NOT_FOUND;
    }
    
    // Read device control register
    status = NvfsReadPciConfigWin(DeviceObject,
                                  pcieCapOffset + PCIE_DEVICE_CONTROL_REG,
                                  &deviceControl,
                                  sizeof(deviceControl));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Extract max payload size (bits 5-7)
    *MaxPayloadSize = (UCHAR)((deviceControl >> 5) & 0x07);
    
    return STATUS_SUCCESS;
}

// Get PCI device basic information
NTSTATUS
NvfsGetPciDeviceInfoWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PNVFS_PCI_DEV_INFO_WIN DeviceInfo
)
{
    NTSTATUS status;
    PCI_COMMON_CONFIG pciConfig;
    
    if (DeviceObject == NULL || DeviceInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlZeroMemory(DeviceInfo, sizeof(NVFS_PCI_DEV_INFO_WIN));
    
    // Read PCI common configuration header
    status = NvfsReadPciConfigWin(DeviceObject, 0, &pciConfig, sizeof(PCI_COMMON_CONFIG));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Fill basic device information
    DeviceInfo->DeviceObject = DeviceObject;
    DeviceInfo->VendorId = pciConfig.VendorID;
    DeviceInfo->DeviceId = pciConfig.DeviceID;
    DeviceInfo->RevisionId = pciConfig.RevisionID;
    RtlCopyMemory(DeviceInfo->ClassCode, pciConfig.BaseClass, 3);
    DeviceInfo->SubsystemVendorId = pciConfig.u.type0.SubVendorID;
    DeviceInfo->SubsystemDeviceId = pciConfig.u.type0.SubSystemID;
    
    // Check for PCIe capability
    DeviceInfo->PcieCapabilityOffset = NvfsFindPciCapabilityWin(DeviceObject, PCI_CAPABILITY_ID_PCIE);
    DeviceInfo->PcieCapable = (DeviceInfo->PcieCapabilityOffset != 0);
    
    // Get PCIe link information if available
    if (DeviceInfo->PcieCapable) {
        NvfsGetPcieLinkInfoWin(DeviceObject, &DeviceInfo->LinkSpeed, &DeviceInfo->LinkWidth);
        NvfsGetPcieMaxPayloadSizeWin(DeviceObject, &DeviceInfo->MaxPayloadSize);
    }
    
    // Check for MSI-X capability
    DeviceInfo->MsixCapabilityOffset = NvfsFindPciCapabilityWin(DeviceObject, PCI_CAPABILITY_ID_MSIX);
    DeviceInfo->MsixSupported = (DeviceInfo->MsixCapabilityOffset != 0);
    
    return STATUS_SUCCESS;
}

// Register PCI device with NVFS
NTSTATUS
NvfsRegisterPciDeviceWin(
    _In_ PDEVICE_OBJECT DeviceObject
)
{
    NTSTATUS status;
    PNVFS_PCI_DEV_INFO_WIN deviceInfo;
    
    if (DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Allocate device info structure
    deviceInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(NVFS_PCI_DEV_INFO_WIN), 'FPCI');
    if (deviceInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Get device information
    status = NvfsGetPciDeviceInfoWin(DeviceObject, deviceInfo);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(deviceInfo, 'FPCI');
        return status;
    }
    
    // Add to device list
    ExAcquireFastMutex(&g_PciDeviceListMutex);
    InsertTailList(&g_PciDeviceList, &deviceInfo->ListEntry);
    ExReleaseFastMutex(&g_PciDeviceListMutex);
    
    nvfs_info("Registered PCI device: %04X:%04X (PCIe: %s, Link: Gen%d x%d)\n",
              deviceInfo->VendorId, deviceInfo->DeviceId,
              deviceInfo->PcieCapable ? "Yes" : "No",
              deviceInfo->LinkSpeed, deviceInfo->LinkWidth);
    
    return STATUS_SUCCESS;
}

// Unregister PCI device from NVFS
VOID
NvfsUnregisterPciDeviceWin(
    _In_ PDEVICE_OBJECT DeviceObject
)
{
    PLIST_ENTRY listEntry;
    PNVFS_PCI_DEV_INFO_WIN deviceInfo;
    BOOLEAN found = FALSE;
    
    if (DeviceObject == NULL) {
        return;
    }
    
    ExAcquireFastMutex(&g_PciDeviceListMutex);
    
    for (listEntry = g_PciDeviceList.Flink;
         listEntry != &g_PciDeviceList;
         listEntry = listEntry->Flink) {
        
        deviceInfo = CONTAINING_RECORD(listEntry, NVFS_PCI_DEV_INFO_WIN, ListEntry);
        
        if (deviceInfo->DeviceObject == DeviceObject) {
            RemoveEntryList(&deviceInfo->ListEntry);
            found = TRUE;
            break;
        }
    }
    
    ExReleaseFastMutex(&g_PciDeviceListMutex);
    
    if (found) {
        nvfs_info("Unregistered PCI device: %04X:%04X\n",
                  deviceInfo->VendorId, deviceInfo->DeviceId);
        ExFreePoolWithTag(deviceInfo, 'FPCI');
    }
}

// Find PCI device by vendor/device ID
PNVFS_PCI_DEV_INFO_WIN
NvfsFindPciDeviceWin(
    _In_ USHORT VendorId,
    _In_ USHORT DeviceId
)
{
    PLIST_ENTRY listEntry;
    PNVFS_PCI_DEV_INFO_WIN deviceInfo;
    PNVFS_PCI_DEV_INFO_WIN foundDevice = NULL;
    
    ExAcquireFastMutex(&g_PciDeviceListMutex);
    
    for (listEntry = g_PciDeviceList.Flink;
         listEntry != &g_PciDeviceList;
         listEntry = listEntry->Flink) {
        
        deviceInfo = CONTAINING_RECORD(listEntry, NVFS_PCI_DEV_INFO_WIN, ListEntry);
        
        if (deviceInfo->VendorId == VendorId && deviceInfo->DeviceId == DeviceId) {
            foundDevice = deviceInfo;
            break;
        }
    }
    
    ExReleaseFastMutex(&g_PciDeviceListMutex);
    
    return foundDevice;
}

// Calculate PCIe bandwidth in MB/s
ULONG
NvfsCalculatePcieBandwidthWin(
    _In_ UCHAR LinkSpeed,
    _In_ UCHAR LinkWidth
)
{
    ULONG speedMbps;
    ULONG lanes;
    
    // Convert link speed to Mbps
    switch (LinkSpeed) {
        case PCIE_LINK_SPEED_25GT:
            speedMbps = 2500;  // 2.5 GT/s
            break;
        case PCIE_LINK_SPEED_50GT:
            speedMbps = 5000;  // 5.0 GT/s
            break;
        case PCIE_LINK_SPEED_80GT:
            speedMbps = 8000;  // 8.0 GT/s
            break;
        case PCIE_LINK_SPEED_160GT:
            speedMbps = 16000; // 16.0 GT/s
            break;
        case PCIE_LINK_SPEED_320GT:
            speedMbps = 32000; // 32.0 GT/s
            break;
        default:
            speedMbps = 2500;  // Default to PCIe 1.0
            break;
    }
    
    // Determine number of lanes
    switch (LinkWidth) {
        case PCIE_LINK_WIDTH_1X:
            lanes = 1;
            break;
        case PCIE_LINK_WIDTH_2X:
            lanes = 2;
            break;
        case PCIE_LINK_WIDTH_4X:
            lanes = 4;
            break;
        case PCIE_LINK_WIDTH_8X:
            lanes = 8;
            break;
        case PCIE_LINK_WIDTH_16X:
            lanes = 16;
            break;
        case PCIE_LINK_WIDTH_32X:
            lanes = 32;
            break;
        default:
            lanes = 1;
            break;
    }
    
    // Calculate total bandwidth (accounting for 8b/10b encoding overhead)
    return (speedMbps * lanes * 8) / 10 / 8; // Convert to MB/s
}

// Initialize PCI subsystem
NTSTATUS
NvfsInitializePciSubsystemWin(VOID)
{
    if (g_PciSubsystemInitialized) {
        return STATUS_SUCCESS;
    }
    
    InitializeListHead(&g_PciDeviceList);
    ExInitializeFastMutex(&g_PciDeviceListMutex);
    
    g_PciSubsystemInitialized = TRUE;
    
    nvfs_info("PCI subsystem initialized\n");
    return STATUS_SUCCESS;
}

// Cleanup PCI subsystem
VOID
NvfsCleanupPciSubsystemWin(VOID)
{
    PLIST_ENTRY listEntry;
    PNVFS_PCI_DEV_INFO_WIN deviceInfo;
    
    if (!g_PciSubsystemInitialized) {
        return;
    }
    
    ExAcquireFastMutex(&g_PciDeviceListMutex);
    
    while (!IsListEmpty(&g_PciDeviceList)) {
        listEntry = RemoveHeadList(&g_PciDeviceList);
        deviceInfo = CONTAINING_RECORD(listEntry, NVFS_PCI_DEV_INFO_WIN, ListEntry);
        ExFreePoolWithTag(deviceInfo, 'FPCI');
    }
    
    ExReleaseFastMutex(&g_PciDeviceListMutex);
    
    g_PciSubsystemInitialized = FALSE;
    
    nvfs_info("PCI subsystem cleaned up\n");
}