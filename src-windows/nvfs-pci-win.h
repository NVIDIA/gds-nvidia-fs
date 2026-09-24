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
 * NVIDIA GDS (GPUDirect Storage) Windows Kernel Driver - PCI Management Header
 */

#ifndef __NVFS_PCI_WIN_H__
#define __NVFS_PCI_WIN_H__

#include <ntddk.h>
#include <wdf.h>

// Forward declarations
typedef struct _NVFS_PCI_DEV_INFO_WIN NVFS_PCI_DEV_INFO_WIN, *PNVFS_PCI_DEV_INFO_WIN;

// PCI configuration space access functions
NTSTATUS
NvfsReadPciConfigWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG Offset,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
);

NTSTATUS
NvfsWritePciConfigWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG Offset,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
);

// PCI capability management functions
UCHAR
NvfsFindPciCapabilityWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR CapabilityId
);

// PCIe-specific functions
NTSTATUS
NvfsGetPcieLinkInfoWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PUCHAR LinkSpeed,
    _Out_ PUCHAR LinkWidth
);

NTSTATUS
NvfsGetPcieMaxPayloadSizeWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PUCHAR MaxPayloadSize
);

ULONG
NvfsCalculatePcieBandwidthWin(
    _In_ UCHAR LinkSpeed,
    _In_ UCHAR LinkWidth
);

// Device management functions
NTSTATUS
NvfsGetPciDeviceInfoWin(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PNVFS_PCI_DEV_INFO_WIN DeviceInfo
);

NTSTATUS
NvfsRegisterPciDeviceWin(
    _In_ PDEVICE_OBJECT DeviceObject
);

VOID
NvfsUnregisterPciDeviceWin(
    _In_ PDEVICE_OBJECT DeviceObject
);

PNVFS_PCI_DEV_INFO_WIN
NvfsFindPciDeviceWin(
    _In_ USHORT VendorId,
    _In_ USHORT DeviceId
);

// Subsystem initialization/cleanup
NTSTATUS
NvfsInitializePciSubsystemWin(VOID);

VOID
NvfsCleanupPciSubsystemWin(VOID);

// PCI constants
#define NVFS_PCI_VENDOR_ID_NVIDIA           0x10DE
#define NVFS_PCI_VENDOR_ID_INTEL            0x8086
#define NVFS_PCI_VENDOR_ID_AMD              0x1022
#define NVFS_PCI_VENDOR_ID_SAMSUNG          0x144D
#define NVFS_PCI_VENDOR_ID_WESTERN_DIGITAL  0x1B96
#define NVFS_PCI_VENDOR_ID_SEAGATE          0x1BB1

// Common NVMe device IDs
#define NVFS_PCI_DEVICE_ID_NVME_GENERIC     0xFFFF

// PCIe speed and width macros for easy conversion
#define NVFS_PCIE_SPEED_TO_MBPS(speed) \
    ((speed) == 1 ? 2500 : \
     (speed) == 2 ? 5000 : \
     (speed) == 3 ? 8000 : \
     (speed) == 4 ? 16000 : \
     (speed) == 5 ? 32000 : 2500)

#define NVFS_PCIE_WIDTH_TO_LANES(width) \
    ((width) == 0x01 ? 1 : \
     (width) == 0x02 ? 2 : \
     (width) == 0x04 ? 4 : \
     (width) == 0x08 ? 8 : \
     (width) == 0x10 ? 16 : \
     (width) == 0x20 ? 32 : 1)

// Inline helper functions

static __inline BOOLEAN
NvfsIsPcieDeviceWin(
    _In_ PNVFS_PCI_DEV_INFO_WIN DeviceInfo
)
{
    return (DeviceInfo != NULL) ? DeviceInfo->PcieCapable : FALSE;
}

static __inline BOOLEAN
NvfsIsMsixSupportedWin(
    _In_ PNVFS_PCI_DEV_INFO_WIN DeviceInfo
)
{
    return (DeviceInfo != NULL) ? DeviceInfo->MsixSupported : FALSE;
}

static __inline ULONG
NvfsGetPcieGenerationWin(
    _In_ UCHAR LinkSpeed
)
{
    switch (LinkSpeed) {
        case 1: return 1; // PCIe 1.0
        case 2: return 2; // PCIe 2.0
        case 3: return 3; // PCIe 3.0
        case 4: return 4; // PCIe 4.0
        case 5: return 5; // PCIe 5.0
        default: return 1;
    }
}

static __inline BOOLEAN
NvfsIsNvmeDeviceWin(
    _In_ PNVFS_PCI_DEV_INFO_WIN DeviceInfo
)
{
    if (DeviceInfo == NULL) {
        return FALSE;
    }
    
    // Check for NVMe controller class code (01:08:02)
    return (DeviceInfo->ClassCode[2] == 0x01 &&  // Mass storage controller
            DeviceInfo->ClassCode[1] == 0x08 &&  // Non-volatile memory controller
            DeviceInfo->ClassCode[0] == 0x02);   // NVM Express
}

static __inline BOOLEAN
NvfsIsStorageDeviceWin(
    _In_ PNVFS_PCI_DEV_INFO_WIN DeviceInfo
)
{
    if (DeviceInfo == NULL) {
        return FALSE;
    }
    
    // Check for mass storage controller class (01:xx:xx)
    return (DeviceInfo->ClassCode[2] == 0x01);
}

static __inline ULONG
NvfsGetMaxPayloadSizeBytesWin(
    _In_ UCHAR MaxPayloadSizeCode
)
{
    // Convert payload size code to actual bytes
    switch (MaxPayloadSizeCode) {
        case 0: return 128;
        case 1: return 256;
        case 2: return 512;
        case 3: return 1024;
        case 4: return 2048;
        case 5: return 4096;
        default: return 128;
    }
}

#endif // __NVFS_PCI_WIN_H__