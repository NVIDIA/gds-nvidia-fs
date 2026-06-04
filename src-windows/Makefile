# Windows Port of NVIDIA GDS (GPUDirect Storage) Filesystem Driver
# Copyright (c) 2021-2025, NVIDIA CORPORATION. All rights reserved.
#
# This Makefile documents the Linux to Windows migration plan and alternatives
# for building the nvidia-fs Windows kernel driver

# ============================================================================
# LINUX TO WINDOWS MIGRATION ALTERNATIVES
# ============================================================================

# BUILD SYSTEM ALTERNATIVES:
# Linux: GNU Make + Kbuild system
# Windows: MSBuild (Visual Studio) + Windows Driver Kit (WDK)
# Alternative: CMake for cross-platform builds

# KERNEL MODULE ALTERNATIVES:
# Linux: .ko (Kernel Object) loadable kernel modules
# Windows: .sys (System) driver files with INF installation files

# HEADER ALTERNATIVES:
# Linux Headers -> Windows Headers
# linux/module.h -> ntddk.h, wdm.h
# linux/fs.h -> ntifs.h
# linux/mm.h -> wdm.h (memory management)
# linux/pci.h -> wdm.h (PCI functions)
# linux/dma-mapping.h -> wdm.h (DMA functions)
# linux/proc_fs.h -> No direct equivalent (use Registry/WMI)
# linux/slab.h -> wdm.h (ExAllocatePool*)
# linux/mutex.h -> wdm.h (KMUTEX, KeWaitForMutexObject)
# linux/wait.h -> wdm.h (KeWaitForSingleObject)
# linux/ktime.h -> wdm.h (KeQuerySystemTime)
# linux/scatterlist.h -> wdm.h (scatter-gather with MDL)

# FUNCTION ALTERNATIVES:
# Linux Functions -> Windows Functions
# printk() -> DbgPrint(), KdPrint()
# kmalloc()/kfree() -> ExAllocatePool()/ExFreePool()
# copy_from_user()/copy_to_user() -> ProbeForRead()/ProbeForWrite()
# ioremap()/iounmap() -> MmMapIoSpace()/MmUnmapIoSpace()
# request_irq()/free_irq() -> IoConnectInterrupt()/IoDisconnectInterrupt()
# mutex_lock()/mutex_unlock() -> KeWaitForMutexObject()/KeReleaseMutex()
# wait_event()/wake_up() -> KeWaitForSingleObject()/KeSetEvent()
# proc_create() -> Registry APIs or WMI
# register_chrdev() -> IoCreateDevice() + IoCreateSymbolicLink()

# RDMA ALTERNATIVES:
# Linux: InfiniBand/RDMA subsystem
# Windows: Windows RDMA (NetworkDirect), Winsock Direct

# PCI ALTERNATIVES:
# Linux: PCI subsystem functions
# Windows: WDM PCI functions (HalGetBusData, etc.)

# DMA ALTERNATIVES:
# Linux: DMA mapping API
# Windows: DMA_ADAPTER structure, GetDmaAdapter()

# ============================================================================
# BUILD CONFIGURATION
# ============================================================================

# Windows Driver Kit (WDK) path
WDK_PATH ?= C:\Program Files (x86)\Windows Kits\10

# Visual Studio path
VS_PATH ?= C:\Program Files\Microsoft Visual Studio\2022\Professional

# Target Windows version
TARGET_VERSION ?= Win10

# Driver type: KMDF (Kernel-Mode Driver Framework) or WDM (Windows Driver Model)
DRIVER_TYPE ?= KMDF

# Architecture
ARCH ?= x64

# Configuration
CONFIG ?= Release

# ============================================================================
# SOURCE FILE MIGRATION MAPPING
# ============================================================================

# Linux Source -> Windows Source Migration Plan:

# CORE FILES:
# nvfs-core.c      -> nvfs-core-win.c     (Main driver entry/exit, device creation)
# nvfs-core.h      -> nvfs-core-win.h     (Common definitions and structures)
# nvfs-mod.c       -> nvfs-module-win.c   (Module loading/symbol resolution)

# MEMORY MANAGEMENT:
# nvfs-mmap.c      -> nvfs-mmap-win.c     (Memory mapping, GPU P2P via MDL)
# nvfs-mmap.h      -> nvfs-mmap-win.h     (Memory structures)

# DMA ENGINE:
# nvfs-dma.c       -> nvfs-dma-win.c      (DMA operations, storage integration)
# nvfs-dma.h       -> nvfs-dma-win.h      (DMA structures and interfaces)

# PCI MANAGEMENT:
# nvfs-pci.c       -> nvfs-pci-win.c      (PCI device management)
# nvfs-pci.h       -> nvfs-pci-win.h      (PCI structures)

# STATISTICS & INTERFACE:
# nvfs-proc.c      -> nvfs-registry-win.c (Registry interface instead of /proc)
# nvfs-stat.c      -> nvfs-stat-win.c     (WMI/ETW performance counters)
# nvfs-stat.h      -> nvfs-stat-win.h     (Statistics structures)

# RDMA SUPPORT:
# nvfs-rdma.c      -> nvfs-rdma-win.c     (Windows RDMA/NetworkDirect)
# nvfs-rdma.h      -> nvfs-rdma-win.h     (RDMA structures)

# ADDITIONAL FEATURES:
# nvfs-batch.c     -> nvfs-batch-win.c    (Batch operations)
# nvfs-batch.h     -> nvfs-batch-win.h    (Batch structures)
# nvfs-fault.c     -> nvfs-fault-win.c    (Fault injection - debugging)
# nvfs-fault.h     -> nvfs-fault-win.h    (Fault injection structures)

# KERNEL INTERFACE:
# nvfs-kernel-interface.c -> nvfs-kernel-interface-win.c (Windows kernel APIs)
# nvfs-kernel-interface.h -> nvfs-kernel-interface-win.h (Kernel interface defs)

# GPU P2P:
# nvfs-p2p.h       -> nvfs-p2p-win.h      (NVIDIA P2P definitions for Windows)

# VERSIONING:
# nvfs-vers.h      -> nvfs-vers-win.h     (Version definitions)

# BUILD SYSTEM:
# Makefile         -> Makefile (this file)
# configure        -> configure.bat       (Windows configuration script)
# dkms.conf        -> Driver.inf          (Windows driver installation)
# create_nv.symvers.sh -> create_nv_symbols.bat (Symbol resolution)
# GDS_VERSION      -> GDS_VERSION         (Version file)

# ============================================================================
# WINDOWS-SPECIFIC FILES (New)
# ============================================================================

# DRIVER FILES:
# nvidia-fs.inf    -> Driver installation file
# nvidia-fs.cat    -> Catalog file for driver signing
# nvidia-fs.rc     -> Resource file
# sources          -> Build configuration for older WDK

# KMDF FILES (if using KMDF):
# driver.c         -> KMDF driver entry point
# device.c         -> Device object management
# queue.c          -> I/O queue management

# MANIFEST FILES:
# nvidia-fs.man    -> Event manifest for ETW
# nvidia-fs.mc     -> Message catalog

# ============================================================================
# BUILD TARGETS
# ============================================================================

.PHONY: all clean install uninstall help migrate-files

all:
	@echo "Building Windows NVIDIA GDS Driver..."
	@echo "This requires Windows Driver Kit (WDK) and Visual Studio"
	@echo "Run 'msbuild nvidia-fs.sln' to build the driver"

clean:
	@echo "Cleaning Windows build artifacts..."
	@if exist x64 rmdir /s /q x64
	@if exist Debug rmdir /s /q Debug
	@if exist Release rmdir /s /q Release
	@if exist *.log del *.log

install:
	@echo "Installing Windows driver..."
	@echo "Use 'pnputil /add-driver nvidia-fs.inf' or Device Manager"

uninstall:
	@echo "Uninstalling Windows driver..."
	@echo "Use Device Manager or 'pnputil /delete-driver nvidia-fs.inf'"

migrate-files:
	@echo "Creating Windows-specific file structure..."
	@echo "This will create all necessary Windows driver files from Linux sources"

help:
	@echo "Windows NVIDIA GDS Driver Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the Windows driver"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install the driver"
	@echo "  uninstall    - Uninstall the driver"
	@echo "  migrate-files - Create Windows file structure"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  - Windows Driver Kit (WDK)"
	@echo "  - Visual Studio 2019/2022"
	@echo "  - NVIDIA GPU Driver SDK"
	@echo ""
	@echo "Linux to Windows API Alternatives:"
	@echo "  Linux                    Windows"
	@echo "  -----                    -------"
	@echo "  module_init()         -> DriverEntry()"
	@echo "  module_exit()         -> DriverUnload()"
	@echo "  register_chrdev()     -> IoCreateDevice()"
	@echo "  proc_create()         -> Registry/WMI"
	@echo "  kmalloc()             -> ExAllocatePool()"
	@echo "  mutex_lock()          -> KeWaitForMutexObject()"
	@echo "  copy_from_user()      -> ProbeForRead()"
	@echo "  printk()              -> DbgPrint()"
	@echo "  ioremap()             -> MmMapIoSpace()"
	@echo ""
	@echo "Driver Types:"
	@echo "  WDM  - Windows Driver Model (legacy)"
	@echo "  KMDF - Kernel-Mode Driver Framework (recommended)"
	@echo "  UMDF - User-Mode Driver Framework (not applicable)"

# ============================================================================
# MIGRATION NOTES
# ============================================================================

# MAJOR DIFFERENCES:
# 1. Windows uses different memory management (MDL vs scatter-gather)
# 2. Different interrupt handling model
# 3. Registry instead of /proc filesystem
# 4. ETW (Event Tracing for Windows) for logging
# 5. WMI for performance counters
# 6. Different PCI enumeration and configuration
# 7. Windows RDMA (NetworkDirect) instead of InfiniBand verbs
# 8. Different module loading mechanism
# 9. Driver signing requirements
# 10. Different build system and tools

# CHALLENGES:
# 1. NVIDIA P2P API differences between Linux and Windows
# 2. Storage stack integration (different for NVMe, SCSI on Windows)
# 3. RDMA integration with Windows networking stack
# 4. Memory locking and pinning mechanisms
# 5. DMA coherency and synchronization
# 6. Error handling and reporting
# 7. Security and privilege requirements
# 8. Driver signing and certification

# TESTING REQUIREMENTS:
# 1. Windows Hardware Lab Kit (HLK) testing
# 2. Driver Verifier compatibility
# 3. Static Driver Verifier (SDV) analysis
# 4. Code Analysis for Drivers
# 5. Performance testing on Windows storage stack
# 6. RDMA functionality testing
# 7. GPU P2P validation
# 8. Multi-GPU configuration testing